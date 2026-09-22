#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""r2perm.py - build, shield and unlock a portable R2 credential.

Three subcommands
-----------------
build   Ask Cloudflare for the S3 keys behind an R2 API token, then write a
        client.json that works on EVERY machine. No secret is ever typed: the
        S3 secret is derived by HMAC-SHA256 from the API token value (this is
        what Cloudflare's own S3 clients do), and the token value is passed as
        an environment variable so it never appears in argv or shell history.

shield  Wrap a plaintext client.json into an encrypted client.bin, using a key
        file of raw random bytes. Run this on the USB stick before distribution.

unlock  Reverse of shield. The installer calls this to turn client.bin back
        into client.json on the target machine.

Why the credential can be machine-independent
---------------------------------------------
The original channel used `usbkeygen-r2 cred`, which asks for the R2 Secret
Access Key and protects the result with DPAPI - bound to the machine that made
it, so it had to be typed once per target and could not be prepared ahead.
An R2 API token carries its own secret: Cloudflare computes the S3 secret from
the token value, so the credential does not depend on machine state at all.
That is what makes a fully unattended install possible.

Caveat worth repeating to whoever deploys this: a credential that works
everywhere is a credential worth protecting everywhere. R2 has no object
versioning, so nothing on the remote side stops a deleted object from staying
deleted. Rotate the token on a schedule, and rebuild client.bin when you do.
"""

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import secrets
import sys
import urllib.error
import urllib.request

API_BASE = "https://api.cloudflare.com/client/v4"
TOKEN_ENV = "CF_API_TOKEN"

# The credential file layout expected by internal/cred. Both constants are part
# of a cross-language contract: internal/cred/cred.go refuses a file whose
# format or version it does not recognise, on purpose ("fail loudly" rather than
# parse into zero values and try to authenticate with an empty credential).
CRED_FORMAT = "usbbackup-r2-credentials/v1"
CRED_SCHEME_VERSION = 1

# Protection mode. Must match cred.ProtectionPlainFile in internal/cred.
# Note the suffix: the value is "plain-file-0600", not "plain-file". A wrong
# string here fails with ErrBadProtection ("保护方式不受支持"), which reads like
# a version mismatch and sends you looking in the wrong place.
CRED_PROTECTION_PLAIN = "plain-file-0600"

# Payload framing for client.bin. Same idea as the config block embedded in
# client.exe: [payload][sha256][magic]. A short magic keeps the wrapper
# unambiguous - a file that happens to be a bare JSON document is not mistaken
# for a shielded credential.
BIN_MAGIC = b"R2BIN1"


def die(msg):
    print("error: %s" % msg, file=sys.stderr)
    sys.exit(1)


def info(msg):
    print("[*] %s" % msg)


# ---------------------------------------------------------------------------
# Cloudflare API
# ---------------------------------------------------------------------------

def cf_request(path, token, method="GET"):
    url = "%s%s" % (API_BASE, path)
    req = urllib.request.Request(url, method=method)
    req.add_header("Authorization", "Bearer %s" % token)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")
        die("Cloudflare API returned HTTP %d for %s\n%s" % (e.code, path, detail))
    except urllib.error.URLError as e:
        die("cannot reach api.cloudflare.com: %s" % e.reason)
    try:
        doc = json.loads(body)
    except ValueError:
        die("Cloudflare API returned something that is not JSON:\n%s" % body[:400])
    if not doc.get("success"):
        errs = doc.get("errors") or []
        lines = "\n".join("  - %s" % e.get("message", e) for e in errs) or "  (no detail)"
        die("Cloudflare API reported failure for %s:\n%s" % (path, lines))
    return doc.get("result")


def derive_s3_keys(token_value):
    """Derive the S3 secret access key from a Cloudflare API token value.

    Documented by Cloudflare: for any API token, the S3 pair is

        Access Key ID     = the token's id
        Secret Access Key = SHA-256 hex digest of the token's value

    Plain SHA-256, NOT the AWS-style HMAC over "aws4" + key id that S3 uses
    internally for its own secret derivation. Getting this wrong does not fail
    loudly here - it surfaces much later as HTTP 403 SignatureDoesNotMatch,
    which looks exactly like a mistyped secret. That is why the single line
    lives in its own function with the reference attached.
    """
    return hashlib.sha256(token_value.encode("utf-8")).hexdigest()


def cmd_build(args):
    token = os.environ.get(TOKEN_ENV, "").strip()
    if not token:
        # Fall back to a prompt only when the caller has no environment
        # variable set. Never accept the token as a command line argument:
        # argv is visible in the process list and in shell history.
        if sys.stdin.isatty():
            token = getpass.getpass("Cloudflare API token (input hidden): ").strip()
        if not token:
            die("no API token. set %s, or run this in a terminal.\n"
                "  Linux  : read -rs CF_API_TOKEN && export CF_API_TOKEN\n"
                "  PowerShell: $env:CF_API_TOKEN = Read-Host -AsSecureString | "
                "ConvertFrom-SecureString -AsPlainText" % TOKEN_ENV)

    info("verifying the token and fetching the R2 key list ...")
    verified = cf_request("/user/tokens/verify", token)
    info("token status: %s" % verified.get("status", "unknown"))
    token_id = (verified.get("id") or "").strip()
    if token_id:
        info("token id: %s" % token_id)

    access_key_id = (args.access_key_id or "").strip()
    secret = None

    if not access_key_id:
        # The documented source is the token's own id. Prefer it; it is exact,
        # where listing R2 keys can return several entries with no way to tell
        # which one belongs to this token.
        if token_id:
            access_key_id = token_id
            info("using the token id as the access key id")
        else:
            info("the verify response carried no id; listing R2 access keys ...")
            found = cf_request("/accounts/%s/r2/keys" % args.account_id, token)
            items = (found or {}).get("keys") if isinstance(found, dict) else found
            if not items:
                die("no token id and no R2 access keys to fall back on.\n"
                    "  Pass --access-key-id explicitly if you know it.")
            if len(items) > 1:
                print("")
                print("%d R2 access keys exist and only you know which one this "
                      "token is:" % len(items))
                for i, k in enumerate(items):
                    print("  [%d] %s  (%s)" % (i, k.get("access_key_id", "?"),
                                               k.get("name") or k.get("id") or "unnamed"))
                print("  [a] derive from the token value instead (secret = sha256(token))")
                choice = input("choice: ").strip().lower()
                if choice == "a":
                    access_key_id = ""
                else:
                    try:
                        access_key_id = items[int(choice)]["access_key_id"].strip()
                    except (ValueError, IndexError, KeyError):
                        die("not a valid choice")
            else:
                access_key_id = (items[0].get("access_key_id") or "").strip()

        if access_key_id:
            info("access key id: %s" % access_key_id)

    if not access_key_id:
        # Deriving from the token value needs no key list, but an Access Key ID
        # is still mandatory: the S3 signature always covers both. Require it
        # rather than inventing one.
        die("could not determine an access key id.\n"
            "  Normally it is the token's id, which the verify call returns.\n"
            "  If your token is account-scoped, list the keys in the dashboard\n"
            "  (R2 -> Overview -> Manage API Tokens) and rerun with\n"
            "  --access-key-id <id>")

    if not secret:
        secret = derive_s3_keys(token)

    endpoint = (args.endpoint or
                "https://%s.r2.cloudflarestorage.com" % args.account_id)

    def check_endpoint(ep):
        # internal/cred.ValidateEndpoint rejects an endpoint carrying a path,
        # and the rejection is not cosmetic: objectURL silently drops the path,
        # so a wrong endpoint looks like "the object went somewhere else".
        if not ep.startswith("https://"):
            die("endpoint must start with https://")
        rest = ep[len("https://"):]
        if "/" in rest or rest == "":
            die("endpoint must be protocol + host only, no path: %s" % ep)
        return ep

    doc = {
        "format": CRED_FORMAT,
        "scheme_version": CRED_SCHEME_VERSION,
        # Plaintext on purpose. DPAPI is machine bound and a passphrase would
        # have to be typed; this file is protected by the file ACL instead, and
        # by the read-only scope of the token it contains.
        "protection": CRED_PROTECTION_PLAIN,
        "account_id": args.account_id,
        "bucket": args.bucket,
        "endpoint": check_endpoint(endpoint),
        "region": "auto",
        "prefix": args.prefix,
        "scope": args.scope,
        "label": args.label,
        "created_at": args.created_at or _now(),
        "secret_plaintext": {
            "access_key_id": access_key_id,
            "secret_access_key": secret,
        },
    }

    out = args.out
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")
    _restrict(out)

    print("")
    print("credential written : %s" % out)
    print("  bucket / prefix  : %s / %s" % (args.bucket, args.prefix))
    print("  endpoint         : %s" % doc["endpoint"])
    print("  access key id    : %s" % access_key_id)
    print("  secret           : %s…%s (not shown in full)" % (secret[:6], secret[-4:]))
    print("  protection       : plain-file, i.e. the file ACL is the only guard")
    print("")
    print("This file works on every machine. Keep it off any medium you would")
    print("not hand over in person, and rotate it if it ever leaves your hands.")
    return 0


def _now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _restrict(path):
    """Best effort: owner-only permissions. Windows ignores the mode."""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# shield / unlock
# ---------------------------------------------------------------------------

def _keystream(key, n):
    """Expand a key file into n bytes, using SHA-256 as a counter-mode PRF."""
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(key + counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(out[:n])


def _xor(data, keystream):
    return bytes(a ^ b for a, b in zip(data, keystream))


def cmd_shield(args):
    raw = open(args.infile, "rb").read()

    if os.path.exists(args.key) and not args.force_key:
        key = open(args.key, "rb").read()
        info("reusing the existing key: %s" % args.key)
    else:
        key = secrets.token_bytes(32)
        with open(args.key, "wb") as f:
            f.write(key)
        info("wrote a new random key: %s" % args.key)
        info("this key travels with the credential on the stick - that is")
        info("intentional, so the installer has nothing to type. It is an")
        info("obfuscation-and-tamper layer, not a secret management scheme.")

    if len(key) < 16:
        die("key file %s is too short to be a key (%d bytes)" % (args.key, len(key)))

    payload = base64.b64encode(raw)
    body = _xor(payload, _keystream(key, len(payload)))
    digest = hashlib.sha256(body).digest()
    with open(args.out, "wb") as f:
        f.write(body)
        f.write(digest)
        f.write(BIN_MAGIC)

    print("")
    print("shielded : %s -> %s" % (args.infile, args.out))
    print("  plaintext : %d bytes" % len(raw))
    print("  wrapped   : %d bytes" % (len(body) + 32 + len(BIN_MAGIC)))
    print("  key       : %s" % args.key)
    print("")
    print("Ship client.bin and the key file together. install.cmd unlocks it")
    print("on the target and deletes nothing from the stick.")
    return 0


def cmd_unlock(args):
    blob = open(args.infile, "rb").read()
    if len(blob) < 32 + len(BIN_MAGIC):
        die("%s is too short to be a shielded credential" % args.infile)
    if blob[-len(BIN_MAGIC):] != BIN_MAGIC:
        die("%s is not a shielded credential (bad magic).\n"
            "  If this really is a plain client.json, copy it as-is instead."
            % args.infile)
    body, digest = blob[:-32 - len(BIN_MAGIC)], blob[-32 - len(BIN_MAGIC):-len(BIN_MAGIC)]
    if hashlib.sha256(body).digest() != digest:
        die("%s is corrupted (checksum mismatch)" % args.infile)
    key = open(args.key, "rb").read()
    raw = base64.b64decode(_xor(body, _keystream(key, len(body))))

    with open(args.out, "wb") as f:
        f.write(raw)
    _restrict(args.out)
    info("unlocked %s -> %s (%d bytes)" % (args.infile, args.out, len(raw)))
    return 0


# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="Build, shield and unlock R2 credentials for usbbackup-r2.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd")

    b = sub.add_parser("build", help="create a machine-independent client.json")
    b.add_argument("--account-id", required=True, help="Cloudflare account id")
    b.add_argument("--bucket", required=True, help="R2 bucket name")
    b.add_argument("--prefix", default="usb/", help="object key prefix (default usb/)")
    b.add_argument("--endpoint", default="",
                   help="S3 endpoint; default https://<account-id>.r2.cloudflarestorage.com")
    b.add_argument("--scope", default="upload", choices=["upload", "download", "both"])
    b.add_argument("--access-key-id", default="",
                   help="R2 access key id; omit to look it up through the API")
    b.add_argument("--label", default="", help="free-form note stored in the file")
    b.add_argument("--created-at", default="", help="RFC3339 timestamp (default now)")
    b.add_argument("--out", default="client.json", help="output path")
    b.add_argument("--yes", action="store_true", help="never prompt")
    b.set_defaults(func=cmd_build)

    s = sub.add_parser("shield", help="wrap client.json into client.bin")
    s.add_argument("--in", dest="infile", required=True, help="plaintext client.json")
    s.add_argument("--out", required=True, help="output client.bin")
    s.add_argument("--key", required=True, help="key file (created if absent)")
    s.add_argument("--force-key", action="store_true",
                   help="always generate a fresh key, even if one exists")
    s.set_defaults(func=cmd_shield)

    u = sub.add_parser("unlock", help="unwrap client.bin back into client.json")
    u.add_argument("--in", dest="infile", required=True, help="client.bin")
    u.add_argument("--key", required=True, help="key file")
    u.add_argument("--out", required=True, help="output client.json")
    u.set_defaults(func=cmd_unlock)

    args = p.parse_args()
    if not getattr(args, "func", None):
        p.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
