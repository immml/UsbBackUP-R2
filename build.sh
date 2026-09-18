#!/usr/bin/env bash
# usbbackup-r2 build script (bash / Git Bash / WSL / Linux cross-compile).
#
# Usage:
#   ./build.sh                  Build all 5 executables into ./dist/
#   ./build.sh -v 0.2.0         Set the version string
#   ./build.sh -t               Run gofmt + go vet + go test first
#   ./build.sh -c               Remove dist/ before building
#
# Standard library only: no network access, no dependency download.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST="$ROOT/dist"          # MSYS 路径，仅给 shell 内建/ls 用
DIST_OUT="dist"            # 传给 go.exe 的必须是**相对**路径，见下方说明
VERSION=""
RUN_TESTS=0
CLEAN=0

while getopts "v:tch" opt; do
  case "$opt" in
    v) VERSION="$OPTARG" ;;
    t) RUN_TESTS=1 ;;
    c) CLEAN=1 ;;
    h) sed -n '2,12p' "$0"; exit 0 ;;
    *) exit 1 ;;
  esac
done

if [ -z "$VERSION" ]; then
  VERSION="$(date +%Y.%m.%d)-dev"
fi

# Resolve go: PATH first, then the isolated toolchain directory.
if command -v go >/dev/null 2>&1; then
  GO="$(command -v go)"
elif [ -x "$HOME/.workbuddy/binaries/go/versions" ]; then
  GO="$(ls -d "$HOME"/.workbuddy/binaries/go/versions/*/bin/go 2>/dev/null | sort -V | tail -1)"
else
  echo "go not found. Install Go 1.24+ and add it to PATH." >&2
  exit 1
fi

if [ "$CLEAN" = "1" ]; then rm -rf "$DIST"; fi
mkdir -p "$DIST"

COMMIT="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo nogit)"
BUILD_TIME="$(date +%Y-%m-%dT%H:%M:%S%z)"
BUILD_USER="$(whoami 2>/dev/null || echo unknown)"

LD="-s -w \
-X github.com/immml/UsbBackUP-R2/internal/version.Version=$VERSION \
-X github.com/immml/UsbBackUP-R2/internal/version.Commit=$COMMIT \
-X github.com/immml/UsbBackUP-R2/internal/version.BuildTime=$BUILD_TIME \
-X github.com/immml/UsbBackUP-R2/internal/version.BuildUser=$BUILD_USER"

echo "go      : $GO"
echo "version : $VERSION"

cd "$ROOT"

if [ "$RUN_TESTS" = "1" ]; then
  echo "[1/4] gofmt";  fmt_out="$("$GO" fmt ./...)"; [ -z "$fmt_out" ] || echo "$fmt_out"
  echo "[2/4] go vet"; "$GO" vet ./...
  echo "[3/4] go test"; "$GO" test ./...
fi

echo "[4/4] build"
export GOOS=windows GOARCH=amd64 CGO_ENABLED=0

# usbbackup-r2 is a background daemon: windowsgui subsystem avoids a console window.
#
# NOTE: -o must be a RELATIVE path. go.exe is a native Windows binary and does not
# understand MSYS paths: an absolute "/d/Users/..." is taken as "D:\d\Users\..." and
# the artifacts silently land in a stray D:\d tree (7 MB x5, no error raised).
# The script has already cd'd into $ROOT, so "dist/xxx.exe" is unambiguous.
"$GO" build -trimpath -ldflags "$LD -H=windowsgui" -o "$DIST_OUT/usbbackup-r2.exe"  ./cmd/usbbackup-r2
"$GO" build -trimpath -ldflags "$LD"                -o "$DIST_OUT/usbkeygen-r2.exe" ./cmd/usbkeygen-r2
"$GO" build -trimpath -ldflags "$LD"                -o "$DIST_OUT/usbsetup-r2.exe"  ./cmd/usbsetup-r2
"$GO" build -trimpath -ldflags "$LD"                -o "$DIST_OUT/usbcomp-r2.exe"   ./cmd/usbcomp-r2
"$GO" build -trimpath -ldflags "$LD"                -o "$DIST_OUT/usbunseal-r2.exe" ./cmd/usbunseal-r2

echo ""
echo "build finished, artifacts in $DIST"
ls -lh "$DIST"/*.exe
