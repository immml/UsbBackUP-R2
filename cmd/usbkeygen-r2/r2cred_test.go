package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/immml/UsbBackUP-R2/internal/cred"
)

// writeR2Conf 落一份 --from 用的 R2 配置文件。
func writeR2Conf(t *testing.T, dir, scope string) string {
	t.Helper()
	p := filepath.Join(dir, "r2.json")
	body := `{
  "account_id": "acct0000000000000000000000000000",
  "bucket": "usbbackup",
  "endpoint": "https://acct0000000000000000000000000000.r2.cloudflarestorage.com",
  "region": "auto",
  "prefix": "usb/",
  "access_key_id": "AKIDTEST000000000000000000000000",
  "secret_access_key": "secret-test-0000000000000000000000",
  "label": "unit-test",
  "scope": "` + scope + `"
}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("写 r2.json 失败：%v", err)
	}
	return p
}

// runCred 跑一次 cred 子命令，返回产物里的 scope。
func runCred(t *testing.T, dir string, extra ...string) string {
	t.Helper()
	out := filepath.Join(dir, "client.json")
	args := append([]string{
		"--yes",
		"--out", out,
		"--from", filepath.Join(dir, "r2.json"),
		"--secret-file", func() string {
			sp := filepath.Join(dir, "secret.txt")
			if err := os.WriteFile(sp, []byte("secret-test-0000000000000000000000\n"), 0o600); err != nil {
				t.Fatalf("写 secret 失败：%v", err)
			}
			return sp
		}(),
		"--plain-file", // 测试要在任意平台成立，不依赖 DPAPI
		"--force",
	}, extra...)

	var stdout, stderr bytes.Buffer
	if code := cmdCred(args, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("cmdCred 返回 %d\nstdout=%s\nstderr=%s", code, stdout.String(), stderr.String())
	}
	c, err := cred.Load(out, cred.WithAllowPlainFile())
	if err != nil {
		t.Fatalf("读回凭据失败：%v", err)
	}
	defer c.Zero()
	return c.Scope
}

// scope 是唯一一个"默认值本身也是合法取值"的字段，所以合并 --from 时不能
// 用 `== ""` 判"未给"——否则显式的 `--scope upload` 会被文件里的 both 反盖。
// 三条分支都钉住，免得日后有人把写法改回 `fs.String("scope", "upload", ...)`。
func TestCredScopePrecedence(t *testing.T) {
	t.Run("显式 --scope 覆盖文件", func(t *testing.T) {
		dir := t.TempDir()
		writeR2Conf(t, dir, cred.ScopeBoth)

		got := runCred(t, dir, "--scope", cred.ScopeUpload)
		if got != cred.ScopeUpload {
			t.Errorf("显式 --scope upload 应压过文件的 both，实际得到 %q", got)
		}
	})

	t.Run("不给 --scope 时文件说了算", func(t *testing.T) {
		dir := t.TempDir()
		writeR2Conf(t, dir, cred.ScopeBoth)

		if got := runCred(t, dir); got != cred.ScopeBoth {
			t.Errorf("未给 --scope 时应沿用文件的 both，实际得到 %q", got)
		}
	})

	t.Run("显式 --scope 压过不同的文件取值", func(t *testing.T) {
		dir := t.TempDir()
		writeR2Conf(t, dir, cred.ScopeUpload)

		if got := runCred(t, dir, "--scope", cred.ScopeDownload); got != cred.ScopeDownload {
			t.Errorf("显式 --scope download 应压过文件的 upload，实际得到 %q", got)
		}
	})

	t.Run("文件没写 scope 时回落到 upload", func(t *testing.T) {
		dir := t.TempDir()
		writeR2Conf(t, dir, "")

		if got := runCred(t, dir); got != cred.ScopeUpload {
			t.Errorf("文件无 scope 且未给 --scope 时应回落 upload，实际得到 %q", got)
		}
	})
}
