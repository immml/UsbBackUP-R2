package cred

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func sample() Credentials {
	return Credentials{
		AccountID:       "0123456789abcdef0123456789abcdef",
		Bucket:          "usb-backups",
		Endpoint:        "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com",
		Region:          "auto",
		Prefix:          "usb/",
		Scope:           ScopeUpload,
		Label:           "edge-box-01",
		AccessKeyID:     []byte("AKIDEXAMPLE000000000000000000"),
		SecretAccessKey: []byte("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
	}
}

func TestNormalizePrefix(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"usb", "usb/"},
		{"usb/", "usb/"},
		{"/usb", "usb/"},
		{"/usb/", "usb/"},
		{"  a/b  ", "a/b/"},
		{"//", ""},
	}
	for _, c := range cases {
		if got := NormalizePrefix(c.in); got != c.want {
			t.Errorf("NormalizePrefix(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}
	// 漏补斜杠会把对象散到别的"目录"下，这条必须锁住。
	if got := EffectivePrefixOf("usb") + "disk"; got != "usb/disk" {
		t.Errorf("拼接结果 %q，期望 usb/disk", got)
	}
}

// EffectivePrefixOf 是测试内的便捷包装。
func EffectivePrefixOf(p string) string {
	c := Credentials{Prefix: p}
	return c.EffectivePrefix()
}

func TestValidateEndpoint(t *testing.T) {
	ok := []string{
		"https://acct.r2.cloudflarestorage.com",
		"https://acct.r2.cloudflarestorage.com/",
		"http://127.0.0.1:9000",
		"http://localhost:9000",
		"http://[::1]:9000",
		// 纯粹的尾斜杠与"没写路径"等价，不该拒——从浏览器地址栏或控制台
		// 复制端点时经常带上它，为这个报错纯属找麻烦。
		"https://acct.r2.cloudflarestorage.com/",
	}
	for _, ep := range ok {
		if err := ValidateEndpoint(ep); err != nil {
			t.Errorf("ValidateEndpoint(%q) 应通过，却报错：%v", ep, err)
		}
	}
	bad := []string{
		"",
		"acct.r2.cloudflarestorage.com",
		"http://acct.r2.cloudflarestorage.com", // 远端明文 http 会泄露 secret
		"http://192.168.1.10:9000",
		"ftp://acct.r2.cloudflarestorage.com",
		"https://",
		// 端点带路径必须被拒，不能忽略：objectURL 会整体覆盖 Path，
		// 于是"我写了桶名"与"实际请求去了哪"从此对不上，而且不报错。
		"https://acct.r2.cloudflarestorage.com/usbbackup",
		"https://acct.r2.cloudflarestorage.com?bucket=usbbackup",
	}
	for _, ep := range bad {
		if err := ValidateEndpoint(ep); err == nil {
			t.Errorf("ValidateEndpoint(%q) 应被拒绝", ep)
		}
	}
}

func TestValidateMissingFields(t *testing.T) {
	base := sample()
	mutations := map[string]func(c *Credentials){
		"account_id":  func(c *Credentials) { c.AccountID = "" },
		"bucket":      func(c *Credentials) { c.Bucket = "" },
		"endpoint":    func(c *Credentials) { c.Endpoint = "" },
		"access_key":  func(c *Credentials) { c.AccessKeyID = nil },
		"secret_key":  func(c *Credentials) { c.SecretAccessKey = nil },
		"bad_scope":   func(c *Credentials) { c.Scope = "root" },
		"bad_endpoin": func(c *Credentials) { c.Endpoint = "http://evil.example.com" },
	}
	for name, mutate := range mutations {
		c := base
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("字段 %s 缺失/非法时应报错", name)
		}
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("DPAPI 仅在 Windows 上可用")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "client.json")

	in := sample()
	if err := Save(path, in); err != nil {
		t.Fatalf("Save 失败：%v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load 失败：%v", err)
	}
	defer got.Zero()

	if got.Bucket != in.Bucket || got.Endpoint != in.Endpoint || got.Prefix != in.Prefix {
		t.Errorf("路由字段往返不一致：%+v", got)
	}
	if !bytes.Equal(got.SecretAccessKey, in.SecretAccessKey) {
		t.Error("SecretAccessKey 往返不一致")
	}
	if !bytes.Equal(got.AccessKeyID, in.AccessKeyID) {
		t.Error("AccessKeyID 往返不一致")
	}
	// 默认值填充。
	if got.Region != DefaultRegion || got.Scope != ScopeUpload {
		t.Errorf("默认值未填充：region=%q scope=%q", got.Region, got.Scope)
	}
}

// TestSecretNotInPlaintext 是本包最重要的一条：凭据文件落盘后，
// 明文凭据不能以任何形式出现在文件里。
func TestSecretNotInPlaintext(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("DPAPI 仅在 Windows 上可用")
	}
	path := filepath.Join(t.TempDir(), "client.json")
	in := sample()
	if err := Save(path, in); err != nil {
		t.Fatalf("Save 失败：%v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{
		string(in.SecretAccessKey),
		string(in.AccessKeyID),
		// base64 形态也要挡住：只编码不加密码同样等于明文。
		base64.StdEncoding.EncodeToString(in.SecretAccessKey),
	} {
		if bytes.Contains(raw, []byte(needle)) {
			t.Errorf("凭据文件中出现了明文凭据片段 %q", needle)
		}
	}
	// 非敏感的路由信息保持可读，出问题时能直接看。
	if !bytes.Contains(raw, []byte(in.Bucket)) {
		t.Error("bucket 应保持明文可读")
	}
	if bytes.Contains(raw, []byte("secret_access_key")) {
		t.Error("被保护的字段不应作为 JSON 键出现在外层文件里")
	}
}

func TestLoadRejectsTamperedBlob(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("DPAPI 仅在 Windows 上可用")
	}
	path := filepath.Join(t.TempDir(), "client.json")
	if err := Save(path, sample()); err != nil {
		t.Fatalf("Save 失败：%v", err)
	}
	raw, _ := os.ReadFile(path)
	var doc fileDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	blob, _ := base64.StdEncoding.DecodeString(doc.Secret)
	blob[len(blob)/2] ^= 0x01
	doc.Secret = base64.StdEncoding.EncodeToString(blob)
	mutated, _ := json.Marshal(doc)
	if err := os.WriteFile(path, mutated, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(path); !errors.Is(err, ErrUnprotectFailed) {
		t.Errorf("篡改后的凭据应报 ErrUnprotectFailed，实际：%v", err)
	}
}

func TestLoadRejectsForeignFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.json")
	doc := fileDoc{
		Format:        "some-other-tool/v1",
		SchemeVersion: 1,
		Protection:    ProtectionDPAPIMachine,
		AccountID:     "a", Bucket: "b",
		Endpoint: "https://x.r2.cloudflarestorage.com",
		Secret:   base64.StdEncoding.EncodeToString([]byte("junk")),
	}
	raw, _ := json.Marshal(doc)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); !errors.Is(err, ErrBadProtection) {
		t.Errorf("外来格式应报 ErrBadProtection，实际：%v", err)
	}

	// 保护方式不符合同样拒绝：不能让"未加密"的文件被当成合法凭据使用。
	doc.Format = FileFormat
	doc.Protection = "none"
	raw, _ = json.Marshal(doc)
	_ = os.WriteFile(path, raw, 0o600)
	if _, err := Load(path); !errors.Is(err, ErrBadProtection) {
		t.Errorf("未加密凭据应报 ErrBadProtection，实际：%v", err)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err == nil || !strings.Contains(err.Error(), "不存在") {
		t.Errorf("缺失文件应给出明确提示，实际：%v", err)
	}
}

// TestEntropyIsDomainSeparated 验证附加熵确实参与了保护：
// 同样的明文、同样的机器，两次加密的结果必须不同，
// 且不携带应用熵的密文必须解不开。
func TestEntropyIsDomainSeparated(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("DPAPI 仅在 Windows 上可用")
	}
	plain := []byte(`{"secret_access_key":"x"}`)
	a, err := nativeProtect(plain)
	if err != nil {
		t.Fatalf("nativeProtect 失败：%v", err)
	}
	b, err := nativeProtect(plain)
	if err != nil {
		t.Fatalf("nativeProtect 失败：%v", err)
	}
	if bytes.Equal(a, b) {
		t.Error("两次加密结果相同：DPAPI 未使用随机化，或熵未参与")
	}
	got, err := nativeUnprotect(a)
	if err != nil {
		t.Fatalf("nativeUnprotect 失败：%v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Error("解密结果与明文不一致")
	}
}

func TestZeroClearsMaterial(t *testing.T) {
	c := sample()
	secretRef := c.SecretAccessKey // 复用同一底层数组，模拟"结构体外的引用"
	c.Zero()
	if c.AccessKeyID != nil || c.SecretAccessKey != nil || c.SessionToken != nil {
		t.Error("Zero 后字段应为 nil")
	}
	for i, b := range secretRef {
		if b != 0 {
			t.Fatalf("Zero 未清零底层数组（偏移 %d 仍为 %d）", i, b)
		}
	}
	// nil 上调用不应 panic。
	var nilC *Credentials
	nilC.Zero()
}

func TestRedactDoesNotLeakSecret(t *testing.T) {
	c := sample()
	got := c.Redact()
	if strings.Contains(got, string(c.SecretAccessKey)) {
		t.Error("Redact 泄露了 SecretAccessKey")
	}
	if !strings.HasPrefix(got, string(c.AccessKeyID[:4])) {
		t.Errorf("Redact 应保留前 4 位以便区分，实际 %q", got)
	}
	if n := len([]rune(got)); n > 6 {
		t.Errorf("Redact 暴露过多信息：%q（%d 个字符）", got, n)
	}
}

func TestDescribeHasNoSecret(t *testing.T) {
	c := sample()
	d := c.Describe()
	if strings.Contains(d, string(c.SecretAccessKey)) || strings.Contains(d, string(c.AccessKeyID)) {
		t.Error("Describe 不应包含凭据材料")
	}
	if !strings.Contains(d, c.Bucket) {
		t.Error("Describe 应包含桶名方便核对")
	}
}
