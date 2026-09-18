package cred

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 口令保护档是 Linux 上的默认交付路径（Linux 没有 DPAPI），
// 所以这一组测试必须在**任何平台**上都能跑——它们刻意不跳过。

const testPass = "correct horse battery"

func TestPassphraseRoundTrip(t *testing.T) {
	withEnvCleared(t)
	path := filepath.Join(t.TempDir(), "client.json")
	in := sample()
	if err := Save(path, in, WithPassphrase([]byte(testPass))); err != nil {
		t.Fatalf("Save 失败：%v", err)
	}
	if p, _ := ProtectionOf(path); p != ProtectionPassphrase {
		t.Fatalf("protection 应为 %s，实际 %s", ProtectionPassphrase, p)
	}
	need, err := NeedsPassphrase(path)
	if err != nil || !need {
		t.Fatalf("NeedsPassphrase 应为 true，实际 %v / %v", need, err)
	}

	// 没给口令 → 必须是明确的「需要口令」，而不是含糊的解密失败。
	if _, err := Load(path); !errors.Is(err, ErrPassphraseRequired) {
		t.Fatalf("缺口令应报 ErrPassphraseRequired，实际：%v", err)
	}

	got, err := Load(path, WithPassphrase([]byte(testPass)))
	if err != nil {
		t.Fatalf("Load 失败：%v", err)
	}
	defer got.Zero()
	if !bytes.Equal(got.SecretAccessKey, in.SecretAccessKey) {
		t.Error("SecretAccessKey 往返不一致")
	}
	if got.Bucket != in.Bucket || got.Prefix != in.Prefix {
		t.Errorf("路由字段往返不一致：%+v", got)
	}
}

func TestPassphraseWrongIsRejected(t *testing.T) {
	withEnvCleared(t)
	path := filepath.Join(t.TempDir(), "client.json")
	if err := Save(path, sample(), WithPassphrase([]byte(testPass))); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path, WithPassphrase([]byte("wrong passphrase here")))
	if !errors.Is(err, ErrPassphraseWrong) {
		t.Fatalf("错误口令应报 ErrPassphraseWrong，实际：%v", err)
	}
}

func TestPassphraseTooShort(t *testing.T) {
	withEnvCleared(t)
	path := filepath.Join(t.TempDir(), "client.json")
	if err := Save(path, sample(), WithPassphrase([]byte("short"))); !errors.Is(err, ErrPassphraseTooShort) {
		t.Fatalf("过短口令应被拒绝，实际：%v", err)
	}
}

// 口令保护的文件落盘后同样不能出现任何明文凭据。
func TestPassphraseFileHidesSecret(t *testing.T) {
	withEnvCleared(t)
	path := filepath.Join(t.TempDir(), "client.json")
	in := sample()
	if err := Save(path, in, WithPassphrase([]byte(testPass))); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	for _, needle := range []string{
		string(in.SecretAccessKey),
		string(in.AccessKeyID),
		base64.StdEncoding.EncodeToString(in.SecretAccessKey),
		testPass, // 口令本身也不能落进文件
	} {
		if bytes.Contains(raw, []byte(needle)) {
			t.Errorf("凭据文件中出现了明文片段 %q", needle)
		}
	}
	if !bytes.Contains(raw, []byte(in.Bucket)) {
		t.Error("bucket 应保持明文可读，便于排障")
	}
	if bytes.Contains(raw, []byte("secret_access_key")) {
		t.Error("被保护的字段不应作为 JSON 键出现在外层文件里")
	}
}

// 明文档必须「两头都显式」：写要显式开，读也要显式开。
func TestPlainFileRequiresExplicitOptIn(t *testing.T) {
	withEnvCleared(t)
	path := filepath.Join(t.TempDir(), "client.json")
	if err := Save(path, sample(), WithForcePlainFile()); err != nil {
		t.Fatalf("Save 失败：%v", err)
	}
	if _, err := Load(path); !errors.Is(err, ErrPlainFileNotAllowed) {
		t.Fatalf("明文凭据默认应拒绝读取，实际：%v", err)
	}
	got, err := Load(path, WithAllowPlainFile())
	if err != nil {
		t.Fatalf("显式许可后应能读取：%v", err)
	}
	defer got.Zero()
	if !bytes.Equal(got.AccessKeyID, sample().AccessKeyID) {
		t.Error("明文档往返不一致")
	}
}

// 明文档的字段名必须让人一眼看出没加密。
func TestPlainFileIsUnmistakablyPlaintext(t *testing.T) {
	withEnvCleared(t)
	path := filepath.Join(t.TempDir(), "client.json")
	if err := Save(path, sample(), WithForcePlainFile()); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if !bytes.Contains(raw, []byte(`"secret_plaintext"`)) {
		t.Error("明文档应使用 secret_plaintext 字段，让人一眼看出没加密")
	}
	if bytes.Contains(raw, []byte(`"secret"`)) {
		t.Error("明文档不应同时出现 secret 字段，避免被误认为有加密")
	}
	if !bytes.Contains(raw, []byte(ProtectionPlainFile)) {
		t.Error("protection 字段应标为明文档")
	}
}

// 把一个保护档的内容改标成另一个档，必须被挡住。
func TestProtectionLabelCannotBeRelabelled(t *testing.T) {
	withEnvCleared(t)
	path := filepath.Join(t.TempDir(), "client.json")

	// 明文内容伪装成口令保护 → 解不开（GCM 的 AAD 绑定了 protection）。
	if err := Save(path, sample(), WithForcePlainFile()); err != nil {
		t.Fatal(err)
	}
	var doc fileDoc
	raw, _ := os.ReadFile(path)
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc.Protection = ProtectionPassphrase
	doc.SecretPlaintext = nil
	doc.Secret = base64.StdEncoding.EncodeToString([]byte("not really encrypted"))
	mutated, _ := json.Marshal(doc)
	if err := os.WriteFile(path, mutated, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, WithPassphrase([]byte(testPass))); !errors.Is(err, ErrPassphraseWrong) {
		t.Fatalf("伪造的密文应被拒绝，实际：%v", err)
	}

	// 口令密文伪装成明文 → 会走到明文路径去解析密文字节，必须报「不是合法凭据」。
	if err := Save(path, sample(), WithPassphrase([]byte(testPass))); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(path)
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc.Protection = ProtectionPlainFile
	doc.SecretPlaintext = &secretDoc{AccessKeyID: "x", SecretAccessKey: "y"}
	mutated, _ = json.Marshal(doc)
	if err := os.WriteFile(path, mutated, 0o600); err != nil {
		t.Fatal(err)
	}
	// 明文档不做认证，所以这里"能读"是预期的；关键是它读到的是被替换后的内容，
	// 而不是把密文字节当作合法凭据。
	got, err := Load(path, WithAllowPlainFile())
	if err != nil {
		t.Fatalf("明文档路径应能读出内容：%v", err)
	}
	if string(got.AccessKeyID) != "x" {
		t.Errorf("明文档读出的应是文件里写的内容，实际 %q", got.AccessKeyID)
	}
	got.Zero()
}

func TestPassphraseFromEnv(t *testing.T) {
	withEnvCleared(t)
	t.Setenv(EnvPassphrase, testPass)
	path := filepath.Join(t.TempDir(), "client.json")
	if err := Save(path, sample()); err != nil {
		t.Fatalf("环境变量应能让 Save 选到口令档：%v", err)
	}
	if p, _ := ProtectionOf(path); p != ProtectionPassphrase {
		t.Fatalf("环境变量给口令时 protection 应为 %s，实际 %s", ProtectionPassphrase, p)
	}
	got, err := Load(path) // 不给参数，靠环境变量
	if err != nil {
		t.Fatalf("应从环境变量取到口令：%v", err)
	}
	got.Zero()
}

func TestPassphraseFileWinsOverEnv(t *testing.T) {
	withEnvCleared(t)
	dir := t.TempDir()
	pf := filepath.Join(dir, "cred.pass")
	if err := os.WriteFile(pf, []byte(testPass+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvPassphrase, "env passphrase that is wrong")
	path := filepath.Join(dir, "client.json")
	if err := Save(path, sample(), WithPassphraseFile(pf)); err != nil {
		t.Fatal(err)
	}
	// 显式口令文件应胜过环境变量。
	if _, err := Load(path, WithPassphraseFile(pf)); err != nil {
		t.Fatalf("显式口令文件应生效：%v", err)
	}
}

// 密文里不能出现明文口令本身，也不能两次封装得到相同结果。
func TestSealPassphraseIsRandomizedAndHidesPlaintext(t *testing.T) {
	plain := []byte(`{"secret_access_key":"AKIA-secret-value"}`)
	a, err := sealPassphrase(plain, []byte(testPass))
	if err != nil {
		t.Fatal(err)
	}
	b, err := sealPassphrase(plain, []byte(testPass))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Error("两次封装结果相同：盐或 nonce 未随机化")
	}
	if bytes.Contains(a, []byte(testPass)) {
		t.Error("密文里出现了明文口令")
	}
	if bytes.Contains(a, []byte("AKIA-secret-value")) {
		t.Error("密文里出现了明文凭据")
	}
	got, err := openPassphrase(a, []byte(testPass))
	if err != nil {
		t.Fatalf("解开失败：%v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Error("解开结果与明文不一致")
	}
}

// 迭代次数写在 blob 头部：将来调大默认值，旧文件仍要能读。
func TestOpenPassphraseHonoursStoredIterations(t *testing.T) {
	plain := []byte(`{"x":1}`)
	blob, err := sealPassphrase(plain, []byte(testPass))
	if err != nil {
		t.Fatal(err)
	}
	if iter := binary.BigEndian.Uint32(blob[5:9]); int(iter) != pbkdf2Iterations {
		t.Fatalf("blob 头部记录的迭代次数应为 %d，实际 %d", pbkdf2Iterations, iter)
	}

	// 模拟旧文件：头部记 1000 次，并用同样的次数重新封装。
	const oldIter = 1000
	binary.BigEndian.PutUint32(blob[5:9], oldIter)
	salt := blob[9 : 9+saltLen]
	nonce := blob[9+saltLen : 9+saltLen+nonceLen]
	key, err := pbkdf2.Key(sha256.New, testPass, salt, oldIter, pbkdf2KeyLen)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	ct := gcm.Seal(nil, nonce, plain, aadFor(ProtectionPassphrase))
	oldBlob := append(append([]byte{}, blob[:9+saltLen+nonceLen]...), ct...)

	got, err := openPassphrase(oldBlob, []byte(testPass))
	if err != nil {
		t.Fatalf("应能按头部记录的迭代次数解开旧文件：%v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Error("解开结果不一致")
	}
}

func TestPassphraseBlobRejectsDamagedHead(t *testing.T) {
	blob, err := sealPassphrase([]byte(`{"x":1}`), []byte(testPass))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func([]byte) []byte{
		"太短":     func(b []byte) []byte { return b[:10] },
		"魔数不对":   func(b []byte) []byte { c := append([]byte{}, b...); c[0] = 'X'; return c },
		"版本不对":   func(b []byte) []byte { c := append([]byte{}, b...); c[4] = 9; return c },
		"迭代次数为零": func(b []byte) []byte { c := append([]byte{}, b...); binary.BigEndian.PutUint32(c[5:9], 0); return c },
		"迭代次数过大": func(b []byte) []byte {
			c := append([]byte{}, b...)
			binary.BigEndian.PutUint32(c[5:9], 1<<31)
			return c
		},
	}
	for name, mutate := range cases {
		if _, err := openPassphrase(mutate(blob), []byte(testPass)); err == nil {
			t.Errorf("%s：应被拒绝", name)
		}
	}
	if _, err := openPassphrase(blob, nil); !errors.Is(err, ErrPassphraseRequired) {
		t.Errorf("空口令应报 ErrPassphraseRequired，实际：%v", err)
	}
}

// 类 Unix 上明文凭据文件必须是 0600，过宽要拒绝。
func TestPlainFilePermTooOpenRejected(t *testing.T) {
	if !enforceFilePerm() {
		t.Skip("该平台不做权限位校验")
	}
	path := filepath.Join(t.TempDir(), "client.json")
	if err := Save(path, sample(), WithForcePlainFile()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Skipf("无法改权限：%v", err)
	}
	if _, err := Load(path, WithAllowPlainFile()); !errors.Is(err, ErrPlainFileTooOpen) {
		t.Fatalf("0644 的明文凭据应被拒绝，实际：%v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, WithAllowPlainFile()); err != nil {
		t.Fatalf("0600 应可读取：%v", err)
	}
}

// DPAPI 文件在非 Windows 上必须给出明确的、可操作的错误，
// 而不是「解密失败」这种让人以为文件坏了的话。
func TestDPAPIFileOnNonWindowsExplainsItself(t *testing.T) {
	if nativeProtection() != "" {
		t.Skip("本平台有原生保管设施，跳过")
	}
	path := filepath.Join(t.TempDir(), "client.json")
	doc := fileDoc{
		Format: FileFormat, SchemeVersion: SchemeVersion,
		Protection: ProtectionDPAPIMachine,
		AccountID:  "a", Bucket: "b",
		Endpoint: "https://x.r2.cloudflarestorage.com",
		Secret:   base64.StdEncoding.EncodeToString([]byte("dpapi-ciphertext")),
	}
	raw, _ := json.Marshal(doc)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "DPAPI") {
		t.Fatalf("应说明这是 DPAPI 文件、只能在 Windows 上读，实际：%v", err)
	}
}

// NormalizePassphrase 只剪尾随换行。
func TestNormalizePassphraseKeepsInnerSpaces(t *testing.T) {
	if got := string(NormalizePassphrase([]byte("a b\r\n"))); got != "a b" {
		t.Errorf("应只去掉尾随换行，实际 %q", got)
	}
	if got := string(NormalizePassphrase([]byte("  lead kept  "))); got != "  lead kept  " {
		t.Errorf("不应动首尾空格，实际 %q", got)
	}
}

// withEnvCleared 清掉会影响判定的环境变量，避免测试互相污染。
func withEnvCleared(t *testing.T) {
	t.Helper()
	t.Setenv(EnvPassphrase, "")
	t.Setenv(EnvPassphraseFile, "")
	_ = os.Unsetenv(EnvPassphrase)
	_ = os.Unsetenv(EnvPassphraseFile)
}

// ProtectionNote 是三处命令行提示文案的唯一来源。
// 它的价值全在"说真话"：DPAPI 那条必须点明读不了 Linux，明文那条必须点明没加密。
func TestProtectionNoteTellsTheTruth(t *testing.T) {
	cases := []struct {
		protection string
		mustHave   string
	}{
		{ProtectionDPAPIMachine, "只有生成它的那台 Windows 机器能读"},
		{ProtectionPassphrase, "跨平台可读"},
		{ProtectionPlainFile, "未加密"},
		{"", "未知"},
	}
	for _, tc := range cases {
		got := ProtectionNote(tc.protection)
		if !strings.Contains(got, tc.mustHave) {
			t.Errorf("protection=%q 的说明应包含 %q，实际 %q", tc.protection, tc.mustHave, got)
		}
	}

	// 不认识的取值不能让说明变成空白——那等于对用户隐瞒了"这里有个我不认识的东西"。
	unknown := ProtectionNote("some-future-mode")
	if unknown == "" || !strings.Contains(unknown, "some-future-mode") {
		t.Errorf("未知保护方式应原样回显，实际 %q", unknown)
	}
}
