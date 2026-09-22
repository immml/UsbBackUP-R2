package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/immml/UsbBackUP-R2/internal/collectpolicy"
	"github.com/immml/UsbBackUP-R2/internal/config"
	"github.com/immml/UsbBackUP-R2/internal/cred"
	"github.com/immml/UsbBackUP-R2/internal/embedcfg"
	"github.com/immml/UsbBackUP-R2/internal/keystore"
)

// writeTestKeys 生成一对测试密钥，返回 (目录, 公钥路径, 私钥路径)。
func writeTestKeys(t *testing.T) (dir, pub, priv string) {
	t.Helper()
	dir = t.TempDir()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	pub = filepath.Join(dir, "usbbackup-r2.pub.pem")
	priv = filepath.Join(dir, "usbbackup-r2.key.pem")
	if err := os.WriteFile(pub, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(priv, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, pub, priv
}

// fakeToolDir 造一个"工具目录"：一个假 exe + 一个假客户端模板。
func fakeToolDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	body := []byte(strings.Repeat("MZ", 4000))
	if err := os.WriteFile(filepath.Join(dir, "usbkeygen-r2.exe"), body, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "usbunseal-r2.exe"), body, 0o755); err != nil {
		t.Fatal(err)
	}
	// 客户端模板必须是一个能被 embedcfg 追加块的文件。
	if err := os.WriteFile(filepath.Join(dir, "usbbackup-r2.exe"), body, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAssembleToolkitWritesExpectedLayout(t *testing.T) {
	_, pub, priv := writeTestKeys(t)
	tools := fakeToolDir(t)
	dest := t.TempDir()

	n, err := assembleToolkit(toolkitOptions{
		Dest:           dest,
		ToolDir:        tools,
		PublicKeyPath:  pub,
		PrivateKeyPath: priv,
		WithPrivate:    true,
		WithClient:     true,
		Force:          true,
	}, io.Discard)
	if err != nil {
		t.Fatalf("assembleToolkit 失败: %v", err)
	}
	if n < 6 {
		t.Errorf("写入项数偏少: %d", n)
	}

	must := []string{
		"usbkeygen-r2.exe", "usbunseal-r2.exe", "client.exe",
		filepath.Join("keys", "usbbackup-r2.pub.pem"),
		filepath.Join("keys", "usbbackup-r2.key.pem"),
		".usbbackup-allow", "README.txt",
	}
	for _, rel := range must {
		if _, err := os.Stat(filepath.Join(dest, rel)); err != nil {
			t.Errorf("缺少 %s: %v", rel, err)
		}
	}
}

func TestToolkitClientIsReallyEmbedded(t *testing.T) {
	// 盘里的 client.exe 必须是可用的内嵌客户端，而不是空壳。
	_, pub, priv := writeTestKeys(t)
	dest := t.TempDir()
	if _, err := assembleToolkit(toolkitOptions{
		Dest: dest, ToolDir: fakeToolDir(t),
		PublicKeyPath: pub, PrivateKeyPath: priv,
		WithClient: true, Force: true,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	got, err := embedcfg.Read(filepath.Join(dest, "client.exe"))
	if err != nil {
		t.Fatalf("盘内 client.exe 无法读回内嵌配置: %v", err)
	}
	if got.ClientName != "usb-toolkit" {
		t.Errorf("客户端标识不符: %q", got.ClientName)
	}
}

func TestAllowMarkerExemptsToolkitFromCollection(t *testing.T) {
	// 最高优先级的一条：工具盘上放着私钥，一旦被采集打包上传就等于把私钥发布到网上。
	// 所以盘根必须写出授权标记，且**任何策略档位**下都要被判豁免。
	_, pub, priv := writeTestKeys(t)
	dest := t.TempDir()
	if _, err := assembleToolkit(toolkitOptions{
		Dest: dest, ToolDir: fakeToolDir(t),
		PublicKeyPath: pub, PrivateKeyPath: priv, Force: true,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dest, ".usbbackup-allow"))
	if err != nil {
		t.Fatal(err)
	}
	pubKey, err := keystore.ParsePublicKeyPEM(mustRead(t, pub))
	if err != nil {
		t.Fatal(err)
	}
	_, fp, err := keystore.PublicKeyFingerprint(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	// 标记内容写指纹只为便于人肉核对"这块盘是谁的"，判定不看内容。
	if !strings.Contains(string(raw), fp) {
		t.Errorf("授权标记应记录公钥指纹 %s，实际内容 %q", fp, string(raw))
	}

	for _, p := range []collectpolicy.Policy{collectpolicy.PolicyAll, collectpolicy.PolicyMarkerOnly} {
		// ExemptMarker 留空 = 用策略包内置默认名。这样测的是"工具盘写出的名字
		// 与豁免判定默认查找的名字确实一致"，而不是两处各写一个字符串碰巧相等。
		d, err := collectpolicy.Decide(dest, collectpolicy.Options{Policy: p})
		if err != nil {
			t.Fatal(err)
		}
		if !d.ExemptMarkerChecked || !d.ExemptMarkerFound {
			t.Errorf("策略 %s：授权标记未被识别，工具盘会被打包走", p)
		}
		if d.Collect {
			t.Errorf("策略 %s：工具盘被判为可采集，私钥会被上传", p)
		}
		if d.Reason != collectpolicy.ReasonExempt {
			t.Errorf("策略 %s：拒绝原因应为 %s，实际 %q", p, collectpolicy.ReasonExempt, d.Reason)
		}
	}
}

// 装盘必须在盘根同时写出两个授权标记，且磁盘级那份能救下**同盘的其它分区**——
// 那正是 2026-09-20 部署实测踩到的场景（Ventoy 盘的 VTOYEFI 分区被整盘采集）。
func TestAssembleToolkitWritesBothExemptionMarkers(t *testing.T) {
	_, pub, priv := writeTestKeys(t)
	dest := t.TempDir()
	if _, err := assembleToolkit(toolkitOptions{
		Dest: dest, ToolDir: fakeToolDir(t),
		PublicKeyPath: pub, PrivateKeyPath: priv, Force: true,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		collectpolicy.DefaultExemptMarkerFile,
		collectpolicy.DefaultExemptDiskMarkerFile,
	} {
		if _, err := os.Stat(filepath.Join(dest, name)); err != nil {
			t.Fatalf("装盘未写出 %s：%v", name, err)
		}
	}

	// 模拟同一支盘上的另一个分区：它自己没有任何标记。
	otherPart := t.TempDir()
	if err := os.WriteFile(filepath.Join(otherPart, "EFI.BIN"), []byte("EFI"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := collectpolicy.Decide(otherPart, collectpolicy.Options{
		Policy: collectpolicy.PolicyAll,
		// 注入"这两个卷根同属一块物理磁盘"——真机上由 winvol 查磁盘号得到。
		SameDiskRoots: func(string) ([]string, error) { return []string{dest, otherPart}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Collect || d.Reason != collectpolicy.ReasonExemptDisk {
		t.Fatalf("同盘的另一个分区没被磁盘级标记救下：%+v", d)
	}
	if d.ExemptDiskMarkerRoot != dest {
		t.Errorf("命中卷根应为 %s，实际 %q", dest, d.ExemptDiskMarkerRoot)
	}
}

func TestAssembleWithoutPrivateOmitsKey(t *testing.T) {
	_, pub, priv := writeTestKeys(t)
	dest := t.TempDir()
	if _, err := assembleToolkit(toolkitOptions{
		Dest: dest, ToolDir: fakeToolDir(t),
		PublicKeyPath: pub, PrivateKeyPath: priv,
		WithPrivate: false, Force: true,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "keys", "usbbackup-r2.key.pem")); err == nil {
		t.Fatal("--without-private 时不应写入私钥")
	}
	if _, err := os.Stat(filepath.Join(dest, "keys", "usbbackup-r2.pub.pem")); err != nil {
		t.Error("公钥仍应写入")
	}
}

func TestAssembleRefusesOverwriteWithoutForce(t *testing.T) {
	_, pub, priv := writeTestKeys(t)
	dest := t.TempDir()
	opt := toolkitOptions{
		Dest: dest, ToolDir: fakeToolDir(t),
		PublicKeyPath: pub, PrivateKeyPath: priv, Force: false,
	}
	if _, err := assembleToolkit(opt, io.Discard); err != nil {
		t.Fatal(err)
	}
	// 第二次不带 Force 应失败，而不是静默覆盖。
	if _, err := assembleToolkit(opt, io.Discard); err == nil {
		t.Fatal("未加 Force 时不应覆盖已存在的文件")
	}
}

func TestAssembleToolkitIntoSubDir(t *testing.T) {
	// 工具可以收进子目录，但授权标记必须留在盘根——
	// 豁免判定只在 <盘根>\.usbbackup-allow 处 Stat 一次，挪走就检测不到，
	// 这个盘（带着私钥）就会被当成普通介质打包上传。
	_, pub, priv := writeTestKeys(t)
	dest := t.TempDir()

	n, err := assembleToolkit(toolkitOptions{
		Dest: dest, SubDir: filepath.Join("backup", "tools"), ToolDir: fakeToolDir(t),
		PublicKeyPath: pub, PrivateKeyPath: priv,
		WithPrivate: true, WithClient: true, Force: true,
	}, io.Discard)
	if err != nil {
		t.Fatalf("assembleToolkit 失败: %v", err)
	}
	if n < 6 {
		t.Errorf("写入项数偏少: %d", n)
	}

	tools := filepath.Join(dest, "backup", "tools")
	for _, rel := range []string{"usbunseal-r2.exe", "client.exe", "README.txt", filepath.Join("keys", "usbbackup-r2.key.pem")} {
		if _, err := os.Stat(filepath.Join(tools, rel)); err != nil {
			t.Errorf("子目录内缺少 %s: %v", rel, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dest, ".usbbackup-allow")); err != nil {
		t.Errorf("授权标记必须在盘根: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "usbunseal-r2.exe")); err == nil {
		t.Error("工具不应再出现在盘根")
	}
}

func TestCleanSubDirRejectsEscape(t *testing.T) {
	bad := []string{
		filepath.Join("..", "escape"),
		"..",
		`C:\Windows`,
		`\absolute`,
		"/etc",
	}
	for _, v := range bad {
		if got := cleanSubDir(v); got != "" {
			t.Errorf("cleanSubDir(%q) = %q，应被拒绝", v, got)
		}
	}
	good := map[string]string{
		filepath.Join("backup", "tools"): filepath.Join("backup", "tools"),
		"backup/tools":                   filepath.Join("backup", "tools"),
		"":                               "",
		"   ":                            "",
	}
	for in, want := range good {
		if got := cleanSubDir(in); got != want {
			t.Errorf("cleanSubDir(%q) = %q，期望 %q", in, got, want)
		}
	}
}

func TestToolkitReadmeWarnsOnlyWhenPrivatePresent(t *testing.T) {
	withPriv := toolkitReadme(toolkitReadmeInput{Fingerprint: "aa bb cc", HasPrivate: true})
	if !strings.Contains(withPriv, "明文私钥") {
		t.Error("带明文私钥时应有风险提示")
	}
	without := toolkitReadme(toolkitReadmeInput{Fingerprint: "aa bb cc"})
	if strings.Contains(without, "明文私钥") {
		t.Error("不带私钥时不应出现私钥风险提示")
	}
	if !strings.Contains(without, "私钥未上盘") {
		t.Error("不带私钥时应说明如何取私钥")
	}
}

func TestToolkitReadmeDistinguishesEncryptedPrivate(t *testing.T) {
	// 带口令的私钥不能再被描述成"明文"——盘上写错风险等级会误导现场的人。
	enc := toolkitReadme(toolkitReadmeInput{Fingerprint: "aa bb cc", HasPrivate: true, PrivateEncrypted: true})
	if strings.Contains(enc, "明文私钥") {
		t.Error("口令保护的私钥不应被写成明文")
	}
	if !strings.Contains(enc, "口令保护") {
		t.Error("应说明私钥带口令保护")
	}
	plain := toolkitReadme(toolkitReadmeInput{Fingerprint: "aa bb cc", HasPrivate: true})
	if !strings.Contains(plain, "明文私钥") {
		t.Error("明文私钥应如实标注")
	}
}

func TestToolkitReadmeExplainsCredentialOnlyWhenPresent(t *testing.T) {
	// DPAPI 凭据是机器范围的，换台机器就失效。README 不写清楚，
	// 现场的人会以为"把这个盘换个机器插上就能自动上传"。
	with := toolkitReadme(toolkitReadmeInput{
		Fingerprint: "aa bb cc", HasCredential: true, CredProtection: cred.ProtectionDPAPIMachine,
	})
	if !strings.Contains(with, "DPAPI") || !strings.Contains(with, "别的机器") {
		t.Error("DPAPI 凭据应说明与机器绑定")
	}
	if !strings.Contains(with, "吊销") {
		t.Error("带凭据时应给出泄漏后的处置办法")
	}
	without := toolkitReadme(toolkitReadmeInput{Fingerprint: "aa bb cc"})
	if strings.Contains(without, "DPAPI") {
		t.Error("不带凭据时不应出现凭据说明")
	}
}

// 口令加密的凭据是**跨机器可用**的。README 若照抄 DPAPI 那一套说法，
// 现场的人会以为要换机重生成，白白多跑一趟；反过来更糟——
// 把机器绑定的说成跨机器，人会拿着注定解不开的凭据去部署。
func TestToolkitReadmeTellsPassphraseCredentialApart(t *testing.T) {
	got := toolkitReadme(toolkitReadmeInput{
		Fingerprint: "aa bb cc", HasCredential: true, CredProtection: cred.ProtectionPassphrase,
	})
	for _, want := range []string{"口令加密", "任何 Windows 机器", "没有写在盘上", "USBBACKUP_R2_CRED_PASSPHRASE"} {
		if !strings.Contains(got, want) {
			t.Errorf("口令加密凭据的说明应包含 %q，实际：\n%s", want, got)
		}
	}
	if strings.Contains(got, "拿到别的机器上解不开") {
		t.Error("口令加密的凭据不该被写成换机失效")
	}
	// 客户端**没有** --cred-pass-file 这个开关，口令只能走环境变量。
	// 差一个字，现场就会去敲一条不存在的命令，或者以为要重新生成凭据。
	if !strings.Contains(got, "客户端只认环境变量") {
		t.Error("应写明客户端取口令的唯一途径是环境变量")
	}
	// 漏设口令不会报错，只是上传被悄悄跳过——这是最难查的一类现场问题。
	if !strings.Contains(got, "上传会被跳过") {
		t.Error("应写明漏设口令的后果是上传被跳过")
	}
	if !strings.Contains(got, "LocalSystem") {
		t.Error("应提醒服务模式看不见用户级变量")
	}
	// 在盘上直接跑有两个硬伤：服务绑死盘符、盘上凭据抢先被读到。
	// README 是现场唯一的离线读物，必须把这条写进去。
	if !strings.Contains(got, "本地目录") {
		t.Error("应提醒先把工具拷到本地目录再跑（服务绑盘符 + 凭据抢先）")
	}
	// "不想设口令"的正解是 DPAPI 档，而不是把凭据塞进二进制。
	// 不写出来，现场的人要么每次给口令，要么去走一条不存在的路。
	if !strings.Contains(got, "DPAPI") || !strings.Contains(got, "不想每次都给口令") {
		t.Error("应给出 DPAPI 机器绑定档作为免口令方案")
	}
}

// 保护方式读不出来时必须写"未知"，不能猜一个填上。
func TestToolkitReadmeAdmitsUnknownCredentialProtection(t *testing.T) {
	got := toolkitReadme(toolkitReadmeInput{
		Fingerprint: "aa bb cc", HasCredential: true, CredProtection: "some-future-mode",
	})
	if !strings.Contains(got, "未能识别") {
		t.Errorf("未知保护方式应如实说明，实际：\n%s", got)
	}
}

// 门控值被写进二进制之后就再也反查不到了，盘上的 README 必须把它记下来——
// 否则现场无从核对"这块盘到底会不会备我那支 30 GB 的 U 盘"。
func TestToolkitReadmeRecordsEffectiveGate(t *testing.T) {
	got := toolkitReadme(toolkitReadmeInput{
		Fingerprint: "aa bb cc", HasClient: true,
		GateThreshold: "10 GiB", GateMaxTotal: "10 GiB", GateCollect: "all",
	})
	for _, want := range []string{"10 GiB", "all", "整盘跳过"} {
		if !strings.Contains(got, want) {
			t.Errorf("README 应记录生效门控 %q，实际：\n%s", want, got)
		}
	}

	// 复用现成 client.exe 时值无从得知，只能引导去问那个二进制本身——
	// 绝不能编一个出来。
	reused := toolkitReadme(toolkitReadmeInput{Fingerprint: "aa bb cc", HasClient: true, GateReused: true})
	if !strings.Contains(reused, "config-check") {
		t.Error("复用客户端时应引导用 config-check 查实际值")
	}
	if strings.Contains(reused, "容量阈值") {
		t.Error("值不知道时不该编一个出来")
	}
}

func TestAssembleCopiesCredentialAndEnablesUpload(t *testing.T) {
	// 给了 --cred 就要：① 凭据落到客户端同目录；② 生成的客户端真的打开上传。
	// 只做其中一件都会让现场表现为"跑了但什么都没传上去"。
	_, pub, priv := writeTestKeys(t)
	credDir := t.TempDir()
	credPath := filepath.Join(credDir, "cred.json")
	if err := os.WriteFile(credPath, []byte(`{"x":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if _, err := assembleToolkit(toolkitOptions{
		Dest: dest, ToolDir: fakeToolDir(t),
		PublicKeyPath: pub, PrivateKeyPath: priv,
		WithClient: true, CredentialPath: credPath, Force: true,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "client.json")); err != nil {
		t.Fatalf("凭据未随盘落地: %v", err)
	}
	got, err := embedcfg.Read(filepath.Join(dest, "client.exe"))
	if err != nil {
		t.Fatal(err)
	}
	var emb config.Config
	if err := json.Unmarshal(got.ConfigJSON, &emb); err != nil {
		t.Fatal(err)
	}
	if !emb.Upload.Enabled {
		t.Error("给了凭据却没有在客户端里打开上传")
	}
	if emb.Upload.CredentialFile != "client.json" {
		t.Errorf("内嵌凭据名应为相对名 client.json（客户端按自身目录解析），实际 %q",
			emb.Upload.CredentialFile)
	}
}

func TestAssembleWithoutCredentialKeepsUploadOff(t *testing.T) {
	// 反面：不给凭据时客户端必须保持"只落本地"，
	// 否则现场会拿到一个每次采集都报上传失败的程序。
	_, pub, priv := writeTestKeys(t)
	dest := t.TempDir()
	if _, err := assembleToolkit(toolkitOptions{
		Dest: dest, ToolDir: fakeToolDir(t),
		PublicKeyPath: pub, PrivateKeyPath: priv,
		WithClient: true, Force: true,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	got, err := embedcfg.Read(filepath.Join(dest, "client.exe"))
	if err != nil {
		t.Fatal(err)
	}
	var emb config.Config
	if err := json.Unmarshal(got.ConfigJSON, &emb); err != nil {
		t.Fatal(err)
	}
	if emb.Upload.Enabled {
		t.Error("没有凭据时不应打开上传")
	}
}

func TestIsEncryptedPrivateKeyPEM(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := keystore.MarshalPrivateKeyPEM(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if keystore.IsEncryptedPrivateKeyPEM(plain) {
		t.Error("无口令私钥被误判为已加密")
	}
	enc, err := keystore.MarshalPrivateKeyPEM(key, []byte("correct horse battery"))
	if err != nil {
		t.Fatal(err)
	}
	if !keystore.IsEncryptedPrivateKeyPEM(enc) {
		t.Error("带口令私钥未被识别")
	}
	if keystore.IsEncryptedPrivateKeyPEM([]byte("not a pem at all")) {
		t.Error("非 PEM 内容不应被判为已加密")
	}
}

func TestCopyFileAndHelpers(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a.txt")
	dst := filepath.Join(dir, "b.txt")
	if err := os.WriteFile(src, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, dst, false); err != nil {
		t.Fatal(err)
	}
	got := string(mustRead(t, dst))
	if got != "hello" {
		t.Errorf("复制内容不符: %q", got)
	}
	// 已存在且不 force → 报错。
	if err := copyFile(src, dst, false); err == nil {
		t.Error("已存在时应报错")
	}
	// force → 可覆盖。
	if err := copyFile(src, dst, true); err != nil {
		t.Error("force 应可覆盖")
	}
	if got := firstNonEmpty("", "  ", "x", "y"); got != "x" {
		t.Errorf("firstNonEmpty 异常: %q", got)
	}
	if got := emptyOr("", "fallback"); got != "fallback" {
		t.Errorf("emptyOr 异常: %q", got)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// 装盘必须能把容量门控写进内嵌客户端——否则盘上的 client.exe 只能用
// 内置默认值，"给这个现场改阈值"这件事就无从做起。
func TestAssembleToolkitInjectsCapacityGate(t *testing.T) {
	_, pub, priv := writeTestKeys(t)
	dest := t.TempDir()
	if _, err := assembleToolkit(toolkitOptions{
		Dest: dest, ToolDir: fakeToolDir(t),
		PublicKeyPath: pub, PrivateKeyPath: priv,
		WithClient: true, Force: true,
		Threshold: "6GiB", MaxTotal: "unlimited", Collect: "marker_only",
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	got, err := embedcfg.Read(filepath.Join(dest, "client.exe"))
	if err != nil {
		t.Fatal(err)
	}
	var emb config.Config
	if err := json.Unmarshal(got.ConfigJSON, &emb); err != nil {
		t.Fatal(err)
	}
	if emb.Gate.UsedThresholdBytes != 6<<30 {
		t.Errorf("容量阈值没有写进客户端：%d", emb.Gate.UsedThresholdBytes)
	}
	if emb.Gate.MaxTotalBytes != 0 {
		t.Errorf("unlimited 应当写成 0，实际 %d", emb.Gate.MaxTotalBytes)
	}
	if emb.Collect.Policy != "marker_only" {
		t.Errorf("采集策略没有写进客户端：%q", emb.Collect.Policy)
	}
}

// 复用现成的 client.exe 时，门控开关无处可施，必须报错。
// 静默忽略的后果是"你以为阈值改了，盘上跑的其实还是旧的"——
// 这种偏差要等到整盘被跳过、或上传撞上体积上限才会暴露出来。
func TestAssembleRefusesGateFlagsWhenReusingClient(t *testing.T) {
	_, pub, priv := writeTestKeys(t)
	tools := fakeToolDir(t)
	src, err := os.ReadFile(filepath.Join(tools, "usbbackup-r2.exe"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tools, "client.exe"), src, 0o755); err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	_, err = assembleToolkit(toolkitOptions{
		Dest: dest, ToolDir: tools,
		PublicKeyPath: pub, PrivateKeyPath: priv,
		WithClient: true, Force: true, Threshold: "6GiB",
	}, io.Discard)
	if err == nil {
		t.Fatal("复用了 client.exe 还传 --threshold，必须报错而不是忽略")
	}
	if !strings.Contains(err.Error(), "client.exe") {
		t.Errorf("报错应点名冲突的那个文件，实际：%v", err)
	}

	// 不传门控开关时复用应当照常成功——否则这个命令就没法用来"补装工具"。
	if _, err := assembleToolkit(toolkitOptions{
		Dest: dest, ToolDir: tools,
		PublicKeyPath: pub, PrivateKeyPath: priv,
		WithClient: true, Force: true,
	}, io.Discard); err != nil {
		t.Fatalf("不传门控开关时复用应成功：%v", err)
	}
}

// 授权标记必须**合并**，绝不能整体覆盖。
//
// 盘根可能已经有另一个项目写的指纹，而那边的判定是逐行比对指纹的。
// 覆盖会让那边认不出这块盘，于是它把这支**装着私钥**的工具盘当普通介质
// 采集打包——这正是本项目最不能出的事故，而且只要一次"顺手覆盖"就会发生。
func TestMergeExemptMarkerNeverDropsExistingFingerprint(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".usbbackup-allow")
	other := "f36b 2b3c 546a d12d 741e f057 5bfc 90de fa42 c4a3 179c d6c4 2820 9e1f 046b 104d"
	ours := "4ca2 b645 1111 2222 3333 4444 5555 6666 7777 8888 9999 aaaa bbbb cccc dddd 8f0f"
	original := "# usbbackup 授权标记：持有该公钥指纹的介质走回写分支\n" +
		"# 生成时间 2026-09-18T21:13:21+08:00（生成器 2026.09.18）\n" +
		"fingerprint=" + other + "\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	action, err := mergeExemptMarker(path, ours)
	if err != nil {
		t.Fatal(err)
	}
	if action != "追加" {
		t.Errorf("应走追加分支，实际 %q", action)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, other) {
		t.Fatalf("原有指纹被覆盖了——另一边的客户端会把这块盘当普通介质采集：\n%s", text)
	}
	if !strings.Contains(text, ours) {
		t.Fatalf("本次指纹没写进去：\n%s", text)
	}

	// 幂等：再装一次盘不该越写越长，也不该失败。
	again, err := mergeExemptMarker(path, ours)
	if err != nil {
		t.Fatal(err)
	}
	if again != "已含相同指纹，未改动" {
		t.Errorf("重复装盘应识别为已存在，实际 %q", again)
	}
	raw2, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw2) != text {
		t.Error("重复装盘改动了标记文件的内容")
	}
}

// 全新的盘：没有标记文件时应当直接创建。
func TestMergeExemptMarkerCreatesWhenAbsent(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".usbbackup-allow")
	action, err := mergeExemptMarker(path, "aa bb")
	if err != nil {
		t.Fatal(err)
	}
	if action != "新建" {
		t.Errorf("应走新建分支，实际 %q", action)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "fingerprint=aa bb") {
		t.Errorf("新标记内容不符：\n%s", raw)
	}
}

// 磁盘级授权标记走的是同一套"只追加、幂等"的实现，但文件里的说明文字必须
// 与卷级那份区分开：现场的人靠注释判断哪一个管"整支盘"，两行都写"本盘被豁免"
// 就等于没写。
func TestMergeExemptDiskMarkerIsAppendAndIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".usbbackup-allow-disk")

	action, err := mergeExemptDiskMarker(path, "aa bb")
	if err != nil {
		t.Fatal(err)
	}
	if action != "新建" {
		t.Errorf("首次写入应走新建分支，实际 %q", action)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "fingerprint=aa bb") {
		t.Fatalf("新标记内容不符：\n%s", text)
	}
	if !strings.Contains(text, "磁盘级") {
		t.Fatalf("标记文件里必须写明它是磁盘级的：\n%s", text)
	}

	// 追加：另一个项目（或上一次装盘）留下的指纹不能被冲掉。
	before := text
	action, err = mergeExemptDiskMarker(path, "cc dd")
	if err != nil {
		t.Fatal(err)
	}
	if action != "追加" {
		t.Errorf("应走追加分支，实际 %q", action)
	}
	raw, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text = string(raw)
	if !strings.Contains(text, before) {
		t.Fatalf("原有内容被覆盖了：\n%s", text)
	}
	if !strings.Contains(text, "fingerprint=cc dd") {
		t.Fatalf("新指纹没写进去：\n%s", text)
	}

	// 幂等：重复装盘不该越写越长。
	again, err := mergeExemptDiskMarker(path, "cc dd")
	if err != nil {
		t.Fatal(err)
	}
	if again != "已含相同指纹，未改动" {
		t.Errorf("重复装盘应识别为已存在，实际 %q", again)
	}
	raw2, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw2) != text {
		t.Error("重复装盘改动了标记文件的内容")
	}
}

// 指纹的比对规则必须与另一边的实现一致（跳注释、剥标签前缀、忽略分组空格
// 与大小写）。两边理解不一致就会冒出"本项目以为写过了、那边却认不出"。
func TestMarkerFingerprintParsing(t *testing.T) {
	other := "f36b 2b3c 546a d12d 741e f057 5bfc 90de fa42 c4a3 179c d6c4 2820 9e1f 046b 104d"
	compact := strings.ReplaceAll(strings.ToUpper(other), " ", "")
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"fingerprint= 前缀", "fingerprint=" + other + "\n", true},
		{"pubkey: 前缀", "pubkey: " + other + "\n", true},
		{"裸指纹", other + "\n", true},
		{"大写且无空格", "FINGERPRINT=" + compact + "\n", true},
		{"注释里的指纹不算", "# 参考 fingerprint=" + other + "\n", false},
		{"空内容", "", false},
		{"别的指纹", "fingerprint=0000 1111\n", false},
	}
	for _, tc := range cases {
		if got := markerHasFingerprint(tc.content, other); got != tc.want {
			t.Errorf("%s：得到 %v，期望 %v", tc.name, got, tc.want)
		}
	}
}

// 盘内 README 是现场唯一的离线读物，"会不会上传"是它最要命的一句话。
// 写错了，现场就是"跑了半天，R2 上什么都没有"，而且全程不报错。
func TestToolkitReadmeStatesUploadOff(t *testing.T) {
	got := toolkitReadme(toolkitReadmeInput{
		Fingerprint: "aa bb", HasClient: true, UploadEnabled: false,
		GateThreshold: "10GiB", GateMaxTotal: "10GiB", GateCollect: "all",
	})
	if !strings.Contains(got, "上传到 R2       关闭") {
		t.Error("上传关闭时必须在门控段写明")
	}
	if !strings.Contains(got, "不会上传") {
		t.Error("上传关闭时必须明说不会上传")
	}
	if strings.Contains(got, "会自动上传到 R2") {
		t.Error("上传关闭时不得再声称会自动上传")
	}
	if !strings.Contains(got, "--upload") {
		t.Error("上传关闭时应指出开启办法")
	}
}

// 上传开着、盘上没有明文 client.json（工具盘的常规形态）：必须写清凭据从哪来。
//
// 现在的形态是凭据以 install\client.bin 随盘分发、装机时用 .machine.key 解开，
// 所以断言落在"bin + key 这套离线流程"上，而不是原来的"现场 cred 交互输入"。
// 否则现场只知道"上传开着"却不知道凭据从哪来，结果一样是没上传。
func TestToolkitReadmeGivesCredentialStepsWhenUploadWithoutCredential(t *testing.T) {
	got := toolkitReadme(toolkitReadmeInput{
		Fingerprint: "aa bb", HasClient: true, UploadEnabled: true,
		HasCredential: false,
		GateThreshold: "10GiB", GateMaxTotal: "10GiB", GateCollect: "all",
	})
	for _, must := range []string{
		"会自动上传到 R2",       // 上传确实开着，这句是实话
		"r2.json",         // 素材要在盘里（r2perm.py build 会用到）
		"client.bin",      // 随盘分发的加密凭据
		".machine.key",    // 解开它用的密钥文件
		"r2perm.py build", // 重新生成凭据的办法
		"cred-check",      // 验证办法（手动路径仍会用）
		"明文",              // 必须如实说明解出来是明文的
	} {
		if !strings.Contains(got, must) {
			t.Errorf("上传开启但盘上无凭据时，README 未提到 %q", must)
		}
	}
	// 没凭据就不该出现"这份凭据是口令加密的"之类描述。
	if strings.Contains(got, "关于 client.json（R2 凭据）") {
		t.Error("盘上没有 client.json，不该写出针对它的保护方式说明")
	}
}

// --upload 必须真的把上传打开：这是本命令唯一能表达
// "盘不带凭据、但客户端要上传"的方式。
func TestAssembleToolkitUploadFlagEnablesUpload(t *testing.T) {
	_, pub, priv := writeTestKeys(t)
	dest := t.TempDir()
	if _, err := assembleToolkit(toolkitOptions{
		Dest: dest, ToolDir: fakeToolDir(t),
		PublicKeyPath: pub, PrivateKeyPath: priv,
		WithClient: true, Force: true, Upload: true,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	got, err := embedcfg.Read(filepath.Join(dest, "client.exe"))
	if err != nil {
		t.Fatal(err)
	}
	var emb config.Config
	if err := json.Unmarshal(got.ConfigJSON, &emb); err != nil {
		t.Fatal(err)
	}
	if !emb.Upload.Enabled {
		t.Error("--upload 没有把上传打开")
	}
	// --upload 不带凭据：不能把内嵌凭据名钉成盘内那个相对名
	// （否则"配置的凭据路径"会指向一个刻意不存在的文件）。
	// 保持默认（%LOCALAPPDATA% 下那份绝对路径），现场生成在哪个目录都能被找到。
	if emb.Upload.CredentialFile == DefaultCredentialFileName {
		t.Errorf("--upload 不该把凭据名钉成相对名 %q", DefaultCredentialFileName)
	}
}

// --no-upload 必须真的关掉，且优先于"给了凭据就开"的默认。
func TestAssembleToolkitNoUploadFlagDisablesUpload(t *testing.T) {
	_, pub, priv := writeTestKeys(t)
	dest := t.TempDir()
	if _, err := assembleToolkit(toolkitOptions{
		Dest: dest, ToolDir: fakeToolDir(t),
		PublicKeyPath: pub, PrivateKeyPath: priv,
		WithClient: true, Force: true, NoUpload: true,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	got, err := embedcfg.Read(filepath.Join(dest, "client.exe"))
	if err != nil {
		t.Fatal(err)
	}
	var emb config.Config
	if err := json.Unmarshal(got.ConfigJSON, &emb); err != nil {
		t.Fatal(err)
	}
	if emb.Upload.Enabled {
		t.Error("--no-upload 没有关掉上传")
	}
}

// 复用现成的 client.exe 时，--upload 同样无处可施，必须报错。
// 静默忽略在这里尤其隐蔽：盘看起来做好了，实际根本不会上传。
func TestAssembleRefusesUploadFlagWhenReusingClient(t *testing.T) {
	_, pub, priv := writeTestKeys(t)
	tools := fakeToolDir(t)
	src, err := os.ReadFile(filepath.Join(tools, "usbbackup-r2.exe"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tools, "client.exe"), src, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = assembleToolkit(toolkitOptions{
		Dest: t.TempDir(), ToolDir: tools,
		PublicKeyPath: pub, PrivateKeyPath: priv,
		WithClient: true, Force: true, Upload: true,
	}, io.Discard)
	if err == nil {
		t.Fatal("复用了 client.exe 还传 --upload，必须报错而不是忽略")
	}
	if !strings.Contains(err.Error(), "--upload") {
		t.Errorf("报错应点名 --upload，实际：%v", err)
	}
}

// 凭据素材是随盘分发的，里面**不能**有 secret——那等于长期凭据明文随盘传播。
func TestCheckCredentialTemplateRefusesSecret(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	ok := write("ok.json", `{"account_id":"a","bucket":"b","endpoint":"https://x",
		"region":"auto","prefix":"usb/","access_key_id":"AKID","secret_access_key":""}`)
	if err := checkCredentialTemplateHasNoSecret(ok); err != nil {
		t.Errorf("secret 留空的素材应当放行，实际：%v", err)
	}

	bad := write("bad.json", `{"access_key_id":"AKID","secret_access_key":"deadbeef"}`)
	if err := checkCredentialTemplateHasNoSecret(bad); err == nil {
		t.Error("secret 非空的素材必须拒绝写进盘")
	}

	tok := write("tok.json", `{"access_key_id":"AKID","secret_access_key":"","session_token":"xyz"}`)
	if err := checkCredentialTemplateHasNoSecret(tok); err == nil {
		t.Error("session_token 非空同样必须拒绝")
	}

	notJSON := write("bad.txt", `secret_access_key: deadbeef`)
	if err := checkCredentialTemplateHasNoSecret(notJSON); err == nil {
		t.Error("不是合法 JSON 的素材必须拒绝")
	}
}

// 素材进了盘，就要出现在盘内清单里——现场的人只有这份 README 可看。
func TestAssembleToolkitCopiesCredentialTemplate(t *testing.T) {
	_, pub, priv := writeTestKeys(t)
	dir := t.TempDir()
	tpl := filepath.Join(dir, "r2-template.json")
	if err := os.WriteFile(tpl, []byte(`{"account_id":"a","bucket":"usbbackup",
		"endpoint":"https://a.r2.cloudflarestorage.com","region":"auto",
		"prefix":"usb/","access_key_id":"AKID","secret_access_key":""}`), 0o600); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if _, err := assembleToolkit(toolkitOptions{
		Dest: dest, ToolDir: fakeToolDir(t),
		PublicKeyPath: pub, PrivateKeyPath: priv,
		WithClient: true, Force: true, Upload: true, CredTemplatePath: tpl,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, CredentialTemplateFileName)); err != nil {
		t.Errorf("凭据素材没有写进盘：%v", err)
	}
	readme, err := os.ReadFile(filepath.Join(dest, "README.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(readme), CredentialTemplateFileName) {
		t.Error("盘内 README 的清单里应列出凭据素材")
	}
}
