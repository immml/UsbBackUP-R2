package clientgen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/immml/UsbBackUP-R2/internal/config"
	"github.com/immml/UsbBackUP-R2/internal/embedcfg"
)

// fakeTemplate 造一个"像 exe"的模板（内容无需真可执行，只验证块读写与复制）。
func fakeTemplate(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "usbbackup-r2.exe")
	if err := os.WriteFile(p, []byte(strings.Repeat("MZ", 5000)), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// pubPEM 生成一把测试公钥的 PEM。
func pubPEM(t *testing.T, bits int) (pemBytes []byte, key *rsa.PrivateKey) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), k
}

func okOptions(t *testing.T, out string) Options {
	t.Helper()
	p, _ := pubPEM(t, 2048)
	return Options{
		PublicKeyPEM: p,
		Template:     fakeTemplate(t),
		Output:       out,
		ClientName:   "unit-test",
		OutputDir:    "D:/out",
		Threshold:    "4GiB",
	}
}

func TestBuildProducesReadableClient(t *testing.T) {
	out := filepath.Join(t.TempDir(), "client.exe")
	res, err := Build(okOptions(t, out))
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	if res.ClientName != "unit-test" {
		t.Errorf("客户端标识不符: %q", res.ClientName)
	}
	if res.KeyBits != 2048 {
		t.Errorf("位数不符: %d", res.KeyBits)
	}
	if res.OutputDir != "D:/out" {
		t.Errorf("输出目录不符: %q", res.OutputDir)
	}
	if !strings.Contains(res.ThresholdText, "4GiB") {
		t.Errorf("阈值展示异常: %q", res.ThresholdText)
	}
	if res.Fingerprint == "" {
		t.Error("应返回公钥指纹")
	}
	// 产物必须比模板大（追加了配置块）。
	tplSize := int64(10000)
	st, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() <= tplSize {
		t.Errorf("产物应大于模板: %d vs %d", st.Size(), tplSize)
	}
}

// 内嵌配置里**不得出现构建机的绝对路径**。
//
// 生成器把整份配置序列化后贴进 client.exe，而它常常在另一台机器上生成。
// 默认路径原本是构建时解析好的绝对路径（C:\Users\<构建者>\...），换台机器之后
// 日志、审计、产物、凭据全都指向一个不存在的用户目录；服务模式下没有控制台，
// 日志目录又建不出来时 logx 会退化成 io.Discard —— 服务照跑，一行日志都不落。
// 所以这里把"必须是模板、必须是相对机器无关的"钉成回归测试。
func TestEmbeddedConfigCarriesNoBuildMachinePaths(t *testing.T) {
	out := filepath.Join(t.TempDir(), "client.exe")
	opt := okOptions(t, out)
	opt.OutputDir = "" // 空 = 用默认值，也就是模板
	opt.BaseConfig = config.Default()
	if _, err := Build(opt); err != nil {
		t.Fatalf("Build 失败: %v", err)
	}

	p, err := embedcfg.Read(out)
	if err != nil {
		t.Fatalf("回读内嵌配置失败: %v", err)
	}
	if la := os.Getenv("LOCALAPPDATA"); la != "" && strings.Contains(string(p.ConfigJSON), la) {
		t.Errorf("内嵌配置里出现了构建机的 LOCALAPPDATA（%s）：换机器后会指向不存在的目录", la)
	}

	var got config.Config
	if err := json.Unmarshal(p.ConfigJSON, &got); err != nil {
		t.Fatalf("内嵌配置无法反序列化: %v", err)
	}
	paths := map[string]string{
		"output_dir":             got.OutputDir,
		"public_key_path":        got.PublicKeyPath,
		"audit_file":             got.AuditFile,
		"log.file":               got.Log.File,
		"upload.credential_file": got.Upload.CredentialFile,
	}
	for name, v := range paths {
		if v == "" {
			t.Errorf("%s 不应为空", name)
			continue
		}
		// public_key_path 是刻意的占位串：客户端用的是内嵌公钥，不读盘上的文件。
		// 它不是路径，所以不参与"必须是模板"的断言。
		if name == "public_key_path" && v == "<内嵌于客户端>" {
			continue
		}
		if vol := filepath.VolumeName(v); vol != "" {
			t.Errorf("%s 被烙成了绝对路径 %q（盘符 %q）：应当留模板，由目标机器解析", name, v, vol)
		}
		if !strings.Contains(v, "%") {
			t.Errorf("%s 应是可展开模板，实际 %q", name, v)
		}
	}
	// 显式指定绝对路径时按原样保留：那是运维有意的选择，不该被"顺手改成模板"。
	opt2 := okOptions(t, filepath.Join(t.TempDir(), "client2.exe"))
	opt2.OutputDir = `D:\explicit-out`
	res2, err := Build(opt2)
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	if res2.OutputDir != `D:\explicit-out` {
		t.Errorf("显式 --output-dir 应原样保留，实际 %q", res2.OutputDir)
	}
	if !strings.Contains(res2.OutputDirText(), "explicit-out") || strings.Contains(res2.OutputDirText(), "模板") {
		t.Errorf("显式绝对路径的展示不该标注为模板: %q", res2.OutputDirText())
	}
}

func TestBuildRejectsPrivateKey(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	priv := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	opt := okOptions(t, filepath.Join(t.TempDir(), "c.exe"))
	opt.PublicKeyPEM = priv
	if _, err := Build(opt); err == nil {
		t.Fatal("内嵌私钥必须被拒绝")
	}
}

func TestBuildValidatesInputs(t *testing.T) {
	base := okOptions(t, filepath.Join(t.TempDir(), "c.exe"))

	// 缺公钥。
	o := base
	o.PublicKeyPEM = nil
	if _, err := Build(o); err == nil {
		t.Error("缺公钥应报错")
	}
	// 缺输出路径。
	o = base
	o.Output = ""
	if _, err := Build(o); err == nil {
		t.Error("缺输出路径应报错")
	}
	// 阈值非法。
	o = base
	o.Threshold = "10XYZ"
	if _, err := Build(o); err == nil {
		t.Error("阈值非法应报错")
	}
	// 打包上限非法。
	o = base
	o.MaxTotal = "abc"
	if _, err := Build(o); err == nil {
		t.Error("上限非法应报错")
	}
	// 模板不存在。
	o = base
	o.Template = filepath.Join(t.TempDir(), "nope.exe")
	if _, err := Build(o); err == nil {
		t.Error("模板不存在应报错")
	}
	// 模板是目录。
	o = base
	o.Template = t.TempDir()
	if _, err := Build(o); err == nil {
		t.Error("模板为目录应报错")
	}
}

func TestBuildRefusesOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "client.exe")
	if _, err := Build(okOptions(t, out)); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(okOptions(t, out)); err == nil {
		t.Fatal("未加 Force 时不应覆盖已存在的产物")
	}
	// 显式 Force 可以覆盖。
	o := okOptions(t, out)
	o.Force = true
	if _, err := Build(o); err != nil {
		t.Fatalf("Force 后应可覆盖: %v", err)
	}
}

func TestBuildAppliesOverrides(t *testing.T) {
	out := filepath.Join(t.TempDir(), "client.exe")
	o := okOptions(t, out)
	o.MaxTotal = "0"
	o.Collect = "marker_only"
	o.EnableUpload = true
	o.CredentialFile = "client.json"
	res, err := Build(o)
	if err != nil {
		t.Fatal(err)
	}
	if res.Config.Collect.Policy != "marker_only" {
		t.Errorf("采集策略覆盖未生效: %q", res.Config.Collect.Policy)
	}
	if !res.UploadEnabled || res.CredentialFile != "client.json" {
		t.Errorf("上传参数未写入配置: enabled=%v cred=%q", res.UploadEnabled, res.CredentialFile)
	}
	if res.MaxTotalText != "不限制" {
		t.Errorf("上限 0 应显示为不限制，实际 %q", res.MaxTotalText)
	}
	if res.Config.Gate.MaxTotalBytes != 0 {
		t.Errorf("上限 0 未生效: %d", res.Config.Gate.MaxTotalBytes)
	}
	if res.Config.PublicKeyPath != "<内嵌于客户端>" {
		t.Errorf("公钥路径应为内嵌占位，实际 %q", res.Config.PublicKeyPath)
	}
}

// 非法的采集策略必须在**生成时**就报错：等到客户端在目标机器上启动才发现，
// 那时人已经不在生成机上了。
func TestBuildRejectsBadCollectPolicy(t *testing.T) {
	out := filepath.Join(t.TempDir(), "client.exe")
	o := okOptions(t, out)
	o.Collect = "collect-everything"
	if _, err := Build(o); err == nil {
		t.Fatal("非法采集策略应在生成时报错")
	}
}

func TestHumanLimit(t *testing.T) {
	if got := humanLimit(0); got != "不限制" {
		t.Errorf("0 应显示不限制，实际 %q", got)
	}
	if got := humanLimit(10 * 1024 * 1024 * 1024); got == "不限制" || got == "" {
		t.Errorf("10GiB 显示异常: %q", got)
	}
}
