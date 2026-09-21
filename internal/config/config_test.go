package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultIsValid(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatalf("内置默认配置应通过校验: %v", err)
	}
	if c.Gate.UsedThresholdBytes != DefaultUsedThresholdBytes {
		t.Fatalf("默认阈值应为 10 GiB，实际 %d", c.Gate.UsedThresholdBytes)
	}
	if c.Gate.UsedThresholdBytes != 10*GiB {
		t.Fatalf("GiB 常量定义错误")
	}
	if c.Archive.KeepPlainZip {
		t.Fatal("默认不应保留明文 zip（决策 D-03）")
	}
	if c.Collect.ExemptMarkerFile != ".usbbackup-allow" {
		t.Fatalf("授权标记默认应为 .usbbackup-allow（与不含出站能力的版本同名），实际 %q", c.Collect.ExemptMarkerFile)
	}
	// 磁盘级标记是**另一个**文件名：卷级与磁盘级语义不同，默认值合并就等于
	// 再也表达不出"豁免一个卷"与"豁免整支盘"的区别。
	if c.Collect.ExemptDiskMarkerFile != ".usbbackup-allow-disk" {
		t.Fatalf("磁盘级授权标记默认应为 .usbbackup-allow-disk，实际 %q", c.Collect.ExemptDiskMarkerFile)
	}
	if c.Collect.Policy != "all" {
		t.Fatalf("采集策略默认应为 all，实际 %q", c.Collect.Policy)
	}
	if c.Upload.Enabled {
		t.Fatal("模板程序默认不应开启上传（生成器产出的客户端会显式打开）")
	}
	if !strings.HasSuffix(c.OutputDir, filepath.Join("", "backup")) {
		t.Fatalf("默认输出目录应以 backup 结尾: %q", c.OutputDir)
	}
}

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "不存在.json")
	cfg, loaded, err := Load(missing)
	if err != nil {
		t.Fatalf("文件不存在不应视为错误: %v", err)
	}
	if loaded {
		t.Fatal("loaded 应为 false")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("默认配置应通过校验: %v", err)
	}
}

func TestLoadSaveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg := Default()
	cfg.Collect.Policy = "marker_only"
	cfg.Gate.UsedThresholdBytes = 5 * GiB
	cfg.Archive.Excludes = []string{"*.tmp", "临时"}
	cfg.Log.Level = "debug"
	if err := Save(path, cfg); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	// 不应留下 .part 临时文件。
	if _, err := os.Stat(path + ".part"); err == nil {
		t.Fatal("残留了 .part 临时文件")
	}

	got, loaded, err := Load(path)
	if err != nil || !loaded {
		t.Fatalf("加载失败: loaded=%v err=%v", loaded, err)
	}
	if got.Collect.Policy != "marker_only" || got.Gate.UsedThresholdBytes != 5*GiB {
		t.Fatalf("字段未正确往返: %+v", got.Collect)
	}
	if len(got.Archive.Excludes) != 2 || got.Log.Level != "debug" {
		t.Fatalf("切片或标量字段未正确往返")
	}
	// 未出现的字段应保留默认值。
	if got.Monitor.PollIntervalSec != Default().Monitor.PollIntervalSec {
		t.Fatal("未出现的字段未保留默认值")
	}
}

func TestLoadRejectsMalformedAndUnknownFields(t *testing.T) {
	dir := t.TempDir()

	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{ this is not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(bad); err == nil {
		t.Fatal("非法 JSON 应报错")
	}

	unknown := filepath.Join(dir, "unknown.json")
	if err := os.WriteFile(unknown, []byte(`{"nope":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(unknown); err == nil {
		t.Fatal("未知字段应报错（DisallowUnknownFields）")
	}

	// 字段值非法应被校验拦下。
	invalid := filepath.Join(dir, "invalid.json")
	if err := os.WriteFile(invalid, []byte(`{"collect":{"policy":"乱写"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(invalid); err == nil {
		t.Fatal("非法 collect.policy 应报错")
	}
}

// 两个标记同名 = 采集标记会把授权盘变成采集目标，是最危险的组合，必须拦下。
func TestValidateRejectsSameMarkerNames(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "same.json")
	if err := os.WriteFile(path, []byte(`{"collect":{"exempt_marker_file":".usbbackup-collect"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(path); err == nil {
		t.Fatal("采集标记与授权标记同名时应报错")
	}
}

// 标记名带路径分隔符会让人以为能指向子目录，实际只是拼路径——必须明确拒绝。
func TestValidateRejectsMarkerWithSeparator(t *testing.T) {
	for _, body := range []string{
		`{"collect":{"marker_file":"sub/x"}}`,
		`{"collect":{"exempt_marker_file":"sub\\x"}}`,
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, "bad.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Load(path); err == nil {
			t.Fatalf("标记名含分隔符应报错：%s", body)
		}
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	mutators := map[string]func(*Config){
		"轮询间隔为 0":   func(c *Config) { c.Monitor.PollIntervalSec = 0 },
		"超时为 0":     func(c *Config) { c.Monitor.JobTimeoutMin = 0 },
		"阈值负数":      func(c *Config) { c.Gate.UsedThresholdBytes = -1 },
		"采集策略非法":    func(c *Config) { c.Collect.Policy = "whatever" },
		"采集标记带分隔符":  func(c *Config) { c.Collect.MarkerFile = `a\b` },
		"授权标记带分隔符":  func(c *Config) { c.Collect.ExemptMarkerFile = "a/b" },
		"磁盘级标记带分隔符": func(c *Config) { c.Collect.ExemptDiskMarkerFile = "a/b" },
		"磁盘级与卷级标记同名": func(c *Config) {
			c.Collect.ExemptDiskMarkerFile = c.Collect.ExemptMarkerFile
		},
		"磁盘级标记与采集标记同名": func(c *Config) {
			c.Collect.ExemptDiskMarkerFile = c.Collect.MarkerFile
		},
		"上传分片过小":     func(c *Config) { c.Upload.PartSizeBytes = 1 << 10 },
		"开启上传但无凭据路径": func(c *Config) { c.Upload.Enabled = true; c.Upload.CredentialFile = "  " },
		"保留份数为 0":    func(c *Config) { c.Retention.KeepPerVolume = 0 },
		"线程数为负":      func(c *Config) { c.Archive.Threads = -1 },
	}
	for name, mut := range mutators {
		t.Run(name, func(t *testing.T) {
			c := Default()
			mut(c)
			if err := c.Validate(); err == nil {
				t.Fatalf("期望校验失败")
			}
		})
	}
}

func TestValidateNormalizesLogDefaults(t *testing.T) {
	c := Default()
	c.Log.MaxSizeMB = 0
	c.Log.MaxBackups = -5
	if err := c.Validate(); err != nil {
		t.Fatalf("日志字段应被静默修正而不是报错: %v", err)
	}
	if c.Log.MaxSizeMB != 10 || c.Log.MaxBackups != 5 {
		t.Fatalf("日志默认值未修正: %d / %d", c.Log.MaxSizeMB, c.Log.MaxBackups)
	}
}

func TestApplyEnv(t *testing.T) {
	t.Setenv("USBBACKUP_R2_COLLECT_POLICY", "marker_only")
	t.Setenv("USBBACKUP_R2_OUTPUT_DIR", `D:\out`)
	t.Setenv("USBBACKUP_R2_PUBLIC_KEY", `D:\keys\pub.pem`)
	t.Setenv("USBBACKUP_R2_LOG_LEVEL", "warn")
	t.Setenv("USBBACKUP_R2_USED_THRESHOLD_BYTES", "1073741824")
	t.Setenv("USBBACKUP_R2_POLL_INTERVAL_SEC", "7")

	c := Default()
	applied := c.ApplyEnv()
	if len(applied) != 6 {
		t.Fatalf("应记录 6 个生效变量，实际 %d: %v", len(applied), applied)
	}
	if c.Collect.Policy != "marker_only" || c.OutputDir != `D:\out` {
		t.Fatalf("变量未生效: %+v", c)
	}
	if c.Gate.UsedThresholdBytes != 1<<30 {
		t.Fatalf("阈值变量未生效: %d", c.Gate.UsedThresholdBytes)
	}
	if c.Monitor.PollIntervalSec != 7 || c.Log.Level != "warn" {
		t.Fatalf("标量变量未生效")
	}

	// 非法数值应被忽略而不是污染配置。
	t.Setenv("USBBACKUP_R2_USED_THRESHOLD_BYTES", "不是数字")
	t.Setenv("USBBACKUP_R2_POLL_INTERVAL_SEC", "-1")
	c2 := Default()
	c2.ApplyEnv()
	if c2.Gate.UsedThresholdBytes != DefaultUsedThresholdBytes {
		t.Fatal("非法阈值不应覆盖默认值")
	}
	if c2.Monitor.PollIntervalSec != Default().Monitor.PollIntervalSec {
		t.Fatal("非法轮询间隔不应覆盖默认值")
	}
}

func TestExpandPath(t *testing.T) {
	t.Setenv("USBBACKUP_R2_TEST_ROOT", `D:\root`)
	if got := ExpandPath(`%USBBACKUP_R2_TEST_ROOT%\a\b`); got != filepath.FromSlash(`D:\root\a\b`) {
		t.Fatalf("百分号变量未展开: %q", got)
	}
	if got := ExpandPath(""); got != "" {
		t.Fatalf("空路径应返回空串，实际 %q", got)
	}
	if got := ExpandPath("relative"); !filepath.IsAbs(got) {
		t.Fatalf("相对路径应转为绝对路径: %q", got)
	}
	// TEMP 单变量写法应能用（Windows 上大小写与语义差异常见）。
	t.Setenv("TEMP", `D:\temp`)
	if got := ExpandPath(`%TEMP%\backup`); !strings.HasSuffix(got, "backup") {
		t.Fatalf("TEMP 展开异常: %q", got)
	}
}

func TestSummaryHasNoSecrets(t *testing.T) {
	c := Default()
	lines := strings.Join(c.Summary(), "\n")
	if lines == "" {
		t.Fatal("摘要不应为空")
	}
	for _, forbidden := range []string{"PRIVATE KEY", "BEGIN RSA", "passphrase", "口令"} {
		if strings.Contains(lines, forbidden) {
			t.Fatalf("配置摘要中出现敏感字样: %q", forbidden)
		}
	}
}

func TestParseSizeUnits(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"0", 0},
		{"unlimited", 0},
		{"none", 0},
		{"1024", 1024},
		{"10GiB", 10 * GiB},
		{"10G", 10 * GiB},
		{"10g", 10 * GiB},
		{"10 gib", 10 * GiB},
		{"10GB", 10 * 1000 * 1000 * 1000},
		{"10gb", 10 * 1000 * 1000 * 1000},
		{"1.5TiB", int64(1.5 * float64(1024*1024*1024*1024))},
		{"512MiB", 512 * 1024 * 1024},
		{"256KiB", 256 * 1024},
		{"1MB", 1000 * 1000},
	}
	for _, c := range cases {
		got, err := ParseSize(c.in)
		if err != nil {
			t.Fatalf("ParseSize(%q) 报错: %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("ParseSize(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestParseSizeRejectsBadInput(t *testing.T) {
	bad := []string{"", "   ", "abc", "GiB", "10 XB", "10QB", "-1GiB", "1e999GiB"}
	for _, b := range bad {
		if _, err := ParseSize(b); err == nil {
			t.Errorf("ParseSize(%q) 期望报错", b)
		}
	}
}

func TestGiBvsGBThresholdDiffers(t *testing.T) {
	// 这正是 Q-01 的意义：两种口径在边界盘上会给出不同的结论。
	gib, _ := ParseSize("10GiB")
	gb, _ := ParseSize("10GB")
	if gib <= gb {
		t.Fatalf("10GiB(%d) 应大于 10GB(%d)", gib, gb)
	}
	// 10.5 GB 的盘：按 GiB 口径放行，按 GB 口径跳过。
	const disk = int64(10_500_000_000)
	if disk > gib {
		t.Errorf("10.5e9 应按 GiB 口径放行（阈值 %d）", gib)
	}
	if disk <= gb {
		t.Errorf("10.5e9 应按 GB 口径跳过（阈值 %d）", gb)
	}
}

func TestHumanReadableThresholdOverridesBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body := `{"gate":{"used_threshold":"4GiB"}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, loaded, err := Load(path)
	if err != nil || !loaded {
		t.Fatalf("加载失败: loaded=%v err=%v", loaded, err)
	}
	cfg.ApplyEnv()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("校验失败: %v", err)
	}
	if cfg.Gate.UsedThresholdBytes != 4*GiB {
		t.Fatalf("人类可读写法未生效: %d", cfg.Gate.UsedThresholdBytes)
	}
}

func TestConflictingThresholdWritesAreRejected(t *testing.T) {
	c := Default()
	c.Gate.UsedThreshold = "4GiB"
	c.Gate.UsedThresholdBytes = 8 * GiB
	if err := c.Validate(); err == nil {
		t.Fatal("两种写法含义冲突时应报错")
	}
}

func TestDefaultMaxTotalBytesIsTenGiB(t *testing.T) {
	c := Default()
	if c.Gate.MaxTotalBytes != DefaultMaxTotalBytes {
		t.Fatalf("默认打包上限应为 %d，实际 %d", DefaultMaxTotalBytes, c.Gate.MaxTotalBytes)
	}
	if DefaultMaxTotalBytes != 10*GiB {
		t.Fatalf("Q-07 定案为 10 GiB，实际 %d", DefaultMaxTotalBytes)
	}
}

func TestHumanLimitShowsUnlimited(t *testing.T) {
	if got := humanLimit(0); got != "不限制" {
		t.Fatalf("0 应显示为“不限制”，实际 %q", got)
	}
	if got := humanLimit(10 * GiB); !strings.Contains(got, "10.00 GiB") {
		t.Fatalf("10GiB 显示异常: %q", got)
	}
}

// 机器相关的默认路径必须是**可展开的模板**，不能是构建机解析好的绝对路径。
//
// 生成器会把整份配置序列化后内嵌进 client.exe，而它常常在另一台机器上生成。
// 一旦默认值烙成了 C:\Users\<构建者>\...，换台机器之后日志、审计、产物、凭据
// 全都落到一个不存在的用户目录下。最坏的情况还不报错：服务模式没有控制台，
// 日志目录又建不出来时 logx 会退化成 io.Discard —— 服务照跑，一行日志都不落。
func TestDefaultPathsArePortableTemplates(t *testing.T) {
	c := Default()
	paths := map[string]string{
		"output_dir":             c.OutputDir,
		"public_key_path":        c.PublicKeyPath,
		"audit_file":             c.AuditFile,
		"log.file":               c.Log.File,
		"upload.credential_file": c.Upload.CredentialFile,
	}
	for name, p := range paths {
		if p == "" {
			t.Errorf("%s 默认值不应为空", name)
			continue
		}
		if !strings.Contains(p, "%") {
			t.Errorf("%s 应是可展开模板（含 %%VAR%%），实际 %q：换机器后会指向构建机的目录", name, p)
		}
		if vol := filepath.VolumeName(p); vol != "" {
			t.Errorf("%s 不应带盘符 %q，实际 %q", name, vol, p)
		}
		got := ExpandPath(p)
		if !filepath.IsAbs(got) {
			t.Errorf("%s 展开后应是绝对路径，实际 %q", name, got)
		}
		if strings.Contains(got, "%") {
			t.Errorf("%s 展开后仍残留 %%，实际 %q", name, got)
		}
	}
}

// LOCALAPPDATA 缺失或为空时必须有兜底，不能把 %LOCALAPPDATA% 当字面量留在路径里，
// 也不能因为变量为空而拼出 "\usbbackup-r2\..." 这种既不绝对、又建不出来的路径。
func TestExpandPercentVarsLocalAppDataFallbacks(t *testing.T) {
	want := filepath.Join(os.TempDir(), "usbbackup-r2", "audit.jsonl")
	for _, val := range []string{"", "   "} {
		t.Setenv("LOCALAPPDATA", val)
		got := ExpandPath(`%LOCALAPPDATA%\usbbackup-r2\audit.jsonl`)
		if strings.Contains(got, "%") {
			t.Fatalf("LOCALAPPDATA=%q 时展开后仍残留 %%：%q", val, got)
		}
		if got != want {
			t.Fatalf("LOCALAPPDATA=%q 时应回退到 %q，实际 %q", val, want, got)
		}
	}
}

// Summary 展示的必须是**本机生效**的路径，而不是 %TEMP% 这类模板——
// 运维看 config-check 是为了知道东西到底落在哪。
func TestSummaryShowsResolvedPaths(t *testing.T) {
	c := Default()
	joined := strings.Join(c.Summary(), "\n")
	if strings.Contains(joined, "%TEMP%") || strings.Contains(joined, "%LOCALAPPDATA%") {
		t.Fatalf("配置摘要里不该出现未展开的模板：\n%s", joined)
	}
	if !strings.Contains(joined, ExpandPath(c.OutputDir)) {
		t.Errorf("配置摘要应展示展开后的产物目录 %q", ExpandPath(c.OutputDir))
	}
}

func TestMaxTotalBytesEnvOverride(t *testing.T) {
	c := Default()
	t.Setenv("USBBACKUP_R2_MAX_TOTAL_BYTES", "2GiB")
	c.ApplyEnv()
	if c.Gate.MaxTotalBytes != 2*GiB {
		t.Fatalf("环境变量未生效: %d", c.Gate.MaxTotalBytes)
	}
}
