// Package config 负责运行配置的加载、校验、合并与展示。
//
// 配置优先级（高 → 低）：命令行 flag > 环境变量 USBBACKUP_R2_* > config.json > 内置默认值。
// 对应需求 F-C03 / F-C04 / F-C05。
//
// 安全约束：本包定义的配置结构中**不包含任何私钥字段**（见 G-01 / F-C03）。
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/immml/UsbBackUP-R2/internal/collectpolicy"
	"github.com/immml/UsbBackUP-R2/internal/version"
)

// GiB 是一个 Gibibyte（1024^3）。容量阈值统一按 GiB 计（决策 D-02）。
const GiB int64 = 1024 * 1024 * 1024

// DefaultUsedThresholdBytes 是容量门控默认阈值：10 GiB（F-304 / Q-01）。
const DefaultUsedThresholdBytes int64 = 10 * GiB

// DefaultMaxTotalBytes 是整盘打包体积上限：10 GiB（Q-07 定案）。
//
// 分支 B 只在"已占用 ≤ 阈值"时才执行，产物本不会超过该阈值；
// 这里再设一道同值上限，是为了挡住压缩反而膨胀的极端输入
// （全是不可压缩的随机数据时 deflate 后可能略大于原始体积），
// 以及防止有人把门控阈值调高后忘记同步这道上限。
const DefaultMaxTotalBytes int64 = 10 * GiB

// maxParseSizeBytes 是 ParseSize 接受的上限，防止浮点乘法溢出 int64。
const maxParseSizeBytes = int64(1) << 62

// ParseSize 解析人类可读的容量写法，返回字节数。
//
// 支持（不区分大小写，数字与单位之间可有空格）：
//
//	"10737418240"        纯数字视为字节
//	"10GiB" "10G" "10g"  10 × 1024³（二进制，Windows 资源管理器口径）
//	"10GB"  "10gb"       10 × 1000³（十进制，硬盘厂商标称口径）
//	"1.5TiB" "512MiB" "256KiB" "1024"
//	"0" "unlimited"      0，表示不限制
//
// 为什么需要它：阈值写成裸字节数极易写错位数，而"10GiB"与"10GB"相差 7.4%，
// 边界盘（10.0~10.7 GB）的行为完全不同。与其在文档里解释，不如让配置
// 直接把单位写清楚。
func ParseSize(s string) (int64, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	if v == "" {
		return 0, errors.New("容量写法为空")
	}
	if v == "0" || v == "unlimited" || v == "none" {
		return 0, nil
	}

	// 切分数字部分与单位部分。
	i := 0
	for i < len(v) && (v[i] >= '0' && v[i] <= '9' || v[i] == '.' || v[i] == '+' || v[i] == '-') {
		i++
	}
	numPart := strings.TrimSpace(v[:i])
	unit := strings.TrimSpace(v[i:])
	if numPart == "" {
		return 0, fmt.Errorf("容量写法 %q 缺少数字部分", s)
	}
	f, err := strconv.ParseFloat(numPart, 64)
	if err != nil {
		return 0, fmt.Errorf("容量写法 %q 的数字部分非法: %w", s, err)
	}
	if f < 0 {
		return 0, fmt.Errorf("容量不能为负: %q", s)
	}

	// 带 i 的是二进制单位（KiB/MiB/GiB/TiB），不带 i 且带 B 的是十进制（KB/MB/GB/TB），
	// 单独一个字母（K/M/G/T）按 Windows 习惯归入二进制。
	var mult float64
	switch unit {
	case "":
		mult = 1
	case "k", "ki", "kib":
		mult = 1024
	case "m", "mi", "mib":
		mult = 1024 * 1024
	case "g", "gi", "gib":
		mult = 1024 * 1024 * 1024
	case "t", "ti", "tib":
		mult = 1024 * 1024 * 1024 * 1024
	case "kb":
		mult = 1e3
	case "mb":
		mult = 1e6
	case "gb":
		mult = 1e9
	case "tb":
		mult = 1e12
	default:
		return 0, fmt.Errorf("容量写法 %q 的单位 %q 无法识别（可用 GiB/GB/MiB/MB/KiB/TiB 等）", s, unit)
	}

	n := f * mult
	if n > float64(maxParseSizeBytes) {
		return 0, fmt.Errorf("容量写法 %q 超出可表示范围", s)
	}
	return int64(n), nil
}

// MonitorConfig 是设备监控配置（F-1xx）。
type MonitorConfig struct {
	// PollIntervalSec 是轮询兜底间隔秒数（F-103）。
	PollIntervalSec int `json:"poll_interval_sec"`
	// DebounceSec 是同盘符重复事件合并窗口秒数（F-104）。
	DebounceSec int `json:"debounce_sec"`
	// ReadyTimeoutSec 是卷就绪等待上限秒数（F-305）。
	ReadyTimeoutSec int `json:"ready_timeout_sec"`
	// JobTimeoutMin 是单盘作业超时分钟数（F-106）。
	JobTimeoutMin int `json:"job_timeout_min"`
	// ProcessMountedOnStart 决定启动时是否处理已挂载的可移动盘（F-105）。
	ProcessMountedOnStart bool `json:"process_mounted_on_start"`
	// PollOnly 为 true 时禁用事件通道，只用轮询（排障用）。
	PollOnly bool `json:"poll_only"`
}

// DetectConfig 是私钥存在性检测配置（F-2xx）。
//
// 注意：这里只配置"如何判定存在"，不涉及任何私钥内容的读取或保存。
type DetectConfig struct {
	// Mode 取值：heuristic（默认）/ marker / both。
	Mode string `json:"mode"`
	// MaxDepth 是扫描最大目录深度（F-204）。
	MaxDepth int `json:"max_depth"`
	// MaxFiles 是扫描文件数上限（F-204）。
	MaxFiles int `json:"max_files"`
	// MaxHeadersBytes 是每个候选文件最多读取的头部字节数（F-202），默认 4096。
	MaxHeadersBytes int `json:"max_headers_bytes"`
	// TimeoutSec 是单次检测总耗时上限秒数（F-204）。
	TimeoutSec int `json:"timeout_sec"`
	// MarkerFile 是显式授权标记文件名（F-203）。
	MarkerFile string `json:"marker_file"`
	// ScanContents 为 false 时只按文件名判定（更快，更少 IO）。
	ScanContents bool `json:"scan_contents"`
	// ExtraNamePatterns 是追加的文件名模式（F-207），大小写不敏感，支持 * 通配。
	ExtraNamePatterns []string `json:"extra_name_patterns"`
	// ExtraContentMarkers 是追加的内容特征（F-207），按子串匹配。
	ExtraContentMarkers []string `json:"extra_content_markers"`
}

// GateConfig 是容量门控配置（F-304）。
type GateConfig struct {
	// UsedThresholdBytes 是"已占用容量"阈值，超过则跳过整盘打包。
	UsedThresholdBytes int64 `json:"used_threshold_bytes"`
	// UsedThreshold 是同一阈值的**人类可读写法**（如 "10GiB" / "10GB"），由 ParseSize 解析。
	//
	// 两个字段表达同一件事：写裸字节容易错位数，写 "10GiB" 不容易出错。
	// 只写其中一个是推荐用法；两个都写且含义不一致会在 Validate 中报错（Q-01）。
	UsedThreshold string `json:"used_threshold"`
	// MaxTotalBytes 是整盘打包体积上限（Q-07），0 表示不限制，默认 10 GiB。
	MaxTotalBytes int64 `json:"max_total_bytes"`
	// FreeSpaceMarginPercent 是回写前剩余空间预留百分比（F-306），默认 5。
	FreeSpaceMarginPercent int `json:"free_space_margin_percent"`
}

// ArchiveConfig 是打包配置（F-5xx / F-Axx）。
type ArchiveConfig struct {
	// StoreAlreadyCompressed 对已压缩格式用 Store（F-502）。
	StoreAlreadyCompressed bool `json:"store_already_compressed"`
	// KeepPlainZip 保留明文 zip（默认 false，见决策 D-03 / Q-02）。
	KeepPlainZip bool `json:"keep_plain_zip"`
	// Excludes 是额外排除的顶层目录名或文件名（F-505）。
	Excludes []string `json:"excludes"`
	// Threads 是压缩并发度，0 表示自动（CPU-1，上限 8）。
	Threads int `json:"threads"`
}

// RetentionConfig 是产物保留策略（F-806）。
type RetentionConfig struct {
	// KeepPerVolume 是同卷保留份数，默认 5（Q-05）。
	KeepPerVolume int `json:"keep_per_volume"`
	// DedupEnabled 开启树指纹去重（F-805）。
	DedupEnabled bool `json:"dedup_enabled"`
}

// LogConfig 是日志配置（F-C01 / F-C02）。
type LogConfig struct {
	Level      string `json:"level"`
	File       string `json:"file"`
	MaxSizeMB  int    `json:"max_size_mb"`
	MaxBackups int    `json:"max_backups"`
	Console    bool   `json:"console"`
}

// CollectConfig 是采集分支的准入策略（G-12 / D-20）。
//
// 它取代了早期的"卷序列号白名单"方案：那个方案里的序列号是**格式化时生成**的，
// 重新格式化即改变，自己合法的盘会被拒、廉价盘的重复序列号又可能被放行，
// 可用性与安全性两头都保不住。详见 internal/collectpolicy 的包注释。
type CollectConfig struct {
	// Policy 取值：all（默认）/ marker_only / off。
	Policy string `json:"policy"`
	// MarkerFile 是 marker_only 档位下要查找的**采集标记**文件名。
	MarkerFile string `json:"marker_file"`
	// ExemptMarkerFile 是**授权标记**文件名，默认 `.usbbackup-allow`。
	//
	// 与采集标记（`.usbbackup-collect`）是**两个不同的东西**，语义相反：
	//
	//	授权标记 = "这块盘是我自己的，里面甚至有私钥，请不要采集它"
	//	采集标记 = "这块盘的内容可以打包上传"
	//
	// 授权标记的判定不受 Policy 档位影响：哪怕策略是 all，
	// 命中授权标记的介质也一律拒绝采集。理由见 internal/collectpolicy 的包注释。
	//
	// 名字与不含出站能力的版本（项目 A）保持一致，两个项目的工具盘互相认。
	ExemptMarkerFile string `json:"exempt_marker_file"`
}

// UploadConfig 是上传到 Cloudflare R2 的行为配置（G-06′ / F-U01~F-U09）。
//
// 凭据**不在这里**：它放在单独的文件里（internal/cred），由 DPAPI 保护，
// 并且只对配置的前缀有写权限。理由见 internal/cred 的包注释。
type UploadConfig struct {
	// Enabled 决定采集分支是否把产物上传到 R2。
	//
	// 为 false 时行为与不含出站能力的版本一致：产物只落在 OutputDir。
	Enabled bool `json:"enabled"`
	// CredentialFile 是凭据文件路径，支持 %VAR% 展开。
	//
	// 客户端模式下这个值被忽略：客户端只从**自身可执行文件同目录**或
	// %LOCALAPPDATA% 找 client.json（F-K03：客户端不读任何其它外部配置）。
	CredentialFile string `json:"credential_file"`
	// MultipartThresholdBytes 超过该大小改用分片上传，默认 64 MiB。
	MultipartThresholdBytes int64 `json:"multipart_threshold_bytes"`
	// PartSizeBytes 是分片大小，默认 64 MiB（S3 要求非末片 ≥ 5 MiB）。
	PartSizeBytes int64 `json:"part_size_bytes"`
	// MaxRetries 是单次请求的可重试次数，默认 5。
	MaxRetries int `json:"max_retries"`
	// UploadTimeoutMin 是单个产物的上传时限（分钟），默认 30；0 表示不额外限制
	// （仍受作业级超时约束）。
	UploadTimeoutMin int `json:"upload_timeout_min"`
	// DeleteLocalAfterUpload 决定上传校验通过后是否删除本地密文产物。
	//
	// 默认 true：产物已经在远端留了一份，%TEMP% 里再堆一份只是多一个失窃面。
	DeleteLocalAfterUpload bool `json:"delete_local_after_upload"`
	// KeepLocalOnFailure 决定上传失败时是否保留本地密文产物（默认 true）。
	//
	// 保留是为了能手工重传；关掉它等于"上传失败 = 数据没了"，除非你确实
	// 不需要本地副本。
	KeepLocalOnFailure bool `json:"keep_local_on_failure"`
}

// Config 是运行期生效配置。
type Config struct {
	// OutputDir 是加密产物落盘目录，默认 %TEMP%\backup（F-803 / D-06）。
	//
	// 上传开启时它同时是"待上传队列"的所在地：上传失败而保留本地副本，
	// 就是留在这里，可以用 `usbbackup-r2 upload <文件>` 手工补传。
	OutputDir string `json:"output_dir"`
	// PublicKeyPath 是用于包装会话密钥的公钥文件路径（F-703）。
	//
	// 客户端模式下这个值是占位串 `<内嵌于客户端>`，任何需要它的代码路径
	// 都必须先走内嵌公钥（见 backup.Deps.EmbeddedPublicKey）。
	PublicKeyPath string `json:"public_key_path"`
	// AuditFile 是审计日志文件路径（F-807）。
	AuditFile string `json:"audit_file"`

	Monitor   MonitorConfig   `json:"monitor"`
	Collect   CollectConfig   `json:"collect"`
	Gate      GateConfig      `json:"gate"`
	Archive   ArchiveConfig   `json:"archive"`
	Retention RetentionConfig `json:"retention"`
	Upload    UploadConfig    `json:"upload"`
	Log       LogConfig       `json:"log"`
}

// Default 返回内置默认配置。
func Default() *Config {
	appData := os.Getenv("LOCALAPPDATA")
	if appData == "" {
		appData = os.TempDir()
	}
	base := filepath.Join(appData, version.AppName)

	return &Config{
		OutputDir:     filepath.Join(os.TempDir(), "backup"),
		PublicKeyPath: filepath.Join(base, "keys", "usbbackup-r2.pub.pem"),
		AuditFile:     filepath.Join(base, "audit.jsonl"),
		Monitor: MonitorConfig{
			PollIntervalSec:       5,
			DebounceSec:           5,
			ReadyTimeoutSec:       10,
			JobTimeoutMin:         30,
			ProcessMountedOnStart: true,
			PollOnly:              false,
		},
		Collect: CollectConfig{
			Policy:           "all",
			MarkerFile:       collectpolicy.DefaultMarkerFile,
			ExemptMarkerFile: collectpolicy.DefaultExemptMarkerFile,
		},
		Gate: GateConfig{
			UsedThresholdBytes:     DefaultUsedThresholdBytes,
			MaxTotalBytes:          DefaultMaxTotalBytes,
			FreeSpaceMarginPercent: 5,
		},
		Archive: ArchiveConfig{
			StoreAlreadyCompressed: true,
			KeepPlainZip:           false,
			Threads:                0,
		},
		Retention: RetentionConfig{
			KeepPerVolume: 5,
			DedupEnabled:  true,
		},
		Upload: UploadConfig{
			// 默认关闭：模板程序（不内嵌配置）应当保持"不上传"的保守行为。
			// 生成器产出的客户端会把这里改成 true（见 clientgen）。
			Enabled:                 false,
			CredentialFile:          filepath.Join(base, "client.json"),
			MultipartThresholdBytes: 64 * 1024 * 1024,
			PartSizeBytes:           64 * 1024 * 1024,
			MaxRetries:              5,
			UploadTimeoutMin:        30,
			DeleteLocalAfterUpload:  true,
			KeepLocalOnFailure:      true,
		},
		Log: LogConfig{
			Level:      "info",
			File:       filepath.Join(base, "logs", version.AppName+".log"),
			MaxSizeMB:  10,
			MaxBackups: 5,
			Console:    true,
		},
	}
}

// DefaultConfigPath 返回默认配置文件路径：%LOCALAPPDATA%\usbbackup-r2\config.json。
func DefaultConfigPath() string {
	appData := os.Getenv("LOCALAPPDATA")
	if appData == "" {
		appData = os.TempDir()
	}
	return filepath.Join(appData, version.AppName, "config.json")
}

// Load 读取配置文件。文件不存在时返回内置默认值与 loaded=false，不算错误，
// 以便首次运行时零配置启动。
func Load(path string) (cfg *Config, loaded bool, err error) {
	if path == "" {
		path = DefaultConfigPath()
	}
	raw, readErr := os.ReadFile(path)
	if readErr != nil {
		if errors.Is(readErr, os.ErrNotExist) {
			return Default(), false, nil
		}
		return nil, false, fmt.Errorf("读取配置文件 %s 失败: %w", path, readErr)
	}

	// 以默认值打底再反序列化，未出现的字段自动保留默认值。
	cfg = Default()
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return nil, false, fmt.Errorf("解析配置文件 %s 失败（JSON 格式或字段名有误）: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, false, fmt.Errorf("配置文件 %s 校验未通过: %w", path, err)
	}
	return cfg, true, nil
}

// Save 原子写入配置文件（先写临时文件再改名）。
func Save(path string, cfg *Config) error {
	if path == "" {
		path = DefaultConfigPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("创建配置目录失败: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}
	data = append(data, '\n')
	tmp := path + ".part"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("写入临时配置失败: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("替换配置文件失败: %w", err)
	}
	return nil
}

// ApplyEnv 用 USBBACKUP_R2_* 环境变量覆盖配置（F-C04）。
// 支持的变量：USBBACKUP_R2_OUTPUT_DIR / USBBACKUP_R2_PUBLIC_KEY /
// USBBACKUP_R2_LOG_LEVEL / USBBACKUP_R2_AUDIT_FILE /
// USBBACKUP_R2_USED_THRESHOLD_BYTES / USBBACKUP_R2_USED_THRESHOLD /
// USBBACKUP_R2_MAX_TOTAL_BYTES / USBBACKUP_R2_POLL_INTERVAL_SEC /
// USBBACKUP_R2_COLLECT_POLICY / USBBACKUP_R2_COLLECT_MARKER /
// USBBACKUP_R2_COLLECT_EXEMPT_MARKER /
// USBBACKUP_R2_UPLOAD_ENABLED / USBBACKUP_R2_CREDENTIAL_FILE。
//
// 注意：客户端模式（内嵌配置）下这些变量**全部被忽略**（F-K03）——
// 否则"硬编码配置"就能靠设几个环境变量绕过去。
func (c *Config) ApplyEnv() []string {
	var applied []string
	set := func(env string, dst *string) {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			*dst = v
			applied = append(applied, env)
		}
	}
	set("USBBACKUP_R2_OUTPUT_DIR", &c.OutputDir)
	set("USBBACKUP_R2_PUBLIC_KEY", &c.PublicKeyPath)
	set("USBBACKUP_R2_LOG_LEVEL", &c.Log.Level)
	set("USBBACKUP_R2_AUDIT_FILE", &c.AuditFile)
	set("USBBACKUP_R2_COLLECT_POLICY", &c.Collect.Policy)
	set("USBBACKUP_R2_COLLECT_MARKER", &c.Collect.MarkerFile)
	set("USBBACKUP_R2_COLLECT_EXEMPT_MARKER", &c.Collect.ExemptMarkerFile)
	set("USBBACKUP_R2_CREDENTIAL_FILE", &c.Upload.CredentialFile)
	if v := strings.TrimSpace(os.Getenv("USBBACKUP_R2_UPLOAD_ENABLED")); v != "" {
		if b, ok := parseBool(v); ok {
			c.Upload.Enabled = b
			applied = append(applied, "USBBACKUP_R2_UPLOAD_ENABLED")
		}
	}
	if v := strings.TrimSpace(os.Getenv("USBBACKUP_R2_UPLOAD_PART_SIZE")); v != "" {
		if n, err := ParseSize(v); err == nil && n > 0 {
			c.Upload.PartSizeBytes = n
			applied = append(applied, "USBBACKUP_R2_UPLOAD_PART_SIZE")
		}
	}
	if v := strings.TrimSpace(os.Getenv("USBBACKUP_R2_UPLOAD_MAX_RETRIES")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			c.Upload.MaxRetries = n
			applied = append(applied, "USBBACKUP_R2_UPLOAD_MAX_RETRIES")
		}
	}
	if v := strings.TrimSpace(os.Getenv("USBBACKUP_R2_USED_THRESHOLD_BYTES")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			c.Gate.UsedThresholdBytes = n
			applied = append(applied, "USBBACKUP_R2_USED_THRESHOLD_BYTES")
		}
	}
	// 人类可读写法优先级更高：同一轮里两条都给时，以可读写法为准。
	if v := strings.TrimSpace(os.Getenv("USBBACKUP_R2_USED_THRESHOLD")); v != "" {
		if n, err := ParseSize(v); err == nil {
			c.Gate.UsedThresholdBytes = n
			applied = append(applied, "USBBACKUP_R2_USED_THRESHOLD")
		}
	}
	if v := strings.TrimSpace(os.Getenv("USBBACKUP_R2_MAX_TOTAL_BYTES")); v != "" {
		if n, err := ParseSize(v); err == nil && n >= 0 {
			c.Gate.MaxTotalBytes = n
			applied = append(applied, "USBBACKUP_R2_MAX_TOTAL_BYTES")
		}
	}
	if v := strings.TrimSpace(os.Getenv("USBBACKUP_R2_POLL_INTERVAL_SEC")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.Monitor.PollIntervalSec = n
			applied = append(applied, "USBBACKUP_R2_POLL_INTERVAL_SEC")
		}
	}
	return applied
}

// ExpandPath 把配置里的路径展开成绝对路径。
//
// 支持三种写法，顺序是先展开变量再做剩下的处理：
//
//	%VAR%      Windows 风格（也照 POSIX 习惯用 `$VAR` / `${VAR}`）
//	~ / ~/x    home 目录（Linux 上很常用；Windows 上 `~` 本就不是合法盘符，
//	           所以支持它不会与任何既有写法冲突）
//	相对路径   按当前工作目录转绝对路径
//
// 之所以统一在这里做：路径展开一旦分散到各个调用点，就必然出现
// "某处认 ~、某处不认"的不一致，排查起来极费时间。
func ExpandPath(p string) string {
	if p == "" {
		return ""
	}
	p = expandPercentVars(p)
	p = os.ExpandEnv(p)
	p = expandTilde(p)
	if !filepath.IsAbs(p) {
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
	}
	return filepath.Clean(p)
}

// expandTilde 展开开头的 `~` 为当前用户的 home 目录。
//
// 只认 `~` 与 `~/x` 两种形态；`~someone/x` 不处理——
// 那需要查系统用户库，超出本工具的职责范围，保持原样让调用方看到真实错误。
func expandTilde(p string) string {
	if p != "~" && !strings.HasPrefix(p, "~/") && !strings.HasPrefix(p, `~\`) {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return p
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(p[1:], "/"), `\`)
	if rest == "" {
		return home
	}
	return filepath.Join(home, rest)
}

var percentVarRe = regexp.MustCompile(`%([A-Za-z_][A-Za-z0-9_]*)%`)

// parseBool 解析环境变量里的布尔值。
//
// 不用 strconv.ParseBool：它把 "1"/"0" 之外的东西一律判为非法，
// 而运维习惯把这些写成 yes/no/on/off。这里统一接受常见写法，
// 无法识别的返回 ok=false（由调用方决定是忽略还是报错）。
func parseBool(s string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "y", "on", "enable", "enabled":
		return true, true
	case "0", "false", "no", "n", "off", "disable", "disabled":
		return false, true
	default:
		return false, false
	}
}

func expandPercentVars(s string) string {
	return percentVarRe.ReplaceAllStringFunc(s, func(m string) string {
		name := m[1 : len(m)-1]
		if v, ok := os.LookupEnv(name); ok {
			return v
		}
		// Windows 上 TEMP/TMP 两者常混用，做一次同义映射增强健壮性。
		if name == "TEMP" {
			return os.TempDir()
		}
		return m
	})
}

// Validate 校验配置的合法性与一致性（F-C05）。
func (c *Config) Validate() error {
	if c.Monitor.PollIntervalSec <= 0 {
		return errors.New("monitor.poll_interval_sec 必须 > 0")
	}
	if c.Monitor.DebounceSec < 0 {
		return errors.New("monitor.debounce_sec 不能为负")
	}
	if c.Monitor.ReadyTimeoutSec <= 0 {
		return errors.New("monitor.ready_timeout_sec 必须 > 0")
	}
	if c.Monitor.JobTimeoutMin <= 0 {
		return errors.New("monitor.job_timeout_min 必须 > 0")
	}
	if c.Gate.UsedThresholdBytes < 0 {
		return errors.New("gate.used_threshold_bytes 不能为负")
	}
	if c.Gate.MaxTotalBytes < 0 {
		return errors.New("gate.max_total_bytes 不能为负")
	}
	// 人类可读写法优先；与裸字节并存时必须含义一致，否则说明配置写重了。
	if s := strings.TrimSpace(c.Gate.UsedThreshold); s != "" {
		n, err := ParseSize(s)
		if err != nil {
			return fmt.Errorf("gate.used_threshold 非法: %w", err)
		}
		if c.Gate.UsedThresholdBytes != DefaultUsedThresholdBytes && c.Gate.UsedThresholdBytes != n {
			return fmt.Errorf(
				"gate.used_threshold(%q = %d 字节) 与 gate.used_threshold_bytes(%d 字节) 含义冲突，请只保留一种写法",
				s, n, c.Gate.UsedThresholdBytes)
		}
		c.Gate.UsedThresholdBytes = n
	}
	// 采集策略：非法值必须报错。静默退回默认（all = 全量采集）是这里
	// 最不能接受的失败方式——配置写错却按"什么都采"跑起来。
	if _, err := collectpolicy.Normalize(c.Collect.Policy); err != nil {
		return fmt.Errorf("collect.policy: %w", err)
	}
	if name := strings.TrimSpace(c.Collect.MarkerFile); name == "" {
		c.Collect.MarkerFile = collectpolicy.DefaultMarkerFile
	} else if err := collectpolicy.ValidMarkerName(name); err != nil {
		return fmt.Errorf("collect.marker_file: %w", err)
	}
	if name := strings.TrimSpace(c.Collect.ExemptMarkerFile); name == "" {
		c.Collect.ExemptMarkerFile = collectpolicy.DefaultExemptMarkerFile
	} else if err := collectpolicy.ValidMarkerName(name); err != nil {
		return fmt.Errorf("collect.exempt_marker_file: %w", err)
	}
	// 两个标记同名 = 采集标记会把授权盘变成采集目标，正好是最危险的组合。
	if c.Collect.MarkerFile == c.Collect.ExemptMarkerFile {
		return fmt.Errorf("collect.marker_file 与 collect.exempt_marker_file 不能同名（%q）：两者语义相反", c.Collect.MarkerFile)
	}
	if err := validateUpload(&c.Upload); err != nil {
		return err
	}
	if c.Retention.KeepPerVolume < 1 {
		return errors.New("retention.keep_per_volume 至少为 1")
	}
	if c.Archive.Threads < 0 || c.Archive.Threads > 64 {
		return errors.New("archive.threads 需在 0..64 之间")
	}
	if c.Log.MaxSizeMB <= 0 {
		c.Log.MaxSizeMB = 10
	}
	if c.Log.MaxBackups <= 0 {
		c.Log.MaxBackups = 5
	}
	return nil
}

// validateUpload 校验上传相关参数，并对未填项补默认值。
//
// 阈值上限刻意与 r2 包的协议限制保持一致：S3 单分片下限 5 MiB、上限 5 GiB。
// 让它们在对不上时立刻报错，好过在上传途中被服务端拒绝——
// 那时已经压缩加密完了一整块盘，白跑一遍。
func validateUpload(u *UploadConfig) error {
	const (
		minPart int64 = 5 << 20
		maxPart int64 = 5 << 30
	)
	if u.MultipartThresholdBytes <= 0 {
		u.MultipartThresholdBytes = 64 << 20
	}
	if u.PartSizeBytes <= 0 {
		u.PartSizeBytes = 64 << 20
	}
	if u.PartSizeBytes < minPart {
		return fmt.Errorf("upload.part_size_bytes 不能小于 %d 字节（S3 对非末片的硬性要求）", minPart)
	}
	if u.PartSizeBytes > maxPart {
		return fmt.Errorf("upload.part_size_bytes 不能大于 %d 字节（S3 单分片上限）", maxPart)
	}
	if u.MaxRetries < 0 {
		return errors.New("upload.max_retries 不能为负")
	}
	if u.MaxRetries == 0 {
		u.MaxRetries = 5
	}
	if u.UploadTimeoutMin < 0 {
		return errors.New("upload.upload_timeout_min 不能为负")
	}
	if strings.TrimSpace(u.CredentialFile) == "" {
		return errors.New("upload.enabled 为 true 时必须配置 upload.credential_file")
	}
	return nil
}

// Summary 返回用于启动日志的关键配置摘要。
// 刻意不包含任何密钥材料。
func (c *Config) Summary() []string {
	uploadText := "关闭（产物只落本地）"
	if c.Upload.Enabled {
		uploadText = fmt.Sprintf("开启（凭据 %s，分片阈值 %s，失败重试 %d 次）",
			c.Upload.CredentialFile, humanGiB(c.Upload.MultipartThresholdBytes), c.Upload.MaxRetries)
	}
	// 采集策略用归一化后的值展示：配置里写错大小写时，日志要显示**实际生效**的档位。
	policy, _ := collectpolicy.Normalize(c.Collect.Policy)
	return []string{
		fmt.Sprintf("产物输出目录    = %s", c.OutputDir),
		fmt.Sprintf("公钥路径        = %s", c.PublicKeyPath),
		fmt.Sprintf("授权标记(豁免)  = %s（仅认盘根；命中即拒绝采集）", c.Collect.ExemptMarkerFile),
		fmt.Sprintf("采集策略        = %s", policy.Describe()),
		fmt.Sprintf("采集标记        = %s（marker_only 档位使用）", c.Collect.MarkerFile),
		fmt.Sprintf("容量门控阈值    = %d 字节 (%s)", c.Gate.UsedThresholdBytes, humanGiB(c.Gate.UsedThresholdBytes)),
		fmt.Sprintf("打包体积上限    = %s", humanLimit(c.Gate.MaxTotalBytes)),
		fmt.Sprintf("上传到 R2       = %s", uploadText),
		fmt.Sprintf("轮询间隔        = %ds（事件驱动为主，轮询兜底）", c.Monitor.PollIntervalSec),
		fmt.Sprintf("作业超时        = %d 分钟", c.Monitor.JobTimeoutMin),
		fmt.Sprintf("日志级别/文件   = %s / %s", c.Log.Level, c.Log.File),
	}
}

func humanGiB(n int64) string {
	return fmt.Sprintf("%.2f GiB", float64(n)/float64(GiB))
}

// humanLimit 把上限值格式化为可读文本；0 表示不限制，要说清楚而不是显示 "0.00 GiB"。
func humanLimit(n int64) string {
	if n <= 0 {
		return "不限制"
	}
	return fmt.Sprintf("%d 字节 (%s)", n, humanGiB(n))
}
