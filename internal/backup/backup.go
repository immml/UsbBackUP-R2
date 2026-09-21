// Package backup 是流水线编排层，把各模块串成一条作业链。
//
// 状态：**已完整实现**（产物命名与审计见本文件，流水线见 pipeline.go，
// 上传见 upload.go，保留策略见 retention.go）。
//
// 对应需求 F-801 ~ F-809 与 F-H01 ~ F-H03。
//
// 分支判定：
//
//	插入事件 → 就绪等待 → 卷类型检查
//	    ├─ 盘根命中授权标记(.usbbackup-allow) → 豁免，直接跳过（不读盘、不打包）
//	    └─ 未豁免 → 采集策略判定（collectpolicy.Decide）
//	          ├─ off / marker_only 未命中 → 跳过
//	          └─ 通过 → 容量门控（winvol.EvaluateGate）
//	                ├─ used > 阈值 → 跳过
//	                └─ 否则 → 整盘打包 + 混合加密（archive + crypto）
//	                        → 上传 R2（可选，见 upload.go）
//	                        → 按配置保留/清理本地密文
//
// 全程对源介质**只读**：不写入、不删除、不改名源盘上任何对象（G-05）。
// 唯一的写动作落在本机 OutputDir 与远端 R2 上。
//
// 审计约束（G-02 / F-G02）：审计记录**只包含**盘符、卷标、容量、分支、
// 布尔判定与计数，绝不包含文件清单、文件名或任何文件内容。
package backup

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/immml/UsbBackUP-R2/internal/archive"
	"github.com/immml/UsbBackUP-R2/internal/collectpolicy"
	"github.com/immml/UsbBackUP-R2/internal/config"
	"github.com/immml/UsbBackUP-R2/internal/crypto"
	"github.com/immml/UsbBackUP-R2/internal/fsutil"
	"github.com/immml/UsbBackUP-R2/internal/winvol"
)

// Branch 是作业走的分支。
type Branch string

// 分支常量。
const (
	// BranchArchive 表示通过全部准入判定，执行整盘打包加密（并按配置上传）。
	BranchArchive Branch = "archive-encrypt"
	// BranchSkipped 表示因准入判定或门控而跳过。
	BranchSkipped Branch = "skipped"
	// BranchFailed 表示作业失败。
	BranchFailed Branch = "failed"
)

// 跳过原因（写入审计，便于事后复盘）。
//
// 容量门控相关的几个（used-over-threshold / max-total-exceeded / volume-not-ready）
// **不在此处定义**：它们由 winvol.EvaluateGate 直接给出稳定码，见 winvol.PolicyCode*。
// 原因见那里的注释——两个阈值语义不同，混用一个码会让复盘时不知道该调哪个配置项。
const (
	// SkipReasonNotRemovable 表示不是可移动卷（F-301）。
	SkipReasonNotRemovable = "not-removable"
	// SkipReasonNotReady 表示卷未就绪（F-305）。
	SkipReasonNotReady = "volume-not-ready"
	// SkipReasonExemptMarker 表示盘根有授权标记，本次豁免（F-G03′）。
	SkipReasonExemptMarker = "exempt-marker"
	// SkipReasonExemptDiskMarker 表示同物理磁盘上存在磁盘级授权标记，整盘豁免（F-G03″）。
	//
	// 单独一个码而不是并进上面那个：复盘的常见问题是"明明只在一个分区放了标记，
	// 为什么另一个分区也被跳过了"，答案就写在这个码里。
	SkipReasonExemptDiskMarker = "exempt-disk-marker"
	// SkipReasonCollectDisabled 表示采集策略为 off。
	SkipReasonCollectDisabled = "collect-disabled"
	// SkipReasonNoCollectMarker 表示 marker_only 档位下未找到采集标记。
	SkipReasonNoCollectMarker = "no-collect-marker"
)

// Deps 是流水线依赖。
type Deps struct {
	Cfg *config.Config
	Log *slog.Logger
	// AllowFixed 允许对固定磁盘执行作业。
	// **仅供验证与排障**（本机没有可移动介质时用来跑通链路），生产环境应保持 false。
	AllowFixed bool
	// DryRun 只做检测与门控判定，不写入任何数据、不发起任何网络请求。
	DryRun bool
	// EmbeddedPublicKey 是客户端模式下**内嵌在可执行文件里**的公钥。
	//
	// 非空时优先于 cfg.PublicKeyPath：客户端运行在他人可控的机器上，
	// 不能依赖外部公钥文件（文件可能被替换、删除或指向攻击者的公钥）。
	// 这只是一把公钥，内嵌不构成泄露（G-01）。
	EmbeddedPublicKey *rsa.PublicKey
	// CredentialPath 覆盖凭据文件位置；为空时按 resolveCredentialPath 解析。
	CredentialPath string
	// Uploader 覆盖上传实现（联调与测试注入）。为 nil 时按配置构造 r2 客户端。
	Uploader Uploader
	// UploadPrefix 覆盖对象键前缀；为空时用凭据里的前缀。
	UploadPrefix string
	// SameDiskRoots 覆盖"同物理磁盘卷根"查询（联调与测试注入）。
	//
	// 为 nil 时用 winvol.SameDiskRoots（真机实现，需管理员权限）；
	// 传入一个返回错误的函数即可复现"权限不足 → 磁盘级豁免未生效"的告警路径。
	SameDiskRoots func(root string) ([]string, error)
}

// AuditRecord 是写入 audit.jsonl 的一行。
//
// 字段经过刻意裁剪：**不含任何路径清单、文件名或文件内容**（G-02）。
type AuditRecord struct {
	Time         string `json:"time"`
	Tool         string `json:"tool"`
	ToolVersion  string `json:"tool_version,omitempty"`
	Root         string `json:"root"`
	Label        string `json:"label,omitempty"`
	FileSystem   string `json:"fs,omitempty"`
	SerialNumber uint32 `json:"serial,omitempty"`
	TotalBytes   int64  `json:"total_bytes"`
	FreeBytes    int64  `json:"free_bytes"`
	UsedBytes    int64  `json:"used_bytes"`
	Branch       Branch `json:"branch"`

	// ---- 采集准入（F-G02 / F-H03）----
	//
	// 全部是布尔值与档位名，不含文件名、不含标记内容。
	CollectPolicy string `json:"collect_policy,omitempty"`
	Collected     bool   `json:"collected"`
	ExemptMarker  bool   `json:"exempt_marker"`
	// ExemptDiskMarker 表示本次是因**同物理磁盘**上的磁盘级授权标记而豁免。
	// 与 ExemptMarker 分开记：复盘时要能区分"本卷自己带标记"与"同盘另一个卷认领了整支盘"。
	ExemptDiskMarker bool   `json:"exempt_disk_marker,omitempty"`
	CollectMarker    bool   `json:"collect_marker,omitempty"`
	CollectSkipped   string `json:"collect_skip_reason,omitempty"`

	// SkipReason 仅在跳过时有值。
	SkipReason string `json:"skip_reason,omitempty"`
	// Product 是产物相对文件名（只含净化后的卷标与扩展名，不含完整路径）。
	Product string `json:"product,omitempty"`
	// Files / RawBytes / CipherBytes 是打包统计。
	Files       int   `json:"files,omitempty"`
	RawBytes    int64 `json:"raw_bytes,omitempty"`
	CipherBytes int64 `json:"cipher_bytes,omitempty"`

	// ---- 上传（F-H03）----
	// 不含 token、不含签名头、不含 URL query。
	R2ObjectKey   string `json:"r2_object_key,omitempty"`
	R2Bucket      string `json:"r2_bucket,omitempty"`
	UploadedBytes int64  `json:"uploaded_bytes,omitempty"`
	UploadResult  string `json:"upload_result,omitempty"`
	UploadErr     string `json:"upload_error,omitempty"`
	// LocalProduct 说明本地产物最后的去向。
	LocalProduct string `json:"local_product,omitempty"`

	OK          bool    `json:"ok"`
	Err         string  `json:"error,omitempty"`
	DurationSec float64 `json:"duration_sec,omitempty"`
}

// ProductName 依据卷标生成产物文件名（F-602）。
//
// 形态：`{净化后的卷标}.zip.usbk`；卷标为空则用 `VOL_<盘符>`。
// 净化保证结果不含任何路径分隔符，防路径穿越。
func ProductName(v winvol.Volume) string {
	base := fsutil.SanitizeName(winvol.LabelOrFallback(v))
	if base == "" {
		base = "VOL_UNKNOWN"
	}
	// 去掉可能残留的扩展名混淆点（如 "x.zip" 之类的卷标）。
	base = strings.TrimSuffix(base, ".zip")
	if base == "" {
		base = "VOL_UNKNOWN"
	}
	return base + ".zip.usbk"
}

// UniqueProductPath 在目标目录下为产物取一个不冲突的路径。
// 冲突时追加 `_YYYYMMDD_HHMMSS`（F-602）。
func UniqueProductPath(outputDir string, v winvol.Volume, at time.Time) string {
	name := ProductName(v)
	full := filepath.Join(outputDir, name)
	if _, err := os.Stat(full); errors.Is(err, os.ErrNotExist) {
		return full
	}
	stem := strings.TrimSuffix(name, ".zip.usbk")
	return filepath.Join(outputDir, fmt.Sprintf("%s_%s.zip.usbk", stem, at.Format("20060102_150405")))
}

// AppendAudit 以 JSON Lines 形式追加一条审计记录（F-807）。
//
// 写失败不致命：返回错误由调用方降级为 WARN，不阻断备份本身。
func AppendAudit(path string, rec AuditRecord) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("审计文件路径为空")
	}
	if rec.Time == "" {
		rec.Time = time.Now().Format(time.RFC3339)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("创建审计目录失败: %w", err)
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("序列化审计记录失败: %w", err)
	}
	line = append(line, '\n')

	f, err := os.OpenFile(fsutil.LongPath(path), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("打开审计文件失败: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("写入审计记录失败: %w", err)
	}
	return nil
}

// Result 是一次作业的结果。
type Result struct {
	Root       string
	Volume     winvol.Volume
	Branch     Branch
	SkipReason string
	// Collect 是采集准入判定的结论（含豁免与标记命中情况）。
	Collect collectpolicy.Decision
	Gate    winvol.Policy
	// ProductPath 是产物绝对路径。
	ProductPath string
	// Zip 是打包统计。
	Zip archive.ZipStats
	// Encrypt 是加密统计。
	Encrypt crypto.EncryptSummary
	// Upload 是上传结果；未开启上传时 Attempted 为 false。
	Upload UploadResult
	OK     bool
	Err    string
	// Duration 是本次作业耗时。
	Duration time.Duration
}
