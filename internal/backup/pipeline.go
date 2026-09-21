package backup

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/immml/UsbBackUP-R2/internal/archive"
	"github.com/immml/UsbBackUP-R2/internal/collectpolicy"
	"github.com/immml/UsbBackUP-R2/internal/config"
	"github.com/immml/UsbBackUP-R2/internal/crypto"
	"github.com/immml/UsbBackUP-R2/internal/fsutil"
	"github.com/immml/UsbBackUP-R2/internal/keystore"
	"github.com/immml/UsbBackUP-R2/internal/version"
	"github.com/immml/UsbBackUP-R2/internal/winvol"
)

// Run 执行一次完整的单盘作业（F-801 / F-H01 / F-H02）。
//
// 流程：
//
//	就绪等待 → 卷类型检查 → 授权标记豁免 → 采集策略判定
//	    ├─ 豁免 / 未通过 → 跳过（零读取、不打包、不上传）
//	    └─ 通过 → 容量门控
//	          ├─ 超阈值 → 跳过
//	          └─ 否则   → 整盘 zip 流式直送混合加密 → 上传 R2 → 本地保留策略
//
// 无论走哪条路径、成功或失败，最后都会写一条审计记录（F-807）。
// 全过程对源介质只读；本机唯一的写入点是 OutputDir（G-05）。
func Run(ctx context.Context, deps Deps, root string) (Result, error) {
	start := time.Now()
	res := Result{Root: root, Branch: BranchFailed}

	if deps.Cfg == nil {
		return res, errors.New("backup: 缺少配置")
	}
	cfg := deps.Cfg
	log := deps.Log

	// 作业级超时（F-106）：防挂起盘把队列拖死。
	timeout := time.Duration(cfg.Monitor.JobTimeoutMin) * time.Minute
	jobCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	norm, err := winvol.NormalizeRoot(root)
	if err != nil {
		res.Err = err.Error()
		auditBestEffort(cfg, log, res, start)
		return res, err
	}
	res.Root = norm

	// ---- 1) 就绪等待（F-305）----
	vol, err := waitReady(jobCtx, norm, time.Duration(cfg.Monitor.ReadyTimeoutSec)*time.Second)
	res.Volume = vol
	if err != nil {
		res.Branch = BranchSkipped
		res.SkipReason = SkipReasonNotReady
		res.Err = err.Error()
		auditBestEffort(cfg, log, res, start)
		return res, nil
	}

	// ---- 2) 卷类型检查（F-301）----
	if !vol.Removable && !deps.AllowFixed {
		res.Branch = BranchSkipped
		res.SkipReason = SkipReasonNotRemovable
		log.Info("作业跳过：非可移动卷", "root", norm, "type", winvol.DriveTypeName(vol.DriveType))
		auditBestEffort(cfg, log, res, start)
		return res, nil
	}

	// ---- 3) 采集准入：授权标记豁免（卷级 → 磁盘级）+ 策略判定（F-G01 / F-G03′ / F-G03″）----
	//
	// 磁盘级那一层要查本卷属于哪块物理磁盘，在 Windows 上需要管理员权限。
	// 权限不足**不影响本次结论**（只是少了这层加固），但会留下告警。
	sameDisk := deps.SameDiskRoots
	if sameDisk == nil {
		sameDisk = winvol.SameDiskRoots
	}
	dec, derr := collectpolicy.Decide(norm, collectpolicy.Options{
		Policy:           mustPolicy(cfg),
		Marker:           cfg.Collect.MarkerFile,
		ExemptMarker:     cfg.Collect.ExemptMarkerFile,
		ExemptDiskMarker: cfg.Collect.ExemptDiskMarkerFile,
		SameDiskRoots:    sameDisk,
	})
	if derr != nil {
		// 判定本身出错（例如标记名非法）说明配置有问题，按失败处理，不冒险采集。
		res.Branch = BranchFailed
		res.Err = derr.Error()
		log.Error("采集准入判定失败", "root", norm, "err", derr)
		auditBestEffort(cfg, log, res, start)
		return res, derr
	}
	res.Collect = dec

	// 磁盘级检查没做完（最常见的原因是权限不足）必须显眼：
	// 此刻只剩卷级判定在挡，多分区介质上仍可能出现"标记过却被部分采集"。
	// 绝不静默——使用者一旦误以为整支盘都豁免了，这个工具就失去了可信度。
	if dec.ExemptDiskCheckErr != "" {
		log.Warn("无法确定本卷所属物理磁盘，磁盘级授权标记本次未生效（只按卷级标记判定）",
			"root", norm, "marker", cfg.Collect.ExemptDiskMarkerFile, "err", dec.ExemptDiskCheckErr)
	}

	if !dec.Collect {
		res.Branch = BranchSkipped
		res.SkipReason = mapCollectReason(dec.Reason)
		res.OK = true
		res.Duration = time.Since(start)
		switch {
		case dec.ExemptMarkerFound:
			// 这条日志要显眼：它意味着"这块盘被认出来是自己人的，主动放过了"。
			log.Info("卷根存在授权标记 → 豁免本次采集（本卷不会被读取或上传）",
				"root", norm, "marker", cfg.Collect.ExemptMarkerFile, "label", winvol.LabelOrFallback(vol))
		case dec.ExemptDiskMarkerFound:
			// 多分区介质上的关键一条：本卷自己没有标记，是同盘另一个卷根认领了整支盘。
			log.Info("同一物理磁盘上存在磁盘级授权标记 → 整支盘豁免（含本卷）",
				"root", norm, "marker", cfg.Collect.ExemptDiskMarkerFile,
				"found_at", dec.ExemptDiskMarkerRoot, "label", winvol.LabelOrFallback(vol))
		default:
			log.Info("采集策略未放行，跳过",
				"root", norm, "policy", string(mustPolicy(cfg)), "reason", dec.Reason)
		}
		auditBestEffort(cfg, log, res, start)
		return res, nil
	}

	return runArchive(jobCtx, deps, norm, vol, res, start)
}

// mustPolicy 返回归一化后的策略档位。
//
// 配置校验阶段已保证取值合法（非法值会让程序起不来），因此这里可以安全地
// 忽略错误；真要出了问题，Decide 里还有一层"未知档位报错"兜着。
func mustPolicy(cfg *config.Config) collectpolicy.Policy {
	p, err := collectpolicy.Normalize(cfg.Collect.Policy)
	if err != nil {
		return collectpolicy.Policy(cfg.Collect.Policy)
	}
	return p
}

// mapCollectReason 把采集判定的原因映射成审计用的跳过原因。
func mapCollectReason(reason string) string {
	switch reason {
	case collectpolicy.ReasonExempt:
		return SkipReasonExemptMarker
	case collectpolicy.ReasonExemptDisk:
		return SkipReasonExemptDiskMarker
	case collectpolicy.ReasonDisabled:
		return SkipReasonCollectDisabled
	case collectpolicy.ReasonMarkerAbsent:
		return SkipReasonNoCollectMarker
	default:
		return reason
	}
}

// waitReady 轮询等待卷就绪（刚插入时卷可能尚未挂载完成）。
func waitReady(ctx context.Context, root string, timeout time.Duration) (winvol.Volume, error) {
	deadline := time.Now().Add(timeout)
	var last winvol.Volume
	var lastErr error

	for {
		v, err := winvol.Query(root)
		last, lastErr = v, err
		if err == nil && v.Ready {
			return v, nil
		}
		// 非可移动卷不必等就绪：直接带着信息返回，由上层决定跳过。
		if errors.Is(err, winvol.ErrNotRemovable) {
			return v, nil
		}
		if time.Now().After(deadline) {
			if lastErr == nil {
				lastErr = winvol.ErrNotReady
			}
			return last, fmt.Errorf("等待卷就绪超时: %w", lastErr)
		}
		select {
		case <-ctx.Done():
			return last, ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
}

// runArchive 执行主流程：容量门控 + 整盘打包 + 混合加密 + 上传（F-304 / F-501 / F-601 / F-H02）。
func runArchive(ctx context.Context, deps Deps, root string, vol winvol.Volume, res Result, start time.Time) (Result, error) {
	cfg := deps.Cfg
	log := deps.Log

	// ---- 容量门控（F-304）----
	gate := winvol.EvaluateGate(vol, cfg.Gate.UsedThresholdBytes, cfg.Gate.MaxTotalBytes)
	res.Gate = gate
	if !gate.Proceed {
		res.Branch = BranchSkipped
		// 用门控自己给出的稳定码（两个阈值语义不同，不能混成一个）。
		res.SkipReason = gate.Code
		res.OK = true
		res.Duration = time.Since(start)
		log.Info("采集策略放行，但容量门控跳过",
			"root", root,
			"used", fsutil.HumanBytes(vol.UsedBytes),
			"threshold", fsutil.HumanBytes(cfg.Gate.UsedThresholdBytes),
			"max_total", limitText(cfg.Gate.MaxTotalBytes),
			"reason", gate.Reason)
		auditBestEffort(cfg, log, res, start)
		return res, nil
	}

	if deps.DryRun {
		res.Branch = BranchArchive
		res.OK = true
		res.Duration = time.Since(start)
		log.Info("dry-run：将通过门控并执行整盘打包加密",
			"root", root, "product", ProductName(vol), "upload", cfg.Upload.Enabled)
		return res, nil
	}

	// ---- 载入公钥（F-601）----
	pub, fp, err := loadEncryptionKey(cfg, deps.EmbeddedPublicKey)
	if err != nil {
		res.Branch = BranchFailed
		res.Err = err.Error()
		log.Error("无法载入公钥，作业中止", "root", root, "err", err)
		auditBestEffort(cfg, log, res, start)
		return res, err
	}

	// ---- 产物路径（F-602 / F-603）----
	outDir := config.ExpandPath(cfg.OutputDir)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		res.Branch = BranchFailed
		res.Err = err.Error()
		auditBestEffort(cfg, log, res, start)
		return res, err
	}
	// 源守卫（F-507）：产物目录不得位于被扫描的卷之内，否则会递归套娃。
	if err := archive.CheckSourceGuard(root, outDir); err != nil {
		res.Branch = BranchFailed
		res.Err = err.Error()
		log.Error("源守卫拒绝执行", "root", root, "output", outDir, "err", err)
		auditBestEffort(cfg, log, res, start)
		return res, err
	}
	finalPath := UniqueProductPath(outDir, vol, start)
	tmpPath := finalPath + ".part"
	res.ProductPath = finalPath

	log.Info("采集策略放行且容量在阈值内 → 整盘打包 + 混合加密",
		"root", root,
		"used", fsutil.HumanBytes(vol.UsedBytes),
		"product", filepath.Base(finalPath),
		"upload", cfg.Upload.Enabled)

	// ---- 打包与加密以管道串联：明文 zip 不落盘（决策 D-03）----
	out, err := os.OpenFile(fsutil.LongPath(tmpPath), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		res.Branch = BranchFailed
		res.Err = err.Error()
		auditBestEffort(cfg, log, res, start)
		return res, err
	}

	pr, pw := io.Pipe()
	type zipOutcome struct {
		stats archive.ZipStats
		err   error
	}
	zipDone := make(chan zipOutcome, 1)

	go func() {
		cw := archive.NewCountingWriter(pw)
		st, zerr := archive.ZipStream(ctx, cw, archive.ZipOptions{
			SourceRoot:             root,
			Excludes:               cfg.Archive.Excludes,
			StoreAlreadyCompressed: cfg.Archive.StoreAlreadyCompressed,
			Threads:                cfg.Archive.Threads,
		})
		// 必须用 CloseWithError 把错误带给加密侧，否则加密侧会一直阻塞在 Read 上。
		_ = pw.CloseWithError(zerr)
		zipDone <- zipOutcome{stats: st, err: zerr}
	}()

	sum, encErr := crypto.EncryptStream(out, pr, crypto.EncryptOptions{
		PublicKey:            pub,
		PublicKeyFingerprint: fp,
		ChunkSize:            crypto.DefaultChunkSize,
	})

	zs := <-zipDone
	res.Zip = zs.stats
	res.Encrypt = sum

	closeErr := out.Close()
	_ = pr.Close()

	if encErr != nil || zs.err != nil {
		// 失败：清理半成品，绝不留一个看起来完整的坏容器（F-801）。
		_ = os.Remove(fsutil.LongPath(tmpPath))
		res.Branch = BranchFailed
		if encErr != nil {
			res.Err = encErr.Error()
			log.Error("加密失败", "root", root, "err", encErr)
		} else {
			res.Err = zs.err.Error()
			log.Error("打包失败", "root", root, "err", zs.err)
		}
		auditBestEffort(cfg, log, res, start)
		return res, fmt.Errorf("打包加密失败: %s", res.Err)
	}
	if closeErr != nil {
		_ = os.Remove(fsutil.LongPath(tmpPath))
		res.Branch = BranchFailed
		res.Err = closeErr.Error()
		auditBestEffort(cfg, log, res, start)
		return res, closeErr
	}

	// ---- 落盘：临时文件改名，保证原子性 ----
	if err := os.Rename(fsutil.LongPath(tmpPath), fsutil.LongPath(finalPath)); err != nil {
		_ = os.Remove(fsutil.LongPath(tmpPath))
		res.Branch = BranchFailed
		res.Err = fmt.Sprintf("重命名产物失败: %v", err)
		auditBestEffort(cfg, log, res, start)
		return res, err
	}

	res.Branch = BranchArchive
	res.OK = true

	log.Info("打包加密完成",
		"root", root,
		"files", zs.stats.Files,
		"skipped", zs.stats.Skipped,
		"raw", fsutil.HumanBytes(zs.stats.RawBytes),
		"zip", fsutil.HumanBytes(sum.PlainBytes),
		"cipher", fsutil.HumanBytes(sum.CipherBytes),
		"product", filepath.Base(finalPath))

	// ---- 上传到 R2（F-H02）----
	uploadStep(ctx, deps, &res, finalPath, vol, start)

	res.Duration = time.Since(start)

	// 保留策略（F-806）：只清理本工具生成的同类产物。
	if n, rerr := EnforceRetention(outDir, ProductBase(vol), cfg.Retention.KeepPerVolume, log); rerr != nil {
		log.Warn("保留策略执行失败（不影响本次备份）", "err", rerr)
	} else if n > 0 {
		log.Info("保留策略已清理旧产物", "removed", n, "keep", cfg.Retention.KeepPerVolume)
	}

	auditBestEffort(cfg, log, res, start)
	return res, nil
}

// uploadStep 在打包加密完成后把产物送上远端，并决定本地产物的去留。
//
// 上传失败**不回滚作业结论**（D-19）：本地已经有一份完好的密文产物，
// 把它标成"整次作业失败"会让人误以为数据丢了。真正的处置是保留本地 +
// 记审计 + 用 `upload` 子命令补传，因此这里把结论写在 res.Upload 里。
func uploadStep(ctx context.Context, deps Deps, res *Result, finalPath string, vol winvol.Volume, start time.Time) {
	cfg := deps.Cfg
	log := deps.Log

	plan := prepareUpload(cfg, deps, log)
	defer plan.Close()

	switch {
	case plan == nil:
		res.Upload.Result = UploadNotEnabled
		res.Upload.LocalAction = "kept"
		return
	case plan.client == nil:
		// F-F06：凭据不可用必须**明确且可见**，然后退回"仅本地产物"。
		res.Upload.Result = UploadUnavailable
		res.Upload.Err = plan.reason
		res.Upload.LocalAction = "kept"
		log.Error("上传已禁用：凭据不可用，本次仅保留本地产物", "reason", plan.reason)
		return
	}

	st, err := os.Stat(fsutil.LongPath(finalPath))
	if err != nil {
		res.Upload.Result = UploadFailed
		res.Upload.Err = fmt.Sprintf("读取产物大小失败: %v", err)
		log.Error("上传前读取产物失败", "err", err)
		return
	}

	key := ObjectKey(plan.prefix, filepath.Base(finalPath), start)
	out, uerr := uploadProduct(ctx, cfg, plan, log, finalPath, key, st.Size())
	applyLocalPolicy(cfg, deps, &out, finalPath, log)
	res.Upload = out
	_ = uerr // 失败已在 out.Result / out.Err 里体现，作业本身不因此失败
	_ = vol
}

// loadEncryptionKey 取得加密用公钥与指纹。
//
// 客户端模式下公钥内嵌在可执行文件里（deps.EmbeddedPublicKey），
// 优先于配置里的路径——客户端不能依赖外部公钥文件。
func loadEncryptionKey(cfg *config.Config, embedded *rsa.PublicKey) (*rsa.PublicKey, [32]byte, error) {
	var zero [32]byte
	if embedded != nil {
		if embedded.N.BitLen() < keystore.MinRSAKeyBits {
			return nil, zero, fmt.Errorf("内嵌公钥仅 %d 位，低于下限 %d 位", embedded.N.BitLen(), keystore.MinRSAKeyBits)
		}
		fp, _, err := keystore.PublicKeyFingerprint(embedded)
		if err != nil {
			return nil, zero, err
		}
		return embedded, fp, nil
	}
	p := config.ExpandPath(cfg.PublicKeyPath)
	if strings.TrimSpace(p) == "" {
		return nil, zero, errors.New("未配置公钥路径，无法执行加密（请先运行 usbkeygen-r2 generate 与 use）")
	}
	pub, err := keystore.LoadPublicKey(p)
	if err != nil {
		return nil, zero, fmt.Errorf("读取公钥 %s 失败: %w", p, err)
	}
	fp, _, err := keystore.PublicKeyFingerprint(pub)
	if err != nil {
		return nil, zero, err
	}
	return pub, fp, nil
}

// auditBestEffort 写审计记录，失败只记录日志（F-807）。
func auditBestEffort(cfg *config.Config, log interface {
	Warn(string, ...any)
}, res Result, start time.Time) {
	if cfg == nil {
		return
	}
	rec := ResultToAudit(res, start)
	// 生效档位取自配置（归一化后），而不是采集判定的结论——这样"被豁免而
	// 完全没走到策略判定"的作业也能在审计里看出当时用的是什么档位。
	if p, err := collectpolicy.Normalize(cfg.Collect.Policy); err == nil {
		rec.CollectPolicy = string(p)
	}
	if err := AppendAudit(config.ExpandPath(cfg.AuditFile), rec); err != nil {
		log.Warn("写入审计记录失败（不影响作业结果）", "err", err)
	}
}

// ResultToAudit 把作业结果转成审计记录。
//
// 注意：这里**不含**任何文件名清单或文件内容（G-02），
// 也不含 token、签名头与 URL query（F-H03）。
func ResultToAudit(res Result, start time.Time) AuditRecord {
	rec := AuditRecord{
		Time:         start.Format(time.RFC3339),
		Tool:         version.AppName,
		ToolVersion:  version.Version,
		Root:         res.Root,
		Label:        res.Volume.Label,
		FileSystem:   res.Volume.FileSystem,
		SerialNumber: res.Volume.SerialNumber,
		TotalBytes:   res.Volume.TotalBytes,
		FreeBytes:    res.Volume.FreeBytes,
		UsedBytes:    res.Volume.UsedBytes,
		Branch:       res.Branch,
		SkipReason:   res.SkipReason,
		OK:           res.OK,
		Err:          res.Err,
		DurationSec:  res.Duration.Seconds(),
	}

	// 采集准入结论（布尔值与档位名，不含盘上内容）。
	//
	// 条件里必须带上磁盘级检查：某次作业可能只有它跑过（卷级标记没命中，
	// 但同盘另一个卷根带磁盘级标记），漏掉会让审计里查不到"凭什么豁免"。
	if res.Collect.ExemptMarkerChecked || res.Collect.ExemptDiskMarkerChecked || res.Collect.MarkerChecked {
		rec.Collected = res.Collect.Collect
		rec.ExemptMarker = res.Collect.ExemptMarkerFound
		rec.ExemptDiskMarker = res.Collect.ExemptDiskMarkerFound
		rec.CollectMarker = res.Collect.MarkerFound
		if !res.Collect.Collect {
			rec.CollectSkipped = res.Collect.Reason
		}
	}

	if res.ProductPath != "" {
		rec.Product = filepath.Base(res.ProductPath)
	}
	if res.Zip.Files > 0 {
		rec.Files = res.Zip.Files
		rec.RawBytes = res.Zip.RawBytes
	}
	if res.Encrypt.CipherBytes > 0 {
		rec.CipherBytes = res.Encrypt.CipherBytes
	}

	if res.Upload.Result != "" {
		rec.R2ObjectKey = res.Upload.ObjectKey
		rec.R2Bucket = res.Upload.Bucket
		rec.UploadedBytes = res.Upload.Bytes
		rec.UploadResult = res.Upload.Result
		rec.UploadErr = res.Upload.Err
		rec.LocalProduct = res.Upload.LocalAction
	}
	return rec
}

// CleanupPartials 清理输出目录中的 `.part` 半成品（F-809）。
//
// 只删除本工具自己命名的临时文件，绝不触碰其它文件。
func CleanupPartials(outputDir string) (int, error) {
	dir := config.ExpandPath(outputDir)
	entries, err := os.ReadDir(fsutil.LongPath(dir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	removed := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".usbk.part") && !strings.HasSuffix(name, ".zip.usbk.part") {
			continue
		}
		if err := os.Remove(fsutil.LongPath(filepath.Join(dir, name))); err == nil {
			removed++
		}
	}
	return removed, nil
}

// limitText 把体积上限渲染成日志友好的文本（0 表示不限制）。
func limitText(n int64) string {
	if n <= 0 {
		return "不限制"
	}
	return fsutil.HumanBytes(n)
}
