package backup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/immml/UsbBackUP-R2/internal/config"
	"github.com/immml/UsbBackUP-R2/internal/cred"
	"github.com/immml/UsbBackUP-R2/internal/crypto"
	"github.com/immml/UsbBackUP-R2/internal/fsutil"
	"github.com/immml/UsbBackUP-R2/internal/r2"
	"github.com/immml/UsbBackUP-R2/internal/version"
)

// CredentialFileName 是凭据文件的固定文件名。
//
// 与生成器产出的名字一致（见 cred.FileName）：两边不一致会导致
// 现场"只拷了 exe"时静默退回本地模式。
const CredentialFileName = cred.FileName

// UploadResult 描述一次上传的结局。
//
// 它同时是审计字段的来源，因此**不含 token、不含签名头、不含 URL query**。
type UploadResult struct {
	// Attempted 为 true 表示确实尝试过上传（凭据可用且文件存在）。
	Attempted bool
	// OK 为 true 表示上传并核对通过。
	OK bool
	// ObjectKey / Bucket / Endpoint 描述落点；凭据不可用时为空。
	ObjectKey string
	Bucket    string
	Endpoint  string
	// Bytes 是上传的密文字节数。
	Bytes int64
	// ETag 是远端返回的实体标签（不含引号）。
	ETag string
	// Result 是结论枚举，见下面的 Upload* 常量。
	Result string
	// Err 是失败原因（人话，不含敏感信息）。
	Err string
	// LocalAction 说明本地产物最后的去向：kept / deleted / removed-after-failure。
	LocalAction string
}

// 上传结论枚举。
const (
	// UploadNotEnabled 表示配置里没开上传。
	UploadNotEnabled = "not-enabled"
	// UploadUnavailable 表示开了上传但凭据不可用，已退回"仅本地产物"。
	UploadUnavailable = "unavailable"
	// Uploaded 表示上传并核对通过。
	Uploaded = "uploaded"
	// UploadFailed 表示上传或核对失败。
	UploadFailed = "failed"
)

// Uploader 抽象"把本地文件放到远端"这一件事。
//
// 它只有两个方法，是因为流水线只需要两件事：传上去、核对传对了没有。
// 刻意不暴露"任意方法 + 任意路径"的入口（见 r2.Client 的同类说明）。
type Uploader interface {
	UploadFile(ctx context.Context, localPath, key string, progress r2.ProgressFunc) (r2.ObjectInfo, error)
	Head(ctx context.Context, key string) (r2.ObjectInfo, error)
}

// uploadPlan 是一次作业的上传通道。
//
// 三种状态：
//
//	client 非 nil            → 可以上传
//	client 为 nil，reason 非空 → 曾想上传但不可用（凭据缺失/解不开），退回仅本地
//	nil                      → 配置里没开上传
type uploadPlan struct {
	client   Uploader
	prefix   string
	bucket   string
	endpoint string
	reason   string
	// creds 仅在本包自行加载凭据时非空，用于收尾清零。
	creds *cred.Credentials
}

// Close 尽力清掉内存中的凭据材料。
func (p *uploadPlan) Close() {
	if p == nil || p.creds == nil {
		return
	}
	p.creds.Zero()
	p.creds = nil
}

// prepareUpload 组装上传通道。
//
// 凭据不可用时**不返回错误**：按 F-F06 的要求，此时应明确报错并退回
// "仅本地产物"模式，而不是让整次备份失败——磁盘就在手边，数据先落下来
// 才是第一优先。调用方通过 plan.client 是否为 nil 判断能不能传。
func prepareUpload(cfg *config.Config, deps Deps, log *slog.Logger) *uploadPlan {
	if cfg == nil || !cfg.Upload.Enabled {
		return nil
	}
	plan := &uploadPlan{prefix: cred.NormalizePrefix(deps.UploadPrefix)}

	// 注入的实现（联调/测试）优先。
	if deps.Uploader != nil {
		plan.client = deps.Uploader
		if plan.prefix == "" {
			plan.prefix = cred.DefaultPrefix
		}
		return plan
	}

	path, cands := ResolveCredentialPath(cfg)
	if path == "" {
		plan.reason = fmt.Sprintf("未找到凭据文件 %s；已查找：%s", CredentialFileName, strings.Join(cands, "、"))
		return plan
	}
	c, err := cred.Load(path)
	if err != nil {
		plan.reason = fmt.Sprintf("凭据不可用（%s）：%v", path, err)
		return plan
	}
	cli, err := r2.New(r2.Options{
		Endpoint:                c.Endpoint,
		Bucket:                  c.Bucket,
		Region:                  c.EffectiveRegion(),
		AccessKeyID:             string(c.AccessKeyID),
		SecretAccessKey:         string(c.SecretAccessKey),
		SessionToken:            string(c.SessionToken),
		MaxRetries:              cfg.Upload.MaxRetries,
		MultipartThresholdBytes: cfg.Upload.MultipartThresholdBytes,
		PartSizeBytes:           cfg.Upload.PartSizeBytes,
		UserAgent:               version.AppName + "/" + version.Version,
	})
	if err != nil {
		c.Zero()
		plan.reason = fmt.Sprintf("凭据可用但无法构造上传客户端（%s）：%v", path, err)
		return plan
	}

	plan.creds = &c
	plan.client = cli
	plan.bucket = c.Bucket
	plan.endpoint = c.Endpoint
	if plan.prefix == "" {
		plan.prefix = c.EffectivePrefix()
	}
	log.Info("上传通道已就绪",
		"endpoint", c.Endpoint,
		"bucket", c.Bucket,
		"prefix", plan.prefix,
		"scope", c.EffectiveScope(),
		"cred", c.Redact())
	return plan
}

// ResolveCredentialPath 按优先级找出凭据文件，返回命中的路径与**全部候选**。
//
// 候选顺序：
//
//  1. 配置里写的 upload.credential_file（相对路径按"与可执行文件同目录"解析：
//     客户端场景下生成器把 client.json 与 client.exe 放在一起）；
//  2. 可执行文件同目录的 client.json；
//  3. %LOCALAPPDATA%\usbbackup-r2\client.json。
//
// 关于第 1、2 条的安全性：把 client.json 放在可执行文件旁边**不引入新的攻击面**——
// 能往那个目录写文件的人本来就能直接替换掉 exe 本身。而且凭据是 DPAPI
// 机器范围加密的，拷到别的机器上解不开，改指向也带不走已加密的历史数据。
//
// 返回全部候选是为了把错误信息写清楚：现场最常见的问题是"文件放错目录"，
// 只说一句"凭据文件不存在"会让人来回试。
func ResolveCredentialPath(cfg *config.Config) (string, []string) {
	var cands []string
	seen := map[string]bool{}
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		key := strings.ToLower(p)
		if seen[key] {
			return
		}
		seen[key] = true
		cands = append(cands, p)
	}

	if raw := strings.TrimSpace(cfg.Upload.CredentialFile); raw != "" {
		expanded := config.ExpandPath(raw)
		if filepath.IsAbs(raw) || strings.HasPrefix(raw, "%") || strings.HasPrefix(raw, "$") {
			add(expanded)
		} else {
			if dir := exeDir(); dir != "" {
				add(filepath.Join(dir, raw))
			}
			add(expanded)
		}
	}
	if dir := exeDir(); dir != "" {
		add(filepath.Join(dir, CredentialFileName))
	}
	if appData := os.Getenv("LOCALAPPDATA"); appData != "" {
		add(filepath.Join(appData, version.AppName, CredentialFileName))
	}

	for _, p := range cands {
		if st, err := os.Stat(fsutil.LongPath(p)); err == nil && !st.IsDir() {
			return p, cands
		}
	}
	return "", cands
}

// exeDir 返回当前可执行文件所在目录；取不到时返回空串。
func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(exe)
}

// ObjectKey 生成远端对象键。
//
// 默认模板（Q-10）：`{prefix}{UTC时间戳}_{卷标}.zip.usbk`。
// 前置时间戳是为了让同一块盘的多次采集互不覆盖——远端不像本地那样
// 有 UniqueProductPath 的冲突处理，重名就是静默覆盖掉上一次的备份。
//
// 产物名来自卷标，属于**不可信输入**（卷标是人可以随便起的），
// 因此这里会重新净化一遍，并拒绝残留的任何路径分隔符与 `..`：
// 对象键里带上 `../` 是能把对象写到前缀之外的。
func ObjectKey(prefix, productName string, at time.Time) string {
	name := sanitizeObjectName(filepath.Base(productName))
	return cred.NormalizePrefix(prefix) + at.UTC().Format("20060102T150405Z") + "_" + name
}

// sanitizeObjectName 净化对象键里的文件名字段。
func sanitizeObjectName(name string) string {
	name = fsutil.SanitizeName(name)
	name = strings.NewReplacer("/", "_", `\`, "_").Replace(name)
	name = strings.Trim(name, " .")
	if name == "" || name == ".." {
		return "backup.usbk"
	}
	return name
}

// uploadProduct 上传产物并核对远端大小（F-E02 ~ F-E08）。
//
// 核对失败会重传一次：远端声明的大小与本地不一致意味着传输链路出了问题，
// 直接标记失败会让人以为"再跑一次就行"，而重传一次的成本远低于一次误判。
func uploadProduct(ctx context.Context, cfg *config.Config, plan *uploadPlan, log *slog.Logger,
	localPath, key string, size int64) (UploadResult, error) {

	res := UploadResult{
		Attempted: true,
		ObjectKey: key,
		Bucket:    plan.bucket,
		Endpoint:  plan.endpoint,
		Bytes:     size,
	}

	// 大对象给足时间；0 表示不额外限制（仍受作业级超时约束）。
	upCtx := ctx
	if m := cfg.Upload.UploadTimeoutMin; m > 0 {
		var cancel context.CancelFunc
		upCtx, cancel = context.WithTimeout(ctx, time.Duration(m)*time.Minute)
		defer cancel()
	}

	progress := newProgressLogger(log, filepath.Base(localPath), size)

	var err error
	for attempt := 1; attempt <= 2; attempt++ {
		if _, uerr := plan.client.UploadFile(upCtx, localPath, key, progress.report); uerr != nil {
			err = uerr
			break
		}
		// 上传后核对（F-E07）：HEAD 比对远端大小。
		head, herr := plan.client.Head(upCtx, key)
		if herr != nil {
			err = herr
			break
		}
		if head.Size == size {
			res.OK = true
			res.ETag = head.ETag
			break
		}
		err = fmt.Errorf("远端对象大小不符（远端 %d 字节，本地 %d 字节）", head.Size, size)
		if attempt == 1 {
			log.Warn("上传后核对不一致，重传一次", "key", key, "err", err)
		}
	}

	if res.OK {
		res.Result = Uploaded
		log.Info("上传完成",
			"key", key,
			"bytes", fsutil.HumanBytes(size),
			"bucket", plan.bucket,
			"elapsed", progress.elapsed().String())
		return res, nil
	}

	res.Result = UploadFailed
	res.Err = err.Error()
	// 403 几乎总是"token 权限不对"，而它与网络故障的处理办法完全不同，
	// 所以在日志里直接点出来，省掉一轮排查。
	if r2.IsForbidden(err) {
		log.Error("上传被拒绝：token 权限范围没覆盖目标桶（应为「Object Read & Write + 仅限该桶」）", "key", key, "err", err)
	} else {
		log.Error("上传失败", "key", key, "err", err)
	}
	return res, err
}

// applyLocalPolicy 按配置决定本地密文产物的去留（F-E12）。
//
// 默认：上传成功即删（产物已在远端有一份，%TEMP% 里再堆一份只是多一个失窃面），
// 上传失败则保留（留着才能手工补传）。
func applyLocalPolicy(cfg *config.Config, deps Deps, res *UploadResult, localPath string, log *slog.Logger) {
	res.LocalAction = "kept"
	if deps.DryRun || localPath == "" {
		return
	}
	remove := false
	switch {
	case res.OK && cfg.Upload.DeleteLocalAfterUpload:
		remove = true
	case !res.OK && !cfg.Upload.KeepLocalOnFailure && res.Attempted:
		// 明确关掉了"失败保留"：删掉。这条要慎用，等于上传失败即数据丢失。
		remove = true
	case !res.Attempted:
		// 没开上传或凭据不可用：产物就是唯一的一份，绝不能删。
		return
	}
	if !remove {
		return
	}
	if err := os.Remove(fsutil.LongPath(localPath)); err != nil {
		// 删除失败只记 WARN：作业结论不该因为一次清理失败而变成失败。
		res.LocalAction = "kept"
		log.Warn("删除本地产物失败（不影响作业结论）", "file", filepath.Base(localPath), "err", err)
		return
	}
	res.LocalAction = "deleted"
	log.Info("已按配置删除本地产物（远端已留存）", "file", filepath.Base(localPath))
}

// progressLogger 按时间间隔节流地上报上传进度。
//
// 为什么要节流：进度回调跑在数据通路上，每次 Read 都可能触发；
// 每个分片都打一行日志会把日志文件刷爆，也会拖慢传输。
type progressLogger struct {
	log   *slog.Logger
	name  string
	total int64
	start time.Time
	last  time.Time
	// step 是下次上报的字节门槛，按总量的 10% 递增。
	step int64
}

func newProgressLogger(log *slog.Logger, name string, total int64) *progressLogger {
	step := total / 10
	if step < 8<<20 {
		step = 8 << 20 // 小文件也别打太密：至少每 8 MiB 一行
	}
	return &progressLogger{log: log, name: name, total: total, start: time.Now(), last: time.Now(), step: step}
}

func (p *progressLogger) report(done, total int64) {
	if p == nil || p.log == nil {
		return
	}
	if total > 0 {
		p.total = total
	}
	if done < p.total && done < p.step && time.Since(p.last) < 5*time.Second {
		return
	}
	p.step = done + p.total/10
	p.last = time.Now()
	pct := "-"
	if p.total > 0 {
		pct = fmt.Sprintf("%.0f%%", float64(done)*100/float64(p.total))
	}
	p.log.Info("上传中",
		"file", p.name,
		"done", fsutil.HumanBytes(done),
		"total", fsutil.HumanBytes(p.total),
		"percent", pct)
}

func (p *progressLogger) elapsed() time.Duration {
	if p == nil {
		return 0
	}
	return time.Since(p.start)
}

// verifyContainerMagic 校验文件确实是本工具产出的 `.usbk` 容器。
//
// 只读容器头（96 字节），不需要私钥。这样 `upload` 子命令就不可能被拿去
// 当"任意文件上传器"用——凭据的权限是"只写"，不该顺带变成通用写入通道。
func verifyContainerMagic(path string) error {
	f, err := os.Open(fsutil.LongPath(path))
	if err != nil {
		return fmt.Errorf("打开文件失败: %w", err)
	}
	defer f.Close()
	if _, _, err := crypto.ReadHeader(f); err != nil {
		return fmt.Errorf("不是本工具产出的加密容器（容器头校验失败）: %w", err)
	}
	return nil
}

// UploadLocalFile 把已在本地的一个容器上传到 R2（供 `upload` 子命令复用）。
//
// 它会先校验容器魔数：只接受本工具产出的 `.usbk`，
// 免得有人拿它当"任意文件上传器"用（那等于把凭据变成通用写入通道）。
func UploadLocalFile(ctx context.Context, cfg *config.Config, deps Deps, log *slog.Logger, localPath, keyOverride string) (UploadResult, error) {
	var res UploadResult
	if cfg == nil {
		return res, errors.New("缺少配置")
	}
	if err := verifyContainerMagic(localPath); err != nil {
		return res, err
	}
	st, err := os.Stat(fsutil.LongPath(localPath))
	if err != nil {
		return res, fmt.Errorf("读取待上传文件失败: %w", err)
	}
	if st.IsDir() {
		return res, fmt.Errorf("%s 是目录，必须指向 .usbk 文件", localPath)
	}

	plan := prepareUpload(cfg, deps, log)
	defer plan.Close()
	if plan == nil {
		res.Result = UploadNotEnabled
		res.Err = "upload.enabled 为 false，未开启上传"
		return res, errors.New(res.Err)
	}
	if plan.client == nil {
		res.Result = UploadUnavailable
		res.Err = plan.reason
		return res, errors.New(plan.reason)
	}

	key := strings.TrimSpace(keyOverride)
	if key == "" {
		key = ObjectKey(plan.prefix, filepath.Base(localPath), time.Now())
	}
	out, err := uploadProduct(ctx, cfg, plan, log, localPath, key, st.Size())
	if err != nil {
		return out, err
	}
	applyLocalPolicy(cfg, deps, &out, localPath, log)
	return out, nil
}
