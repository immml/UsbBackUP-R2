package main

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/immml/UsbBackUP-R2/internal/archive"
	"github.com/immml/UsbBackUP-R2/internal/cli"
	"github.com/immml/UsbBackUP-R2/internal/cred"
	"github.com/immml/UsbBackUP-R2/internal/crypto"
	"github.com/immml/UsbBackUP-R2/internal/fsutil"
	"github.com/immml/UsbBackUP-R2/internal/r2"
	"github.com/immml/UsbBackUP-R2/internal/version"
)

// DefaultCredentialFileName 是凭据文件名（与生成器产出的名字一致）。
const DefaultCredentialFileName = cred.FileName

// resolveCredPath 按优先级找凭据文件：显式路径 > 配置文件目录 > 可执行文件同目录 > %LOCALAPPDATA%。
//
// 与客户端用的是同一套思路（backup.ResolveCredentialPath），
// 但解密器是**人来跑**的，所以显式指定永远排第一。
func resolveCredPath(explicit string) (string, []string) {
	var cands []string
	seen := map[string]bool{}
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		k := strings.ToLower(p)
		if seen[k] {
			return
		}
		seen[k] = true
		cands = append(cands, p)
	}
	if strings.TrimSpace(explicit) != "" {
		add(expand(explicit))
	}
	add(filepath.Join(defaultConfigDir(), DefaultCredentialFileName))
	if exe, err := os.Executable(); err == nil {
		add(filepath.Join(filepath.Dir(exe), DefaultCredentialFileName))
	}
	if appData := os.Getenv("LOCALAPPDATA"); appData != "" {
		add(filepath.Join(appData, version.AppName, DefaultCredentialFileName))
	}
	if cwd, err := os.Getwd(); err == nil {
		add(filepath.Join(cwd, DefaultCredentialFileName))
	}
	for _, p := range cands {
		if st, err := os.Stat(fsutil.LongPath(p)); err == nil && !st.IsDir() {
			return p, cands
		}
	}
	return "", cands
}

// loadRemoteClient 读取凭据并构造 R2 客户端。
//
// 凭据材料用完即清零（返回的清理函数由调用方 defer）。
// 需要口令时会先看配置/环境变量，都没有再按需交互提示——
// 提示之前**先问清楚这个文件到底需不需要口令**（cred.NeedsPassphrase），
// 免得出现"先让人输口令，再告诉他这是 DPAPI 文件、在 Linux 上根本读不了"。
func loadRemoteClient(cfg unsealConfig, stdout, stderr io.Writer) (*r2.Client, string, func(), int) {
	noop := func() {}
	path, cands := resolveCredPath(cfg.CredFile)
	if path == "" {
		fmt.Fprintln(stderr, "错误：找不到 R2 凭据文件。")
		if len(cands) > 0 {
			fmt.Fprintf(stderr, "      已查找：%s\n", strings.Join(cands, "、"))
		}
		fmt.Fprintln(stderr, "      请用 --cred 指定，或在配置文件里写 cred_file，")
		fmt.Fprintln(stderr, "      或用 usbkeygen-r2 cred 生成一份。")
		return nil, "", noop, cli.ExitRuntime
	}

	opts, oerr := credOptionsFor(cfg, path, stderr)
	if oerr != nil {
		return nil, "", noop, cli.ExitRuntime
	}
	c, err := cred.Load(path, opts...)
	if err != nil {
		fmt.Fprintf(stderr, "错误：凭据不可用：%v\n", err)
		switch {
		case errors.Is(err, cred.ErrPassphraseRequired):
			fmt.Fprintln(stderr, "      该凭据由口令保护。用 --cred-pass-file 指定口令文件，")
			fmt.Fprintf(stderr, "      或设环境变量 %s。\n", cred.EnvPassphrase)
		case errors.Is(err, cred.ErrPassphraseWrong):
			fmt.Fprintln(stderr, "      口令不对。")
		case errors.Is(err, cred.ErrUnprotectFailed):
			fmt.Fprintln(stderr, "      常见原因：文件来自别的机器（DPAPI 解不开）、被截断，或不是本工具生成的。")
		case errors.Is(err, cred.ErrPlainFileNotAllowed):
			fmt.Fprintln(stderr, "      该凭据未加密，需显式加 --allow-plain-cred 才读取。")
		default:
			fmt.Fprintln(stderr, "      常见原因：文件来自别的机器（DPAPI 解不开）、被截断，或不是本工具生成的。")
		}
		return nil, "", noop, cli.ExitRuntime
	}
	cleanup := func() { c.Zero() }

	client, err := r2.New(r2.Options{
		Endpoint:        c.Endpoint,
		Bucket:          c.Bucket,
		Region:          c.EffectiveRegion(),
		AccessKeyID:     string(c.AccessKeyID),
		SecretAccessKey: string(c.SecretAccessKey),
		SessionToken:    string(c.SessionToken),
		UserAgent:       version.AppName + "/" + version.Version,
	})
	if err != nil {
		cleanup()
		fmt.Fprintf(stderr, "错误：无法构造 R2 客户端：%v\n", err)
		return nil, "", noop, cli.ExitRuntime
	}
	if stdout != nil {
		fmt.Fprintf(stdout, "凭据      : %s（%s / %s ，用途 %s）\n",
			path, c.Endpoint, c.Bucket, c.EffectiveScope())
	}
	return client, c.EffectivePrefix(), cleanup, cli.ExitOK
}

// credOptionsFor 组出读凭据所需的选择项，必要时交互索要口令。
func credOptionsFor(cfg unsealConfig, credPath string, stderr io.Writer) ([]cred.Option, error) {
	opts := []cred.Option{}
	if cfg.AllowPlainCred {
		opts = append(opts, cred.WithAllowPlainFile())
	}

	protection, err := cred.ProtectionOf(credPath)
	if err != nil {
		// 读不出保护方式就交给 cred.Load 去报具体的错，这里不抢先下结论。
		if cfg.CredPassFile != "" {
			opts = append(opts, cred.WithPassphraseFile(expand(cfg.CredPassFile)))
		}
		return opts, nil
	}

	switch protection {
	case cred.ProtectionPassphrase:
		if cfg.CredPassFile != "" {
			opts = append(opts, cred.WithPassphraseFile(expand(cfg.CredPassFile)))
			return opts, nil
		}
		if hasEnvPassphrase() {
			return opts, nil // 交给 cred 自己按环境变量取
		}
		if !cli.IsTerminal(int(os.Stdin.Fd())) {
			return opts, nil // 非交互环境：让 Load 报 ErrPassphraseRequired，提示反而更准确
		}
		pass, perr := cli.ReadPassphrase("请输入 R2 凭据文件口令：")
		if perr != nil {
			return nil, perr
		}
		opts = append(opts, cred.WithPassphrase(pass))
	case cred.ProtectionDPAPIMachine:
		// DPAPI 不需要口令；如果当前不是 Windows，Load 会给出明确说明。
	case cred.ProtectionPlainFile:
		if !cfg.AllowPlainCred {
			fmt.Fprintln(stderr, "提示：该凭据文件未加密（仅靠文件权限保护）。")
			fmt.Fprintln(stderr, "      如果确认它就在你自己的机器上，加 --allow-plain-cred 继续。")
		}
	}
	return opts, nil
}

// hasEnvPassphrase 判断环境里有没有配凭据口令。
func hasEnvPassphrase() bool {
	for _, k := range []string{cred.EnvPassphrase, cred.EnvPassphraseFile} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return true
		}
	}
	return false
}

// cmdLs 列出远端可用产物（对应 git 的 ls-remote 心智）。
//
// 只列举，不下载、不解密，所以不需要私钥。
func cmdLs(args []string, cfg unsealConfig, cfgPath, cfgSource string, stdout, stderr io.Writer) int {
	fs := newFlagSet("ls", stderr)
	credFile := fs.String("cred", cfg.CredFile, "R2 凭据文件")
	credPass := fs.String("cred-pass-file", cfg.CredPassFile, "凭据文件口令（首行）")
	allowPlain := fs.Bool("allow-plain-cred", cfg.AllowPlainCred, "允许读取未加密的凭据文件")
	prefix := fs.String("prefix", cfg.Prefix, "对象键前缀")
	limit := fs.Int("limit", cfg.Limit, "最多列出多少个（0 表示不限）")
	showCfg := fs.Bool("show-config", false, "先打印生效配置")
	if err := cli.ParseArgs(fs, args); err != nil {
		return cli.ExitUsage
	}
	// 允许 `usbunseal-r2 ls usb/photos/` 这种位置参数写法。
	if fs.NArg() > 1 {
		fmt.Fprintln(stderr, "用法：usbunseal-r2 ls [前缀]")
		return cli.ExitUsage
	}
	if fs.NArg() == 1 {
		*prefix = fs.Arg(0)
	}
	cfg = applyOverride(cfg, *credFile, *credPass, *allowPlain, *prefix, 0)
	if *showCfg {
		cfg.Describe(stdout, cfgPath, cfgSource)
		fmt.Fprintln(stdout)
	}

	client, defPrefix, cleanup, code := loadRemoteClient(cfg, stdout, stderr)
	if client == nil {
		return code
	}
	defer cleanup()

	p := strings.TrimSpace(*prefix)
	if p == "" {
		p = defPrefix
	} else {
		p = cred.NormalizePrefix(p)
	}

	ctx := context.Background()
	objs, err := client.List(ctx, p, *limit)
	if err != nil {
		fmt.Fprintf(stderr, "列举失败：%v\n", err)
		return cli.ExitRuntime
	}
	fmt.Fprintf(stdout, "前缀      : %s\n", p)
	if len(objs) == 0 {
		fmt.Fprintln(stdout, "未找到任何对象。")
		fmt.Fprintln(stdout, "提示：若确认上传过，请检查 token 是否具备读/列举权限（上传用的 token 通常没有）。")
		return cli.ExitOK
	}

	total := int64(0)
	for _, o := range objs {
		total += o.Size
	}
	fmt.Fprintf(stdout, "对象数    : %d（合计 %s）\n\n", len(objs), fsutil.HumanBytes(total))
	sorted := make([]r2.ObjectInfo, len(objs))
	copy(sorted, objs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Key < sorted[j].Key })
	for _, o := range sorted {
		fmt.Fprintf(stdout, "  %s  %10s  %s\n", humanTime(o.LastModified), fsutil.HumanBytes(o.Size), o.Key)
	}
	fmt.Fprintln(stdout, "\n取回并解密：usbunseal-r2 pull          （取最新一个）")
	fmt.Fprintln(stdout, "            usbunseal-r2 pull --all    （全部取回）")
	fmt.Fprintln(stdout, "            usbunseal-r2 pull <对象键>  （只取指定对象）")
	return cli.ExitOK
}

// cmdPull 从 R2 下载容器并用本机私钥解密还原（F-B08 ~ F-B10）。
//
// 这是"解密器自动下载"那一环：默认只取**最新一个**，因为它对应
// "我刚插了一次盘"这个最常见的场景；要批量补历史就加 --all。
func cmdPull(args []string, cfg unsealConfig, cfgPath, cfgSource string, stdout, stderr io.Writer) int {
	fs := newFlagSet("pull", stderr)
	credFile := fs.String("cred", cfg.CredFile, "R2 凭据文件")
	credPass := fs.String("cred-pass-file", cfg.CredPassFile, "凭据文件口令（首行）")
	allowPlain := fs.Bool("allow-plain-cred", cfg.AllowPlainCred, "允许读取未加密的凭据文件")
	prefix := fs.String("prefix", cfg.Prefix, "对象键前缀")
	objectKey := fs.String("object", "", "只处理指定的对象键（也可作为位置参数给出）")
	latest := fs.Bool("latest", false, "只取最新一个对象（默认行为）")
	all := fs.Bool("all", false, "取回该前缀下的全部对象")
	out := fs.String("out", cfg.OutDir, "解压目标目录")
	key := fs.String("key", cfg.KeyFile, "私钥文件（必填）")
	keyPass := fs.String("pass-file", cfg.KeyPassFile, "私钥口令文件（首行）")
	usePass := fs.Bool("pass", false, "交互式输入私钥口令")
	force := fs.Bool("force", false, "覆盖已存在的文件")
	skipExisting := fs.Bool("skip-existing", cfg.SkipExisting, "目标目录已存在时跳过（重跑幂等）")
	keepContainer := fs.Bool("keep-container", cfg.KeepContainer, "解密后保留下载下来的 .usbk")
	delRemote := fs.Bool("delete-remote", cfg.DeleteRemote, "解密成功后删除远端对象（默认不动远端）")
	dryRun := fs.Bool("dry-run", false, "只显示将要做什么，不下载不写盘")
	showCfg := fs.Bool("show-config", false, "先打印生效配置")
	if err := cli.ParseArgs(fs, args); err != nil {
		return cli.ExitUsage
	}
	if fs.NArg() > 1 {
		fmt.Fprintln(stderr, "用法：usbunseal-r2 pull [对象键]")
		return cli.ExitUsage
	}
	if fs.NArg() == 1 {
		if strings.TrimSpace(*objectKey) != "" {
			fmt.Fprintln(stderr, "错误：--object 与位置参数只能给一个。")
			return cli.ExitUsage
		}
		*objectKey = fs.Arg(0)
	}
	if *latest && *all {
		fmt.Fprintln(stderr, "错误：--latest 与 --all 不能同时给出。")
		return cli.ExitUsage
	}

	cfg = applyOverride(cfg, *credFile, *credPass, *allowPlain, *prefix, 0)
	if *showCfg {
		cfg.Describe(stdout, cfgPath, cfgSource)
		fmt.Fprintln(stdout)
	}

	// 私钥是硬需求：没有它连"能不能解密"都无从谈起。
	// 配置文件里配了就自动用，没配才报错——报错要说清楚有哪三种给法。
	keyPath := expand(*key)
	if strings.TrimSpace(keyPath) == "" {
		fmt.Fprintln(stderr, "错误：没有可用的私钥。")
		fmt.Fprintln(stderr, "      三种给法：--key <私钥.pem>；配置文件里的 key_file；")
		fmt.Fprintf(stderr, "      或把私钥放到 %s\n", filepath.Join(defaultConfigDir(), "usbbackup-r2.key.pem"))
		fmt.Fprintln(stderr, "      解密需要的是**私钥**；公钥只能加密，不能解开。")
		return cli.ExitUsage
	}
	if _, err := os.Stat(fsutil.LongPath(keyPath)); err != nil {
		fmt.Fprintf(stderr, "错误：私钥文件不可读：%s（%v）\n", keyPath, err)
		return cli.ExitRuntime
	}

	destRoot := expand(*out)
	if strings.TrimSpace(destRoot) == "" {
		destRoot = filepath.Join(".", "usbbackup-restore")
	}

	client, defPrefix, cleanup, code := loadRemoteClient(cfg, stdout, stderr)
	if client == nil {
		return code
	}
	defer cleanup()

	p := strings.TrimSpace(*prefix)
	if p == "" {
		p = defPrefix
	} else {
		p = cred.NormalizePrefix(p)
	}

	ctx := context.Background()
	var targets []r2.ObjectInfo
	switch {
	case strings.TrimSpace(*objectKey) != "":
		info, err := client.Head(ctx, strings.TrimSpace(*objectKey))
		if err != nil {
			fmt.Fprintf(stderr, "读取远端对象失败：%v\n", err)
			return cli.ExitRuntime
		}
		targets = []r2.ObjectInfo{info}
	default:
		objs, err := client.List(ctx, p, 0)
		if err != nil {
			fmt.Fprintf(stderr, "列举失败：%v\n", err)
			return cli.ExitRuntime
		}
		if len(objs) == 0 {
			fmt.Fprintf(stderr, "错误：前缀 %s 下没有对象。\n", p)
			fmt.Fprintln(stderr, "提示：用 `usbunseal-r2 ls` 看看远端到底有什么；")
			fmt.Fprintln(stderr, "      若列举本身就被拒，说明 token 没有读/列举权限。")
			return cli.ExitRuntime
		}
		if *all {
			targets = objs
		} else {
			targets = []r2.ObjectInfo{newest(objs)}
		}
	}

	fmt.Fprintf(stdout, "目标目录  : %s\n", destRoot)
	fmt.Fprintf(stdout, "私钥      : %s\n", keyPath)
	fmt.Fprintf(stdout, "待处理    : %d 个对象\n", len(targets))

	priv, code := loadPrivateKey(keyPath, *usePass, expand(*keyPass), stderr)
	if code != cli.ExitOK {
		return code
	}
	defer wipePrivate(priv)

	failures := 0
	for _, o := range targets {
		if err := pullOne(ctx, client, o, destRoot, priv, pullOptions{
			force:         *force,
			skipExisting:  *skipExisting,
			keepContainer: *keepContainer,
			deleteRemote:  *delRemote,
			dryRun:        *dryRun,
		}, stdout, stderr); err != nil {
			failures++
			fmt.Fprintf(stderr, "  [失败] %s：%v\n", o.Key, err)
			continue
		}
	}
	if failures > 0 {
		fmt.Fprintf(stderr, "\n完成，但 %d 个对象处理失败。\n", failures)
		return cli.ExitPartial
	}
	fmt.Fprintln(stdout, "\n全部完成。")
	return cli.ExitOK
}

// applyOverride 把命令行显式给出的值覆盖回配置。
//
// 只在非空时覆盖：Go 的 flag 包以配置值作为默认值，所以"用户没给"
// 时字段本就是配置里的值，再写一遍是幂等的。空值不覆盖是为了让
// `--prefix ""` 这种手滑退化成"用配置值"，而不是把前缀清掉后
// 把对象列到别人看不见的地方。
func applyOverride(cfg unsealConfig, credFile, credPass string, allowPlain bool, prefix string, limit int) unsealConfig {
	if strings.TrimSpace(credFile) != "" {
		cfg.CredFile = credFile
	}
	if strings.TrimSpace(credPass) != "" {
		cfg.CredPassFile = credPass
	}
	if allowPlain {
		cfg.AllowPlainCred = true
	}
	if strings.TrimSpace(prefix) != "" {
		cfg.Prefix = prefix
	}
	if limit != 0 {
		cfg.Limit = limit
	}
	return cfg
}

// newest 返回最近修改（缺失时按对象键最大）的那个对象。
func newest(objs []r2.ObjectInfo) r2.ObjectInfo {
	sorted := make([]r2.ObjectInfo, len(objs))
	copy(sorted, objs)
	sort.Slice(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.LastModified.IsZero() || b.LastModified.IsZero() {
			return a.Key < b.Key
		}
		if a.LastModified.Equal(b.LastModified) {
			return a.Key < b.Key
		}
		return a.LastModified.Before(b.LastModified)
	})
	return sorted[len(sorted)-1]
}

// pullOptions 是 pullOne 的行为开关。
type pullOptions struct {
	force         bool
	skipExisting  bool
	keepContainer bool
	deleteRemote  bool
	dryRun        bool
}

// pullOne 处理一个对象：下载 → 校验容器头 → 解密 → 解压 → （可选）删远端。
//
// 整个流程刻意保持"任一步失败就不留半成品"：
// 下载写 `.part` 后改名，解压由 archive.UnzipStream 自己保证不逃逸目标目录。
func pullOne(ctx context.Context, client *r2.Client, o r2.ObjectInfo, destRoot string,
	priv *rsa.PrivateKey, opt pullOptions, stdout, stderr io.Writer) error {

	name := objectStem(o.Key)
	destDir := filepath.Join(destRoot, name)

	if st, err := os.Stat(fsutil.LongPath(destDir)); err == nil && st.IsDir() && opt.skipExisting && !opt.force {
		fmt.Fprintf(stdout, "  [跳过] %s（%s 已存在）\n", o.Key, destDir)
		return nil
	}
	if opt.dryRun {
		fmt.Fprintf(stdout, "  [dry-run] %s（%s，%s）→ %s\n",
			o.Key, fsutil.HumanBytes(o.Size), humanTime(o.LastModified), destDir)
		return nil
	}

	fmt.Fprintf(stdout, "\n处理：%s（%s，%s）\n", o.Key, fsutil.HumanBytes(o.Size), humanTime(o.LastModified))

	// 1) 下载到临时文件（同卷，保证改名是原子的）。
	if err := os.MkdirAll(fsutil.LongPath(destRoot), 0o755); err != nil {
		return fmt.Errorf("创建目标目录失败: %w", err)
	}
	tmpDir, err := os.MkdirTemp(destRoot, ".usbunseal-*")
	if err != nil {
		return fmt.Errorf("创建临时目录失败: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	container := filepath.Join(tmpDir, "container.usbk")
	dlStart := time.Now()
	info, err := client.Download(ctx, o.Key, container, nil)
	if err != nil {
		return fmt.Errorf("下载失败: %w", err)
	}
	fmt.Fprintf(stdout, "  下载完成：%s（耗时 %s，ETag %s）\n",
		fsutil.HumanBytes(info.Size), time.Since(dlStart).Round(time.Millisecond), strings.Trim(info.ETag, `"`))
	if o.Size > 0 && info.Size != o.Size {
		return fmt.Errorf("下载长度与列举结果不符（得到 %d，列举为 %d）", info.Size, o.Size)
	}

	// 2) 解密到临时 zip，再解压。
	in, err := os.Open(fsutil.LongPath(container))
	if err != nil {
		return err
	}
	defer in.Close()

	tmpZip := filepath.Join(tmpDir, "plain.zip")
	zout, err := os.OpenFile(fsutil.LongPath(tmpZip), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	sum, derr := crypto.DecryptStream(zout, in, crypto.DecryptOptions{PrivateKey: priv})
	closeErr := zout.Close()
	if derr != nil {
		return fmt.Errorf("解密失败（密钥不对或数据被篡改）: %w", derr)
	}
	if closeErr != nil {
		return fmt.Errorf("写入临时 zip 失败: %w", closeErr)
	}
	fmt.Fprintf(stdout, "  解密完成：明文 %s（%d 块，公钥指纹 %s）\n",
		fsutil.HumanBytes(sum.PlainBytes), sum.Chunks, sum.Header.FingerprintHex())

	zr, err := os.Open(fsutil.LongPath(tmpZip))
	if err != nil {
		return err
	}
	defer zr.Close()

	ust, err := archive.UnzipStream(osCtx(), zr, sum.PlainBytes, archive.UnzipOptions{
		DestDir: destDir,
		Force:   opt.force,
	})
	if err != nil {
		return fmt.Errorf("解压失败: %w", err)
	}
	fmt.Fprintf(stdout, "  解压完成：%d 个文件 / %s（跳过 %d）→ %s\n",
		ust.Files, fsutil.HumanBytes(ust.Bytes), ust.Skipped, destDir)
	if ust.RejectedUnsafe > 0 {
		// Zip Slip 条目被挡住了，但这说明容器可能被人为构造过，必须让人看见。
		fmt.Fprintf(stderr, "  [警告] 归档中有 %d 个不安全条目已被拒绝，请留意该对象来源。\n", ust.RejectedUnsafe)
	}

	// 3) 保留容器（可选）。
	if opt.keepContainer {
		kept := filepath.Join(destRoot, name+".usbk")
		if err := copyFileLocal(container, kept, true); err != nil {
			fmt.Fprintf(stderr, "  [警告] 保留容器失败：%v\n", err)
		} else {
			fmt.Fprintf(stdout, "  容器已保留：%s\n", kept)
		}
	}

	// 4) 删远端（显式要求才做：远端生命周期默认由 bucket 侧的 rule 管）。
	if opt.deleteRemote {
		if err := client.Delete(ctx, o.Key); err != nil {
			return fmt.Errorf("删除远端对象失败: %w", err)
		}
		fmt.Fprintf(stdout, "  远端对象已删除：%s\n", o.Key)
	}
	return nil
}

// objectStem 把对象键转成本地目录名。
//
// 去掉 `.zip.usbk` 与 `.usbk` 后缀，再把名字净化一遍：
// 对象键来自远端（可能是别人写的），直接当路径用会逃出目标目录。
func objectStem(key string) string {
	base := filepath.Base(strings.TrimRight(key, "/"))
	if base == "" || base == "." || base == "/" {
		base = "object"
	}
	base = strings.TrimSuffix(base, ".zip.usbk")
	base = strings.TrimSuffix(base, ".usbk")
	base = fsutil.SanitizeName(base)
	if base == "" || base == "." || base == ".." {
		return "object"
	}
	return base
}

// copyFileLocal 复制文件（覆盖与否由 force 决定）。
func copyFileLocal(src, dst string, force bool) error {
	if !force {
		if _, err := os.Stat(fsutil.LongPath(dst)); err == nil {
			return errors.New("目标已存在")
		}
	}
	in, err := os.Open(fsutil.LongPath(src))
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(fsutil.LongPath(filepath.Dir(dst)), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(fsutil.LongPath(dst), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// humanTime 格式化远端返回的时间；缺失时给一个明确的占位符。
//
// 取不到时间是**常见**情况而不是异常：ListObjects 的 LastModified 依赖
// 服务端实现，某些兼容层不返回它。显示"-"比显示 1970 年诚实。
func humanTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04")
}
