// Command usbbackup-r2 是常驻主程序（也用作生成器的客户端模板）。
//
// 用法：
//
//	usbbackup-r2 run [--allow-fixed] [--dry-run] [--poll-only] [--service]
//	usbbackup-r2 once --drive E: [--allow-fixed] [--dry-run]
//	usbbackup-r2 list [--all]
//	usbbackup-r2 probe --drive E:
//	usbbackup-r2 upload <产物.usbk> [--key <对象键>] [--keep]
//	usbbackup-r2 cred-check
//	usbbackup-r2 config-check
//	usbbackup-r2 install-service / uninstall-service / start / stop / status
//	usbbackup-r2 version
//
// 对应需求 F-101 ~ F-107、F-801 ~ F-809、F-H01 ~ F-H04、F-D01 ~ F-D03。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/immml/UsbBackUP-R2/internal/agreement"
	"github.com/immml/UsbBackUP-R2/internal/backup"
	"github.com/immml/UsbBackUP-R2/internal/cli"
	"github.com/immml/UsbBackUP-R2/internal/collectpolicy"
	"github.com/immml/UsbBackUP-R2/internal/config"
	"github.com/immml/UsbBackUP-R2/internal/fsutil"
	"github.com/immml/UsbBackUP-R2/internal/keystore"
	"github.com/immml/UsbBackUP-R2/internal/logx"
	"github.com/immml/UsbBackUP-R2/internal/version"
	"github.com/immml/UsbBackUP-R2/internal/winmon"
	"github.com/immml/UsbBackUP-R2/internal/winsvc"
	"github.com/immml/UsbBackUP-R2/internal/winvol"
)

const toolName = "usbbackup-r2"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stdout)
		return cli.ExitUsage
	}
	sub, rest := args[0], args[1:]

	switch sub {
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, version.MultiLineFor(toolName))
		return cli.ExitOK
	case "help", "--help", "-h":
		printUsage(stdout)
		return cli.ExitOK
	}

	cfgPath, skipConfirm := cli.ExtractGlobalFlags(args)

	// 客户端模式探测：读取自身可执行文件尾部的内嵌配置（普通构建没有这个块）。
	loadEmbedded(stderr)

	// 会写数据的子命令需要确认；只读诊断子命令不打扰用户。
	switch sub {
	case "run", "once":
		switch {
		case hasArg(args, "--service"):
			// 服务模式：由 SCM 启动，既没有控制台也无法交互确认。
			// 这里必须静默通过——否则读不到 I AGREE 会立刻退出，
			// SCM 会报 1053「服务没有及时响应启动或控制请求」。
		case agreement.Accepted():
			// 已用 `accept` 确认过：无人值守运行，不打印横幅、不交互。
			// 摘要与作业结果照常输出到 stdout 与日志文件，方便命令行下排障；
			// 双击运行（windowsgui）本就看不到这些输出。
		case skipConfirm:
			cli.RenderNotice(stdout, toolName)
		default:
			cli.RenderBanner(stdout, toolName)
			if err := cli.ConfirmAgreement(stdin, stdout); err != nil {
				fmt.Fprintf(stderr, "\n提示：若要无人值守运行，请先执行一次：%s accept\n\n", toolName)
				return cli.ExitNotAgreed
			}
		}
	}

	switch sub {
	case "run":
		return cmdRun(rest, cfgPath, stdout, stderr)
	case "once":
		return cmdOnce(rest, cfgPath, stdout, stderr)
	case "accept":
		return cmdAccept(rest, stdin, stdout, stderr)
	case "list":
		return cmdList(rest, stdout, stderr)
	case "probe":
		return cmdProbe(rest, cfgPath, stdout, stderr)
	case "upload":
		return cmdUpload(rest, cfgPath, stdout, stderr)
	case "cred-check":
		return cmdCredCheck(cfgPath, stdout, stderr)
	case "config-check":
		return cmdConfigCheck(cfgPath, stdout, stderr)
	case "install-service", "uninstall-service", "start", "stop", "status":
		return cmdService(sub, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "未知子命令 %q\n\n", sub)
		printUsage(stderr)
		return cli.ExitUsage
	}
}

func printUsage(w io.Writer) {
	cli.PrintHelp(w, "usbbackup-r2 —— Windows 专用 U 盘自动备份与加密上传工具", []string{
		"用法：",
		"  usbbackup-r2 run [选项]                    前台常驻运行（监控 U 盘插入）",
		"  usbbackup-r2 once --drive E: [选项]        对指定盘符执行一次作业",
		"  usbbackup-r2 list [--all]                  列出可移动卷及其容量",
		"  usbbackup-r2 probe --drive E:              只读诊断（不写数据、不发请求）",
		"  usbbackup-r2 upload <产物.usbk>            手工补传一个本地密文产物到 R2",
		"  usbbackup-r2 cred-check                    检查凭据文件能否在本机解开",
		"  usbbackup-r2 config-check                  校验配置与运行环境",
		"  usbbackup-r2 install-service               注册为 Windows 服务（需管理员）",
		"  usbbackup-r2 uninstall-service             删除服务（需管理员）",
		"  usbbackup-r2 start | stop | status         控制已注册的服务",
		"  usbbackup-r2 version                       显示版本信息",
		"  usbbackup-r2 accept                        首次知情同意（确认后 run/once 静默运行）",
		"",
		"accept 选项：",
		"  --yes             非交互确认（供部署脚本使用）",
		"  --check           只查看当前是否已确认（未确认退出码 2）",
		"  --revoke          撤销确认，恢复首次确认流程",
		"  --force           已确认时也重新确认",
		"",
		"全局开关（可放在任意位置）：",
		"  --config string   配置文件路径",
		"  --yes             跳过免责声明确认（自动化用）",
		"",
		"run / once 选项：",
		"  --dry-run         只做准入与门控判定，不写入数据、不发起网络请求",
		"  --poll-only       强制仅使用轮询（排障用；默认事件驱动）",
		"  --allow-fixed     允许对固定磁盘执行作业",
		"                    【仅供验证与排障】生产环境不要开启",
		"  --service         以 Windows 服务方式运行（由 SCM 调用）",
		"  --simulate-arrival E:",
		"                    注入一次模拟的卷到达事件（仅用于验证链路，可重复）",
		"",
		"upload 选项：",
		"  --key string      指定远端对象键（默认 {前缀}{UTC时间戳}_{文件名}）",
		"  --keep            上传成功后保留本地产物",
		"",
		"行为概述：",
		"  盘根有授权标记 .usbbackup-allow → **豁免**，不读取不打包不上传；",
		"  否则按采集策略（all / marker_only / off）决定是否采集；",
		"  采集 + 已占用容量 ≤ 阈值 → 整盘打包、混合加密，并按配置上传到 R2；",
		"  全程对源介质只读，不删除或改写源盘上的任何文件。",
		"",
		"提示：首次使用请先跑 `usbbackup-r2 probe --drive <盘符>` 确认判定符合预期。",
	})
}

// ---- 运行参数 ----

type runFlags struct {
	drive    string
	dryRun   bool
	pollOnly bool
	allowFix bool
	service  bool
	// simArrival 是验证辅助开关：在没有物理介质时注入一次"卷到达"事件，
	// 用来跑通"监控 → 作业队列 → 流水线"的完整链路。生产不要使用。
	simArrival stringList
}

// stringList 支持重复出现的字符串选项。
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func parseRunFlags(args []string, wantDrive bool, stderr io.Writer) (runFlags, string, int) {
	var rf runFlags
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if wantDrive {
		fs.StringVar(&rf.drive, "drive", "", "盘符，如 E:")
	}
	fs.BoolVar(&rf.dryRun, "dry-run", false, "不写入任何数据")
	fs.BoolVar(&rf.pollOnly, "poll-only", false, "仅使用轮询")
	fs.BoolVar(&rf.allowFix, "allow-fixed", false, "允许对固定磁盘执行（仅供验证）")
	fs.BoolVar(&rf.service, "service", false, "以 Windows 服务方式运行")
	fs.Var(&rf.simArrival, "simulate-arrival", "注入一次模拟的卷到达事件（验证用，可重复）")
	if err := cli.ParseArgs(fs, args); err != nil {
		return rf, "", cli.ExitUsage
	}
	return rf, "", cli.ExitOK
}

// buildDeps 组装流水线依赖：配置、日志、内嵌公钥。
//
// 这里没有"私钥判定器"这类东西了：采集准入完全由授权标记 + 采集策略决定，
// 不再扫描介质内容（见 internal/collectpolicy 的包注释）。
func buildDeps(cfg *config.Config, logger *slog.Logger, rf runFlags) backup.Deps {
	deps := backup.Deps{
		Cfg:            cfg,
		Log:            logger,
		AllowFixed:     rf.allowFix,
		DryRun:         rf.dryRun,
		UploadPrefix:   "",
		CredentialPath: "",
	}
	if clientBuild.ok {
		deps.EmbeddedPublicKey = clientBuild.pub
	}
	return deps
}

// ---- run ----

func cmdRun(args []string, cfgPath string, stdout, stderr io.Writer) int {
	rf, _, code := parseRunFlags(args, false, stderr)
	if code != cli.ExitOK {
		return code
	}

	cfg, path, code := loadConfig(cfgPath, stderr)
	if cfg == nil {
		return code
	}

	// 服务模式下日志不写控制台（服务没有控制台），只用文件。
	useConsole := !rf.service
	logHandle, err := logx.New(logx.Options{
		Level:      cfg.Log.Level,
		File:       config.ExpandPath(cfg.Log.File),
		MaxSizeMB:  cfg.Log.MaxSizeMB,
		MaxBackups: cfg.Log.MaxBackups,
		Console:    useConsole,
	})
	if err != nil {
		fmt.Fprintf(stderr, "初始化日志失败：%v\n", err)
		return cli.ExitRuntime
	}
	defer logHandle.Close()
	logger := logHandle.Logger

	if rf.service {
		logger.Info("以 Windows 服务方式启动")
		if err := winsvc.RunAsService(func(ctx context.Context) error {
			return serve(ctx, cfg, logger, rf, stdout, stderr)
		}); err != nil {
			logger.Error("服务运行失败", "err", err)
			return cli.ExitRuntime
		}
		return cli.ExitOK
	}

	// 单实例互斥（F-808）：避免重复挂载监控。
	release, err := winsvc.AcquireSingleInstance(version.AppName)
	if err != nil {
		if errors.Is(err, winsvc.ErrAlreadyRunning) {
			fmt.Fprintf(stderr, "错误：%v\n", err)
			return cli.ExitRuntime
		}
		fmt.Fprintf(stderr, "警告：单实例互斥体创建失败（%v），继续运行\n", err)
	} else {
		defer release()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	fmt.Fprintf(stdout, "已启动，配置文件：%s\n", path)
	for _, line := range cfg.Summary() {
		fmt.Fprintf(stdout, "  %s\n", line)
	}
	fmt.Fprintln(stdout, "按 Ctrl+C 退出。")

	if err := serve(ctx, cfg, logger, rf, stdout, stderr); err != nil {
		logger.Error("运行结束（异常）", "err", err)
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return cli.ExitRuntime
	}
	fmt.Fprintln(stdout, "已退出。")
	return cli.ExitOK
}

// serve 是 run 与 service 共用的监控主体。
func serve(ctx context.Context, cfg *config.Config, logger *slog.Logger, rf runFlags, stdout, stderr io.Writer) error {
	// 启动时清理上次中断留下的半成品（F-809）。
	if n, err := backup.CleanupPartials(cfg.OutputDir); err == nil && n > 0 {
		logger.Info("已清理上次遗留的半成品", "count", n)
	}

	deps := buildDeps(cfg, logger, rf)
	// F-F06：上传通道的可用性必须在启动时就讲清楚，不允许静默降级。
	reportUploadChannel(cfg, logger)

	// 作业串行队列（F-104）：同一时刻只处理一个介质，避免 IO 抖动。
	type job struct {
		root string
		at   time.Time
	}
	jobs := make(chan job, 16)
	pending := map[string]bool{}
	var mu sync.Mutex

	var workerWG sync.WaitGroup
	workerWG.Add(1)
	go func() {
		defer workerWG.Done()
		for j := range jobs {
			logger.Info("开始作业", "root", j.root)
			res, err := backup.Run(ctx, deps, j.root)
			if err != nil {
				logger.Error("作业失败", "root", j.root, "err", err)
			} else {
				logger.Info("作业完成",
					"root", j.root,
					"branch", string(res.Branch),
					"ok", res.OK,
					"duration", res.Duration.String())
			}
			mu.Lock()
			delete(pending, j.root)
			mu.Unlock()
		}
	}()

	enqueue := func(ev winmon.Event) {
		if ev.Kind != winmon.EventArrival {
			return
		}
		mu.Lock()
		if pending[ev.Root] {
			mu.Unlock()
			return
		}
		pending[ev.Root] = true
		mu.Unlock()

		select {
		case jobs <- job{root: ev.Root, at: ev.At}:
		default:
			mu.Lock()
			delete(pending, ev.Root)
			mu.Unlock()
			logger.Warn("作业队列已满，丢弃该事件", "root", ev.Root)
		}
	}

	// 验证辅助：无物理介质时注入一次"卷到达"，跑通完整链路。
	if len(rf.simArrival) > 0 {
		logger.Warn("已启用 --simulate-arrival：将注入模拟事件，仅用于验证")
		go func() {
			time.Sleep(400 * time.Millisecond)
			for _, d := range rf.simArrival {
				root, err := winvol.NormalizeRoot(d)
				if err != nil {
					logger.Warn("模拟事件盘符非法，已忽略", "drive", d, "err", err)
					continue
				}
				logger.Info("注入模拟卷到达事件", "root", root)
				enqueue(winmon.Event{Root: root, Kind: winmon.EventArrival, At: time.Now(), Source: "simulated"})
			}
		}()
	}

	mon := winmon.New(winmon.Options{
		PollInterval:          time.Duration(cfg.Monitor.PollIntervalSec) * time.Second,
		Debounce:              time.Duration(cfg.Monitor.DebounceSec) * time.Second,
		PollOnly:              rf.pollOnly || cfg.Monitor.PollOnly,
		ProcessMountedOnStart: cfg.Monitor.ProcessMountedOnStart,
		Logger:                logger,
	})

	runErr := mon.Run(ctx, enqueue)
	close(jobs)
	workerWG.Wait()
	return runErr
}

// ---- once ----

func cmdOnce(args []string, cfgPath string, stdout, stderr io.Writer) int {
	rf, _, code := parseRunFlags(args, true, stderr)
	if code != cli.ExitOK {
		return code
	}
	if strings.TrimSpace(rf.drive) == "" {
		fmt.Fprintln(stderr, "错误：必须指定 --drive，例如 --drive E:")
		return cli.ExitUsage
	}
	root, err := winvol.NormalizeRoot(rf.drive)
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return cli.ExitUsage
	}

	cfg, _, code := loadConfig(cfgPath, stderr)
	if cfg == nil {
		return code
	}
	logHandle, err := logx.New(logx.Options{
		Level: cfg.Log.Level, MaxSizeMB: cfg.Log.MaxSizeMB,
		MaxBackups: cfg.Log.MaxBackups, Console: true,
	})
	if err != nil {
		fmt.Fprintf(stderr, "初始化日志失败：%v\n", err)
		return cli.ExitRuntime
	}
	defer logHandle.Close()

	if clientBuild.ok {
		for _, line := range clientInfoLines() {
			fmt.Fprintf(stdout, "%s\n", line)
		}
	}
	reportUploadChannel(cfg, logHandle.Logger)

	deps := buildDeps(cfg, logHandle.Logger, rf)
	if rf.dryRun {
		fmt.Fprintln(stdout, "[dry-run] 不会写入任何数据。")
	}
	if rf.allowFix {
		fmt.Fprintln(stdout, "[警告] 已启用 --allow-fixed：允许对固定磁盘执行作业，仅供验证使用。")
	}

	res, err := backup.Run(context.Background(), deps, root)
	if err != nil {
		fmt.Fprintf(stderr, "作业失败：%v\n", err)
		return cli.ExitRuntime
	}

	fmt.Fprintf(stdout, "盘符            : %s\n", res.Root)
	fmt.Fprintf(stdout, "卷标 / 文件系统 : %s / %s\n",
		winvol.LabelOrFallback(res.Volume), emptyDash(res.Volume.FileSystem))
	fmt.Fprintf(stdout, "已占用 / 阈值   : %s / %s\n",
		fsutil.HumanBytes(res.Volume.UsedBytes), fsutil.HumanBytes(cfg.Gate.UsedThresholdBytes))
	fmt.Fprintf(stdout, "授权标记        : %s\n", yesNoText(res.Collect.ExemptMarkerFound,
		"命中（本盘豁免，不会被读取或上传）", "未命中"))
	fmt.Fprintf(stdout, "采集判定        : %s\n", collectDecisionText(res.Collect))
	fmt.Fprintf(stdout, "分支            : %s\n", res.Branch)
	if res.SkipReason != "" {
		fmt.Fprintf(stdout, "跳过原因        : %s\n", res.SkipReason)
	}
	if res.ProductPath != "" {
		fmt.Fprintf(stdout, "产物            : %s\n", res.ProductPath)
		fmt.Fprintf(stdout, "打包/加密       : %d 文件，原始 %s → zip %s → 密文 %s\n",
			res.Zip.Files, fsutil.HumanBytes(res.Zip.RawBytes),
			fsutil.HumanBytes(res.Encrypt.PlainBytes), fsutil.HumanBytes(res.Encrypt.CipherBytes))
		fmt.Fprintf(stdout, "公钥指纹        : %s\n", res.Encrypt.Header.FingerprintHex())
	}
	if res.Upload.Result != "" {
		fmt.Fprintf(stdout, "上传            : %s\n", uploadText(res.Upload))
		if res.Upload.ObjectKey != "" {
			fmt.Fprintf(stdout, "  远端对象      : %s\n", res.Upload.ObjectKey)
		}
		if res.Upload.Err != "" {
			fmt.Fprintf(stdout, "  说明          : %s\n", res.Upload.Err)
		}
	}
	fmt.Fprintf(stdout, "耗时            : %s\n", res.Duration)
	fmt.Fprintf(stdout, "结果            : %s\n", okText(res.OK))

	// 作业成功但上传没成功时，退出码给 5（部分成功）：
	// 数据安全地留在本地，但没到该到的地方，脚本应当能区分这两种结局。
	if !res.OK {
		return cli.ExitPartial
	}
	if res.ProductPath != "" && res.Upload.Result != "" && !res.Upload.OK && res.Upload.Attempted {
		return cli.ExitPartial
	}
	return cli.ExitOK
}

// collectDecisionText 把采集判定翻译成一行中文。
func collectDecisionText(d collectpolicy.Decision) string {
	switch {
	case d.ExemptMarkerFound:
		return "豁免（盘根有授权标记）"
	case d.Collect:
		return "允许采集"
	case d.Reason == collectpolicy.ReasonDisabled:
		return "拒绝（采集策略为 off）"
	case d.Reason == collectpolicy.ReasonMarkerAbsent:
		return "拒绝（未找到采集标记）"
	case d.Reason != "":
		return "拒绝（" + d.Reason + "）"
	default:
		return "拒绝"
	}
}

// uploadText 把上传结果翻译成一行中文。
func uploadText(u backup.UploadResult) string {
	switch u.Result {
	case backup.Uploaded:
		s := fmt.Sprintf("已上传（%s）", fsutil.HumanBytes(u.Bytes))
		switch u.LocalAction {
		case "deleted":
			s += "，本地副本已删除"
		case "kept":
			s += "，本地副本保留"
		}
		return s
	case backup.UploadFailed:
		return "失败（本地产物已保留，可用 `upload` 子命令补传）"
	case backup.UploadUnavailable:
		return "未执行（凭据不可用，已退回仅本地产物）"
	case backup.UploadNotEnabled:
		return "未开启（配置中 upload.enabled = false）"
	default:
		return u.Result
	}
}

// yesNoText 按布尔值选择两句说明里的一句。
func yesNoText(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}

// ---- 只读诊断 ----

func cmdList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var showAll bool
	fs.BoolVar(&showAll, "all", false, "显示全部盘符（含固定磁盘、光驱等）")
	if err := cli.ParseArgs(fs, args); err != nil {
		return cli.ExitUsage
	}

	roots, err := winvol.Roots()
	if err != nil {
		fmt.Fprintf(stderr, "枚举盘符失败：%v\n", err)
		return cli.ExitRuntime
	}
	if len(roots) == 0 {
		fmt.Fprintln(stdout, "未检测到任何盘符。")
		return cli.ExitOK
	}

	const (
		wDrive, wType, wReady, wFS = 7, 12, 6, 10
		wTotal, wUsed, wFree       = 12, 12, 12
	)
	line := func(drive, typ, ready, fsname, total, used, free, label string) {
		fmt.Fprintf(stdout, "%s %s %s %s %s %s %s  %s\n",
			padRight(drive, wDrive), padRight(typ, wType), padRight(ready, wReady),
			padRight(fsname, wFS), padLeft(total, wTotal), padLeft(used, wUsed),
			padLeft(free, wFree), label)
	}
	line("盘符", "类型", "就绪", "文件系统", "总容量", "已占用", "剩余", "卷标")

	shown := 0
	for _, r := range roots {
		v, qerr := winvol.Query(r)
		if !v.Removable && !showAll {
			continue
		}
		if v.Removable {
			shown++
		}
		line(v.Root, winvol.DriveTypeName(v.DriveType), yesNo(v.Ready),
			emptyDash(v.FileSystem), fsutil.HumanBytes(v.TotalBytes),
			fsutil.HumanBytes(v.UsedBytes), fsutil.HumanBytes(v.FreeBytes), emptyDash(v.Label))
		if qerr != nil && v.Removable {
			fmt.Fprintf(stdout, "  注：%v\n", qerr)
		}
	}
	if shown == 0 && !showAll {
		fmt.Fprintln(stdout, "\n当前没有可移动卷。插好 U 盘后重试，或用 `list --all` 查看全部盘符。")
	}
	return cli.ExitOK
}

func cmdProbe(args []string, cfgPath string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var drive string
	fs.StringVar(&drive, "drive", "", "盘符，如 E:（必填）")
	if err := cli.ParseArgs(fs, args); err != nil {
		return cli.ExitUsage
	}
	if drive == "" {
		fmt.Fprintln(stderr, "错误：必须指定 --drive，例如 --drive E:")
		return cli.ExitUsage
	}
	cfg, _, code := loadConfig(cfgPath, stderr)
	if cfg == nil {
		return code
	}
	root, err := winvol.NormalizeRoot(drive)
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return cli.ExitUsage
	}

	fmt.Fprintln(stdout, "只读诊断（本命令不写任何数据、不修改任何文件）：")
	fmt.Fprintf(stdout, "  目标卷根        : %s\n", root)

	v, qerr := winvol.Query(root)
	fmt.Fprintf(stdout, "  卷类型          : %s\n", winvol.DriveTypeName(v.DriveType))
	if !v.Removable {
		fmt.Fprintln(stdout, "  判定            : 非可移动卷 → 生产运行时会直接跳过（F-301）")
		if qerr != nil {
			fmt.Fprintf(stdout, "  查询补充        : %v\n", qerr)
		}
		return cli.ExitPartial
	}
	if !v.Ready {
		fmt.Fprintf(stdout, "  就绪            : 否（%v）\n", qerr)
		fmt.Fprintln(stdout, "  判定            : 卷未就绪 → 生产运行时会跳过（F-305）")
		return cli.ExitPartial
	}
	fmt.Fprintf(stdout, "  卷标 / 文件系统 : %s / %s\n",
		winvol.LabelOrFallback(v), emptyDash(v.FileSystem))
	fmt.Fprintf(stdout, "  卷序列号        : %08X（仅供事后对账，不参与准入判定）\n", v.SerialNumber)
	fmt.Fprintf(stdout, "  总容量/已占用/剩余: %s / %s / %s\n",
		fsutil.HumanBytes(v.TotalBytes), fsutil.HumanBytes(v.UsedBytes), fsutil.HumanBytes(v.FreeBytes))
	fmt.Fprintf(stdout, "  产物命名        : %s\n", backup.ProductName(v))

	// 采集准入：授权标记豁免 + 策略判定。这一步**只 Stat 两个文件名**，
	// 不打开盘上任何文件，所以 probe 在满盘上也几乎是瞬时的。
	policy, perr := collectpolicy.Normalize(cfg.Collect.Policy)
	if perr != nil {
		fmt.Fprintf(stderr, "错误：%v\n", perr)
		return cli.ExitRuntime
	}
	dec, derr := collectpolicy.Decide(root, collectpolicy.Options{
		Policy:       policy,
		Marker:       cfg.Collect.MarkerFile,
		ExemptMarker: cfg.Collect.ExemptMarkerFile,
	})
	if derr != nil {
		fmt.Fprintf(stderr, "错误：%v\n", derr)
		return cli.ExitRuntime
	}
	fmt.Fprintf(stdout, "  采集策略        : %s\n", policy.Describe())
	fmt.Fprintf(stdout, "  授权标记检查    : %s（%s）\n",
		yesNo(dec.ExemptMarkerFound), cfg.Collect.ExemptMarkerFile)
	if policy.NeedsMarker() {
		fmt.Fprintf(stdout, "  采集标记检查    : %s（%s）\n",
			yesNo(dec.MarkerFound), cfg.Collect.MarkerFile)
	}

	if !dec.Collect {
		fmt.Fprintf(stdout, "  判定            : 不采集（%s）\n", dec.Reason)
		if dec.ExemptMarkerFound {
			fmt.Fprintln(stdout, "                    本盘被识别为自己的盘 → 豁免，不会读取或上传其内容。")
		}
		return cli.ExitOK
	}

	gate := winvol.EvaluateGate(v, cfg.Gate.UsedThresholdBytes, cfg.Gate.MaxTotalBytes)
	if !gate.Proceed {
		fmt.Fprintf(stdout, "  判定            : 跳过（%s）\n", gate.Reason)
		return cli.ExitOK
	}

	fmt.Fprintf(stdout, "  将执行          : 整盘打包 → 混合加密 → %s\n",
		filepath.Join(config.ExpandPath(cfg.OutputDir), backup.ProductName(v)))
	if cfg.Upload.Enabled {
		// 这里只说"配置上会尝试上传"。真的能不能传，要看凭据能不能在本机解开，
		// 以及 endpoint 通不通——probe 刻意不发任何网络请求。
		fmt.Fprintln(stdout, "                    随后尝试上传到 R2（本命令不发网络请求，不做实际验证）")
		if _, err := credSummary(cfg); err != nil {
			fmt.Fprintf(stdout, "  [警告] 凭据不可用，届时会退回仅本地产物：%v\n", err)
			return cli.ExitPartial
		}
	} else {
		fmt.Fprintln(stdout, "                    上传未开启（upload.enabled = false），产物只落本地")
	}
	fmt.Fprintln(stdout, "                    源盘只读，不删除源文件。")
	return cli.ExitOK
}

func cmdConfigCheck(cfgPath string, stdout, stderr io.Writer) int {
	cfg, path, code := loadConfig(cfgPath, stderr)
	if cfg == nil {
		return code
	}
	fmt.Fprintf(stdout, "配置文件：%s\n\n", path)
	fmt.Fprintln(stdout, "生效配置：")
	for _, line := range cfg.Summary() {
		fmt.Fprintf(stdout, "  %s\n", line)
	}

	problems := 0
	fmt.Fprintln(stdout, "\n检查项：")
	report := func(name string, ok bool, detail string) {
		mark := "OK  "
		if !ok {
			mark = "FAIL"
			problems++
		}
		fmt.Fprintf(stdout, "  [%s] %s %s\n", mark, name, detail)
	}
	// note 用于「不是问题、但值得说一声」的项。这类不该把退出码拉成"部分成功"。
	note := func(name string, detail string) {
		fmt.Fprintf(stdout, "  [--  ] %s %s\n", name, detail)
	}

	out := config.ExpandPath(cfg.OutputDir)
	if st, err := os.Stat(fsutil.LongPath(out)); err == nil && st.IsDir() {
		report("产物输出目录存在", true, out)
	} else {
		// 目录不存在是正常的首次状态（作业时会 MkdirAll），不算问题。
		note("产物输出目录存在", fmt.Sprintf("尚未创建：%s（首次作业时自动创建）", out))
	}

	// 静态合法性：必须是绝对路径，且不能直接指向某个卷的根。
	//
	// 前者：相对路径会跟着工作目录跑，SCM 拉起服务时工作目录是 System32，
	// 产物会落到意想不到的地方。
	// 后者：把产物目录配成 `E:\` 就等于把 .usbk 写进介质根，
	// 而介质根正是运行期要扫描的对象——那种情形由流水线里的
	// archive.CheckSourceGuard 在拿到真实盘符后拦下，这里先做静态提示。
	switch {
	case !filepath.IsAbs(out):
		report("产物输出目录合法", false, fmt.Sprintf("必须是绝对路径（当前 %q 会跟随工作目录变动）", out))
	case isVolumeRoot(out):
		report("产物输出目录合法", false,
			fmt.Sprintf("%s 是卷根：产物会与待采集数据混在同一块盘上，请改到本机目录", out))
	default:
		report("产物输出目录合法", true, "绝对路径，且不是卷根")
	}

	if err := os.MkdirAll(out, 0o755); err != nil {
		report("产物输出目录可写", false, fmt.Sprintf("%s（%v）", out, err))
	} else if f, err := os.CreateTemp(out, ".usbbackup-r2-writecheck-*"); err != nil {
		report("产物输出目录可写", false, fmt.Sprintf("%s（%v）", out, err))
	} else {
		name := f.Name()
		_ = f.Close()
		_ = os.Remove(name)
		report("产物输出目录可写", true, out)
	}

	// 客户端模式：公钥内嵌在可执行文件里，没有独立文件可供校验。
	if clientBuild.ok && clientBuild.pub != nil {
		bits := clientBuild.pub.N.BitLen()
		_, fp, ferr := keystore.PublicKeyFingerprint(clientBuild.pub)
		if ferr == nil && bits >= keystore.MinRSAKeyBits {
			report("内嵌公钥可用", true, fmt.Sprintf("%d 位，指纹 %s", bits, fp))
		} else {
			report("内嵌公钥可用", false, fmt.Sprintf("%d 位（下限 %d 位）%v", bits, keystore.MinRSAKeyBits, ferr))
		}
	} else {
		pubPath := config.ExpandPath(cfg.PublicKeyPath)
		if _, err := keystoreLoadPub(pubPath); err == nil {
			report("公钥可加载", true, pubPath)
		} else {
			report("公钥可加载", false, fmt.Sprintf("%s（%v）", pubPath, err))
		}
	}

	audit := config.ExpandPath(cfg.AuditFile)
	if err := os.MkdirAll(dirOf(audit), 0o755); err == nil {
		report("审计目录可写", true, audit)
	} else {
		report("审计目录可写", false, fmt.Sprintf("%s（%v）", audit, err))
	}

	// 源守卫（防递归套娃）的真正落点在流水线里：只有拿到**真实盘符**之后，
	// 才能判断产物目录是否落在待采集介质之内（archive.CheckSourceGuard）。
	// 配置阶段没有介质可查，所以这里只能把「产物目录是不是卷根」这条静态线索
	// 检查出来（上面已做），不再拿输出目录跟自己比较——那样永远判失败。

	// 上传能力：开了就必须能解开凭据，否则会静默退回本地（F-F06）。
	if !cfg.Upload.Enabled {
		report("上传到 R2", true, "未开启（upload.enabled = false），产物只落本地")
	} else if summary, err := credSummary(cfg); err != nil {
		report("上传到 R2", false, fmt.Sprintf("已开启但凭据不可用，届时会退回仅本地产物：%v", err))
	} else {
		report("上传到 R2", true, summary)
	}

	if problems > 0 {
		fmt.Fprintf(stderr, "\n共 %d 项检查未通过。\n", problems)
		return cli.ExitPartial
	}
	fmt.Fprintln(stdout, "\n全部检查通过。")
	return cli.ExitOK
}

func cmdService(sub string, stdout, stderr io.Writer) int {
	var err error
	switch sub {
	case "install-service":
		// 服务由 SCM 启动、没有控制台，不可能再弹确认。
		// 所以在注册之前就把"是否已确认"讲清楚，避免装完才发现服务跑不起来或未经确认就跑了。
		if !agreement.Accepted() {
			fmt.Fprintln(stdout, "提示：本机尚未执行过知情同意确认。")
			fmt.Fprintf(stdout, "      服务无控制台，不会也不该在启动时弹确认。请先执行：%s accept\n", toolName)
			fmt.Fprintln(stdout, "      （服务模式下即使未确认也会运行——请确保已获授权后再注册服务。）")
		}
		err = winsvc.Install("")
		if err == nil {
			fmt.Fprintln(stdout, "服务已注册为 usbbackup-r2（启动类型：手动）。")
			fmt.Fprintln(stdout, "启动：usbbackup-r2 start     删除：usbbackup-r2 uninstall-service")
		}
	case "uninstall-service":
		err = winsvc.Uninstall()
		if err == nil {
			fmt.Fprintln(stdout, "服务已删除。")
		}
	case "start":
		err = winsvc.Start()
		if err == nil {
			fmt.Fprintln(stdout, "已发出启动指令。用 `usbbackup-r2 status` 查看状态。")
		}
	case "stop":
		err = winsvc.Stop()
		if err == nil {
			fmt.Fprintln(stdout, "已发出停止指令。")
		}
	case "status":
		var out string
		out, err = winsvc.Status()
		if out != "" {
			fmt.Fprintln(stdout, out)
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return cli.ExitRuntime
	}
	return cli.ExitOK
}

// ---- 小工具 ----

// hasArg 判断参数列表中是否出现某个开关（只用于少数需要在解析前决策的场景）。
func hasArg(args []string, name string) bool {
	for _, a := range args {
		if a == name {
			return true
		}
	}
	return false
}

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func yesNo(b bool) string {
	if b {
		return "是"
	}
	return "否"
}

func okText(ok bool) string {
	if ok {
		return "成功"
	}
	return "部分失败（详见上方统计与审计日志）"
}

func truncatedNote(t bool) string {
	if t {
		return "（已达扫描上限，结果可能不完整）"
	}
	return ""
}

// isVolumeRoot 判断路径是否直接就是某个卷的根（`E:\`、`E:/`、`/`）。
//
// 用途：产物目录若指向卷根，就等于把 .usbk 写进可能正在被采集的那块盘，
// 与「输出目录不得位于扫描源之内」这条守卫直接冲突。运行期有真实盘符时
// 由 archive.CheckSourceGuard 兜底，配置阶段只能靠这个静态线索先提醒。
func isVolumeRoot(p string) bool {
	p = strings.TrimSpace(p)
	if p == "" {
		return false
	}
	trimmed := strings.TrimRight(p, `\/`)
	// 盘符根：去掉分隔符后形如 `E:`（长度为 2 且第二字符是冒号）。
	if len(trimmed) == 2 && trimmed[1] == ':' {
		return true
	}
	// 卷影路径（\\?\E:\）与 UNC 根本不在此处判定：它们由运行期守卫兜底。
	return trimmed == ""
}

func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '\\' || p[i] == '/' {
			if i == 0 {
				return p[:1]
			}
			return p[:i]
		}
	}
	return "."
}

// padRight / padLeft 按**显示宽度**补齐（CJK 字符占两列）。
// 直接用 fmt 的 %-Ns 会按字符数计算，中文列必然错位。
func padRight(s string, width int) string {
	w := dispWidth(s)
	if w >= width {
		return s
	}
	return s + strings.Repeat(" ", width-w)
}

func padLeft(s string, width int) string {
	w := dispWidth(s)
	if w >= width {
		return s
	}
	return strings.Repeat(" ", width-w) + s
}

func dispWidth(s string) int {
	n := 0
	for _, r := range s {
		if isWideRune(r) {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// isWideRune 判断是否为双宽字符（East Asian Wide / Fullwidth）。
func isWideRune(r rune) bool {
	switch {
	case r < 0x1100:
		return false
	case r >= 0x1100 && r <= 0x115F,
		r >= 0x2E80 && r <= 0x303E,
		r >= 0x3041 && r <= 0x33FF,
		r >= 0x3400 && r <= 0x4DBF,
		r >= 0x4E00 && r <= 0x9FFF,
		r >= 0xA000 && r <= 0xA4CF,
		r >= 0xAC00 && r <= 0xD7A3,
		r >= 0xF900 && r <= 0xFAFF,
		r >= 0xFE30 && r <= 0xFE6F,
		r >= 0xFF00 && r <= 0xFF60,
		r >= 0xFFE0 && r <= 0xFFE6,
		r >= 0x20000 && r <= 0x3FFFD:
		return true
	}
	return false
}
