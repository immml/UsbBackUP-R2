package main

import (
	"context"
	"crypto/rsa"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"

	"github.com/immml/UsbBackUP-R2/internal/backup"
	"github.com/immml/UsbBackUP-R2/internal/cli"
	"github.com/immml/UsbBackUP-R2/internal/cred"
	"github.com/immml/UsbBackUP-R2/internal/fsutil"
)

// cmdUpload 手工补传一个本地密文产物（F-H04）。
//
// 存在的理由很具体：常驻服务遇到网络不通时**不会**阻塞后续介质（D-19），
// 于是本机会攒下若干 `.usbk`。等网络恢复了，需要一条命令把它们补传上去，
// 而不是重插一遍 U 盘重跑整盘打包。
//
// 只接受本工具产出的容器（校验 `USBK` 魔数）：凭据的权限是"目标前缀下的写"，
// 不该被拿来当通用文件上传通道。
func cmdUpload(args []string, cfgPath string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("upload", flag.ContinueOnError)
	fs.SetOutput(stderr)
	key := fs.String("key", "", "指定远端对象键（默认按 {前缀}{时间戳}_{文件名} 生成）")
	keep := fs.Bool("keep", false, "上传成功后保留本地产物")
	if err := cli.ParseArgs(fs, args); err != nil {
		return cli.ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "用法：usbbackup-r2 upload <产物.usbk> [--key <对象键>] [--keep]")
		return cli.ExitUsage
	}
	local := fs.Arg(0)

	cfg, path, code := loadConfig(cfgPath, stderr)
	if cfg == nil {
		return code
	}
	deps := backup.Deps{
		Cfg:               cfg,
		Log:               newSimpleLogger(stdout),
		CredentialPath:    "",
		UploadPrefix:      "",
		EmbeddedPublicKey: embeddedPublicKey(),
	}

	fmt.Fprintf(stdout, "配置文件  : %s\n", path)
	fmt.Fprintf(stdout, "待上传    : %s\n", local)
	if !cfg.Upload.Enabled {
		fmt.Fprintln(stderr, "错误：配置中 upload.enabled 为 false，未开启上传能力。")
		fmt.Fprintln(stderr, "      请先在配置里打开上传，或使用生成器产出的客户端。")
		return cli.ExitRuntime
	}
	// --keep 覆盖"上传后删除本地"，供"传完还想本地留一份核对"的场景。
	if *keep {
		cfg.Upload.DeleteLocalAfterUpload = false
	}

	res, err := backup.UploadLocalFile(context.Background(), cfg, deps, deps.Log, local, *key)
	if err != nil {
		fmt.Fprintf(stderr, "\n上传失败：%v\n", err)
		if res.Err != "" && res.Err != err.Error() {
			fmt.Fprintf(stderr, "说明：%s\n", res.Err)
		}
		return cli.ExitRuntime
	}

	fmt.Fprintf(stdout, "\n上传完成。\n")
	fmt.Fprintf(stdout, "  远端对象  : %s\n", res.ObjectKey)
	if res.Bucket != "" {
		fmt.Fprintf(stdout, "  桶        : %s\n", res.Bucket)
	}
	fmt.Fprintf(stdout, "  密文字节  : %s\n", fsutil.HumanBytes(res.Bytes))
	if res.ETag != "" {
		fmt.Fprintf(stdout, "  ETag      : %s\n", res.ETag)
	}
	switch res.LocalAction {
	case "deleted":
		fmt.Fprintln(stdout, "  本地文件  : 已按配置删除（远端已留存）")
	default:
		fmt.Fprintf(stdout, "  本地文件  : 保留在 %s\n", local)
	}
	return cli.ExitOK
}

// cmdCredCheck 只读检查凭据文件的可用性与落点（不需要真的连网）。
//
// 它回答的是"我这份 client.json 到底会往哪传"，不负责证明"能传成功"——
// 后者需要真的发一次请求，那是生成器 `r2-check` 的职责。
func cmdCredCheck(cfgPath string, stdout, stderr io.Writer) int {
	cfg, _, code := loadConfig(cfgPath, stderr)
	if cfg == nil {
		return code
	}
	fmt.Fprintf(stdout, "上传开关      : %v\n", cfg.Upload.Enabled)
	fmt.Fprintf(stdout, "配置的凭据路径: %s\n", cfg.Upload.CredentialFile)

	path, cands := credCandidates(cfg)
	fmt.Fprintln(stdout, "\n候选路径（按优先级）：")
	for _, p := range cands {
		mark := "    "
		if p == path {
			mark = " -> "
		}
		fmt.Fprintf(stdout, "%s%s\n", mark, p)
	}
	if path == "" {
		fmt.Fprintln(stderr, "\n未找到任何凭据文件。请把生成器产出的 client.json 放到上面任一路径。")
		return cli.ExitPartial
	}

	summary, err := credSummary(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "\n凭据不可用：%v\n", err)
		fmt.Fprintf(stderr, "怎么处理：%s\n", credErrorHint(err))
		return cli.ExitRuntime
	}
	fmt.Fprintf(stdout, "\n生效凭据：\n  %s\n", summary)
	fmt.Fprintln(stdout, "\n提示：这里只做本地解密检查，不发任何网络请求。")
	fmt.Fprintln(stdout, "      要验证端点/桶/权限是否可用，请用生成器：usbkeygen-r2 r2-check")
	return cli.ExitOK
}

// newSimpleLogger 给一次性命令（upload）一个往 stdout 打日志的 logger。
//
// 不用 logx：那个是常驻服务用的（带文件轮转），一次性命令只需要能看到就行。
func newSimpleLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// embeddedPublicKey 返回客户端模式下内嵌的公钥；非客户端模式返回 nil。
func embeddedPublicKey() *rsa.PublicKey {
	if clientBuild.ok {
		return clientBuild.pub
	}
	return nil
}

// credErrorHint 把凭据加载失败翻译成**对症**的下一步。
//
// 必须按错误类型分派。原先不管什么错都打印同一句
// "文件来自别的机器（DPAPI 解不开）、被截断，或不是本工具生成的"，
// 于是"我只是忘了设口令环境变量"的人会跑去重新生成凭据——白折腾一趟，
// 而真正的修法只是加一个环境变量。
func credErrorHint(err error) string {
	switch {
	case errors.Is(err, cred.ErrPassphraseRequired):
		return "凭据是口令加密的，但这次没拿到口令。设 USBBACKUP_R2_CRED_PASSPHRASE_FILE 指向含口令的文件，" +
			"或设 USBBACKUP_R2_CRED_PASSPHRASE。（客户端没有 --cred-pass-file 开关，它只认这两个环境变量；" +
			"生成器与解密器才有 --cred-pass-file。）服务模式下还要注意：服务以 LocalSystem 运行，用户级变量它看不见，要用 setx /M。"
	case errors.Is(err, cred.ErrPassphraseWrong):
		return "口令不对。口令没有找回途径：换用记得住的那份，或重新生成一份凭据。"
	case errors.Is(err, cred.ErrPlainFileNotAllowed):
		return "凭据是明文的，读取需要显式放行（生成器 / 解密器加 --allow-plain-cred）。"
	case errors.Is(err, cred.ErrUnsupportedPlatform), errors.Is(err, cred.ErrUnprotectFailed):
		return "凭据是 DPAPI 机器绑定的，只能在生成它的那台 Windows 上解开。换机器请在目标机器上重新生成一份。"
	case errors.Is(err, cred.ErrBadProtection):
		return "凭据文件的 protection 字段不被识别——可能是更新版本写的，或文件被改过。"
	default:
		return "文件可能被截断或不是本工具生成的。"
	}
}
