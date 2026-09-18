// Command usbunseal-r2 是解密器：从 R2 取回容器并解密还原，或解密本地容器。
//
// 用法（git 风格子命令）：
//
//	usbunseal-r2 init                      生成配置骨架
//	usbunseal-r2 config                    打印生效配置
//	usbunseal-r2 ls [前缀]                  列出远端可用产物（不需要私钥）
//	usbunseal-r2 pull [对象键] [--all]      从 R2 下载并自动解密解压
//	usbunseal-r2 unseal <容器.usbk> -d <目录> --key <私钥>
//	usbunseal-r2 verify <容器.usbk> --key <私钥>
//	usbunseal-r2 list <容器.usbk>
//
// 配置放在 ~/.config/usbbackup-r2/unseal.json（Windows 为 %AppData%\usbbackup-r2\），
// 命令行参数覆盖配置文件。对应需求 F-B01 ~ F-B10。
//
// 安全设计：目标目录必须显式指定（或来自配置文件）；拒绝一切逃逸目标目录的
// 条目名（Zip Slip）；解密失败统一报错不区分原因。
package main

import (
	"crypto/rsa"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/immml/UsbBackUP-R2/internal/archive"
	"github.com/immml/UsbBackUP-R2/internal/cli"
	"github.com/immml/UsbBackUP-R2/internal/crypto"
	"github.com/immml/UsbBackUP-R2/internal/fsutil"
	"github.com/immml/UsbBackUP-R2/internal/keystore"
	"github.com/immml/UsbBackUP-R2/internal/version"
)

const toolName = "usbunseal-r2"

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
	case "list":
		// 只读查看容器头，不接触任何密钥，不需要免责声明确认。
		return cmdList(rest, stdout, stderr)
	case "help", "--help", "-h":
		cli.RenderBanner(stdout, toolName)
		printUsage(stdout)
		return cli.ExitOK
	}

	// init 也不碰密钥（只写路径），但仍属于"会改磁盘上的东西"，
	// 所以照样走一次告示流程，保持一致。
	_, skipConfirm := cli.ExtractGlobalFlags(args)
	if skipConfirm {
		cli.RenderNotice(stdout, toolName)
	} else {
		cli.RenderBanner(stdout, toolName)
		if err := cli.ConfirmAgreement(stdin, stdout); err != nil {
			return cli.ExitNotAgreed
		}
	}

	switch sub {
	case "verify":
		return cmdVerify(rest, stdout, stderr)
	case "unseal":
		return cmdUnseal(rest, stdout, stderr)
	case "init":
		return cmdInit(rest, stdout, stderr)
	}

	// 需要"远端"的子命令共用一个配置加载路径。
	cfg, cfgPath, cfgSource, code := loadConfigForRun(args, stdout)
	if code != cli.ExitOK {
		return code
	}
	switch sub {
	case "ls", "remote":
		return cmdLs(rest, cfg, cfgPath, cfgSource, stdout, stderr)
	case "pull":
		return cmdPull(rest, cfg, cfgPath, cfgSource, stdout, stderr)
	case "config":
		return cmdConfig(rest, cfg, cfgPath, cfgSource, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "未知子命令 %q\n\n", sub)
		printUsage(stderr)
		return cli.ExitUsage
	}
}

func printUsage(w io.Writer) {
	cli.PrintHelp(w, "usbunseal-r2 —— 解密器（从 R2 取回并解密，或解密本地容器）", []string{
		"用法（git 风格）：",
		"  usbunseal-r2 init [--out 路径]                        生成配置骨架（~/.config/usbbackup-r2/unseal.json）",
		"  usbunseal-r2 config                                   打印生效配置与关键文件状态",
		"  usbunseal-r2 ls [前缀]                                 列出远端可用产物（不需要私钥）",
		"  usbunseal-r2 pull [对象键] [选项]                       从 R2 下载并自动解密解压",
		"  usbunseal-r2 unseal <容器.usbk> -d <目录> --key <私钥>   解密本地已有的容器",
		"  usbunseal-r2 list <容器.usbk>                          查看容器头（无需私钥）",
		"  usbunseal-r2 verify <容器.usbk> --key <私钥>            仅校验完整性，不解出明文",
		"  usbunseal-r2 version",
		"",
		"配置文件（字段留空即用内置默认值）：",
		"  " + DefaultUnsealConfigPath(),
		"  " + strings.SplitN(configTemplateComment, "\n", 2)[0],
		"",
		"ls / pull 选项：",
		"  --cred string             R2 凭据文件（默认从配置/常见位置查找）",
		"  --cred-pass-file string   凭据文件口令（首行）",
		"  --allow-plain-cred        允许读取未加密的凭据文件（仅 0600 保护）",
		"  --prefix string           对象键前缀（默认用凭据里配置的）",
		"  --limit int               ls 最多列出多少个（0 表示不限）",
		"  --show-config             先打印生效配置再执行",
		"",
		"pull 选项：",
		"  --object string           只处理指定对象键（也可作为位置参数）",
		"  --latest                  只取最新一个（默认行为）",
		"  --all                     取回该前缀下的全部对象",
		"  --out DIR                 解压目标目录",
		"  --key string              私钥文件（或配置文件里的 key_file）",
		"  --pass                    交互式输入私钥口令（无回显）",
		"  --pass-file string        从文件读取私钥口令（首行）",
		"  --skip-existing           目标目录已存在时跳过（默认开启，重跑幂等）",
		"  --keep-container          解密后保留下载下来的 .usbk",
		"  --delete-remote           解密成功后删除远端对象（默认不动远端）",
		"  --dry-run                 只显示将要做什么",
		"",
		"unseal / verify 选项：",
		"  --key string        私钥文件（PKCS#8 / PKCS#1 PEM）",
		"  --pass              交互式输入私钥口令（无回显）",
		"  --pass-file string  从文件读取口令（首行）",
		"  --force             覆盖已存在的文件（默认跳过）",
		"  --dry-run           只校验条目，不实际写入",
		"  --keep-zip          只解出明文 zip，不再解压",
		"",
		"全局开关（可放在任意位置）：",
		"  --config string     配置文件路径（默认 " + DefaultUnsealConfigPath() + "）",
		"  --yes               跳过免责声明确认（自动化用）",
		"",
		"凭据口令的三种给法（按优先级）：",
		"  --cred-pass-file <文件>  /  配置文件 cred_pass_file",
		"  环境变量 " + credEnvPassphrase + "  /  " + credEnvPassphraseFile,
		"  交互式提示（需要 TTY）",
		"",
		"安全说明：",
		"  · 解包会拒绝一切可能逃逸目标目录的条目名（Zip Slip 防护）；",
		"  · 默认不覆盖已存在文件；",
		"  · 解密失败时不区分「密钥错误」与「数据被篡改」，避免信息泄露；",
		"  · 远端对象的生命周期默认由 bucket 侧的 lifecycle rule 管理，",
		"    工具不会主动删除远端内容（除非显式加 --delete-remote）。",
		"",
		"平台：本二进制可在 Linux / Windows 上运行；" + platformNote(),
	})
}

// platformNote 针对当前平台给一句使用提示。
func platformNote() string {
	if runtime.GOOS == "windows" {
		return "Windows 上凭据可用 DPAPI 保护（与机器绑定）。"
	}
	return "本平台没有 DPAPI，凭据需用口令保护（cred_pass_file 或环境变量）。"
}

// credEnvPassphrase / credEnvPassphraseFile 是凭据口令的环境变量名。
//
// 取自 cred 包，避免文档与实际读的变量名不一致——这种不一致
// 会让人照着帮助输一遍却没生效，且完全不报错。
var (
	credEnvPassphrase     = "USBBACKUP_R2_CRED_PASSPHRASE"
	credEnvPassphraseFile = "USBBACKUP_R2_CRED_PASSPHRASE_FILE"
)

// cmdList 读取并展示容器头（F-B01）。不涉及任何密钥材料。
func cmdList(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("list", stderr)
	if err := cli.ParseArgs(fs, args); err != nil {
		return cli.ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "用法：usbunseal-r2 list <容器.usbk>")
		return cli.ExitUsage
	}
	path := fs.Arg(0)

	f, err := os.Open(fsutil.LongPath(path))
	if err != nil {
		fmt.Fprintf(stderr, "打开容器失败：%v\n", err)
		return cli.ExitRuntime
	}
	defer f.Close()

	hdr, headerBytes, err := crypto.ReadHeader(f)
	if err != nil {
		fmt.Fprintf(stderr, "解析容器头失败：%v\n", err)
		return cli.ExitRuntime
	}
	st, err := f.Stat()
	if err != nil {
		fmt.Fprintf(stderr, "读取文件信息失败：%v\n", err)
		return cli.ExitRuntime
	}

	fmt.Fprintf(stdout, "容器文件        : %s\n", path)
	fmt.Fprintf(stdout, "文件大小        : %s（%d 字节）\n", fsutil.HumanBytes(st.Size()), st.Size())
	fmt.Fprintln(stdout, hdr.Describe())
	fmt.Fprintf(stdout, "容器头长度      : %d 字节\n", headerBytes)
	fmt.Fprintf(stdout, "密文负载长度    : %s\n", fsutil.HumanBytes(st.Size()-headerBytes))
	fmt.Fprintln(stdout, "\n提示：该文件为混合加密容器，需要使用配套私钥才能解密。")
	return cli.ExitOK
}

// decryptArgs 是 verify / unseal 共用的密钥相关参数。
type decryptArgs struct {
	key        string
	passphrase []byte
	usePass    bool
	passFile   string
	noPass     bool
}

// cmdVerify 仅校验完整性（F-B02），不落任何明文。
func cmdVerify(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("verify", stderr)
	key := fs.String("key", "", "私钥文件（必填）")
	usePass := fs.Bool("pass", false, "交互式输入私钥口令")
	passFile := fs.String("pass-file", "", "从文件读取口令")
	if err := cli.ParseArgs(fs, args); err != nil {
		return cli.ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "用法：usbunseal-r2 verify <容器.usbk> --key <私钥>")
		return cli.ExitUsage
	}
	if *key == "" {
		fmt.Fprintln(stderr, "错误：必须通过 --key 指定私钥文件。")
		return cli.ExitUsage
	}
	container := fs.Arg(0)

	priv, code := loadPrivateKey(*key, *usePass, *passFile, stderr)
	if code != cli.ExitOK {
		return code
	}
	defer wipePrivate(priv)

	f, err := os.Open(fsutil.LongPath(container))
	if err != nil {
		fmt.Fprintf(stderr, "打开容器失败：%v\n", err)
		return cli.ExitRuntime
	}
	defer f.Close()

	fmt.Fprintf(stdout, "容器            : %s\n", container)
	fmt.Fprintf(stdout, "私钥            : %s\n", *key)
	fmt.Fprintln(stdout, "正在解密校验（不写出任何明文）...")

	// 解密结果全部丢弃，只关心是否通过认证与完整性校验。
	sum, err := crypto.DecryptStream(io.Discard, f, crypto.DecryptOptions{PrivateKey: priv})
	if err != nil {
		fmt.Fprintf(stderr, "\n校验失败：%v\n", err)
		return cli.ExitRuntime
	}
	fmt.Fprintln(stdout, "\n校验通过。")
	fmt.Fprintf(stdout, "  明文长度      : %s\n", fsutil.HumanBytes(sum.PlainBytes))
	fmt.Fprintf(stdout, "  加密块数      : %d\n", sum.Chunks)
	fmt.Fprintf(stdout, "  明文 SHA-256  : %x\n", sum.PlainSHA256)
	fmt.Fprintf(stdout, "  密文长度      : %s\n", fsutil.HumanBytes(sum.CipherBytes))
	fmt.Fprintf(stdout, "  公钥指纹      : %s\n", sum.Header.FingerprintHex())
	fmt.Fprintln(stdout, "\n注意：本命令未验证内层 zip 是否可用（如需完整验证请执行 unseal）。")
	return cli.ExitOK
}

// cmdUnseal 解密并解压（F-B03 ~ F-B07）。
func cmdUnseal(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("unseal", stderr)
	dest := fs.String("d", "", "解压目标目录（必填）")
	key := fs.String("key", "", "私钥文件（必填）")
	usePass := fs.Bool("pass", false, "交互式输入私钥口令")
	passFile := fs.String("pass-file", "", "从文件读取口令")
	force := fs.Bool("force", false, "覆盖已存在文件")
	dryRun := fs.Bool("dry-run", false, "只校验条目，不写入")
	keepZip := fs.Bool("keep-zip", false, "只解出明文 zip，不再解压")
	if err := cli.ParseArgs(fs, args); err != nil {
		return cli.ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "用法：usbunseal-r2 unseal <容器.usbk> -d <目录> --key <私钥>")
		return cli.ExitUsage
	}
	// 目标目录允许从配置文件取，但仍要求"有明确来源"——
	// 静默落到当前目录是最容易把解密结果写到不该去的地方的一种行为。
	if *dest == "" {
		cfg, _, _, code := loadConfigForRun(args, nil)
		if code == cli.ExitOK && strings.TrimSpace(cfg.OutDir) != "" {
			*dest = cfg.OutDir
		}
	}
	if *dest == "" {
		fmt.Fprintln(stderr, "错误：必须显式指定解压目标目录（-d <目录>，或在配置文件里设 out_dir）。")
		return cli.ExitUsage
	}
	if *key == "" {
		fmt.Fprintln(stderr, "错误：必须通过 --key 指定私钥文件。")
		return cli.ExitUsage
	}
	container := fs.Arg(0)

	priv, code := loadPrivateKey(*key, *usePass, *passFile, stderr)
	if code != cli.ExitOK {
		return code
	}
	defer wipePrivate(priv)

	in, err := os.Open(fsutil.LongPath(container))
	if err != nil {
		fmt.Fprintf(stderr, "打开容器失败：%v\n", err)
		return cli.ExitRuntime
	}
	defer in.Close()

	fmt.Fprintf(stdout, "容器            : %s\n", container)
	fmt.Fprintf(stdout, "目标目录        : %s\n", *dest)
	fmt.Fprintf(stdout, "私钥            : %s\n", *key)
	fmt.Fprintf(stdout, "覆盖已存在文件  : %v\n", *force)

	if *keepZip {
		// 只解出明文 zip：明文产物敏感，需要用户自行处置。
		zipPath := strings.TrimSuffix(container, ".usbk") + ".zip"
		out, err := os.OpenFile(fsutil.LongPath(zipPath), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			fmt.Fprintf(stderr, "错误：无法创建 %s：%v\n", zipPath, err)
			return cli.ExitRuntime
		}
		sum, derr := crypto.DecryptStream(out, in, crypto.DecryptOptions{PrivateKey: priv})
		closeErr := out.Close()
		if derr != nil || closeErr != nil {
			_ = os.Remove(fsutil.LongPath(zipPath))
			fmt.Fprintf(stderr, "错误：解密失败：%v\n", derr)
			return cli.ExitRuntime
		}
		fmt.Fprintf(stdout, "\n已解出明文 zip：%s（%s）\n", zipPath, fsutil.HumanBytes(sum.PlainBytes))
		fmt.Fprintln(stdout, "[警告] 明文 zip 等于绕过加密，请在使用后立即安全删除。")
		return cli.ExitOK
	}

	// 解密到临时文件：zip 需要随机访问中央目录（io.ReaderAt + 长度）。
	tmp, err := os.CreateTemp("", "usbbackup-r2-unseal-*.zip")
	if err != nil {
		fmt.Fprintf(stderr, "错误：无法创建临时文件：%v\n", err)
		return cli.ExitRuntime
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	fmt.Fprintln(stdout, "正在解密...")
	sum, err := crypto.DecryptStream(tmp, in, crypto.DecryptOptions{PrivateKey: priv})
	if err != nil {
		fmt.Fprintf(stderr, "解密失败：%v\n", err)
		return cli.ExitRuntime
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		fmt.Fprintf(stderr, "错误：无法定位临时文件：%v\n", err)
		return cli.ExitRuntime
	}
	fmt.Fprintf(stdout, "解密完成：明文 %s，%d 块，正在解压...\n",
		fsutil.HumanBytes(sum.PlainBytes), sum.Chunks)

	ust, err := archive.UnzipStream(osCtx(), tmp, sum.PlainBytes, archive.UnzipOptions{
		DestDir: *dest,
		Force:   *force,
		DryRun:  *dryRun,
	})
	if err != nil {
		fmt.Fprintf(stderr, "解压失败：%v\n", err)
		return cli.ExitRuntime
	}

	if *dryRun {
		fmt.Fprintln(stdout, "\n[dry-run] 未写入任何文件。")
	}
	fmt.Fprintf(stdout, "\n完成。\n")
	fmt.Fprintf(stdout, "  写出文件      : %d（跳过 %d）\n", ust.Files, ust.Skipped)
	fmt.Fprintf(stdout, "  写出字节      : %s\n", fsutil.HumanBytes(ust.Bytes))
	if ust.RejectedUnsafe > 0 {
		fmt.Fprintf(stdout, "  拒绝的不安全条目: %d（Zip Slip 等，已阻断）\n", ust.RejectedUnsafe)
	}
	fmt.Fprintf(stdout, "  目标目录      : %s\n", *dest)
	fmt.Fprintf(stdout, "  耗时          : %s\n", ust.Duration)
	if ust.RejectedUnsafe > 0 {
		fmt.Fprintln(stdout, "\n[注意] 本次归档中包含被拒绝的条目，说明该容器可能被人为构造过，请留意。")
		return cli.ExitPartial
	}
	return cli.ExitOK
}

// loadPrivateKey 读取私钥（必要时交互输入口令），并校验位数。
func loadPrivateKey(path string, usePass bool, passFile string, stderr io.Writer) (*rsa.PrivateKey, int) {
	var passphrase []byte
	switch {
	case passFile != "":
		p, err := cli.ReadPassphraseFromFile(passFile)
		if err != nil {
			fmt.Fprintf(stderr, "错误：%v\n", err)
			return nil, cli.ExitRuntime
		}
		passphrase = p
	case usePass:
		p, err := cli.ReadPassphrase("请输入私钥口令：")
		if err != nil {
			fmt.Fprintf(stderr, "错误：%v\n", err)
			return nil, cli.ExitRuntime
		}
		passphrase = p
	}
	defer func() {
		for i := range passphrase {
			passphrase[i] = 0
		}
	}()

	k, err := keystore.LoadPrivateKey(path, passphrase)
	if err != nil {
		followed := func(e error) bool {
			if strings.Contains(e.Error(), "口令") {
				fmt.Fprintf(stderr, "私钥加载失败：%v（可加 --pass 或 --pass-file）\n", e)
				return true
			}
			return false
		}
		if !followed(err) {
			fmt.Fprintf(stderr, "私钥加载失败：%v\n", err)
		}
		return nil, cli.ExitRuntime
	}
	if k.N.BitLen() < crypto.MinRSAKeyBits {
		fmt.Fprintf(stderr, "私钥仅 %d 位，低于下限 %d 位，拒绝使用。\n", k.N.BitLen(), crypto.MinRSAKeyBits)
		return nil, cli.ExitRuntime
	}
	return k, cli.ExitOK
}

// wipePrivate 尽力清除内存中的私钥材料（Go 标准库无完整清零 API，见 README）。
func wipePrivate(k *rsa.PrivateKey) {
	if k == nil {
		return
	}
	if k.D != nil {
		k.D.SetInt64(0)
	}
	for i := range k.Primes {
		if k.Primes[i] != nil {
			k.Primes[i].SetInt64(0)
		}
	}
}

var _ = flag.ContinueOnError
var _ = filepath.Separator
