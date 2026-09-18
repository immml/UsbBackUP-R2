package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/immml/UsbBackUP-R2/internal/cli"
	"github.com/immml/UsbBackUP-R2/internal/cred"
	"github.com/immml/UsbBackUP-R2/internal/fsutil"
	"github.com/immml/UsbBackUP-R2/internal/keystore"
)

// newFlagSet 构造本工具的统一 FlagSet。
//
// 集中一个构造点是为了保证 `--help` 之类的行为各处一致，
// 也免得某个子命令漏掉 SetOutput 把错误打到 stdout 去。
func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// loadConfigForRun 读取本次运行要用的配置。
//
// 返回值里带上"用的是哪个文件、来源是什么"，因为排障时第一个要回答的问题
// 永远是"它到底读了哪个配置"——尤其在默认位置改了文件却没生效的时候。
func loadConfigForRun(args []string, stdout io.Writer) (unsealConfig, string, string, int) {
	cfgPath, _ := cli.ExtractGlobalFlags(args)
	explicit := strings.TrimSpace(cfgPath) != ""
	if !explicit {
		cfgPath = DefaultUnsealConfigPath()
	}
	cfg, err := LoadUnsealConfig(cfgPath, explicit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误：%v\n", err)
		return cfg, cfgPath, "", cli.ExitRuntime
	}
	// 把路径类字段展开成绝对路径，后续所有判断都用展开后的值。
	cfg.CredFile = expand(cfg.CredFile)
	cfg.CredPassFile = expand(cfg.CredPassFile)
	cfg.KeyFile = expand(cfg.KeyFile)
	cfg.KeyPassFile = expand(cfg.KeyPassFile)
	cfg.OutDir = expand(cfg.OutDir)

	source := "默认路径"
	switch {
	case explicit:
		source = "命令行 --config"
	case fileExists(cfgPath):
		source = "存在，已加载"
	default:
		source = "不存在，使用内置默认值"
	}
	_ = stdout
	return cfg, cfgPath, source, cli.ExitOK
}

// fileExists 判断普通文件是否存在。
func fileExists(p string) bool {
	st, err := os.Stat(fsutil.LongPath(p))
	return err == nil && !st.IsDir()
}

// cmdConfig 打印生效配置（对应 `git config --list` 的心智）。
//
// 不需要凭据、不联网，纯粹回答"它现在到底按什么参数跑"。
func cmdConfig(args []string, cfg unsealConfig, cfgPath, cfgSource string, stdout, stderr io.Writer) int {
	fs := newFlagSet("config", stderr)
	credFile := fs.String("cred", cfg.CredFile, "R2 凭据文件")
	credPass := fs.String("cred-pass-file", cfg.CredPassFile, "凭据文件口令（首行）")
	allowPlain := fs.Bool("allow-plain-cred", cfg.AllowPlainCred, "允许读取未加密的凭据文件")
	prefix := fs.String("prefix", cfg.Prefix, "对象键前缀")
	if err := cli.ParseArgs(fs, args); err != nil {
		return cli.ExitUsage
	}
	cfg = applyOverride(cfg, *credFile, *credPass, *allowPlain, *prefix, 0)

	cfg.Describe(stdout, cfgPath, cfgSource)

	// 顺带把关键文件的存在性报出来：配置写得对、文件不在，
	// 是现场最常见的一类"配置没生效"。
	fmt.Fprintln(stdout, "\n关键文件：")
	report := func(label, p string, required bool) {
		if strings.TrimSpace(p) == "" {
			fmt.Fprintf(stdout, "  %-10s: (未配置)\n", label)
			return
		}
		if fileExists(p) {
			fmt.Fprintf(stdout, "  %-10s: 存在  %s\n", label, p)
			return
		}
		mark := "缺失  "
		if !required {
			mark = "可选  "
		}
		fmt.Fprintf(stdout, "  %-10s: %s%s\n", label, mark, p)
	}
	report("凭据文件", cfg.CredFile, true)
	report("凭据口令", cfg.CredPassFile, false)
	report("私钥文件", cfg.KeyFile, true)
	report("私钥口令", cfg.KeyPassFile, false)
	fmt.Fprintf(stdout, "  %-10s: %s\n", "解压目录", cfg.OutDir)

	if fileExists(cfg.CredFile) {
		if p, err := cred.ProtectionOf(cfg.CredFile); err == nil {
			fmt.Fprintf(stdout, "\n凭据保护方式：%s\n", cred.ProtectionNote(p))
		}
	}
	fmt.Fprintln(stdout, "\n命令：usbunseal-r2 ls / pull / unseal / verify / list / init")
	return cli.ExitOK
}

// cmdInit 生成一份配置骨架（对应 `git init` 的心智）。
//
// 只写路径与开关，**不写任何凭据材料**：配置文件是给人看和改的，
// 往里塞秘密等于把秘密摊开在一个 0600 的文本文件里，
// 而它旁边本来就该有一个专门的、受保护的凭据文件。
func cmdInit(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("init", stderr)
	out := fs.String("out", "", "配置文件输出路径（默认 ~/.config/usbbackup-r2/unseal.json）")
	force := fs.Bool("force", false, "覆盖已存在的配置文件")
	credFile := fs.String("cred", "", "预填的凭据文件路径")
	credPassFile := fs.String("cred-pass", "",
		"预填的凭据文件口令路径（凭据是口令加密时必须给，否则 ls/pull 会因缺口令失败）")
	keyFile := fs.String("key", "", "预填的私钥路径")
	keyPassFile := fs.String("key-pass", "", "预填的私钥口令路径（私钥带口令时必须给）")
	outDir := fs.String("out-dir", "", "预填的解压目标目录")
	prefix := fs.String("prefix", "", "预填的对象键前缀")
	if err := cli.ParseArgs(fs, args); err != nil {
		return cli.ExitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "用法：usbunseal-r2 init [--out 路径] [--force]")
		return cli.ExitUsage
	}

	path := strings.TrimSpace(*out)
	if path == "" {
		path = DefaultUnsealConfigPath()
	}
	path = expand(path)

	cfg := DefaultUnsealConfig()
	if strings.TrimSpace(*credFile) != "" {
		cfg.CredFile = expand(*credFile)
	}
	if strings.TrimSpace(*credPassFile) != "" {
		cfg.CredPassFile = expand(*credPassFile)
	}
	if strings.TrimSpace(*keyFile) != "" {
		cfg.KeyFile = expand(*keyFile)
	}
	if strings.TrimSpace(*keyPassFile) != "" {
		cfg.KeyPassFile = expand(*keyPassFile)
	}
	if strings.TrimSpace(*outDir) != "" {
		cfg.OutDir = expand(*outDir)
	}
	if strings.TrimSpace(*prefix) != "" {
		cfg.Prefix = cred.NormalizePrefix(*prefix)
	}

	if err := SaveUnsealConfig(path, cfg, *force); err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return cli.ExitRuntime
	}
	fmt.Fprintf(stdout, "配置已写入：%s（权限 0600）\n\n", path)
	fmt.Fprintln(stdout, "下一步：")
	fmt.Fprintf(stdout, "  1) 按需编辑该文件（改端点/桶/前缀/路径）\n")
	fmt.Fprintf(stdout, "  2) 确认凭据文件在位：%s\n", cfg.CredFile)
	fmt.Fprintf(stdout, "     类型：%s\n", protectionHint(cfg.CredFile))
	// 口令加密的凭据 + 空 cred_pass_file = 一份注定失败的配置。
	// 这一步当场点出来，比让人在 ls 的时候撞上「需要口令」强。
	if need, err := cred.NeedsPassphrase(cfg.CredFile); err == nil && need && cfg.CredPassFile == "" {
		fmt.Fprintln(stdout, "     [!] 该凭据是**口令加密**的，但这份配置里 cred_pass_file 是空的：")
		fmt.Fprintln(stdout, "         ls / pull 会因为拿不到口令而失败。请补上 cred_pass_file，")
		fmt.Fprintln(stdout, "         或加 --cred-pass <口令文件> 用 `init --force` 重新生成。")
	}
	if strings.TrimSpace(cfg.KeyPassFile) == "" {
		if enc, err := keystore.KeyFileNeedsPassphrase(cfg.KeyFile); err == nil && enc {
			fmt.Fprintln(stdout, "     [!] 私钥是**带口令**的，但这份配置里 key_pass_file 是空的：")
			fmt.Fprintln(stdout, "         解密时会要口令。请补上 key_pass_file，或加 --key-pass <口令文件> 重新生成。")
		}
	}
	fmt.Fprintf(stdout, "  3) 试一下：usbunseal-r2 ls\n")
	fmt.Fprintf(stdout, "  4) 取回并解密：usbunseal-r2 pull\n")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "该文件只登记路径与开关，不保存任何凭据或私钥内容。")
	return cli.ExitOK
}

// protectionHint 给出一句"这个凭据文件是什么保护方式"的说明。
func protectionHint(path string) string {
	if !fileExists(path) {
		return "文件不存在（请用 usbkeygen-r2 cred 生成，或把已有的拷到这个路径）"
	}
	p, err := cred.ProtectionOf(path)
	if err != nil {
		return "无法识别（文件可能损坏）"
	}
	switch p {
	case cred.ProtectionPassphrase:
		return "口令保护（跨机器可读，需配合 cred_pass_file 或环境变量）"
	case cred.ProtectionPlainFile:
		return "未加密（仅靠 0600 权限，需 --allow-plain-cred）"
	default:
		return cred.ProtectionNote(p)
	}
}

// configTemplateComment 说明配置文件里每个字段的含义。
//
// 单独留一份是为了让 `init` 产出的骨架带注释的意图有处可写：
// encoding/json 不支持注释，所以把说明放在 stdout 而不是文件里，
// 避免产出一个"JSON 里塞了注释导致解析失败"的配置文件。
const configTemplateComment = `字段说明（JSON 不支持注释，故写在这里）：
  cred_file          R2 凭据文件路径（由 usbkeygen-r2 cred 产出）
  cred_pass_file     凭据文件口令（首行）；凭据是 DPAPI 时留空
  allow_plain_cred   凭据未加密时才需要设 true
  key_file           解密私钥路径；私钥口令用 key_pass_file
  out_dir            解压目标目录
  prefix             对象键前缀（留空则用凭据里记的）
  skip_existing      目标目录已存在时跳过（默认 true，重跑幂等）
  keep_container     解密后保留下载的 .usbk
  delete_remote      解密成功后删除远端对象（默认 false）
路径支持 ~ / %VAR% / $VAR。`

var _ = filepath.Separator
