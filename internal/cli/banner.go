// Package cli 提供命令行程序共用组件：安全警告横幅、免责声明确认、无回显口令输入。
//
// 对应需求 F-901 / F-902 / F-706 / F-906。
package cli

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/immml/UsbBackUP-R2/internal/version"
)

// 退出码约定（供全部子命令统一使用）。
const (
	// ExitOK 表示成功。
	ExitOK = 0
	// ExitUsage 表示命令行用法错误。
	ExitUsage = 1
	// ExitNotAgreed 表示用户未接受免责声明。
	ExitNotAgreed = 2
	// ExitNotImplemented 表示该功能尚未实现。
	ExitNotImplemented = 3
	// ExitRuntime 表示运行期错误。
	ExitRuntime = 4
	// ExitPartial 表示部分成功。
	ExitPartial = 5
)

// WarningBanner 是必须显著展示的安全警告与免责声明摘要（F-901）。
//
// 文案要点（G-05 / G-06′ / G-07 / G-12 / G-15）：
//   - 仅限本人自有的机器与介质；
//   - 对源介质全程只读：不写入、不删除、不改写、不移动任何源文件；
//   - 唯一出站是向你自己配置的 R2 端点执行 S3 读写，无入站、无远程指令；
//   - 无隐蔽能力、无免杀处理；
//   - 私钥一旦丢失，密文不可恢复。
const WarningBanner = `================================================================================
                        安  全  警  告   /   SECURITY WARNING
================================================================================

  [1] 使用范围
      本工具仅限用于【本人自有】的计算机，以及【本人自有】的可移动存储介质。
      严禁用于他人设备，或处理他人介质内的数据。

      客户端按【显式采集策略】处理介质：
        · 盘根有 .usbbackup-allow  → 直接【豁免】，不读取、不打包、不上传；
        · 否则按策略决定：all（默认，未命中豁免的即采集）/ marker_only
          （仅采集盘根带 .usbbackup-collect 的介质）/ off（关闭采集）。

  [2] 关于对源介质的影响
      本工具对源介质【全程只读】：不写入、不删除、不改写、不移动源盘上的
      任何文件。唯一的写入动作落在【本机的产物目录】与【远端对象存储】上。
      本工具【不包含】任何"把本机数据回写进介质"的功能。

  [3] 关于数据上传
      通过准入判定的介质，其【全部内容】会被打包并混合加密，随后容器会被
      【上传到你配置的 Cloudflare R2 桶】。
      上传前请确认：该介质的全部内容都是你有权处置的数据。

      关于上传凭据的权限：R2 控制台可签发的长效 token 中，最小档位是
      【桶级 Object Read & Write】，它同时具备读取、覆盖与删除对象的能力，
      而 R2 不提供对象版本控制——删除【没有原生兜底】。请定期轮换凭据，
      并自行评估远端对象被删除的风险。读取由端到端加密兜住，
      覆盖由对象键带时间戳消除。

  [4] 关于密钥
      加密采用混合加密：AES-256-GCM 加密数据，RSA-OAEP(SHA-256) 仅包装会话密钥
      （密钥位数由你生成时决定，默认 4096 位、下限 2048 位）。
      客户端只内嵌【公钥】，能加密、不能解密；私钥只应留在你自己的机器上。
      私钥一旦丢失或口令遗忘，密文【无法恢复】。本工具不提供任何后门、
      密钥托管或找回机制。请务必自行离线备份私钥与口令。

  [5] 关于网络与隐蔽性
      本工具【不包含】加壳、免杀、反调试、隐藏进程/窗口/端口、绕过安全软件
      等任何能力。

      网络方面：唯一的出站是向【你自己配置的 R2 端点】执行 S3 请求（写入、
      读取、列举、删除对应的对象），仅 HTTPS 且强制校验证书。没有入站监听、
      不接受任何远程指令、不存在控制通道，也不做遥测上报；
      除该端点外不会访问任何地址。

      客户端持有的 R2 凭据存放于本机受保护文件（DPAPI 的【机器范围】加密，
      本机管理员或 SYSTEM 可以提取），应授予最小权限并定期轮换。任何落在
      机器上的凭据都存在被本机管理员提取的可能——本工具【不声称】它不可提取。

      若安全软件告警，请自行判断。

================================================================================
                        免  责  声  明  摘要   /   DISCLAIMER
================================================================================

  本软件按"现状"（AS IS）提供，不附带任何明示或默示担保，包括但不限于对
  适销性、特定用途适用性及不侵权的担保。作者与贡献者不对因使用本软件产生
  的任何直接、间接、附带、特殊、惩罚性或后果性损害承担责任，包括但不限于
  数据丢失、数据损坏、数据泄露、业务中断、设备损坏或利润损失。

  使用者须自行确保其使用行为符合所在国家/地区的法律法规，并自行承担全部
  法律后果。在将本工具用于重要数据之前，请务必先在非生产环境中验证。

  完整条款见随附的 DISCLAIMER.md 文件。

  本作品采用知识共享 署名-非商业性使用-相同方式共享 4.0 国际 协议
  （CC BY-NC-SA 4.0）进行许可。
      · 署名（BY）        —— 必须保留原作者署名
      · 非商业性使用（NC）—— 不得用于任何商业目的
      · 相同方式共享（SA）—— 改编作品须以相同协议分发
  协议全文：https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode

================================================================================
`

// RenderBanner 输出安全警告横幅，并在末尾附上程序名与版本。
func RenderBanner(w io.Writer, toolName string) {
	fmt.Fprint(w, WarningBanner)
	fmt.Fprintf(w, "  程序：%s   版本：%s\n", toolName, version.Version)
	fmt.Fprint(w, "================================================================================"+"\n\n")
}

// NoticeShort 是自动化模式（--yes）下的简短提示。
//
// 交互式启动仍会完整展示 WarningBanner（F-901）；--yes 面向脚本，
// 这里保留最关键的几条约束，避免把整屏警告重复刷进日志。
const NoticeShort = `[安全提示] 本工具仅限用于本人自有的计算机与存储介质。
  · 对源介质全程只读：不写入、不删除、不改写、不移动源盘上的任何文件；
    本工具不含任何"把本机数据回写进介质"的功能；
  · 采集范围由显式策略控制；盘根有 .usbbackup-allow 的介质一律豁免（不采集）；
  · 通过准入的介质会被打包加密，容器【上传到你配置的 R2 桶】（唯一出站，仅 HTTPS）；
    上传凭据应选桶级 Object Read & Write 并定期轮换；R2 无对象版本控制，删除无原生兜底；
  · 客户端只内嵌公钥，解不开任何密文；私钥请只留在自己机器上；
  · 无加壳免杀、无隐藏行为、无入站监听、无远程指令；
  · 私钥与口令一旦丢失，密文不可恢复。
  完整条款见随附 DISCLAIMER.md。本作品采用 CC BY-NC-SA 4.0 许可（非商业性使用）。`

// RenderNotice 输出简短提示（配合 --yes 使用）。
func RenderNotice(w io.Writer, toolName string) {
	fmt.Fprintln(w, NoticeShort)
	fmt.Fprintf(w, "  程序：%s   版本：%s（--yes 已跳过完整警告与确认）\n\n", toolName, version.Version)
}

// RegisterGlobalFlags 在子命令的 FlagSet 上注册全局开关。
//
// 为什么需要：`--config` 与 `--yes` 是全局开关，但每个子命令各自持有 FlagSet，
// 未注册的 flag 会直接报 "flag provided but not defined" 而中断。
// 这里统一注册，取值由 ExtractGlobalFlags 负责读取，避免各处重复解析。
//
// 已存在同名 flag 时跳过注册：子命令可以自己定义语义更具体的同名开关
// （例如 build-client 的 `--config` 指"基础配置文件"），
// 重复注册同名 flag 会让 flag 包直接 panic。
func RegisterGlobalFlags(fs *flag.FlagSet) {
	if fs.Lookup("config") == nil {
		fs.String("config", "", "配置文件路径（全局开关）")
	}
	if fs.Lookup("yes") == nil {
		fs.Bool("yes", false, "跳过免责声明确认（全局开关，仅供自动化使用）")
	}
}

// ParseArgs 解析子命令参数：先重排 flag 顺序，再交给 flag 包解析。
//
// 统一入口，保证所有子命令都：（1）接受全局开关；（2）允许 flag 写在位置参数之后。
func ParseArgs(fs *flag.FlagSet, args []string) error {
	RegisterGlobalFlags(fs)
	return fs.Parse(ReorderArgs(fs, args))
}

// ExtractGlobalFlags 从参数中读出全局开关的值（全局开关可出现在任意位置）。
//
// 只读值、不改动参数，因此可以被多个 FlagSet 各取所需而互不影响。
// 支持 `--config x` / `--config=x` / `-config x` / `--yes` 等写法。
func ExtractGlobalFlags(args []string) (configPath string, yes bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--yes" || a == "-yes":
			yes = true
		case a == "--config" || a == "-config":
			if i+1 < len(args) {
				configPath = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "--config="):
			configPath = strings.TrimPrefix(a, "--config=")
		case strings.HasPrefix(a, "-config="):
			configPath = strings.TrimPrefix(a, "-config=")
		}
	}
	return configPath, yes
}

// ReorderArgs 把参数重排为「所有 flag 在前，所有位置参数在后」。
//
// 为什么需要：Go 标准库的 flag 包在遇到第一个非 flag 参数后会**停止解析**，
// 因此下面这种自然写法会失效：
//
//	usbkeygen-r2 use C:\keys\usbbackup-r2.pub.pem --config D:\cfg\config.json
//	usbcomp-r2   pack D:\data -o D:\out\x.usbk
//
// 这里依据 FlagSet 中已注册的 flag 定义做一次重排（知道哪些 flag 需要取值），
// 让 flag 写在位置参数之后同样生效，不改变任何 flag 的语义。
//
// `--` 语义：其后的参数全部视为位置参数。重排后会保留一个 `--` 放在 flag 之后，
// 这样 flag 包同样会在该处分界，不会把 `--foo` 误当成 flag。
func ReorderArgs(fs *flag.FlagSet, args []string) []string {
	isBool := make(map[string]bool)
	fs.VisitAll(func(f *flag.Flag) {
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			isBool[f.Name] = true
		}
	})

	flags := make([]string, 0, len(args))
	positional := make([]string, 0, len(args))
	sawTerminator := false
	endOfFlags := false

	for i := 0; i < len(args); {
		a := args[i]
		switch {
		case endOfFlags:
			positional = append(positional, a)
			i++
		case a == "--":
			sawTerminator = true
			endOfFlags = true
			i++
		case len(a) > 1 && a[0] == '-':
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if strings.ContainsRune(name, '=') {
				// `--flag=value` 形式自带取值。
				i++
				continue
			}
			if !isBool[name] && i+1 < len(args) {
				// 该 flag 需要取值，把下一个参数一并搬过去。
				flags = append(flags, args[i+1])
				i += 2
				continue
			}
			i++
		default:
			positional = append(positional, a)
			i++
		}
	}

	out := make([]string, 0, len(args)+1)
	out = append(out, flags...)
	if sawTerminator {
		// 保留分隔符，避免位置参数中的 `-xxx` 被重新解释成 flag。
		out = append(out, "--")
	}
	out = append(out, positional...)
	return out
}

// ConfirmAgreement 要求用户输入 I AGREE 才继续（F-902）。
//
// 返回 nil 表示已同意；返回 ErrNotAgreed 表示未同意。
// ConfirmAgreement 读取并校验 I AGREE 确认输入。
//
// 若调用方已持有 *bufio.Reader，会直接使用它（见 ConfirmAgreementBuf 的说明）。
func ConfirmAgreement(r io.Reader, w io.Writer) error {
	if br, ok := r.(*bufio.Reader); ok {
		return ConfirmAgreementBuf(br, w)
	}
	return ConfirmAgreementBuf(bufio.NewReader(r), w)
}

// ConfirmAgreementBuf 是给「已经持有 bufio.Reader 的调用方」用的入口。
//
// 为什么需要它：bufio 会一次性预读一整块（默认 4 KiB）。若这里再包一层 reader，
// 后面所有输入都会被留在内层缓冲里，外层的后续提问一个字都读不到——
// 交互式向导会表现为「每一步都莫名其妙用了默认值」。
// 因此共用 reader 的场景必须走这个不包装的入口。
func ConfirmAgreementBuf(r *bufio.Reader, w io.Writer) error {
	fmt.Fprint(w, "  继续操作前请输入 I AGREE（不区分大小写）表示你已阅读并同意上述条款：\n  > ")
	line, err := r.ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		fmt.Fprintln(w, "\n  未收到输入，已退出。")
		return ErrNotAgreed
	}
	// 统一空格，容忍 "I  AGREE" 这类多空格写法。
	normalized := strings.Join(strings.Fields(strings.ToUpper(strings.TrimSpace(line))), " ")
	if normalized != "I AGREE" {
		fmt.Fprintf(w, "\n  输入为 %q，未通过确认，已退出。\n", strings.TrimSpace(line))
		return ErrNotAgreed
	}
	fmt.Fprintln(w, "\n  已确认。")
	return nil
}

// ErrNotAgreed 表示用户未接受免责声明。
var ErrNotAgreed = errNotAgreed{}

type errNotAgreed struct{}

func (errNotAgreed) Error() string { return "用户未接受免责声明" }

// PrintHelp 以统一格式输出子命令帮助。
func PrintHelp(w io.Writer, usage string, lines []string) {
	fmt.Fprintf(w, "%s\n\n", usage)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
}
