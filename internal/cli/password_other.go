//go:build !windows && !linux

package cli

// 除 Windows 与 Linux 之外的平台没有无回显实现。
//
// 这两个平台才是本项目的交付目标：Windows 跑客户端与生成器，
// Linux 跑解密器。其余平台（darwin/bsd 等）保留这个兜底**只为让
// `GOOS=xxx go vet ./...` 能跑通**，不作为交付能力——
// 在这些平台上 ReadPassphrase 会明确告知输入未被隐藏。

// IsTerminal 无平台实现时一律返回 false，让调用方走非交互路径。
func IsTerminal(fd int) bool { return false }

// ReadPassphrase 退化为普通读取（会提示未隐藏）。
func ReadPassphrase(prompt string) ([]byte, error) {
	return readPlainPassphrase(prompt)
}
