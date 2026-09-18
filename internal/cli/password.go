package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// 本文件放着与平台无关的口令输入辅助：
//   - readPlainPassphrase 在无法关闭回显时使用（管道、重定向、非 TTY）；
//   - ReadPassphraseFromFile 用于无人值守场景。
//
// 真正的"无回显读取"由各平台的 ReadPassphrase 实现，
// 见 password_windows.go（SetConsoleMode）与 password_linux.go（termios）。

// readPlainPassphrase 在无法关闭回显时退化为普通读取，但**必须**告诉使用者
// 输入没有被隐藏——否则他会以为口令是保密的，从而在有人看着的终端里照打。
func readPlainPassphrase(prompt string) ([]byte, error) {
	fmt.Fprintf(os.Stderr, "%s（注意：当前输入未隐藏）", prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读取口令失败: %w", err)
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}

// ReadPassphraseFromFile 从文件读取口令，适合无人值守场景（F-706）。
// 文件内容的首行（去除行尾换行）即为口令。
//
// 只取首行，且**不**去首尾空格：口令里的空格是有效字符。
func ReadPassphraseFromFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取口令文件失败 %s: %w", path, err)
	}
	s := string(raw)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return []byte(s), nil
}
