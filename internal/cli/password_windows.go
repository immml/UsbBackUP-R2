//go:build windows

package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

// enableEchoInput 对应 ENABLE_ECHO_INPUT 控制台模式位。
const enableEchoInput = 0x0004

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
)

// setConsoleMode 包装 SetConsoleMode。
// Go 标准库的 syscall 包只导出了 GetConsoleMode，因此这里直接走 kernel32。
func setConsoleMode(h syscall.Handle, mode uint32) error {
	r, _, callErr := procSetConsoleMode.Call(uintptr(h), uintptr(mode))
	if r == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return callErr
		}
		return errors.New("SetConsoleMode 调用失败")
	}
	return nil
}

// ReadPassphrase 在控制台上无回显地读取口令（F-706）。
//
// 优先关闭终端回显；若 stdin 被重定向（非控制台），则退化为普通读取并提示用户，
// 以保证在脚本/服务场景下仍可用，同时不让用户误以为输入被隐藏。
func ReadPassphrase(prompt string) ([]byte, error) {
	h, err := syscall.GetStdHandle(int(syscall.Stdin))
	if err != nil {
		return readPlainPassphrase(prompt)
	}
	var mode uint32
	if err := syscall.GetConsoleMode(h, &mode); err != nil {
		// 非控制台（管道/文件重定向）。
		return readPlainPassphrase(prompt)
	}
	restore := mode | enableEchoInput
	if err := setConsoleMode(h, mode&^enableEchoInput); err != nil {
		return readPlainPassphrase(prompt)
	}
	defer func() {
		_ = setConsoleMode(h, restore)
		fmt.Fprintln(os.Stderr)
	}()

	fmt.Fprint(os.Stderr, prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读取口令失败: %w", err)
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}

// IsTerminal 判断标准输入是否连着控制台。
//
// 与 ReadPassphrase 用同一套判据（GetConsoleMode 是否成功），
// 免得出现"这里说是终端、那里说是管道"的不一致。
func IsTerminal(fd int) bool {
	h, err := syscall.GetStdHandle(int(syscall.Stdin))
	if err != nil {
		return false
	}
	var mode uint32
	return syscall.GetConsoleMode(h, &mode) == nil
}
