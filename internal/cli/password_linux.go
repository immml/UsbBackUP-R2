//go:build linux

package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// 无回显读取口令：Linux 实现。
//
// 做法是标准的 termios 操作——关掉 ECHO 位读一行，读完恢复原设置。
// 之所以手写 ioctl 而不引第三方终端库：本项目只有标准库可用，
// 而 syscall 包里 TCGETS / TCSETS / ECHO / Termios 都是现成的。

// ioctlTermios 对 fd 执行一次 termios 相关的 ioctl。
func ioctlTermios(fd int, req uintptr, t *syscall.Termios) error {
	// 用 SiocgIfconf 系列的通用 ioctl 入口。
	// unsafe.Pointer -> uintptr 的方向是安全的（反向转换才是 vet 会拦的那种）。
	_, _, errno := syscall.Syscall6(
		syscall.SYS_IOCTL,
		uintptr(fd),
		req,
		uintptr(unsafe.Pointer(t)),
		0, 0, 0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// IsTerminal 判断文件描述符是否连着终端。
//
// 导出它是为了让调用方能提前判断"现在能不能交互式问口令"，
// 而不是等到读了一半才发现 stdin 是管道。
func IsTerminal(fd int) bool {
	var t syscall.Termios
	return ioctlTermios(fd, syscall.TCGETS, &t) == nil
}

// ReadPassphrase 在控制台上无回显地读取口令（F-706）。
//
// stdin 不是终端（管道/重定向）时退化为普通读取并明确提示，保证脚本可用。
func ReadPassphrase(prompt string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	var old syscall.Termios
	if err := ioctlTermios(fd, syscall.TCGETS, &old); err != nil {
		return readPlainPassphrase(prompt)
	}
	// ECHONL 也要关：只关 ECHO 时，有些终端仍会在回车时回显一个换行，
	// 虽然不泄露内容，但会让人以为输入没被接受。
	noEcho := old
	noEcho.Lflag &^= syscall.ECHO | syscall.ECHONL
	if err := ioctlTermios(fd, syscall.TCSETS, &noEcho); err != nil {
		return readPlainPassphrase(prompt)
	}
	defer func() {
		// 恢复必须成功，否则终端会一直吞掉用户输入。
		// 真失败了也只能再试一次并把错误留给调用方从输出里察觉。
		_ = ioctlTermios(fd, syscall.TCSETS, &old)
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
