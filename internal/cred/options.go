package cred

import (
	"fmt"
	"os"
	"strings"
)

// 口令来源的环境变量。
//
// 环境变量方便脚本与 systemd unit 使用，但要知道它的代价：
// `/proc/<pid>/environ` 对同用户与 root 可读，`ps eww` 也可能带出来。
// 单用户机器上可以接受；多用户机器上请改用口令文件（0600）+ `--cred-pass-file`。
const (
	// EnvPassphrase 是直接给出凭据文件口令的环境变量。
	EnvPassphrase = "USBBACKUP_R2_CRED_PASSPHRASE"
	// EnvPassphraseFile 是指向"首行为口令"的文件的环境变量。
	EnvPassphraseFile = "USBBACKUP_R2_CRED_PASSPHRASE_FILE"
)

// options 是 Save / Load 的行为开关。
type options struct {
	passphrase     []byte
	passphraseFile string
	// passphraseSet 区分"显式传了空口令"与"没传"。
	passphraseSet bool

	// allowPlainFile 允许**读取**明文凭据文件。
	allowPlainFile bool
	// forcePlainFile 允许**写出**明文凭据文件。
	forcePlainFile bool
}

// Option 是 Save / Load 的可选参数。
type Option func(*options)

func newOptions(opts []Option) *options {
	o := &options{}
	for _, f := range opts {
		if f != nil {
			f(o)
		}
	}
	return o
}

// WithPassphrase 直接给出凭据文件口令（内存中的字节）。
func WithPassphrase(p []byte) Option {
	return func(o *options) {
		o.passphrase = NormalizePassphrase(p)
		o.passphraseSet = true
	}
}

// WithPassphraseFile 从文件读取口令（首行）。
//
// 用"读文件"而非"传字符串"，是为了让口令不出现在进程命令行里——
// `ps aux`、`/proc/<pid>/cmdline` 对同机用户是可见的。
func WithPassphraseFile(path string) Option {
	return func(o *options) { o.passphraseFile = strings.TrimSpace(path) }
}

// WithAllowPlainFile 允许读取未加密的凭据文件（仅靠 0600 权限保护）。
//
// 必须显式开启：让"文件忘了加密"变成一个当场看得见的错误，
// 而不是一个谁都没注意到的默认行为。
func WithAllowPlainFile() Option {
	return func(o *options) { o.allowPlainFile = true }
}

// WithForcePlainFile 要求以明文写出凭据文件。
//
// 这是给无人值守场景的逃生口（既没有 DPAPI 又无法在启动时提供口令）。
// 它的安全性等于"文件权限"，调用方必须自己承担，并且应当配合
// 受限 token + 桶锁使用（R2 不提供对象版本控制，桶锁才是防删手段）。
func WithForcePlainFile() Option {
	return func(o *options) { o.forcePlainFile = true }
}

// resolvePassphrase 按优先级找出口令，并返回它的来源（用于日志，不含口令本身）。
//
// 顺序：显式参数 > 显式文件 > EnvPassphrase > EnvPassphraseFile。
// 环境变量排在文件之后，是因为显式指定永远该赢过环境。
func (o *options) resolvePassphrase() (pass []byte, source string, err error) {
	if o.passphraseSet {
		return o.passphrase, "命令行/调用方参数", nil
	}
	if o.passphraseFile != "" {
		p, err := readPassphraseFile(o.passphraseFile)
		if err != nil {
			return nil, "", err
		}
		return p, "口令文件 " + o.passphraseFile, nil
	}
	if v, ok := os.LookupEnv(EnvPassphrase); ok && strings.TrimSpace(v) != "" {
		return NormalizePassphrase([]byte(v)), "环境变量 " + EnvPassphrase, nil
	}
	if v, ok := os.LookupEnv(EnvPassphraseFile); ok && strings.TrimSpace(v) != "" {
		p, err := readPassphraseFile(strings.TrimSpace(v))
		if err != nil {
			return nil, "", err
		}
		return p, "环境变量 " + EnvPassphraseFile, nil
	}
	return nil, "", nil
}

// readPassphraseFile 读取口令文件的首行。
func readPassphraseFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取凭据口令文件失败 %s: %w", path, err)
	}
	return NormalizePassphrase(raw), nil
}
