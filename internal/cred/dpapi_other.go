//go:build !windows

package cred

// 非 Windows 平台没有 DPAPI，因此凭据必须由调用方提供口令保护
// （见 secretbox.go 的 ProtectionPassphrase），或显式选择明文文件降级。
//
// 这里刻意**不**提供"悄悄用明文"的兜底：换了操作系统就让保护级别下降，
// 是最不该发生的一类静默行为。

// nativeProtection 返回本平台的原生保护方式；空串表示没有。
func nativeProtection() string { return "" }

// nativeProtect 在非 Windows 平台不可用。
func nativeProtect(plain []byte) ([]byte, error) {
	return nil, ErrUnsupportedPlatform
}

// nativeUnprotect 在非 Windows 平台不可用。
func nativeUnprotect(blob []byte) ([]byte, error) {
	return nil, ErrUnsupportedPlatform
}

// enforceFilePerm 在类 Unix 上为真：明文凭据文件必须是 0600。
//
// Windows 的权限模型不同，os.FileMode 的权限位没有意义，那里返回 false。
func enforceFilePerm() bool { return true }
