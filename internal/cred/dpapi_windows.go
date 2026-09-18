//go:build windows

package cred

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

// CRYPTPROTECT_LOCAL_MACHINE 让密文与**本机**绑定而非当前用户绑定。
//
// 为什么用机器范围而不是用户范围：
//
//	客户端常常以 Windows 服务身份运行（LocalSystem），而生成凭据文件的操作员
//	是交互登录的管理员账号。用户范围的 DPAPI 两者之间解不开，部署时必然踩坑。
//	机器范围换来的是"同一台机器上任何账户都能解"——这在本项目的威胁模型里
//	可以接受：能在这台机器上以任意账户执行代码的人，本来就能读到内存里的明文。
const cryptProtectLocalMachine = 0x00000004

// CRYPTPROTECT_UI_FORBIDDEN 禁止 DPAPI 弹任何 UI。
// 服务进程没有交互桌面，一旦弹窗就是永久挂起。
const cryptProtectUIForbidden = 0x00000001

// entropy 是附加熵（域分隔）。
//
// 作用：同机上其它程序也能调用 DPAPI。没有熵时，别的程序产生的密文可以原样
// 塞进我们的凭据文件里，我们的程序会老老实实解开并把攻击者的密钥当成合法凭据。
// 加上固定的应用熵之后，只有同样知道这串字节的程序才能生成可被解开的密文。
var entropy = []byte("usbbackup-r2/cred/v1")

// dataBlob 对应 Win32 的 DATA_BLOB。
//
// 布局：DWORD cbData; BYTE *pbData;
// 在 amd64 上 C 侧为 4 字节 + 4 字节对齐填充 + 8 字节指针 = 16 字节，
// Go 结构体经同样的对齐也是 16 字节。这里**不用** unsafe.Sizeof 去填
// 任何 C 侧长度字段（本项目在 DEV_BROADCAST_VOLUME 上踩过这个坑），
// 所有 size 字段都由调用点显式给出。
type dataBlob struct {
	cbData uint32
	pbData *byte
}

var (
	modCrypt32  = syscall.NewLazyDLL("crypt32.dll")
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")

	procCryptProtectData   = modCrypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = modCrypt32.NewProc("CryptUnprotectData")
	procLocalFree          = modKernel32.NewProc("LocalFree")
)

// newBlob 构造一个指向 b 的 DATA_BLOB。b 必须非空且在整个调用期间保持存活。
func newBlob(b []byte) dataBlob {
	return dataBlob{cbData: uint32(len(b)), pbData: &b[0]}
}

// nativeProtection 返回本平台的首选保护方式。
func nativeProtection() string { return ProtectionDPAPIMachine }

// enforceFilePerm 表示是否用文件权限位做校验。
//
// Windows 上 os.FileMode 的权限位没有意义（一律 0666/0444），
// 拿它判断"文件是否过宽"只会得到假阳性，所以跳过。
func enforceFilePerm() bool { return false }

// nativeProtect 用机器范围的 DPAPI 加密明文。
func nativeProtect(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, errors.New("待保护的凭据内容为空")
	}
	in := newBlob(plain)
	ent := newBlob(entropy)
	var out dataBlob

	desc, err := syscall.UTF16PtrFromString("usbbackup-r2 credential")
	if err != nil {
		return nil, fmt.Errorf("构造 DPAPI 描述失败: %w", err)
	}

	ret, _, callErr := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&in)),
		uintptr(unsafe.Pointer(desc)),
		uintptr(unsafe.Pointer(&ent)),
		0, // pvReserved：文档要求为 NULL
		0, // pPromptStruct：不弹 UI
		cryptProtectLocalMachine|cryptProtectUIForbidden,
		uintptr(unsafe.Pointer(&out)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("DPAPI 加密失败: %w", callErr)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))

	res := make([]byte, out.cbData)
	copy(res, unsafe.Slice(out.pbData, int(out.cbData)))
	return res, nil
}

// nativeUnprotect 解开 nativeProtect 产生的密文。
func nativeUnprotect(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, errors.New("待解密的凭据内容为空")
	}
	in := newBlob(blob)
	ent := newBlob(entropy)
	var out dataBlob

	// ppszDataDescr 传 NULL：描述信息只是给人看的，不参与解密。
	ret, _, callErr := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0,
		uintptr(unsafe.Pointer(&ent)),
		0,
		0,
		cryptProtectUIForbidden,
		uintptr(unsafe.Pointer(&out)),
	)
	if ret == 0 {
		return nil, callErr
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))

	res := make([]byte, out.cbData)
	copy(res, unsafe.Slice(out.pbData, int(out.cbData)))
	return res, nil
}
