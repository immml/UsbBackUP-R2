//go:build windows

package winvol

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

// 物理磁盘归属查询——「磁盘级豁免」的支撑原语。
//
// # 为什么需要它
//
// 授权标记的判定天然是**按卷根**做的（`<root>\.usbbackup-allow`），
// 而使用者的心智模型是**「这支 U 盘」**。两者在单分区介质上重合，
// 在多分区介质上必然分叉：一支 Ventoy 盘至少有 `I:`（数据）+ `J:`（VTOYEFI）两个分区，
// 标记只写在 `I:` 根上，客户端扫到 `J:` 时会认定"没标记"→ 照常整盘打包上传。
// 于是"我明明标记过它"却仍被部分采集——备份工具最不该有的失误。
//
// 所以除卷级标记外，再加一个**磁盘级标记**（见 collectpolicy）：
// 某个卷根带着它就代表"整支盘豁免"，**同一物理磁盘上的所有卷**一起放过。
// 本文件只负责那条判定所需的唯一原语：**这个卷属于哪块物理磁盘**。
//
// # 权限
//
// 打开卷句柄（`\\.\X:`）通常需要管理员权限。生产形态是 Windows 服务
// （LocalSystem），权限充足；但手工 `once` 用普通权限跑时会失败。
// 那种情况下**绝不静默按"没有标记"处理**——上层会明确告警
// （`ErrDiskQueryDenied`），否则使用者会误以为整支盘都豁免了。
var (
	procCreateFileW     = kernel32.NewProc("CreateFileW")
	procDeviceIoControl = kernel32.NewProc("DeviceIoControl")
	procCloseHandle     = kernel32.NewProc("CloseHandle")
)

const (
	// ioctlVolumeGetVolumeDiskExtents 为 IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS
	// （winioctl.h）的数值：CTL_CODE(IOCTL_VOLUME_BASE=0x56, 0, METHOD_BUFFERED, FILE_ANY_ACCESS)。
	ioctlVolumeGetVolumeDiskExtents = 0x00560000

	genericRead    = 0x80000000
	fileShareRead  = 0x00000001
	fileShareWrite = 0x00000002
	openExisting   = 3

	// VOLUME_DISK_EXTENTS 的内存布局：
	//
	//	struct { DWORD NumberOfDiskExtents; DISK_EXTENT Extents[]; }
	//	struct DISK_EXTENT { DWORD DiskNumber; LARGE_INTEGER StartingOffset; LARGE_INTEGER ExtentLength; }
	//
	// DISK_EXTENT 含 8 字节对齐的 LARGE_INTEGER，所以尺寸是 4+4(pad)+8+8 = 24；
	// 数组同理从偏移 8 开始（NumberOfDiskExtents 占 4、填充 4）。
	diskExtentSize     = 24
	extentsHeaderSize  = 8
	extentsQueryCount  = 8 // 一次问 8 段足够：分区数远超它的盘不属于本工具的适用面
	invalidHandleValue = ^uintptr(0)
)

// ErrDiskQueryDenied 表示无法打开卷句柄。
//
// 两种成因都可能，而且**从错误码上分不出来**（都是 `ERROR_ACCESS_DENIED`）：
//
//   - 当前会话缺少管理员权限（生产形态是 Windows 服务，天然满足）；
//   - 这个卷根本没有对应的设备对象——`subst` 造出来的虚拟盘就是这样。
//
// 所以文案只描述现象、**不当断言原因**。实测踩到过：在**已经是管理员**的会话里
// 对 subst 盘做查询，报出来的却是"需要管理员权限"，照着提示去提权只会白跑一趟。
//
// 之所以单列一个错误、而不并进 ErrQueryFailed：上层要能据此识别出
// "磁盘级豁免这次没生效"并给出告警，而不是退化成沉默的放行。
var ErrDiskQueryDenied = errors.New("无法打开卷句柄（权限不足，或该卷不是真实设备，例如 subst 虚拟盘）")

// DiskNumber 返回该卷所在物理磁盘的盘号（0 起）。
//
// 只读查询：打开卷句柄后发一次 IOCTL，随即关闭，不写任何东西。
func DiskNumber(root string) (uint32, error) {
	norm, err := NormalizeRoot(root)
	if err != nil {
		return 0, err
	}

	// 卷设备路径写作 `\\.\I:` —— 注意**尾部没有反斜杠**，带斜杠会被 CreateFileW 拒绝。
	dev := `\\.\` + strings.TrimSuffix(norm, `\`)
	p, err := syscall.UTF16PtrFromString(dev)
	if err != nil {
		return 0, fmt.Errorf("%w: 路径编码失败: %v", ErrQueryFailed, err)
	}

	h, _, callErr := procCreateFileW.Call(
		uintptr(unsafe.Pointer(p)),
		genericRead,
		fileShareRead|fileShareWrite,
		0,
		openExisting,
		0,
		0,
	)
	if h == invalidHandleValue || h == 0 {
		return 0, fmt.Errorf("%w: CreateFileW(%s): %v", ErrDiskQueryDenied, dev, callErr)
	}
	defer func() { _, _, _ = procCloseHandle.Call(h) }()

	buf := make([]byte, extentsHeaderSize+diskExtentSize*extentsQueryCount)
	var returned uint32
	r, _, callErr := procDeviceIoControl.Call(
		h,
		ioctlVolumeGetVolumeDiskExtents,
		0,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&returned)),
		0,
	)
	if r == 0 {
		return 0, fmt.Errorf("%w: IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS(%s): %v", ErrQueryFailed, dev, callErr)
	}
	if returned < extentsHeaderSize+diskExtentSize {
		return 0, fmt.Errorf("%w: %s 返回数据长度异常（%d 字节）", ErrQueryFailed, dev, returned)
	}
	if n := *(*uint32)(unsafe.Pointer(&buf[0])); n == 0 {
		return 0, fmt.Errorf("%w: %s 未报告任何磁盘区段", ErrQueryFailed, dev)
	}
	// 取第一段：本工具面对的是一支盘一个区段的情形，多区段（跨区卷）无此使用场景。
	return *(*uint32)(unsafe.Pointer(&buf[extentsHeaderSize])), nil
}

// SameDiskRoots 返回与 root 同属一块物理磁盘的所有卷根（**含 root 自身**，均为 `X:\` 形式）。
//
// 单个盘符打不开（例如空读卡器槽位、无权限的加密卷）只跳过它，不影响其余结果——
// 我们要回答的是"这块盘上还有哪些卷根值得去看一眼标记"，
// 少看一个卷的代价是那一个分区可能不被豁免，而因此报错会让整条链路停摆。
func SameDiskRoots(root string) ([]string, error) {
	norm, err := NormalizeRoot(root)
	if err != nil {
		return nil, err
	}
	want, err := DiskNumber(norm)
	if err != nil {
		return nil, err
	}

	roots, err := Roots()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(roots))
	for _, r := range roots {
		got, err := DiskNumber(r)
		if err != nil {
			continue
		}
		if got == want {
			out = append(out, r)
		}
	}
	return out, nil
}
