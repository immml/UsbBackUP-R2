// Package collectpolicy 决定「一块介质要不要进采集分支」。
//
// # 为什么单独一个包
//
// 这个判断只有三档取值，本来塞进 backup 里也就十几行。把它抽出来是因为
// 它承载的是一条**安全语义**：什么情况下允许把一块盘的内容打包上传。
// 这条语义此前换过一次方案（卷序列号白名单 → 显式策略），将来还可能再调，
// 独立成包并配齐测试，是为了让它只在一个地方被定义、被验证、被引用。
//
// # 为什么废弃了卷序列号白名单（决策 D-20）
//
// 原方案是"只采集卷序列号在白名单内的介质"。它不成立：
//
//   - `GetVolumeInformationW` 的序列号是**格式化时生成**的。重新格式化即改变，
//     于是自己合法的盘会被拒（可用性失效）；
//   - 廉价 U 盘主控常上报空白序列号，或量产时写死的重复号，陌生盘反而可能被放行
//     （安全性失效）；
//   - 改用 USB 硬件序列号要走 SetupAPI 打开物理设备，成本高，且廉价盘同样可能重复。
//
// 结论：**没有任何硬件身份可以拿来当准入依据**。与其留一个两头都保不住的机制，
// 不如把它换成使用者可以明确理解与选择的策略，并把权属判断的责任显式写进使用前提。
//
// 卷序列号降级为**审计字段**：它擅长的是事后对账（"那次上传是哪块盘"），
// 不擅长事前唯一识别。
//
// # 三个标记文件
//
//	授权标记·卷级   .usbbackup-allow       "这个卷是我自己的，别动它"   → 豁免该卷
//	授权标记·磁盘级 .usbbackup-allow-disk  "这支盘是我自己的，别动它"   → 同物理磁盘所有卷一起豁免
//	采集标记        .usbbackup-collect     "这个卷的内容可以打包上传"   → 仅供 marker_only 档位使用
//
// 为什么授权标记要分两级：**卷**与**盘**在多分区介质上不是一回事。
// 卷级判定读的是 `<卷根>\.usbbackup-allow`，而使用者的心智模型是"这支 U 盘"。
// 一支 Ventoy 盘至少两个分区（数据区 + VTOYEFI），标记只落在数据区，
// 客户端扫到 VTOYEFI 分区时认定"没标记"→ 照常打包上传，
// 于是出现"我明明标记过它"却被部分采集的情形（2026-09-20 部署实测踩到）。
//
// 判定顺序固定：**卷级 → 磁盘级 → 策略档位**，前两级都不受档位影响。
// 授权标记的判定之所以必须无条件先做，理由很实际：工具盘上放着私钥
// （或带口令的私钥文件），一旦被采集打包上传到对象存储，等于把私钥发布到了网上
// ——这是本项目最不能出的事故，因此不允许"因为策略是 all 所以跳过豁免检查"这种组合出现。
//
// # 三档策略
//
//	all         默认。凡未命中授权标记的介质一律进采集分支（仍受容量门控约束）
//	marker_only 仅采集盘根带**采集标记**的介质；未命中则零读取
//	off         采集分支整体关闭（只剩手工 `upload <文件.usbk>` 一条路）
package collectpolicy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/immml/UsbBackUP-R2/internal/fsutil"
)

// Policy 是采集策略档位。
type Policy string

// 策略档位常量。
const (
	// PolicyAll 表示不区分介质，未授权介质一律进采集分支。
	PolicyAll Policy = "all"
	// PolicyMarkerOnly 表示仅采集盘根带采集标记的介质。
	PolicyMarkerOnly Policy = "marker_only"
	// PolicyOff 表示关闭采集分支。
	PolicyOff Policy = "off"
)

// DefaultMarkerFile 是**采集标记**的默认文件名。
//
// 刻意与**授权标记**（`.usbbackup-allow`）区分开：
//
//	授权标记 = "这块盘是我自己的，请不要采集它"
//	采集标记 = "这块盘的内容可以打包上传"
//
// 两者语义相反，用同一个文件名会让"我的工具盘自动变成采集目标"，
// 那正好是使用者最不想要的组合。
const DefaultMarkerFile = ".usbbackup-collect"

// DefaultExemptMarkerFile 是**授权标记（卷级）**的默认文件名。
//
// 这个名字与不含出站能力的版本（项目 A）**完全一致**，两边的盘可以互相认：
// 项目 A 的工具盘根上就有这个文件，本项目读到它就知道"这是自己人的盘，
// 里面还有私钥，绝不能打包上传"。
//
// 语义始终是**卷级**的（只豁免写了它的那个卷根）——项目 A 也按这个语义判定，
// 改它等于让两边的判定悄悄分叉。要表达"整支盘"请用磁盘级标记。
const DefaultExemptMarkerFile = ".usbbackup-allow"

// DefaultExemptDiskMarkerFile 是**授权标记（磁盘级）**的默认文件名。
//
// 作用域跨卷：**只要同一物理磁盘上的任意一个卷根带着它，该磁盘上所有卷一起豁免**。
//
// 新增一个文件名而不是把 `.usbbackup-allow` 升级成磁盘级语义，是为了让
// "我想豁免哪一个层级"这件事在介质上**显式可见**：
//
//	只放 .usbbackup-allow        → 豁免这个卷
//	再放一个 .usbbackup-allow-disk → 豁免整支盘（含盘上其它分区）
//
// 代价是多一个文件；收益是使用者不必理解"物理磁盘号"这种东西，
// 也不会因为两个项目的同名文件被赋予不同语义而互相踩到。
const DefaultExemptDiskMarkerFile = ".usbbackup-allow-disk"

// 跳过原因（写入审计，便于事后复盘）。
const (
	// ReasonDisabled 表示策略为 off。
	ReasonDisabled = "collect-disabled"
	// ReasonMarkerAbsent 表示 marker_only 档位下未找到采集标记。
	ReasonMarkerAbsent = "collect-marker-absent"
	// ReasonExempt 表示卷根存在卷级授权标记，本次直接豁免。
	ReasonExempt = "exempt-marker-present"
	// ReasonExemptDisk 表示同物理磁盘上的某个卷根存在磁盘级授权标记，整盘豁免。
	ReasonExemptDisk = "exempt-disk-marker-present"
)

// Options 是一次判定的输入。
type Options struct {
	// Policy 是策略档位；空串按 all 处理。
	Policy Policy
	// Marker 是采集标记文件名；空则用 DefaultMarkerFile。
	Marker string
	// ExemptMarker 是卷级授权标记文件名；空则用 DefaultExemptMarkerFile。
	ExemptMarker string
	// ExemptDiskMarker 是磁盘级授权标记文件名；空则用 DefaultExemptDiskMarkerFile。
	//
	// 仅在 SameDiskRoots 非 nil 时参与判定。
	ExemptDiskMarker string
	// SameDiskRoots 返回与给定卷根同属一块物理磁盘的所有卷根（**含自身**）。
	//
	// 由调用方注入（Windows 上即 winvol.SameDiskRoots）。这样做是为了让本包
	// 保持纯文件系统层面、可用假函数测全部分支；而"查磁盘号需要管理员权限"
	// 这类平台差异留在 winvol 里。置 nil 表示本平台不做磁盘级判定。
	SameDiskRoots func(root string) ([]string, error)
}

// Decision 是一次判定结论。
type Decision struct {
	// Collect 为 true 表示允许进入采集分支。
	Collect bool
	// Reason 在拒绝时有值，描述拒绝原因（可直接写入审计）。
	Reason string
	// ExemptMarkerChecked / ExemptMarkerFound 描述卷级授权标记的检查情况。
	ExemptMarkerChecked bool
	ExemptMarkerFound   bool
	// ExemptDiskMarkerChecked / ExemptDiskMarkerFound 描述磁盘级授权标记的检查情况。
	ExemptDiskMarkerChecked bool
	ExemptDiskMarkerFound   bool
	// ExemptDiskMarkerRoot 记录是在哪个卷根上发现磁盘级标记的（空表示未命中）。
	// 带上它是为了审计时能回答"凭什么说这块盘是自家人"。
	ExemptDiskMarkerRoot string
	// ExemptDiskCheckErr 非空表示**磁盘级检查没做完**（例如缺少卷句柄权限）。
	//
	// 这不是判定失败，不影响 Collect；但调用方必须把它当告警看待：
	// 此刻只剩卷级判定在起作用，多分区介质仍可能出现"标记过却被部分采集"。
	ExemptDiskCheckErr string
	// MarkerChecked 表示本次是否真的去看过采集标记文件。
	MarkerChecked bool
	// MarkerFound 表示采集标记是否存在。
	MarkerFound bool
}

// Normalize 把配置里的字符串归一化成合法档位。
// 空值取默认（all），非法值返回错误而不是静默取默认——
// 策略配置写错却继续按默认全量采集，是这里最不能接受的失败方式。
func Normalize(s string) (Policy, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	switch v {
	case "":
		return PolicyAll, nil
	case string(PolicyAll):
		return PolicyAll, nil
	case string(PolicyMarkerOnly):
		return PolicyMarkerOnly, nil
	case string(PolicyOff):
		return PolicyOff, nil
	default:
		return "", fmt.Errorf("采集策略取值非法 %q（可用 all / marker_only / off）", s)
	}
}

// ValidMarkerName 校验一个标记文件名是否合法：必须是盘根下的单层文件名。
//
// 不接受任何路径分隔符——标记文件的作用域是"卷根那一个文件"，
// 一旦允许子路径，判定的代价与语义都会变（不再是 O(1) 的 Stat）。
func ValidMarkerName(name string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("标记文件名不能为空")
	}
	if strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("标记文件名 %q 非法：必须是盘根下的单层文件名", name)
	}
	return nil
}

// Decide 依据策略与介质实际情况给出结论。
//
// 判定顺序是固定的，不能交换：
//
//  1. 卷级授权标记豁免（**与策略无关**，任何档位都先做）；
//  2. 磁盘级授权标记豁免（同上，仅当调用方提供了 SameDiskRoots）；
//  3. 策略档位（off 关闭 / all 放行 / marker_only 看采集标记）。
//
// 只读操作：除各 `Stat` 一次标记文件外，不打开任何文件。
func Decide(root string, opt Options) (Decision, error) {
	p := opt.Policy
	if p == "" {
		p = PolicyAll
	}

	exempt, err := markerPresent(root, opt.ExemptMarker, DefaultExemptMarkerFile)
	if err != nil {
		return Decision{}, err
	}
	d := Decision{ExemptMarkerChecked: true, ExemptMarkerFound: exempt}
	if exempt {
		d.Reason = ReasonExempt
		return d, nil
	}

	// 磁盘级豁免：这块物理磁盘上**任意一个**卷根带着磁盘级标记，整盘放过。
	if opt.SameDiskRoots != nil {
		found, where, derr := diskMarkerPresent(root, opt.ExemptDiskMarker, DefaultExemptDiskMarkerFile, opt.SameDiskRoots)
		d.ExemptDiskMarkerChecked = true
		switch {
		case derr != nil:
			// 查不到磁盘归属（通常是权限不足）**不改变采集结论**——磁盘级标记是加固，
			// 不是准入前提，因此不能因此拒绝一块本来该备份的盘。
			// 但要把原因带出去让上层告警：否则使用者会误以为整支盘都豁免了。
			d.ExemptDiskCheckErr = derr.Error()
		case found:
			d.ExemptDiskMarkerFound = true
			d.ExemptDiskMarkerRoot = where
			d.Reason = ReasonExemptDisk
			return d, nil
		}
	}

	switch p {
	case PolicyOff:
		d.Reason = ReasonDisabled
		return d, nil
	case PolicyAll:
		// 不读任何东西：默认档位下连采集标记都不看。
		d.Collect = true
		return d, nil
	case PolicyMarkerOnly:
		found, err := markerPresent(root, opt.Marker, DefaultMarkerFile)
		if err != nil {
			return Decision{}, err
		}
		d.MarkerChecked = true
		d.MarkerFound = found
		d.Collect = found
		if !found {
			d.Reason = ReasonMarkerAbsent
		}
		return d, nil
	default:
		return Decision{}, fmt.Errorf("采集策略取值非法 %q", p)
	}
}

// markerPresent 判断卷根下是否存在名为 name 的标记文件（目录不算）。
//
// 只判存在性，不读内容：存在性就足以表达"这块盘是谁的"，
// 而读内容既不能用来做权限判定（能写标记的人也能伪造内容），
// 又平白多一次文件打开动作。
func markerPresent(root, name, fallback string) (bool, error) {
	n := strings.TrimSpace(name)
	if n == "" {
		n = fallback
	}
	if err := ValidMarkerName(n); err != nil {
		return false, err
	}
	if strings.TrimSpace(root) == "" {
		return false, errors.New("卷根为空")
	}
	st, err := os.Stat(fsutil.LongPath(filepath.Join(root, n)))
	if err != nil {
		// 不存在（或不可访问）一律当作"没有标记"：读不到标记只可能让采集
		// **更保守**（marker_only 下拒绝、all 下照常），不会变成放行他人数据。
		return false, nil
	}
	return !st.IsDir(), nil
}

// diskMarkerPresent 在同物理磁盘的各卷根上查找磁盘级授权标记。
//
// 命中时返回命中的那个卷根（`where`），供审计回答"凭什么说这块盘是自家人"。
// 与卷级判定同理，这里也只 `Stat` 存在性、不读内容。
//
// 注意入参 root 本身也在查询结果里（SameDiskRoots 的约定是含自身），
// 于是"标记就写在当前这个卷上"这种情况天然被覆盖，不需要额外分支。
func diskMarkerPresent(root, name, fallback string,
	sameDiskRoots func(string) ([]string, error)) (bool, string, error) {

	roots, err := sameDiskRoots(root)
	if err != nil {
		return false, "", err
	}
	for _, r := range roots {
		ok, err := markerPresent(r, name, fallback)
		if err != nil {
			return false, "", err
		}
		if ok {
			return true, r, nil
		}
	}
	return false, "", nil
}

// Describe 返回一句人话，用于启动日志与诊断输出。
func (p Policy) Describe() string {
	switch p {
	case PolicyAll:
		return "all —— 未命中授权标记的介质一律进采集分支（受容量门控约束）"
	case PolicyMarkerOnly:
		return "marker_only —— 仅采集盘根带 " + DefaultMarkerFile + " 的介质，未命中则零读取"
	case PolicyOff:
		return "off —— 采集分支整体关闭（仅保留手工 upload）"
	default:
		return string(p)
	}
}

// NeedsMarker 表示该档位下是否会出现"零读取即跳过"的行为。
func (p Policy) NeedsMarker() bool { return p == PolicyMarkerOnly }
