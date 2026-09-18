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
// # 两个标记，语义相反，都要有
//
//	授权标记 .usbbackup-allow   "这块盘是我自己的，别动它" → **豁免**，绝不采集
//	采集标记 .usbbackup-collect "这块盘的内容可以打包上传" → 仅供 marker_only 档位使用
//
// 授权标记的判定**不受策略档位影响**，任何档位下都先做这一步。原因很实际：
// 工具盘上放着私钥（或带口令的私钥文件），一旦被采集打包上传到对象存储，
// 等于把私钥发布到了网上——这是本项目最不能出的事故，
// 因此不允许"因为策略是 all 所以跳过豁免检查"这种组合出现。
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

// DefaultExemptMarkerFile 是**授权标记**的默认文件名。
//
// 这个名字与不含出站能力的版本（项目 A）**完全一致**，两边的盘可以互相认：
// 项目 A 的工具盘根上就有这个文件，本项目读到它就知道"这是自己人的盘，
// 里面还有私钥，绝不能打包上传"。
const DefaultExemptMarkerFile = ".usbbackup-allow"

// 跳过原因（写入审计，便于事后复盘）。
const (
	// ReasonDisabled 表示策略为 off。
	ReasonDisabled = "collect-disabled"
	// ReasonMarkerAbsent 表示 marker_only 档位下未找到采集标记。
	ReasonMarkerAbsent = "collect-marker-absent"
	// ReasonExempt 表示盘根存在授权标记，本次直接豁免。
	ReasonExempt = "exempt-marker-present"
)

// Options 是一次判定的输入。
type Options struct {
	// Policy 是策略档位；空串按 all 处理。
	Policy Policy
	// Marker 是采集标记文件名；空则用 DefaultMarkerFile。
	Marker string
	// ExemptMarker 是授权标记文件名；空则用 DefaultExemptMarkerFile。
	ExemptMarker string
}

// Decision 是一次判定结论。
type Decision struct {
	// Collect 为 true 表示允许进入采集分支。
	Collect bool
	// Reason 在拒绝时有值，描述拒绝原因（可直接写入审计）。
	Reason string
	// ExemptMarkerChecked / ExemptMarkerFound 描述授权标记的检查情况。
	ExemptMarkerChecked bool
	ExemptMarkerFound   bool
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
//  1. 授权标记豁免（**与策略无关**，任何档位都先做）；
//  2. 策略档位（off 关闭 / all 放行 / marker_only 看采集标记）。
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
