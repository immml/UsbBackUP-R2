package collectpolicy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	ok := map[string]Policy{
		"":            PolicyAll,
		"all":         PolicyAll,
		"  ALL  ":     PolicyAll,
		"marker_only": PolicyMarkerOnly,
		"Marker_Only": PolicyMarkerOnly,
		"off":         PolicyOff,
	}
	for in, want := range ok {
		got, err := Normalize(in)
		if err != nil {
			t.Errorf("Normalize(%q) 报错：%v", in, err)
			continue
		}
		if got != want {
			t.Errorf("Normalize(%q) = %q，期望 %q", in, got, want)
		}
	}
	// 非法值必须报错，不能静默退回默认——配置写错却继续按"全量采集"跑，
	// 是这里最不能接受的失败方式。
	for _, bad := range []string{"none", "true", "1", "marker", "ALLOW"} {
		if _, err := Normalize(bad); err == nil {
			t.Errorf("Normalize(%q) 应当报错", bad)
		}
	}
}

// 授权标记名字必须与不含出站能力的版本一致，两边的盘才能互相认。
// 这条是硬约定，被改掉就等于两个项目的工具盘互相不认了。
func TestExemptMarkerNameMatchesSiblingProject(t *testing.T) {
	if DefaultExemptMarkerFile != ".usbbackup-allow" {
		t.Fatalf("授权标记名 = %q，必须保持 .usbbackup-allow", DefaultExemptMarkerFile)
	}
	if DefaultMarkerFile == DefaultExemptMarkerFile {
		t.Fatal("采集标记与授权标记不能同名：语义相反，混用会让工具盘变成采集目标")
	}
}

func TestDecideAllDoesNotInspectCollectMarker(t *testing.T) {
	// all 档位下不应去读采集标记（豁免标记仍会 Stat 一次，那是安全底线）。
	d, err := Decide(filepath.Join(t.TempDir(), "not-mounted"), Options{Policy: PolicyAll})
	if err != nil {
		t.Fatalf("Decide 报错：%v", err)
	}
	if !d.Collect {
		t.Error("all 档位应放行")
	}
	if d.MarkerChecked {
		t.Error("all 档位不该去检查采集标记")
	}
	if d.Reason != "" {
		t.Errorf("放行时不应有拒绝原因，实际 %q", d.Reason)
	}
}

func TestDecideOff(t *testing.T) {
	d, err := Decide(t.TempDir(), Options{Policy: PolicyOff})
	if err != nil {
		t.Fatal(err)
	}
	if d.Collect {
		t.Error("off 档位不应采集")
	}
	if d.Reason != ReasonDisabled {
		t.Errorf("拒绝原因 = %q，期望 %q", d.Reason, ReasonDisabled)
	}
}

func TestDecideMarkerOnly(t *testing.T) {
	dir := t.TempDir()

	d, err := Decide(dir, Options{Policy: PolicyMarkerOnly})
	if err != nil {
		t.Fatal(err)
	}
	if d.Collect || d.Reason != ReasonMarkerAbsent || !d.MarkerChecked {
		t.Errorf("无标记时应拒绝且标记检查过：%+v", d)
	}

	if err := os.WriteFile(filepath.Join(dir, DefaultMarkerFile), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err = Decide(dir, Options{Policy: PolicyMarkerOnly})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Collect || !d.MarkerFound || d.Reason != "" {
		t.Errorf("有标记时应放行：%+v", d)
	}
}

// 授权标记的豁免**不受档位影响**：三档都必须拒绝。
//
// 这是本项目最要紧的一条测试：工具盘上放着私钥，只要它在 all 档位下
// 被放行一次，私钥就会被打包上传到对象存储。
func TestExemptMarkerWinsInEveryPolicy(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, DefaultExemptMarkerFile), []byte("fingerprint=x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 连采集标记也放上，确认豁免优先于采集标记。
	if err := os.WriteFile(filepath.Join(dir, DefaultMarkerFile), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []Policy{PolicyAll, PolicyMarkerOnly, PolicyOff, ""} {
		d, err := Decide(dir, Options{Policy: p})
		if err != nil {
			t.Fatalf("档位 %q：%v", p, err)
		}
		if d.Collect {
			t.Errorf("档位 %q：存在授权标记时必须拒绝采集", p)
		}
		if d.Reason != ReasonExempt {
			t.Errorf("档位 %q：拒绝原因 = %q，期望 %q", p, d.Reason, ReasonExempt)
		}
		if !d.ExemptMarkerChecked || !d.ExemptMarkerFound {
			t.Errorf("档位 %q：豁免标记的检查情况未记录：%+v", p, d)
		}
	}
}

func TestDecideMarkerOnlyRejectsDirectoryNamedLikeMarker(t *testing.T) {
	dir := t.TempDir()
	// 一个同名**目录**不是标记文件。若把它当标记，等于任何人插一块盘
	// 只要建个同名文件夹就能让内容被采集。
	if err := os.Mkdir(filepath.Join(dir, DefaultMarkerFile), 0o755); err != nil {
		t.Fatal(err)
	}
	d, err := Decide(dir, Options{Policy: PolicyMarkerOnly})
	if err != nil {
		t.Fatal(err)
	}
	if d.Collect {
		t.Error("同名目录不应被当作采集标记")
	}
}

// 授权标记是目录时不算命中——否则「拒绝采集」会被一个文件夹轻易绕过，
// 而那正是保护私钥盘的唯一防线。
func TestExemptMarkerRejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, DefaultExemptMarkerFile), 0o755); err != nil {
		t.Fatal(err)
	}
	d, err := Decide(dir, Options{Policy: PolicyAll})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Collect {
		t.Error("同名目录不应触发豁免")
	}
	if d.ExemptMarkerFound {
		t.Error("目录不应被记为豁免标记命中")
	}
}

func TestDecideCustomMarkerName(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "my-collect.flag"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := Decide(dir, Options{Policy: PolicyMarkerOnly, Marker: "my-collect.flag"})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Collect {
		t.Error("自定义标记名未生效")
	}
	// 带路径分隔符的名字会让人以为能指向子目录，实际只是拼路径——
	// 必须明确拒绝，避免"看起来生效了"。
	for _, bad := range []string{"sub/x", `sub\x`, "../x"} {
		if _, err := Decide(dir, Options{Policy: PolicyMarkerOnly, Marker: bad}); err == nil {
			t.Errorf("标记名 %q 应当被拒绝", bad)
		}
	}
}

func TestDecideCustomExemptMarkerName(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".my-allow"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := Decide(dir, Options{Policy: PolicyAll, ExemptMarker: ".my-allow"})
	if err != nil {
		t.Fatal(err)
	}
	if d.Collect || d.Reason != ReasonExempt {
		t.Errorf("自定义授权标记名未生效：%+v", d)
	}
}

func TestDecideRejectsUnknownPolicy(t *testing.T) {
	if _, err := Decide(t.TempDir(), Options{Policy: Policy("collect-everything")}); err == nil {
		t.Error("未知档位应报错")
	}
}

func TestDecideRejectsEmptyRoot(t *testing.T) {
	if _, err := Decide("", Options{Policy: PolicyAll}); err == nil {
		t.Error("空卷根应报错而不是默默放行")
	}
}

func TestDescribeMentionsDefaults(t *testing.T) {
	if !strings.Contains(PolicyMarkerOnly.Describe(), DefaultMarkerFile) {
		t.Error("marker_only 的说明里应写明用的是哪个标记文件")
	}
	if !PolicyMarkerOnly.NeedsMarker() || PolicyAll.NeedsMarker() {
		t.Error("NeedsMarker 判定错误")
	}
}

// ---- 磁盘级授权标记（.usbbackup-allow-disk）----
//
// 这一层存在的理由：卷级判定只认"写了标记的那个卷根"，
// 而一支多分区盘（Ventoy 必然如此）的其余分区会被照常采集。
// 下面用假函数模拟"同盘卷根"，把各分支覆盖全——真机上的磁盘号查询
// 由 winvol 的用例负责，这里只验证判定语义。

// fakeDisk 返回一个"这些卷根同属一块物理磁盘"的查询函数。
func fakeDisk(roots ...string) func(string) ([]string, error) {
	return func(string) ([]string, error) { return roots, nil }
}

func TestExemptDiskMarkerNameIsDistinct(t *testing.T) {
	if DefaultExemptDiskMarkerFile != ".usbbackup-allow-disk" {
		t.Fatalf("磁盘级授权标记名 = %q，期望 .usbbackup-allow-disk", DefaultExemptDiskMarkerFile)
	}
	if DefaultExemptDiskMarkerFile == DefaultExemptMarkerFile ||
		DefaultExemptDiskMarkerFile == DefaultMarkerFile {
		t.Fatal("三个标记文件名必须互不相同，否则语义会互相污染")
	}
	if err := ValidMarkerName(DefaultExemptDiskMarkerFile); err != nil {
		t.Fatalf("磁盘级标记名必须是合法的单层文件名：%v", err)
	}
}

// 核心场景：这是一支 Ventoy 盘——数据区带标记，固件区什么都没有。
// 从固件区看过去，必须因为"同盘的数据区有磁盘级标记"而整盘豁免。
func TestDecideExemptBySiblingDiskMarker(t *testing.T) {
	base := t.TempDir()
	data := filepath.Join(base, "data")
	firm := filepath.Join(base, "firm")
	for _, d := range []string{data, firm} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(data, DefaultExemptDiskMarkerFile), []byte("fp"), 0o644); err != nil {
		t.Fatal(err)
	}

	d, err := Decide(firm, Options{Policy: PolicyAll, SameDiskRoots: fakeDisk(data, firm)})
	if err != nil {
		t.Fatal(err)
	}
	if d.Collect {
		t.Fatal("同盘任一卷根带磁盘级标记时应整盘豁免，实际仍要采集")
	}
	if d.Reason != ReasonExemptDisk {
		t.Errorf("拒绝原因 = %q，期望 %q", d.Reason, ReasonExemptDisk)
	}
	if !d.ExemptDiskMarkerChecked || !d.ExemptDiskMarkerFound {
		t.Errorf("应记录磁盘级标记的检查情况：%+v", d)
	}
	if d.ExemptDiskMarkerRoot != data {
		t.Errorf("命中的卷根 = %q，期望 %q（审计要能说清凭什么豁免）", d.ExemptDiskMarkerRoot, data)
	}
}

// 磁盘级标记与卷级一样，不受策略档位影响——off / marker_only 下都要豁免。
func TestDecideDiskMarkerOverridesPolicy(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, DefaultExemptDiskMarkerFile), []byte("fp"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []Policy{PolicyAll, PolicyMarkerOnly, PolicyOff} {
		d, err := Decide(dir, Options{Policy: p, SameDiskRoots: fakeDisk(dir)})
		if err != nil {
			t.Fatalf("档位 %s：%v", p, err)
		}
		if d.Collect || d.Reason != ReasonExemptDisk {
			t.Errorf("档位 %s 下磁盘级标记应豁免，实际 %+v", p, d)
		}
	}
}

func TestDecideDiskMarkerAbsent(t *testing.T) {
	dir := t.TempDir()
	d, err := Decide(dir, Options{
		Policy:        PolicyAll,
		SameDiskRoots: fakeDisk(dir, filepath.Join(dir, "sibling")),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Collect || d.Reason != "" {
		t.Errorf("没有磁盘级标记时应照常按策略放行：%+v", d)
	}
	if !d.ExemptDiskMarkerChecked || d.ExemptDiskMarkerFound {
		t.Errorf("应记录已查过但未命中的状态：%+v", d)
	}
	if d.ExemptDiskCheckErr != "" {
		t.Errorf("正常查询不应留下错误：%q", d.ExemptDiskCheckErr)
	}
}

// 查不到磁盘归属（最常见的是普通权限下打不开卷句柄）时的行为：
// **不能因此拒绝一块本来该备份的盘**，但必须把原因带出去让上层告警。
func TestDecideDiskQueryFailureIsLoudButNotFatal(t *testing.T) {
	boom := errors.New("缺少管理员权限")
	d, err := Decide(t.TempDir(), Options{
		Policy:        PolicyAll,
		SameDiskRoots: func(string) ([]string, error) { return nil, boom },
	})
	if err != nil {
		t.Fatalf("磁盘查询失败不该让整个判定报错：%v", err)
	}
	if !d.Collect {
		t.Error("磁盘查询失败时仍应按策略放行，不能因此跳过备份")
	}
	if !strings.Contains(d.ExemptDiskCheckErr, "缺少管理员权限") {
		t.Errorf("必须把失败原因带出来供上层告警，实际 %q", d.ExemptDiskCheckErr)
	}
	if d.ExemptDiskMarkerFound {
		t.Error("查询失败时不能声称命中了标记")
	}
}

// 没有注入查询能力（非 Windows，或调用方选择不做这一层）：
// 只做卷级判定，且不能声称"检查过磁盘级标记"。
func TestDecideDiskMarkerSkippedWithoutQuery(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, DefaultExemptDiskMarkerFile), []byte("fp"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := Decide(dir, Options{Policy: PolicyAll})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Collect {
		t.Error("没有磁盘查询能力时只做卷级判定，磁盘级标记不该被识别")
	}
	if d.ExemptDiskMarkerChecked {
		t.Error("没有查询能力就不该声称检查过磁盘级标记")
	}
}

// 同名目录不算标记文件（与卷级标记同一约定）。
func TestDecideDiskMarkerDirectoryDoesNotCount(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, DefaultExemptDiskMarkerFile), 0o755); err != nil {
		t.Fatal(err)
	}
	d, err := Decide(dir, Options{Policy: PolicyAll, SameDiskRoots: fakeDisk(dir)})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Collect {
		t.Error("同名目录不是标记文件，不应触发豁免")
	}
}

// 自定义磁盘级标记名。
func TestDecideCustomDiskMarkerName(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".my-allow-disk"), []byte("fp"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := Decide(dir, Options{
		Policy:           PolicyAll,
		ExemptDiskMarker: ".my-allow-disk",
		SameDiskRoots:    fakeDisk(dir),
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Collect || d.Reason != ReasonExemptDisk {
		t.Errorf("自定义磁盘级标记名未生效：%+v", d)
	}
}
