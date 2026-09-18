package collectpolicy

import (
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
