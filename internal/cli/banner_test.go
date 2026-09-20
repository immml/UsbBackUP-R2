package cli

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

// TestReorderArgs 覆盖"flag 写在位置参数之后"这一自然写法。
// 回归背景：Go 的 flag 包遇到第一个非 flag 参数就停止解析，
// 导致 `usbkeygen-r2 use <路径> --config x.json` 里的 --config 被当成位置参数。
func TestReorderArgs(t *testing.T) {
	build := func() *flag.FlagSet {
		fs := flag.NewFlagSet("probe", flag.ContinueOnError)
		fs.SetOutput(&bytes.Buffer{})
		fs.String("config", "", "")
		fs.String("out", "", "")
		fs.Int("bits", 4096, "")
		fs.Bool("force", false, "")
		fs.Bool("yes", false, "")
		return fs
	}

	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "flag 在前（原样）",
			in:   []string{"--config", "a.json", "pub.pem"},
			want: []string{"--config", "a.json", "pub.pem"},
		},
		{
			name: "flag 在后",
			in:   []string{"pub.pem", "--config", "a.json"},
			want: []string{"--config", "a.json", "pub.pem"},
		},
		{
			name: "多个 flag 混排",
			in:   []string{"dir", "--out", "x.usbk", "--force"},
			want: []string{"--out", "x.usbk", "--force", "dir"},
		},
		{
			name: "等号写法自带取值",
			in:   []string{"dir", "--out=x.usbk", "--bits=2048"},
			want: []string{"--out=x.usbk", "--bits=2048", "dir"},
		},
		{
			name: "布尔 flag 不吞下一个参数",
			in:   []string{"file", "--force", "another"},
			want: []string{"--force", "file", "another"},
		},
		{
			name: "双横线分隔符之后全部视为位置参数",
			in:   []string{"--force", "--", "--config", "x"},
			want: []string{"--force", "--", "--config", "x"},
		},
		{
			name: "分隔符后的位置参数不会被当成 flag",
			in:   []string{"file.txt", "--", "--out"},
			want: []string{"--", "file.txt", "--out"},
		},
		{
			name: "单独一个减号视为位置参数",
			in:   []string{"-", "--force"},
			want: []string{"--force", "-"},
		},
		{
			name: "纯位置参数",
			in:   []string{"a", "b"},
			want: []string{"a", "b"},
		},
		{
			name: "空输入",
			in:   nil,
			want: []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ReorderArgs(build(), tc.in)
			if strings.Join(got, "\x00") != strings.Join(tc.want, "\x00") {
				t.Fatalf("ReorderArgs(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestReorderArgsMakesPositionalAfterFlagWork 验证端到端效果：重排后 flag 真正生效。
func TestReorderArgsMakesPositionalAfterFlagWork(t *testing.T) {
	fs := flag.NewFlagSet("use", flag.ContinueOnError)
	fs.SetOutput(&bytes.Buffer{})
	cfg := fs.String("config", "", "")
	force := fs.Bool("force", false, "")

	args := []string{`C:\keys\usbbackup-r2.pub.pem`, "--config", `D:\cfg.json`, "--force"}
	if err := fs.Parse(ReorderArgs(fs, args)); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if *cfg != `D:\cfg.json` {
		t.Fatalf("--config 未生效，实际 %q", *cfg)
	}
	if !*force {
		t.Fatal("--force 未生效")
	}
	if fs.NArg() != 1 || fs.Arg(0) != `C:\keys\usbbackup-r2.pub.pem` {
		t.Fatalf("位置参数不正确: narg=%d arg0=%q", fs.NArg(), fs.Arg(0))
	}
}

func TestConfirmAgreement(t *testing.T) {
	cases := []struct {
		in     string
		wantOK bool
	}{
		{"I AGREE\n", true},
		{"i agree\n", true},
		{"I  AGREE\n", true},
		{"  I agree  \n", true},
		{"agree\n", false},
		{"I AGREED\n", false},
		{"no\n", false},
		{"", false},
	}
	for _, tc := range cases {
		var out bytes.Buffer
		err := ConfirmAgreement(strings.NewReader(tc.in), &out)
		if tc.wantOK && err != nil {
			t.Errorf("输入 %q 应通过，实际 %v", tc.in, err)
		}
		if !tc.wantOK && err == nil {
			t.Errorf("输入 %q 不应通过", tc.in)
		}
	}
}

// TestConfirmAgreementDoesNotEchoInput 锁住「拒绝时不回显输入内容」。
//
// 同意提示就紧挨着光标，用户很容易把本该填进后续提问的 Secret / 口令粘到这里。
// 原样回显等于把凭据写进屏幕和日志——2026-09-20 部署实测中真实发生过一次，
// 所以这里连「输入片段」也一并禁止。
func TestConfirmAgreementDoesNotEchoInput(t *testing.T) {
	const secret = "13f1a8de1a1b366a186337dcf27ed6880f89cfa6209fc9ea23c01791567f0e91"

	var out bytes.Buffer
	if err := ConfirmAgreement(strings.NewReader(secret+"\n"), &out); err == nil {
		t.Fatal("非 I AGREE 输入不应通过")
	}
	got := out.String()
	if strings.Contains(got, secret) {
		t.Errorf("拒绝提示回显了完整输入：\n%s", got)
	}
	for i := 0; i+8 <= len(secret); i++ {
		if strings.Contains(got, secret[i:i+8]) {
			t.Fatalf("拒绝提示泄露了输入片段 %q：\n%s", secret[i:i+8], got)
		}
	}
	// 但要报出字符数：让粘错的人能察觉「我粘了一大坨东西进来」。
	if !strings.Contains(got, "64 个字符") {
		t.Errorf("应报出输入字符数以便察觉粘错，实际：\n%s", got)
	}
}

func TestRenderBannerContainsRequiredNotices(t *testing.T) {
	var buf bytes.Buffer
	RenderBanner(&buf, "usbkeygen-r2")
	// 横幅为了视觉强调在标题字之间插了空格，比较前先去掉所有空白。
	flat := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, buf.String())

	// F-901 要求包含的关键声明。
	// 注意 "R2端点" / "采集策略" / "没有入站监听" 三项对应 G-06′ 与 G-12：
	// 本项目起客户端具备一项受限出站，横幅必须如实披露，否则构成虚假陈述。
	for _, must := range []string{
		"安全警告", "免责声明", "CCBY-NC-SA", "私钥", "不删除",
		"R2端点", "R2桶", "采集策略", "没有入站监听",
	} {
		if !strings.Contains(flat, must) {
			t.Errorf("横幅缺少必要内容 %q", must)
		}
	}

	// 反向守卫：横幅不得再出现"不做任何网络通信"这类 v2.0 的旧表述。
	// 加出站能力后这句话不再成立，留着就是虚假陈述。
	for _, banned := range []string{"不进行任何网络", "零网络", "无网络通信"} {
		if strings.Contains(flat, banned) {
			t.Errorf("横幅仍含过期的「无网络」表述 %q，与 G-06′ 不符", banned)
		}
	}
	if !strings.Contains(buf.String(), "usbkeygen-r2") {
		t.Error("横幅应包含程序名")
	}
}

// 反向守卫（第二组）：横幅不得再描述**已被移除**的能力。
//
// 这条测试针对的是一类很特别的缺陷：功能删了、文案没删。用户读完
// 警告后会以为"检测到私钥就会回写"，进而按错误的心智模型去用工具——
// 而声明本身已经构成不实陈述。文案与能力必须同步，所以要有测试锁住。
func TestBannerDoesNotClaimRemovedFeatures(t *testing.T) {
	flat := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' {
			return -1
		}
		return r
	}, WarningBanner)
	flatShort := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' {
			return -1
		}
		return r
	}, NoticeShort)

	// 注意："回写"本身不列为禁用词——文案里有一句"本工具不包含把本机数据
	// 回写进介质的功能"，那是一句**否定式澄清**，比不提更好。要禁的是断言
	// 旧行为存在的那种表述，因此这里禁的是"回写分支"而不是"回写"。
	for _, banned := range []string{
		"私钥检测",     // keyfile 包已删除
		"已授权分支",    // copier 包已删除
		"未授权分支",    // 单分支了，没有"未授权"这个说法
		"回写分支",     // 不存在任何"把本机数据写进介质"的路径
		`\backup\`, // 那是回写目标目录，已不存在
		"自动备份文件夹",  // 同上
		"桶锁",       // 2026-09-20 用户决定不启用桶锁，横幅不该再要求用户去配
	} {
		if strings.Contains(flat, banned) {
			t.Errorf("横幅仍描述已移除的能力：%q", banned)
		}
		if strings.Contains(flatShort, banned) {
			t.Errorf("简短提示仍描述已移除的能力：%q", banned)
		}
	}

	// 正向：当前准入语义必须如实写出来——豁免标记与三档策略。
	// 另需锁住"R2 没有对象版本控制"这个事实：别再退回"去开版本控制"的旧说法。
	for _, must := range []string{".usbbackup-allow", "豁免", "marker_only", "off", "对象版本控制"} {
		if !strings.Contains(flat, must) {
			t.Errorf("横幅未披露当前准入语义的关键项 %q", must)
		}
	}
}

func TestRenderNoticeIsShort(t *testing.T) {
	var buf bytes.Buffer
	RenderNotice(&buf, "usbbackup-r2")
	out := buf.String()
	if !strings.Contains(out, "DISCLAIMER.md") {
		t.Error("简短提示应指向完整免责声明文件")
	}
	if len(out) > 1200 {
		t.Errorf("简短提示过长（%d 字节），失去了自动化场景的意义", len(out))
	}
	if strings.Contains(out, "安  全  警  告") {
		t.Error("--yes 模式不应再打印整屏警告")
	}
}
