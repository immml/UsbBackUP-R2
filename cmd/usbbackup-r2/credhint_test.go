package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/immml/UsbBackUP-R2/internal/cred"
)

// credErrorHint 的价值全在"对症"二字：告诉用户**下一步做什么**。
//
// 它错一次的代价很具体——缺口令的人被指去"重新生成一份凭据"，
// 于是在目标机器和生成机之间白跑一趟，而真正要做的只是设一个环境变量。
// 所以每个错误分支都钉住：必须出现该分支特有的关键词，
// 且**不得**出现别的分支的关键词（防的是分派写错、落到 default 去）。
func TestCredErrorHintMatchesTheActualCause(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		mustHave []string
		mustNot  []string
	}{
		{
			name:     "缺口令",
			err:      fmt.Errorf("读凭据: %w", cred.ErrPassphraseRequired),
			mustHave: []string{"没拿到口令", "USBBACKUP_R2_CRED_PASSPHRASE_FILE", "LocalSystem"},
			// 这条最要紧：不能把人指向"凭据来自别的机器"。
			mustNot: []string{"换机器", "DPAPI 机器绑定"},
		},
		{
			name:     "口令错",
			err:      cred.ErrPassphraseWrong,
			mustHave: []string{"口令不对", "没有找回途径"},
			mustNot:  []string{"USBBACKUP_R2_CRED_PASSPHRASE_FILE"},
		},
		{
			name:     "明文未放行",
			err:      cred.ErrPlainFileNotAllowed,
			mustHave: []string{"明文", "--allow-plain-cred"},
			mustNot:  []string{"DPAPI"},
		},
		{
			name:     "DPAPI 解不开",
			err:      cred.ErrUnprotectFailed,
			mustHave: []string{"DPAPI", "重新生成"},
			mustNot:  []string{"--allow-plain-cred"},
		},
		{
			name:     "非 Windows 上读 DPAPI",
			err:      cred.ErrUnsupportedPlatform,
			mustHave: []string{"DPAPI"},
			mustNot:  []string{"--cred-pass-file"},
		},
		{
			name:     "未知保护方式",
			err:      cred.ErrBadProtection,
			mustHave: []string{"protection"},
			// 认不出来就别乱猜怎么修。
			mustNot: []string{"setx", "--allow-plain-cred"},
		},
	}

	for _, tc := range cases {
		got := credErrorHint(tc.err)
		for _, want := range tc.mustHave {
			if !strings.Contains(got, want) {
				t.Errorf("%s：提示应包含 %q，实际 %q", tc.name, want, got)
			}
		}
		for _, bad := range tc.mustNot {
			if strings.Contains(got, bad) {
				t.Errorf("%s：提示不该出现 %q，实际 %q", tc.name, bad, got)
			}
		}
	}
}

// 认不出来的错误也要给一句话，不能是空串——
// 空提示比含糊的提示更糟：用户连"有个东西失败了"都读不到。
func TestCredErrorHintNeverEmpty(t *testing.T) {
	if got := credErrorHint(errors.New("完全没见过的错")); strings.TrimSpace(got) == "" {
		t.Error("未知错误也必须给出非空提示")
	}
}
