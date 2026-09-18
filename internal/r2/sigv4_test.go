package r2

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// AWS 官方 SigV4 测试向量的密钥与日期（sigv4 测试套件公开样本）。
const (
	vectorAccessKey = "AKIDEXAMPLE"
	vectorSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	vectorAmzDate   = "20150830T123600Z"
	vectorDateStamp = "20150830"
	vectorRegion    = "us-east-1"
	// 官方向量的作用域里服务名就是字面量 "service"。
	vectorService = "service"
)

// TestSigV4KnownAnswer 用 AWS 官方发布的测试向量做已知答案校验。
//
// 这是本包最重要的一条测试：SigV4 写错了，代码能编译、能跑、能连上，
// 但每次请求都会被服务端拒签——而拒签的表现（403 SignatureDoesNotMatch）
// 与"权限不足"一模一样，现场极难区分。所以签名必须在这里被钉死。
//
// 期望值同时也是用 Python（hmac + hashlib）按规范独立复算过的，
// 两条独立路径一致才写进这里。
func TestSigV4KnownAnswer(t *testing.T) {
	cases := []struct {
		name string
		cr   string
		want string
	}{
		{
			name: "get-vanilla",
			cr: canonicalRequest(
				"GET", "/", "",
				"host:example.amazonaws.com\nx-amz-date:20150830T123600Z\n",
				"host;x-amz-date",
				emptyPayloadSHA256,
			),
			want: "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
		},
		{
			name: "get-vanilla-query-order-key-case",
			cr: canonicalRequest(
				"GET", "/", "Param1=value1&Param2=value2",
				"host:example.amazonaws.com\nx-amz-date:20150830T123600Z\n",
				"host;x-amz-date",
				emptyPayloadSHA256,
			),
			want: "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			scope := credentialScope(vectorDateStamp, vectorRegion, vectorService)
			got := computeSignature(vectorSecretKey, scope, vectorAmzDate, c.cr)
			if got != c.want {
				t.Errorf("签名不匹配\n  得到 : %s\n  期望 : %s", got, c.want)
			}
		})
	}
}

// TestCanonicalQueryOrdering 验证查询串按**键名**排序（不按值）。
func TestCanonicalQueryOrdering(t *testing.T) {
	u, err := url.Parse("https://example.amazonaws.com/?Param2=value2&Param1=value1")
	if err != nil {
		t.Fatal(err)
	}
	if got := canonicalQuery(u); got != "Param1=value1&Param2=value2" {
		t.Errorf("canonicalQuery = %q，期望按键名升序", got)
	}
	if got := canonicalQuery(&url.URL{}); got != "" {
		t.Errorf("无查询串时应返回空串，得到 %q", got)
	}
	// 同名多值按值排序。
	u2, _ := url.Parse("https://h/?a=z&a=a&b=1")
	if got := canonicalQuery(u2); got != "a=a&a=z&b=1" {
		t.Errorf("同名多值排序错误：%q", got)
	}
}

// TestURIEncodeMatchesAWSRules 钉住转义规则。
//
// 与 Go 自带转义的差别就在这里：`+` `:` `=` `@` `&` `$` `,` 在 Go 的路径转义里
// 会原样保留，而 SigV4 要求全部百分号转义。差一个字节就是拒签。
func TestURIEncodeMatchesAWSRules(t *testing.T) {
	cases := []struct {
		in          string
		encodeSlash bool
		want        string
	}{
		{"usb/UDISK", false, "usb/UDISK"},
		{"usb/UDISK", true, "usb%2FUDISK"},
		{"a b", false, "a%20b"},           // 必须是 %20，不能是 +
		{"a+b", false, "a%2Bb"},           // + 必须转义
		{"a:b", false, "a%3Ab"},           // : 必须转义
		{"a=b", false, "a%3Db"},           //
		{"a@b", false, "a%40b"},           //
		{"a&b", false, "a%26b"},           //
		{"a~b-c_d.e", false, "a~b-c_d.e"}, // 未保留字符集必须原样
		{"中文盘", false, "%E4%B8%AD%E6%96%87%E7%9B%98"},
		{"100%", false, "100%25"},
	}
	for _, c := range cases {
		if got := uriEncode(c.in, c.encodeSlash); got != c.want {
			t.Errorf("uriEncode(%q, %v) = %q，期望 %q", c.in, c.encodeSlash, got, c.want)
		}
	}
}

func TestObjectURLEncodingIsSignedConsistently(t *testing.T) {
	c, err := New(Options{
		Endpoint:        "https://acct.r2.cloudflarestorage.com",
		Bucket:          "my-bucket",
		AccessKeyID:     "ak",
		SecretAccessKey: "sk",
	})
	if err != nil {
		t.Fatal(err)
	}
	// 含空格与 + 的对象键：发出去的路径与参与签名的路径必须一致。
	u := c.objectURL("usb/a b+c.zip.usbk", nil)
	if !strings.Contains(u.String(), "a%20b%2Bc") {
		t.Errorf("对象 URL 未按 AWS 规则转义：%s", u.String())
	}
	if got := canonicalURI(u); got != "/my-bucket/usb/a%20b%2Bc.zip.usbk" {
		t.Errorf("canonicalURI = %q", got)
	}
	// 编码后的路径必须能被 Go 原样发出（RawPath 合法）。
	if u.EscapedPath() != canonicalURI(u) {
		t.Errorf("实际发出的路径 %q 与参与签名的路径 %q 不一致",
			u.EscapedPath(), canonicalURI(u))
	}
}

func TestSignProducesSignedHeadersCoveringAmzHeaders(t *testing.T) {
	c, err := New(Options{
		Endpoint:        "https://acct.r2.cloudflarestorage.com",
		Bucket:          "b",
		AccessKeyID:     "ak",
		SecretAccessKey: "sk",
		SessionToken:    "tok",
		Now:             func() time.Time { return time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, c.objectURL("k", nil).String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.signer.sign(req, emptyPayloadSHA256, c.now()); err != nil {
		t.Fatal(err)
	}
	auth := req.Header.Get("Authorization")
	for _, must := range []string{
		"Credential=ak/20260918/auto/s3/aws4_request",
		// 所有 x-amz-* 头都必须参与签名：没被签的头等于可被中间人改写。
		"SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token",
	} {
		if !strings.Contains(auth, must) {
			t.Errorf("Authorization 缺少 %q\n实际：%s", must, auth)
		}
	}
	if got := req.Header.Get("x-amz-date"); got != "20260918T120000Z" {
		t.Errorf("x-amz-date = %q", got)
	}
	if got := req.Header.Get("x-amz-content-sha256"); got != emptyPayloadSHA256 {
		t.Errorf("x-amz-content-sha256 = %q", got)
	}
	if req.Header.Get("x-amz-security-token") != "tok" {
		t.Error("临时凭据令牌未随请求发出")
	}
}

func TestNormalizeHeaderValue(t *testing.T) {
	cases := map[string]string{
		"  a  b  ": "a b",
		"a\tb":     "a b",
		"plain":    "plain",
		"":         "",
	}
	for in, want := range cases {
		if got := normalizeHeaderValue(in); got != want {
			t.Errorf("normalizeHeaderValue(%q) = %q，期望 %q", in, got, want)
		}
	}
}
