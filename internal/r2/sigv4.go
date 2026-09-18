// Package r2 实现 Cloudflare R2 的对象读写（S3 兼容 API）。
//
// # 为什么手写 SigV4 而不引入 SDK
//
// 本项目的硬约束是「仅 Go 标准库、零第三方依赖、可离线构建」
// （aws-sdk-go-v2 会带进几十个模块，minio-go 也一样）。
// 而这里需要的只是签名 + 几个对象操作，SigV4 的算法是完全公开且稳定的规范，
// 手写约两百行，比引入一棵依赖树更可控。代价是签名细节必须自己保证正确——
// 因此本包带 AWS 官方测试向量的已知答案测试（见 sigv4_test.go）。
//
// # 安全边界
//
//   - 只允许 https 出站（本机回环地址例外，供自带假服务端联调用）；
//   - 凭据不落日志：出错时把 URL 的查询串剥掉再报，Access Key ID 只露前 4 位；
//   - 上传路径固定为 `PUT/POST/DELETE <bucket>/<key>`，不存在"任意请求"入口。
package r2

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// serviceName 是签名作用域中的服务名。S3 兼容 API 固定为 s3。
const serviceName = "s3"

// algorithm 是签名算法标识。
const algorithm = "AWS4-HMAC-SHA256"

// amzDateFormat / amzDateShortFormat 是 SigV4 要求的两种时间写法。
const (
	amzDateFormat      = "20060102T150405Z"
	amzDateShortFormat = "20060102"
)

// emptyPayloadSHA256 是空载荷的 SHA-256 十六进制值。
const emptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// signer 持有签名所需的密钥材料与作用域。
//
// service 可被替换：正常运行时恒为 "s3"，只有跑 AWS 官方向量测试时
// 需要传 "service"（官方向量的作用域就是字面量 "service"）。
type signer struct {
	accessKey    string
	secretKey    string
	sessionToken string
	region       string
	service      string
}

// sign 给请求补上 SigV4 所需的一切。
//
// payloadHash 是请求体的 SHA-256 十六进制值；调用方必须与实际发送的字节一致，
// 否则服务端会拒签。空体传 emptyPayloadSHA256。
func (s *signer) sign(req *http.Request, payloadHash string, now time.Time) error {
	if payloadHash == "" {
		payloadHash = emptyPayloadSHA256
	}
	now = now.UTC()
	amzDate := now.Format(amzDateFormat)
	dateStamp := now.Format(amzDateShortFormat)

	// host 头在 Go 里不放在 Header 中，需要自己补上参与签名。
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if host == "" {
		return errors.New("r2: 请求缺少主机名")
	}

	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	if s.sessionToken != "" {
		req.Header.Set("x-amz-security-token", s.sessionToken)
	}

	// 参与签名的头：host 必签，其余只签 x-amz-*。
	// content-type 之类不需要签名（签了也必须与发送值逐字一致，徒增出错面）。
	names := []string{"host"}
	for name := range req.Header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-amz-") {
			names = append(names, lower)
		}
	}
	sort.Strings(names)
	names = dedupeSorted(names)

	var canonicalHeaders strings.Builder
	for _, name := range names {
		var v string
		if name == "host" {
			v = host
		} else {
			v = req.Header.Get(name)
		}
		canonicalHeaders.WriteString(name)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(normalizeHeaderValue(v))
		canonicalHeaders.WriteByte('\n')
	}
	signedHeaders := strings.Join(names, ";")

	cr := canonicalRequest(
		req.Method,
		canonicalURI(req.URL),
		canonicalQuery(req.URL),
		canonicalHeaders.String(),
		signedHeaders,
		payloadHash,
	)
	scope := credentialScope(dateStamp, s.region, s.service)
	sig := computeSignature(s.secretKey, scope, amzDate, cr)

	req.Header.Set("Authorization", fmt.Sprintf(
		"%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		algorithm, s.accessKey, scope, signedHeaders, sig))
	return nil
}

// canonicalRequest 按 SigV4 规范拼接规范请求。
//
// 单独抽出来是为了能被测试直接调用：AWS 官方测试向量的期望值是对
// **规范请求**求签名，而 sign() 会给任何请求都补上 x-amz-content-sha256，
// 使得它无法原样复现"只签 host 与 x-amz-date"的向量。
func canonicalRequest(method, uri, query, headers, signedHeaders, payloadHash string) string {
	return strings.Join([]string{method, uri, query, headers, signedHeaders, payloadHash}, "\n")
}

// credentialScope 生成 `日期/区域/服务/aws4_request` 的作用域串。
func credentialScope(dateStamp, region, service string) string {
	return strings.Join([]string{dateStamp, region, service, "aws4_request"}, "/")
}

// computeSignature 由规范请求算出最终签名。
func computeSignature(secret, scope, amzDate, canonicalRequestText string) string {
	parts := strings.Split(scope, "/")
	dateStamp := ""
	if len(parts) > 0 {
		dateStamp = parts[0]
	}
	region, service := "", ""
	if len(parts) == 4 {
		region, service = parts[1], parts[2]
	}
	canonicalSum := sha256.Sum256([]byte(canonicalRequestText))
	stringToSign := strings.Join([]string{
		algorithm,
		amzDate,
		scope,
		hex.EncodeToString(canonicalSum[:]),
	}, "\n")
	return hex.EncodeToString(hmacSHA256(signingKey(secret, dateStamp, region, service), stringToSign))
}

// signingKey 按 SigV4 规定的四层派生得到最终签名密钥。
func signingKey(secret, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	return hmacSHA256(kService, "aws4_request")
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// canonicalURI 生成规范 URI。
//
// 关键点：**不能用 Go 的 URL.EscapedPath()**。Go 的转义规则允许路径中出现
// `:` `@` `&` `=` `+` `$` `,` `;` 等字符原样保留；AWS 的 encodeURIComponent
// 规则要求除 `A-Za-z0-9-_.~` 与路径分隔符 `/` 外全部百分号转义。
// 两者对含这些字符的对象键会给出不同结果，签名随即不匹配。
func canonicalURI(u *url.URL) string {
	p := u.Path
	if p == "" {
		return "/"
	}
	return uriEncode(p, false)
}

// canonicalQuery 生成规范查询串：键值各自转义，按键名、再按值排序。
func canonicalQuery(u *url.URL) string {
	q := u.Query()
	if len(q) == 0 {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		vals := append([]string(nil), q[k]...)
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, uriEncode(k, true)+"="+uriEncode(v, true))
		}
	}
	return strings.Join(parts, "&")
}

// uriEncode 按 AWS 规则做百分号编码。
//
// 不转义：A-Z a-z 0-9 - _ . ~ ，以及（encodeSlash 为 false 时的）/ 。
func uriEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			b.WriteString("%")
			b.WriteString(strings.ToUpper(hex.EncodeToString([]byte{c})))
		}
	}
	return b.String()
}

// normalizeHeaderValue 按规范要求裁剪首尾空白并把连续空白压成一个空格。
func normalizeHeaderValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	// 折叠连续的空格/制表符为单个空格。头部值里的制表符虽少见，
	// 但它是合法的 OWS，不归一化就会与服务端的规范形式不一致。
	var b strings.Builder
	b.Grow(len(v))
	prevSpace := false
	for _, r := range v {
		if r == ' ' || r == '\t' {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		b.WriteRune(r)
		prevSpace = false
	}
	return b.String()
}

func dedupeSorted(sorted []string) []string {
	if len(sorted) < 2 {
		return sorted
	}
	out := sorted[:1]
	for _, s := range sorted[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}
