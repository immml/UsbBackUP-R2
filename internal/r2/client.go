package r2

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// 上传参数默认值与 S3 协议硬限制。
const (
	// DefaultMultipartThresholdBytes 是改用分片上传的文件大小阈值。
	DefaultMultipartThresholdBytes int64 = 64 << 20
	// DefaultPartSizeBytes 是默认分片大小。
	DefaultPartSizeBytes int64 = 64 << 20
	// MinPartSizeBytes 是 S3 对"非末片"分片大小的下限。
	MinPartSizeBytes int64 = 5 << 20
	// MaxPartSizeBytes 是 S3 单分片上限。
	MaxPartSizeBytes int64 = 5 << 30
	// MaxParts 是单次分片上传的分片数上限。
	MaxParts = 10000
	// MaxSinglePutBytes 是单次 PUT 的载荷上限。
	MaxSinglePutBytes int64 = 5 << 30
	// DefaultMaxRetries 是默认可重试次数（不含首次尝试）。
	DefaultMaxRetries = 5
	// defaultRetryBaseDelay 是退避基数。
	defaultRetryBaseDelay = 500 * time.Millisecond
	// maxRetryDelay 是退避上限。
	maxRetryDelay = 30 * time.Second
	// maxErrorBodyBytes 是读取错误响应体的上限。
	maxErrorBodyBytes = 8 << 10
)

// Options 是构造客户端的输入。
type Options struct {
	// Endpoint 形如 https://<account_id>.r2.cloudflarestorage.com。
	Endpoint string
	// Bucket 是目标桶。
	Bucket string
	// Region 是签名区域，R2 用 auto。
	Region string
	// AccessKeyID / SecretAccessKey / SessionToken 是凭据。
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string

	// HTTPClient 为 nil 时使用内置客户端（带连接/响应头超时，无整体超时）。
	HTTPClient *http.Client
	// MaxRetries 为 0 时用 DefaultMaxRetries；负值表示不重试。
	MaxRetries int
	// RetryBaseDelay 为 0 时用 500ms。
	RetryBaseDelay time.Duration
	// MultipartThresholdBytes / PartSizeBytes 为 0 时用默认值。
	MultipartThresholdBytes int64
	PartSizeBytes           int64
	// Now 便于测试注入时间；为 nil 时用 time.Now。
	Now func() time.Time
	// UserAgent 会附加到请求上。
	UserAgent string
}

// Client 是一个 S3 兼容对象存储客户端。
//
// 它只暴露本项目需要的操作：上传、下载、列举、探测、删除。
// 刻意不提供"任意方法 + 任意路径"的通用入口——那等于把签名能力开放出去，
// 一旦上层参数被污染就变成对任意对象的任意操作。
type Client struct {
	base    *url.URL
	bucket  string
	signer  *signer
	http    *http.Client
	opt     Options
	now     func() time.Time
	baseDel time.Duration
}

// ObjectInfo 描述一个远端对象。
type ObjectInfo struct {
	Key          string
	Size         int64
	ETag         string
	LastModified time.Time
}

// ProgressFunc 报告上传进度。done 与 total 单位都是字节。
//
// 实现必须快速返回：它在数据通路上被调用。
type ProgressFunc func(done, total int64)

// New 校验参数并构造客户端。
func New(opt Options) (*Client, error) {
	ep := strings.TrimSpace(opt.Endpoint)
	if ep == "" {
		return nil, errors.New("r2: 缺少 endpoint")
	}
	u, err := url.Parse(ep)
	if err != nil {
		return nil, fmt.Errorf("r2: endpoint 无法解析: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		// 仅允许回环地址走明文，供自带假服务端联调。
		host := u.Hostname()
		if host != "127.0.0.1" && host != "localhost" && host != "::1" {
			return nil, fmt.Errorf("r2: endpoint 只允许 https://（当前 %s）", ep)
		}
	default:
		return nil, fmt.Errorf("r2: endpoint 协议不受支持：%s", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("r2: endpoint 缺少主机名")
	}
	if strings.TrimSpace(opt.Bucket) == "" {
		return nil, errors.New("r2: 缺少 bucket")
	}
	if strings.TrimSpace(opt.AccessKeyID) == "" || strings.TrimSpace(opt.SecretAccessKey) == "" {
		return nil, errors.New("r2: 缺少凭据（access key id / secret access key）")
	}

	region := strings.TrimSpace(opt.Region)
	if region == "" {
		region = "auto"
	}
	if opt.MultipartThresholdBytes <= 0 {
		opt.MultipartThresholdBytes = DefaultMultipartThresholdBytes
	}
	if opt.PartSizeBytes <= 0 {
		opt.PartSizeBytes = DefaultPartSizeBytes
	}
	if opt.PartSizeBytes < MinPartSizeBytes {
		opt.PartSizeBytes = MinPartSizeBytes
	}
	if opt.PartSizeBytes > MaxPartSizeBytes {
		return nil, fmt.Errorf("r2: 分片大小 %d 超过 S3 上限 %d", opt.PartSizeBytes, MaxPartSizeBytes)
	}

	httpClient := opt.HTTPClient
	if httpClient == nil {
		httpClient = defaultHTTPClient()
	}
	baseDelay := opt.RetryBaseDelay
	if baseDelay <= 0 {
		baseDelay = defaultRetryBaseDelay
	}
	now := opt.Now
	if now == nil {
		now = time.Now
	}

	// 去掉 endpoint 的路径与查询串：对象路径由 bucket + key 决定，
	// 端点里残留的路径会让拼出来的 URL 指向别处。
	base := &url.URL{Scheme: strings.ToLower(u.Scheme), Host: u.Host}

	return &Client{
		base:   base,
		bucket: strings.Trim(opt.Bucket, "/"),
		signer: &signer{
			accessKey:    opt.AccessKeyID,
			secretKey:    opt.SecretAccessKey,
			sessionToken: opt.SessionToken,
			region:       region,
			service:      serviceName,
		},
		http:    httpClient,
		opt:     opt,
		now:     now,
		baseDel: baseDelay,
	}, nil
}

// Bucket 返回目标桶名（非敏感，可入日志）。
func (c *Client) Bucket() string { return c.bucket }

// Endpoint 返回端点（非敏感，可入日志）。
func (c *Client) Endpoint() string { return c.base.String() }

// objectURL 拼出对象 URL。
//
// 路径风格（`/<bucket>/<key>`）而非虚拟主机风格：R2 的账户端点支持前者，
// 且不必处理桶名里的点导致 TLS 通配符失配的问题。
//
// 注意这里**整体覆盖**了 base 的 Path：endpoint 里带的路径会被丢掉。
// 这是故意的（路径只有一个合法来源：bucket + key），但"悄悄丢掉"是个陷阱，
// 所以入口处由 cred.ValidateEndpoint 拒绝带路径的 endpoint——别把这个校验去掉。
func (c *Client) objectURL(key string, query url.Values) *url.URL {
	u := *c.base
	p := "/" + c.bucket
	if key != "" {
		p += "/" + key
	}
	u.Path = p
	// 同步设置 RawPath：实际发出的路径与参与签名的规范 URI 必须逐字节一致，
	// 否则签名对不上。Go 默认的路径转义规则与 AWS 的 encodeURIComponent 不同，
	// 因此两者都用手写的 uriEncode 结果。
	u.RawPath = uriEncode(p, false)
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	return &u
}

// request 描述一次待发送的请求。
type request struct {
	op          string
	method      string
	url         *url.URL
	headers     map[string]string
	payloadHash string
	body        io.ReadSeeker
	length      int64
	// progress 非空时，body 读取的字节会被回报。
	progress ProgressFunc
	// progressBase 是本次上报的起始偏移（分片上传时累计已完成分片）。
	progressBase int64
	// progressTotal 是上报的总量。
	progressTotal int64
}

// send 发送请求并处理重试。返回的响应由调用方负责 Close。
func (c *Client) send(ctx context.Context, r request) (*http.Response, error) {
	maxRetries := c.opt.MaxRetries
	if maxRetries == 0 {
		maxRetries = DefaultMaxRetries
	} else if maxRetries < 0 {
		maxRetries = 0
	}

	var lastErr error
	for attempt := 0; ; attempt++ {
		var body io.ReadCloser
		if r.body != nil {
			if _, err := r.body.Seek(0, io.SeekStart); err != nil {
				return nil, fmt.Errorf("r2: 回绕请求体失败: %w", err)
			}
			var src io.Reader = r.body
			if r.progress != nil {
				src = &progressReader{
					r:    r.body,
					cb:   r.progress,
					base: r.progressBase,
					tot:  r.progressTotal,
				}
			}
			body = io.NopCloser(src)
		}

		req, err := http.NewRequestWithContext(ctx, r.method, r.url.String(), body)
		if err != nil {
			return nil, fmt.Errorf("r2: 构造请求失败: %w", err)
		}
		if r.length > 0 || r.body != nil {
			req.ContentLength = r.length
		}
		for k, v := range r.headers {
			req.Header.Set(k, v)
		}
		if c.opt.UserAgent != "" {
			req.Header.Set("User-Agent", c.opt.UserAgent)
		}
		if err := c.signer.sign(req, r.payloadHash, c.now()); err != nil {
			return nil, err
		}

		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			if attempt >= maxRetries || ctx.Err() != nil {
				return nil, fmt.Errorf("r2: %s 请求失败（已重试 %d 次）: %w", r.op, attempt, err)
			}
			if !sleepCtx(ctx, c.backoff(attempt)) {
				return nil, fmt.Errorf("r2: %s 已取消: %w", r.op, ctx.Err())
			}
			continue
		}

		if shouldRetryStatus(resp.StatusCode) && attempt < maxRetries {
			lastErr = parseAPIError(r.op, r.url.Path, resp)
			sleepCtx(ctx, c.backoff(attempt)) // 重试前先把响应体读掉并关闭，否则连接不会复用
			if ctx.Err() != nil {
				return nil, fmt.Errorf("r2: %s 已取消: %w", r.op, ctx.Err())
			}
			continue
		}
		_ = lastErr
		return resp, nil
	}
}

// backoff 返回带抖动的指数退避时长。
//
// 抖动是必要的：多个客户端同时重试时会形成同步的脉冲，
// 让已经在恢复的服务端再挨一轮打。
func (c *Client) backoff(attempt int) time.Duration {
	d := c.baseDel << uint(attempt)
	if d > maxRetryDelay || d <= 0 {
		d = maxRetryDelay
	}
	// 全抖动：在 [d/2, d) 之间取值。
	half := d / 2
	return half + time.Duration(rand.Int63n(int64(half)+1))
}

func shouldRetryStatus(code int) bool {
	switch code {
	case http.StatusRequestTimeout, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// progressReader 在读取过程中回报累计进度。
type progressReader struct {
	r    io.Reader
	cb   ProgressFunc
	n    int64
	base int64
	tot  int64
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.n += int64(n)
		p.cb(p.base+p.n, p.tot)
	}
	return n, err
}

// APIError 是一次被服务端拒绝的请求。
type APIError struct {
	Op         string
	Path       string
	StatusCode int
	Code       string
	Message    string
	RequestID  string
}

func (e *APIError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "r2: %s 失败（HTTP %d", e.Op, e.StatusCode)
	if e.Code != "" {
		fmt.Fprintf(&b, " %s", e.Code)
	}
	b.WriteString("）")
	if e.Message != "" {
		fmt.Fprintf(&b, "：%s", e.Message)
	}
	if e.Path != "" {
		fmt.Fprintf(&b, "（对象：%s）", e.Path)
	}
	if e.RequestID != "" {
		fmt.Fprintf(&b, "（请求 ID %s）", e.RequestID)
	}
	return b.String()
}

// IsNotFound 判断错误是否是"对象不存在"。
func IsNotFound(err error) bool {
	var api *APIError
	if errors.As(err, &api) {
		return api.StatusCode == http.StatusNotFound || api.Code == "NoSuchKey"
	}
	return false
}

// IsForbidden 判断错误是否是权限不足。
//
// 上传时拿到它，几乎总是因为 token 没给 Object Write 权限，
// 或者是写到了策略不允许的前缀上——这两件事的处理办法完全不同，
// 所以调用方要能把它与其它错误区分开。
func IsForbidden(err error) bool {
	var api *APIError
	if errors.As(err, &api) {
		return api.StatusCode == http.StatusForbidden || api.Code == "AccessDenied"
	}
	return false
}

// apiErrorXML 是 S3 的错误响应体。
type apiErrorXML struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	RequestID string   `xml:"RequestId"`
}

// parseAPIError 把错误响应转成 APIError。它会读完并关闭响应体。
func parseAPIError(op, path string, resp *http.Response) error {
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBodyBytes))
		_ = resp.Body.Close()
	}()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))

	e := &APIError{
		Op:         op,
		Path:       strings.TrimPrefix(path, "/"),
		StatusCode: resp.StatusCode,
	}
	var xe apiErrorXML
	if err := xml.Unmarshal(body, &xe); err == nil {
		e.Code = xe.Code
		e.Message = xe.Message
		e.RequestID = xe.RequestID
	}
	if e.Code == "" {
		// 非 XML 响应（网关错误页等）：截断保留一段，便于排障但不要灌满日志。
		msg := strings.TrimSpace(string(body))
		if len(msg) > 300 {
			msg = msg[:300] + "…"
		}
		if msg == "" {
			msg = resp.Status
		}
		e.Message = msg
	}
	return e
}

// drainAndClose 读掉并关闭响应体，使底层连接可被复用。
func drainAndClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
}

// defaultHTTPClient 返回内置 HTTP 客户端。
//
// 刻意不设 Client.Timeout：一次 10 GiB 的上传需要很久，整体超时会把正常上传掐死。
// 真正需要防的是"连接建立/握手/响应头迟迟不来"，这些都由 Transport 层的超时覆盖。
// 单次上传的整体时限由调用方通过 context 控制。
func defaultHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   15 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          8,
			MaxIdleConnsPerHost:   4,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   15 * time.Second,
			ExpectContinueTimeout: 5 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
		},
	}
}

// XML 响应体结构（只声明用得到的字段；未知字段被忽略）。

type listBucketResultXML struct {
	XMLName               xml.Name    `xml:"ListBucketResult"`
	IsTruncated           bool        `xml:"IsTruncated"`
	NextContinuationToken string      `xml:"NextContinuationToken"`
	Contents              []objectXML `xml:"Contents"`
}

type objectXML struct {
	Key          string `xml:"Key"`
	Size         int64  `xml:"Size"`
	ETag         string `xml:"ETag"`
	LastModified string `xml:"LastModified"`
}

type initiateMultipartXML struct {
	XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadID string   `xml:"UploadId"`
}

type completeMultipartXML struct {
	XMLName xml.Name `xml:"CompleteMultipartUploadResult"`
	ETag    string   `xml:"ETag"`
}

type completePartXML struct {
	PartNumber int    `xml:"PartNumber"`
	ETag       string `xml:"ETag"`
}

type completeMultipartRequestXML struct {
	XMLName xml.Name          `xml:"CompleteMultipartUpload"`
	Parts   []completePartXML `xml:"Part"`
}

// listAllMyBucketsResultXML 是 ListBuckets 的响应（只关心桶名）。
type listAllMyBucketsResultXML struct {
	XMLName xml.Name `xml:"ListAllMyBucketsResult"`
	Buckets struct {
		Bucket []struct {
			Name string `xml:"Name"`
		} `xml:"Bucket"`
	} `xml:"Buckets"`
}
