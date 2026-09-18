package r2

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// 本文件实现一个**自带签名校验**的假 S3 服务端。
//
// 为什么值得写这一大坨：真实 R2 桶需要联网与凭据，CI 与本机都跑不了；
// 而"上传到云"这条链路里最容易错、也最难在事后发现的地方是——
//   - SigV4 的规范请求拼错（表现是被拒签，但错误信息与权限不足长得一样）；
//   - 分片上传的 ?partNumber / ?uploadId 查询串写错；
//   - 上传说好的字节数与实际发出的不一致；
//   - 失败路径上没有 AbortMultipartUpload（远端残留分片，且**计费**）。
//
// 假服务端对每一个请求都做三件事，任一条不成立就拒绝：
//  1. 用服务端**自己写的**规范请求实现复算签名，与 Authorization 头比对；
//     这份实现对规范请求的拼装是独立写的（不复用被测包的 canonicalURI /
//     canonicalQuery），因此能抓出被测实现里的转义或排序错误；
//  2. 把收到的请求体重新哈希，与 x-amz-content-sha256 头比对——
//     确认客户端"说发的"就是"实际发的"；
//  3. 按 S3 的语义维护对象与分片状态，供测试断言。

// ---- 假服务端 ----

type fakeUpload struct {
	parts map[int][]byte
	etags map[int]string
}

type fakeS3 struct {
	mu        sync.Mutex
	accessKey string
	secretKey string
	region    string
	bucket    string

	objects map[string][]byte
	etags   map[string]string
	uploads map[string]*fakeUpload

	// fail 记录各操作还需失败多少次（用于注入故障）。
	fail      map[string]int
	failCode  int
	calls     map[string]int
	aborted   []string
	completed []string
	nextID    int

	// adminToken 为 true 时 `GET /`（ListBuckets）才会成功。
	//
	// 真实 R2 上这个区分是**权限档位**造成的：桶级 token 会被 403 拒掉，
	// 只有 Admin 级才能列举账户下的桶。假服务端用一个开关复现这两种结果。
	adminToken bool
}

func newFakeS3(bucket string) *fakeS3 {
	return &fakeS3{
		accessKey: "AKIDEXAMPLE",
		secretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		region:    "auto",
		bucket:    bucket,
		objects:   map[string][]byte{},
		etags:     map[string]string{},
		uploads:   map[string]*fakeUpload{},
		fail:      map[string]int{},
		calls:     map[string]int{},
	}
}

func (s *fakeS3) url() string { return "" } // 占位，保持结构体可读（实际 URL 由 httptest 提供）

func (s *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.replyError(w, http.StatusBadRequest, "MalformedBody", err.Error())
		return
	}
	_ = r.Body.Close()

	q := r.URL.Query()
	op := s.route(r, q)
	s.mu.Lock()
	s.calls[op]++
	failLeft := s.fail[op]
	if failLeft > 0 {
		s.fail[op] = failLeft - 1
	}
	s.mu.Unlock()

	// 1) 签名校验。
	if err := s.verifySignature(r, body); err != nil {
		s.replyError(w, http.StatusForbidden, "SignatureDoesNotMatch", err.Error())
		return
	}

	if failLeft > 0 {
		s.replyError(w, s.failCode, "InjectedFailure", "测试注入的故障")
		return
	}

	switch op {
	case "PutObject":
		s.handlePut(w, r, body)
	case "CreateMultipartUpload":
		s.handleCreateMultipart(w, r)
	case "UploadPart":
		s.handleUploadPart(w, r, body)
	case "CompleteMultipartUpload":
		s.handleCompleteMultipart(w, r, body)
	case "AbortMultipartUpload":
		s.handleAbort(w, r)
	case "ListObjectsV2":
		s.handleList(w, r, q)
	case "HeadObject":
		s.handleHead(w, r)
	case "GetObject":
		s.handleGet(w, r)
	case "DeleteObject":
		s.handleDelete(w, r)
	case "ListBuckets":
		s.handleListBuckets(w)
	default:
		s.replyError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", r.Method+" "+r.URL.Path)
	}
}

// route 归类请求。没有任何"通用"分支：无法归类的直接拒绝，
// 这样测试不会因为某条路径没被覆盖而静默通过。
func (s *fakeS3) route(r *http.Request, q url.Values) string {
	switch r.Method {
	case http.MethodPut:
		if q.Has("partNumber") {
			return "UploadPart"
		}
		return "PutObject"
	case http.MethodPost:
		if q.Has("uploads") {
			return "CreateMultipartUpload"
		}
		if q.Has("uploadId") {
			return "CompleteMultipartUpload"
		}
		return ""
	case http.MethodDelete:
		if q.Has("uploadId") {
			return "AbortMultipartUpload"
		}
		return "DeleteObject"
	case http.MethodHead:
		return "HeadObject"
	case http.MethodGet:
		// `GET /`（路径里没有桶）是 ListBuckets，账户级操作。
		if strings.Trim(r.URL.Path, "/") == "" {
			return "ListBuckets"
		}
		if q.Get("list-type") == "2" {
			return "ListObjectsV2"
		}
		return "GetObject"
	}
	return ""
}

// bucketAndKey 从路径中拆出桶与对象键。
func (s *fakeS3) bucketAndKey(r *http.Request) (string, string, bool) {
	p := r.URL.Path
	if i := strings.Index(p, s.bucket+"/"); i >= 0 {
		after := p[i+len(s.bucket)+1:]
		return s.bucket, after, true
	}
	if strings.Trim(p, "/") == s.bucket {
		return s.bucket, "", true
	}
	return "", "", false
}

// ---- 签名校验（服务端独立实现） ----

// verifySignature 用与客户端**不同的代码路径**复算签名。
func (s *fakeS3) verifySignature(r *http.Request, body []byte) error {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, algorithm+" ") {
		return fmt.Errorf("缺少 Authorization 头")
	}
	fields := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(auth, algorithm+" "), ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		fields[k] = v
	}
	cred := fields["Credential"]
	signedHeaders := fields["SignedHeaders"]
	signature := fields["Signature"]
	if cred == "" || signedHeaders == "" || signature == "" {
		return fmt.Errorf("Authorization 头字段不完整：%s", auth)
	}
	credParts := strings.Split(cred, "/")
	if len(credParts) != 5 {
		return fmt.Errorf("Credential 作用域格式错误：%s", cred)
	}
	if credParts[0] != s.accessKey {
		return fmt.Errorf("Access Key 不匹配：%s", credParts[0])
	}
	if credParts[2] != s.region || credParts[3] != serviceName {
		return fmt.Errorf("作用域区域/服务错误：%s", cred)
	}

	// 请求体摘要必须与实际字节一致。
	gotHash := r.Header.Get("x-amz-content-sha256")
	wantHash := hex.EncodeToString(sha256Sum(body))
	if gotHash != wantHash {
		return fmt.Errorf("载荷摘要不符：声明 %s，实际 %s", gotHash, wantHash)
	}
	amzDate := r.Header.Get("x-amz-date")
	if amzDate == "" {
		return fmt.Errorf("缺少 x-amz-date")
	}

	// 规范请求：用本文件自己写的实现拼装。
	canonicalHeaders := ""
	for _, name := range strings.Split(signedHeaders, ";") {
		var v string
		if name == "host" {
			v = r.Host
		} else {
			v = strings.Join(r.Header.Values(name), ",")
		}
		canonicalHeaders += name + ":" + collapseSpaces(strings.TrimSpace(v)) + "\n"
	}
	cr := strings.Join([]string{
		r.Method,
		r.URL.EscapedPath(),
		canonicalizeQuery(r.URL.RawQuery),
		canonicalHeaders,
		signedHeaders,
		wantHash,
	}, "\n")

	// StringToSign 的第 3 行是**作用域**（日期/区域/服务/aws4_request），不含
	// Access Key ID。这一点最容易写错：Authorization 头里的 Credential 是
	// `AKID/scope` 的整体，而参与摘要的只有 scope 部分。
	scope := strings.Join(credParts[1:], "/")
	sts := strings.Join([]string{
		algorithm,
		amzDate,
		scope,
		hex.EncodeToString(sha256Sum([]byte(cr))),
	}, "\n")
	key := testSigningKey(s.secretKey, credParts[1], credParts[2], credParts[3])
	want := hex.EncodeToString(testHMAC(key, sts))
	if want != signature {
		return fmt.Errorf("签名不符\n  规范请求：\n%s\n  得到 %s\n  期望 %s", cr, signature, want)
	}
	return nil
}

// collapseSpaces 是服务端侧独立的头部值归一化实现。
func collapseSpaces(v string) string {
	var b strings.Builder
	prev := false
	for _, r := range v {
		if r == ' ' || r == '\t' {
			if !prev {
				b.WriteByte(' ')
				prev = true
			}
			continue
		}
		b.WriteRune(r)
		prev = false
	}
	return b.String()
}

// canonicalizeQuery 从**原始查询串**重建规范查询串。
func canonicalizeQuery(raw string) string {
	if raw == "" {
		return ""
	}
	type kv struct{ k, v string }
	var list []kv
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		dk, err1 := url.QueryUnescape(k)
		dv, err2 := url.QueryUnescape(v)
		if err1 != nil || err2 != nil {
			continue
		}
		list = append(list, kv{testEncode(dk), testEncode(dv)})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].k != list[j].k {
			return list[i].k < list[j].k
		}
		return list[i].v < list[j].v
	})
	parts := make([]string, 0, len(list))
	for _, p := range list {
		parts = append(parts, p.k+"="+p.v)
	}
	return strings.Join(parts, "&")
}

// testEncode 是服务端侧独立的 AWS 风格百分号编码实现。
func testEncode(s string) string {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(unreserved, s[i]) >= 0 {
			b.WriteByte(s[i])
			continue
		}
		fmt.Fprintf(&b, "%%%02X", s[i])
	}
	return b.String()
}

// ---- 各操作 ----

func (s *fakeS3) handlePut(w http.ResponseWriter, r *http.Request, body []byte) {
	_, key, ok := s.bucketAndKey(r)
	if !ok {
		s.replyError(w, http.StatusNotFound, "NoSuchBucket", "桶名不匹配")
		return
	}
	s.mu.Lock()
	content := append([]byte(nil), body...)
	s.objects[key] = content
	s.etags[key] = hex.EncodeToString(sha256Sum(content))
	etag := s.etags[key]
	s.mu.Unlock()
	w.Header().Set("ETag", `"`+etag+`"`)
	w.WriteHeader(http.StatusOK)
}

func (s *fakeS3) handleCreateMultipart(w http.ResponseWriter, r *http.Request) {
	_, key, ok := s.bucketAndKey(r)
	if !ok {
		s.replyError(w, http.StatusNotFound, "NoSuchBucket", "")
		return
	}
	s.mu.Lock()
	s.nextID++
	id := fmt.Sprintf("upload-%d", s.nextID)
	s.uploads[id] = &fakeUpload{parts: map[int][]byte{}, etags: map[int]string{}}
	s.mu.Unlock()

	type result struct {
		XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
		Bucket   string   `xml:"Bucket"`
		Key      string   `xml:"Key"`
		UploadID string   `xml:"UploadId"`
	}
	writeXML(w, result{Bucket: s.bucket, Key: key, UploadID: id})
}

func (s *fakeS3) handleUploadPart(w http.ResponseWriter, r *http.Request, body []byte) {
	q := r.URL.Query()
	id := q.Get("uploadId")
	num, _ := strconv.Atoi(q.Get("partNumber"))
	if num < 1 {
		s.replyError(w, http.StatusBadRequest, "InvalidPart", "partNumber 非法")
		return
	}
	s.mu.Lock()
	up := s.uploads[id]
	if up == nil {
		s.mu.Unlock()
		s.replyError(w, http.StatusNotFound, "NoSuchUpload", id)
		return
	}
	up.parts[num] = append([]byte(nil), body...)
	up.etags[num] = hex.EncodeToString(sha256Sum(body))
	etag := up.etags[num]
	s.mu.Unlock()
	w.Header().Set("ETag", `"`+etag+`"`)
	w.WriteHeader(http.StatusOK)
}

func (s *fakeS3) handleCompleteMultipart(w http.ResponseWriter, r *http.Request, body []byte) {
	_, key, _ := s.bucketAndKey(r)
	id := r.URL.Query().Get("uploadId")

	var req struct {
		Parts []struct {
			PartNumber int    `xml:"PartNumber"`
			ETag       string `xml:"ETag"`
		} `xml:"Part"`
	}
	if err := xml.Unmarshal(body, &req); err != nil {
		s.replyError(w, http.StatusBadRequest, "MalformedXML", err.Error())
		return
	}

	s.mu.Lock()
	up := s.uploads[id]
	if up == nil {
		s.mu.Unlock()
		s.replyError(w, http.StatusNotFound, "NoSuchUpload", id)
		return
	}
	var assembled []byte
	for i, p := range req.Parts {
		got, ok := up.parts[p.PartNumber]
		if !ok {
			s.mu.Unlock()
			s.replyError(w, http.StatusBadRequest, "InvalidPart", fmt.Sprintf("缺少第 %d 片", p.PartNumber))
			return
		}
		// 分片必须按 partNumber 升序拼接；客户端传错顺序会在这里被抓出来。
		if i > 0 && req.Parts[i-1].PartNumber >= p.PartNumber {
			s.mu.Unlock()
			s.replyError(w, http.StatusBadRequest, "InvalidPartOrder", "分片顺序错误")
			return
		}
		if strings.Trim(p.ETag, `"`) != up.etags[p.PartNumber] {
			s.mu.Unlock()
			s.replyError(w, http.StatusBadRequest, "InvalidPart", "ETag 不匹配")
			return
		}
		assembled = append(assembled, got...)
	}
	s.objects[key] = assembled
	s.etags[key] = hex.EncodeToString(sha256Sum(assembled))
	delete(s.uploads, id)
	s.completed = append(s.completed, id)
	s.mu.Unlock()

	type result struct {
		XMLName xml.Name `xml:"CompleteMultipartUploadResult"`
		Key     string   `xml:"Key"`
		ETag    string   `xml:"ETag"`
	}
	writeXML(w, result{Key: key, ETag: s.etags[key]})
}

func (s *fakeS3) handleAbort(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("uploadId")
	s.mu.Lock()
	_, existed := s.uploads[id]
	delete(s.uploads, id)
	s.aborted = append(s.aborted, id)
	s.mu.Unlock()
	if !existed {
		s.replyError(w, http.StatusNotFound, "NoSuchUpload", id)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *fakeS3) handleList(w http.ResponseWriter, r *http.Request, q url.Values) {
	prefix := q.Get("prefix")
	maxKeys := 1000
	if v := q.Get("max-keys"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxKeys = n
		}
	}

	s.mu.Lock()
	var keys []string
	for k := range s.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	s.mu.Unlock()

	type content struct {
		Key          string `xml:"Key"`
		LastModified string `xml:"LastModified"`
		ETag         string `xml:"ETag"`
		Size         int64  `xml:"Size"`
	}
	type result struct {
		XMLName               xml.Name  `xml:"ListBucketResult"`
		IsTruncated           bool      `xml:"IsTruncated"`
		NextContinuationToken string    `xml:"NextContinuationToken,omitempty"`
		Contents              []content `xml:"Contents"`
	}
	var res result
	for i, k := range keys {
		if i >= maxKeys {
			res.IsTruncated = true
			res.NextContinuationToken = keys[i-1]
			break
		}
		s.mu.Lock()
		size := int64(len(s.objects[k]))
		etag := s.etags[k]
		s.mu.Unlock()
		res.Contents = append(res.Contents, content{Key: k, Size: size, ETag: etag,
			LastModified: time.Now().UTC().Format(time.RFC3339)})
	}
	writeXML(w, res)
}

func (s *fakeS3) handleHead(w http.ResponseWriter, r *http.Request) {
	_, key, _ := s.bucketAndKey(r)
	s.mu.Lock()
	content, ok := s.objects[key]
	etag := s.etags[key]
	s.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	w.Header().Set("ETag", `"`+etag+`"`)
	w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
	w.WriteHeader(http.StatusOK)
}

func (s *fakeS3) handleGet(w http.ResponseWriter, r *http.Request) {
	_, key, _ := s.bucketAndKey(r)
	s.mu.Lock()
	content, ok := s.objects[key]
	etag := s.etags[key]
	s.mu.Unlock()
	if !ok {
		s.replyError(w, http.StatusNotFound, "NoSuchKey", key)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	w.Header().Set("ETag", `"`+etag+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func (s *fakeS3) handleDelete(w http.ResponseWriter, r *http.Request) {
	_, key, _ := s.bucketAndKey(r)
	s.mu.Lock()
	delete(s.objects, key)
	delete(s.etags, key)
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// handleListBuckets 复现 R2 的权限档位差异：桶级 token 被拒，Admin 级才放行。
func (s *fakeS3) handleListBuckets(w http.ResponseWriter) {
	if !s.adminToken {
		s.replyError(w, http.StatusForbidden, "AccessDenied",
			"该凭据为桶级权限，不允许列举账户下的桶")
		return
	}
	type bucketXML struct {
		Name string `xml:"Name"`
	}
	type bucketsXML struct {
		Bucket []bucketXML `xml:"Bucket"`
	}
	type resultXML struct {
		XMLName xml.Name   `xml:"ListAllMyBucketsResult"`
		Buckets bucketsXML `xml:"Buckets"`
	}
	writeXMLStatus(w, http.StatusOK, resultXML{
		Buckets: bucketsXML{Bucket: []bucketXML{{Name: s.bucket}, {Name: "another-bucket"}}},
	})
}

func (s *fakeS3) replyError(w http.ResponseWriter, code int, apiCode, msg string) {
	type errXML struct {
		XMLName xml.Name `xml:"Error"`
		Code    string   `xml:"Code"`
		Message string   `xml:"Message"`
	}
	writeXMLStatus(w, code, errXML{Code: apiCode, Message: msg})
}

func (s *fakeS3) objectCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.objects)
}

func (s *fakeS3) callCount(op string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[op]
}

// ---- 测试脚手架 ----

func newTestClient(t *testing.T, srv *httptest.Server, opt Options) *Client {
	t.Helper()
	opt.Endpoint = srv.URL
	if opt.Bucket == "" {
		opt.Bucket = "test-bucket"
	}
	if opt.AccessKeyID == "" {
		opt.AccessKeyID = "AKIDEXAMPLE"
	}
	if opt.SecretAccessKey == "" {
		opt.SecretAccessKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	}
	if opt.Region == "" {
		opt.Region = "auto"
	}
	if opt.RetryBaseDelay == 0 {
		opt.RetryBaseDelay = time.Millisecond
	}
	opt.MaxRetries = 3
	c, err := New(opt)
	if err != nil {
		t.Fatalf("New 失败：%v", err)
	}
	return c
}

func TestPutObjectRoundTrip(t *testing.T) {
	fake := newFakeS3("test-bucket")
	srv := httptest.NewServer(fake)
	defer srv.Close()
	c := newTestClient(t, srv, Options{})

	payload := []byte("hello r2 world")
	var lastDone, lastTotal int64
	info, err := c.PutObject(t.Context(), "usb/UDISK/a.zip.usbk", bytes.NewReader(payload), int64(len(payload)),
		func(done, total int64) { lastDone, lastTotal = done, total })
	if err != nil {
		t.Fatalf("PutObject 失败：%v", err)
	}
	if fake.callCount("PutObject") != 1 {
		t.Errorf("PutObject 调用次数 %d，期望 1", fake.callCount("PutObject"))
	}
	if info.Size != int64(len(payload)) || info.Key != "usb/UDISK/a.zip.usbk" {
		t.Errorf("返回的对象信息不符：%+v", info)
	}
	if lastDone != int64(len(payload)) || lastTotal != int64(len(payload)) {
		t.Errorf("进度回调最终值 done=%d total=%d", lastDone, lastTotal)
	}

	// 回读校验：服务端存的字节必须与发出的一致（服务端已顺带校过载荷摘要）。
	dest := filepath.Join(t.TempDir(), "back.zip.usbk")
	got, err := c.Download(t.Context(), "usb/UDISK/a.zip.usbk", dest, nil)
	if err != nil {
		t.Fatalf("Download 失败：%v", err)
	}
	if got.Size != int64(len(payload)) {
		t.Errorf("下载大小 %d，期望 %d", got.Size, len(payload))
	}
	raw, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, payload) {
		t.Error("下载内容与上传内容不一致")
	}
}

func TestMultipartUploadRoundTrip(t *testing.T) {
	fake := newFakeS3("test-bucket")
	srv := httptest.NewServer(fake)
	defer srv.Close()
	// 分片大小取下限 5 MiB，让 12 MiB 的文件切成 3 片，测试跑得快。
	c := newTestClient(t, srv, Options{
		PartSizeBytes:           MinPartSizeBytes,
		MultipartThresholdBytes: MinPartSizeBytes,
	})

	const size = 12 << 20
	blob := make([]byte, size)
	for i := range blob {
		blob[i] = byte(i * 7 % 251)
	}
	src := filepath.Join(t.TempDir(), "big.zip.usbk")
	if err := os.WriteFile(src, blob, 0o600); err != nil {
		t.Fatal(err)
	}

	info, err := c.UploadFile(t.Context(), src, "usb/BIG/big.zip.usbk", nil)
	if err != nil {
		t.Fatalf("UploadFile 失败：%v", err)
	}
	if info.Size != size {
		t.Errorf("返回大小 %d，期望 %d", info.Size, size)
	}
	if n := fake.callCount("UploadPart"); n != 3 {
		t.Errorf("分片数 %d，期望 3（12 MiB / 5 MiB）", n)
	}
	if fake.callCount("CreateMultipartUpload") != 1 || fake.callCount("CompleteMultipartUpload") != 1 {
		t.Errorf("分片流程调用次数异常：create=%d complete=%d",
			fake.callCount("CreateMultipartUpload"), fake.callCount("CompleteMultipartUpload"))
	}
	if len(fake.aborted) != 0 {
		t.Errorf("成功路径不应有 abort，实际 %v", fake.aborted)
	}

	// 拼装结果必须逐字节一致——顺序错、分片内容错都会在这里暴露。
	fake.mu.Lock()
	got := fake.objects["usb/BIG/big.zip.usbk"]
	fake.mu.Unlock()
	if !bytes.Equal(got, blob) {
		t.Fatalf("远端拼装结果与源文件不一致（得到 %d 字节，期望 %d 字节）", len(got), len(blob))
	}
}

func TestMultipartAbortsOnFailure(t *testing.T) {
	fake := newFakeS3("test-bucket")
	fake.failCode = http.StatusBadRequest // 4xx 不重试，直接走失败路径
	srv := httptest.NewServer(fake)
	defer srv.Close()
	c := newTestClient(t, srv, Options{
		PartSizeBytes:           MinPartSizeBytes,
		MultipartThresholdBytes: 1, // 强制走分片
	})

	blob := make([]byte, 11<<20)
	src := filepath.Join(t.TempDir(), "x.bin")
	if err := os.WriteFile(src, blob, 0o600); err != nil {
		t.Fatal(err)
	}

	fake.mu.Lock()
	fake.fail["UploadPart"] = 1 // 第 1 次上传分片失败
	fake.mu.Unlock()

	if _, err := c.UploadFile(t.Context(), src, "usb/X/x.zip.usbk", nil); err == nil {
		t.Fatal("分片上传应当失败")
	}

	if len(fake.aborted) != 1 {
		t.Fatalf("失败路径必须调用 AbortMultipartUpload，实际 abort 次数 %d", len(fake.aborted))
	}
	fake.mu.Lock()
	left := len(fake.uploads)
	fake.mu.Unlock()
	if left != 0 {
		t.Errorf("远端仍有 %d 个未取消的分片上传（会持续计费）", left)
	}
	if fake.objectCount() != 0 {
		t.Error("失败的上传不应产出对象")
	}
	_ = os.Remove(src)
}

func TestRetryOnServerError(t *testing.T) {
	fake := newFakeS3("test-bucket")
	fake.failCode = http.StatusServiceUnavailable
	srv := httptest.NewServer(fake)
	defer srv.Close()
	c := newTestClient(t, srv, Options{})

	fake.mu.Lock()
	fake.fail["PutObject"] = 2 // 失败两次后成功
	fake.mu.Unlock()

	payload := []byte("retry me")
	if _, err := c.PutObject(t.Context(), "k", bytes.NewReader(payload), int64(len(payload)), nil); err != nil {
		t.Fatalf("应当在重试后成功：%v", err)
	}
	if n := fake.callCount("PutObject"); n != 3 {
		t.Errorf("调用次数 %d，期望 3（两次失败 + 一次成功）", n)
	}
}

func TestNoRetryOnClientError(t *testing.T) {
	fake := newFakeS3("test-bucket")
	fake.failCode = http.StatusForbidden
	srv := httptest.NewServer(fake)
	defer srv.Close()
	c := newTestClient(t, srv, Options{})

	fake.mu.Lock()
	fake.fail["PutObject"] = 99
	fake.mu.Unlock()

	payload := []byte("denied")
	_, err := c.PutObject(t.Context(), "k", bytes.NewReader(payload), int64(len(payload)), nil)
	if err == nil {
		t.Fatal("应当返回错误")
	}
	// 4xx 是确定的拒绝，重试不会改变结果，只会拖慢并加重服务端负担。
	if n := fake.callCount("PutObject"); n != 1 {
		t.Errorf("4xx 不应重试，实际调用 %d 次", n)
	}
	if !IsForbidden(err) {
		t.Errorf("应能被 IsForbidden 识别，实际：%v", err)
	}
	var api *APIError
	if !asAPIError(err, &api) || api.StatusCode != http.StatusForbidden {
		t.Errorf("错误应携带状态码，实际：%v", err)
	}
	// 错误信息里不得出现凭据。
	if strings.Contains(err.Error(), "wJalrXUtnFEMI") {
		t.Error("错误信息泄露了 Secret Access Key")
	}
}

func TestSignatureActuallyVerified(t *testing.T) {
	// 反向守卫：如果假服务端根本没在校验签名，上面的测试会全部变成空转。
	// 这里故意用错误的密钥签名，必须被拒。
	fake := newFakeS3("test-bucket")
	srv := httptest.NewServer(fake)
	defer srv.Close()
	c := newTestClient(t, srv, Options{SecretAccessKey: "wrong-secret-key"})

	payload := []byte("x")
	_, err := c.PutObject(t.Context(), "k", bytes.NewReader(payload), int64(len(payload)), nil)
	if err == nil {
		t.Fatal("错误密钥应当被服务端拒绝")
	}
	if !IsForbidden(err) {
		t.Errorf("应返回 403，实际：%v", err)
	}
	if fake.objectCount() != 0 {
		t.Error("拒签的请求不应写入对象")
	}
}

func TestListHeadDelete(t *testing.T) {
	fake := newFakeS3("test-bucket")
	srv := httptest.NewServer(fake)
	defer srv.Close()
	c := newTestClient(t, srv, Options{})

	keys := []string{"usb/A/1.zip.usbk", "usb/A/2.zip.usbk", "usb/B/3.zip.usbk"}
	for _, k := range keys {
		b := []byte(k)
		if _, err := c.PutObject(t.Context(), k, bytes.NewReader(b), int64(len(b)), nil); err != nil {
			t.Fatalf("准备数据失败：%v", err)
		}
	}

	all, err := c.List(t.Context(), "usb/", 0)
	if err != nil {
		t.Fatalf("List 失败：%v", err)
	}
	if len(all) != 3 {
		t.Fatalf("列举到 %d 个对象，期望 3", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].Key > all[i].Key {
			t.Error("列举结果应按 Key 升序")
		}
	}
	onlyA, err := c.List(t.Context(), "usb/A/", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(onlyA) != 2 {
		t.Errorf("前缀过滤失效，得到 %d 个", len(onlyA))
	}
	limited, err := c.List(t.Context(), "usb/", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(limited) != 1 {
		t.Errorf("limit 未生效，得到 %d 个", len(limited))
	}

	h, err := c.Head(t.Context(), "usb/A/1.zip.usbk")
	if err != nil {
		t.Fatalf("Head 失败：%v", err)
	}
	if h.Size != int64(len("usb/A/1.zip.usbk")) {
		t.Errorf("Head 返回大小 %d", h.Size)
	}

	if err := c.Delete(t.Context(), "usb/A/1.zip.usbk"); err != nil {
		t.Fatalf("Delete 失败：%v", err)
	}
	if fake.objectCount() != 2 {
		t.Errorf("删除后对象数 %d，期望 2", fake.objectCount())
	}
	_, err = c.Head(t.Context(), "usb/A/1.zip.usbk")
	if !IsNotFound(err) {
		t.Errorf("已删除对象应报 NotFound，实际：%v", err)
	}
}

func TestListBucketsDetectsOverPrivilegedToken(t *testing.T) {
	// 这条测的是**权限过大检测**这条能力：R2 上桶级 token 调 ListBuckets 会被
	// 403 拒掉，只有 Admin 级才成功。所以"能列举桶"== "权限开大了"。
	fake := newFakeS3("test-bucket")
	srv := httptest.NewServer(fake)
	defer srv.Close()
	c := newTestClient(t, srv, Options{})

	// 桶级 token：必须被拒，且错误可被 IsForbidden 识别
	// （调用方据此把它当作"通过"）。
	if _, err := c.ListBuckets(t.Context()); err == nil {
		t.Fatal("桶级凭据不应能列举账户下的桶")
	} else if !IsForbidden(err) {
		t.Fatalf("拒绝原因应能识别为 403，实际：%v", err)
	}

	// Admin 级 token：能列举，且桶名解析正确。
	fake.mu.Lock()
	fake.adminToken = true
	fake.mu.Unlock()
	names, err := c.ListBuckets(t.Context())
	if err != nil {
		t.Fatalf("Admin 级凭据应能列举桶：%v", err)
	}
	if len(names) != 2 || names[0] != "test-bucket" {
		t.Fatalf("桶名解析不正确：%v", names)
	}
}

func TestDownloadRejectsTruncatedBody(t *testing.T) {
	// 服务端声明 100 字节却只发 10 字节：必须报错，且不留下半截文件。
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("0123456789"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := newTestClient(t, srv, Options{})

	// 不用 t.TempDir()：Windows 上刚删掉的临时文件偶尔还被安全软件短暂占用，
	// t.TempDir 的清理失败会直接判测试失败，把真正要验的逻辑淹没掉。
	dir, err := os.MkdirTemp("", "r2-dl-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	dest := filepath.Join(dir, "short.bin")
	if _, err := c.Download(t.Context(), "k", dest, nil); err == nil {
		t.Fatal("长度不符的下载应当报错")
	}
	if _, statErr := os.Stat(dest); statErr == nil {
		t.Error("失败时不应留下目标文件")
	}
	if _, statErr := os.Stat(dest + ".part"); statErr == nil {
		t.Error("失败时不应留下 .part 半成品")
	}
}

func TestUploadFilePicksSinglePutForSmallFile(t *testing.T) {
	fake := newFakeS3("test-bucket")
	srv := httptest.NewServer(fake)
	defer srv.Close()
	c := newTestClient(t, srv, Options{MultipartThresholdBytes: 1 << 20})

	src := filepath.Join(t.TempDir(), "small.bin")
	if err := os.WriteFile(src, []byte("tiny"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.UploadFile(t.Context(), src, "k", nil); err != nil {
		t.Fatal(err)
	}
	if fake.callCount("PutObject") != 1 || fake.callCount("CreateMultipartUpload") != 0 {
		t.Errorf("小文件应走单次 PUT：put=%d create=%d",
			fake.callCount("PutObject"), fake.callCount("CreateMultipartUpload"))
	}

	// 空文件也必须能上传（走单次 PUT，不能进分片路径）。
	empty := filepath.Join(t.TempDir(), "empty.bin")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := c.UploadFile(t.Context(), empty, "empty", nil)
	if err != nil {
		t.Fatalf("空文件上传失败：%v", err)
	}
	if info.Size != 0 {
		t.Errorf("空文件大小应为 0，实际 %d", info.Size)
	}
}

func TestNewRejectsInsecureOptions(t *testing.T) {
	cases := map[string]Options{
		"缺失 endpoint": {Bucket: "b", AccessKeyID: "a", SecretAccessKey: "s"},
		"缺失 bucket":   {Endpoint: "https://x.r2.cloudflarestorage.com", AccessKeyID: "a", SecretAccessKey: "s"},
		"缺失凭据":        {Endpoint: "https://x.r2.cloudflarestorage.com", Bucket: "b"},
		"明文远端端点":      {Endpoint: "http://evil.example.com", Bucket: "b", AccessKeyID: "a", SecretAccessKey: "s"},
		"非法协议":        {Endpoint: "ftp://x.example.com", Bucket: "b", AccessKeyID: "a", SecretAccessKey: "s"},
		"分片过大":        {Endpoint: "https://x.r2.cloudflarestorage.com", Bucket: "b", AccessKeyID: "a", SecretAccessKey: "s", PartSizeBytes: MaxPartSizeBytes + 1},
	}
	for name, opt := range cases {
		if _, err := New(opt); err == nil {
			t.Errorf("%s：应当被拒绝", name)
		}
	}
}

func TestBackoffIsBoundedAndJittered(t *testing.T) {
	c := &Client{baseDel: time.Millisecond}
	prev := time.Duration(0)
	for attempt := 0; attempt < 12; attempt++ {
		d := c.backoff(attempt)
		if d <= 0 || d > maxRetryDelay {
			t.Fatalf("退避时长 %v 越界", d)
		}
		if attempt < 5 && d < prev/4 {
			// 只要求不退化为 0；抖动会让相邻值有大有小。
			t.Logf("attempt %d 退避 %v", attempt, d)
		}
		prev = d
	}
}

// ---- 小工具 ----

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// testHMAC / testSigningKey 是**服务端侧的独立实现**（手写 HMAC，不复用被测包的
// hmacSHA256 / signingKey）。签名校验如果复用被测代码，就等于自己给自己判卷。
func testHMAC(key []byte, msg string) []byte {
	const blockSize = 64
	k := make([]byte, blockSize)
	if len(key) > blockSize {
		sum := sha256.Sum256(key)
		key = sum[:]
	}
	copy(k, key)

	ipad := make([]byte, blockSize)
	opad := make([]byte, blockSize)
	for i := 0; i < blockSize; i++ {
		ipad[i] = k[i] ^ 0x36
		opad[i] = k[i] ^ 0x5c
	}
	inner := sha256.Sum256(append(ipad, []byte(msg)...))
	return sha256Sum(append(opad, inner[:]...))
}

func testSigningKey(secret, dateStamp, region, service string) []byte {
	k := testHMAC([]byte("AWS4"+secret), dateStamp)
	k = testHMAC(k, region)
	k = testHMAC(k, service)
	return testHMAC(k, "aws4_request")
}

func writeXML(w http.ResponseWriter, v any) {
	writeXMLStatus(w, http.StatusOK, v)
}

func writeXMLStatus(w http.ResponseWriter, code int, v any) {
	body, err := xml.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(body)
}

func asAPIError(err error, target **APIError) bool {
	for err != nil {
		if e, ok := err.(*APIError); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
