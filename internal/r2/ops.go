package r2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/immml/UsbBackUP-R2/internal/fsutil"
)

// ObjectInfo 的 Key 是不可信输入（来自远端列举结果），
// 但本包只在拼 URL 时使用它，拼出来的一定是 `/<bucket>/<key>` 单段路径，
// 不会逃出桶外——S3 的对象键本就允许包含 `/`，它就是"路径"。
//
// 上传时的 key 由调用方生成，必须是净化过的名字（见 backup.ObjectKey）。

// PutObject 用单次 PUT 上传。
//
// size 必须准确：它同时用于 Content-Length 与签名。空体（size==0）合法。
func (c *Client) PutObject(ctx context.Context, key string, body io.ReadSeeker, size int64, progress ProgressFunc) (ObjectInfo, error) {
	var info ObjectInfo
	if size < 0 {
		return info, errors.New("r2: 对象大小不能为负")
	}
	if size > MaxSinglePutBytes {
		return info, fmt.Errorf("r2: 单次 PUT 上限 %d 字节，本次 %d 字节，请改用分片上传", MaxSinglePutBytes, size)
	}
	sum, err := hashReader(body, size)
	if err != nil {
		return info, err
	}

	resp, err := c.send(ctx, request{
		op:            "PutObject",
		method:        http.MethodPut,
		url:           c.objectURL(key, nil),
		headers:       map[string]string{"Content-Type": "application/octet-stream"},
		payloadHash:   sum,
		body:          body,
		length:        size,
		progress:      progress,
		progressTotal: size,
	})
	if err != nil {
		return info, err
	}
	if resp.StatusCode/100 != 2 {
		return info, parseAPIError("PutObject", key, resp)
	}
	defer drainAndClose(resp)
	info = ObjectInfo{
		Key:          key,
		Size:         size,
		ETag:         strings.Trim(resp.Header.Get("ETag"), `"`),
		LastModified: c.now(),
	}
	if progress != nil {
		progress(size, size)
	}
	return info, nil
}

// UploadFile 上传本地文件，按大小自动选择单次 PUT 或分片上传。
func (c *Client) UploadFile(ctx context.Context, localPath, key string, progress ProgressFunc) (ObjectInfo, error) {
	var info ObjectInfo
	f, err := os.Open(fsutil.LongPath(localPath))
	if err != nil {
		return info, fmt.Errorf("r2: 打开待上传文件失败: %w", err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return info, fmt.Errorf("r2: 读取待上传文件信息失败: %w", err)
	}
	size := st.Size()
	if size == 0 || (size <= c.opt.MultipartThresholdBytes && size <= MaxSinglePutBytes) {
		return c.PutObject(ctx, key, f, size, progress)
	}
	return c.uploadMultipart(ctx, f, size, key, progress)
}

// uploadMultipart 走 S3 分片上传。
//
// 为什么必须支持分片：S3 单次 PUT 的载荷上限是 5 GiB，而容量门控的上限
// 默认就是 10 GiB——不开分片，超过 5 GiB 的介质必然传不上去。
//
// 失败路径上一定会 AbortMultipartUpload：已上传的分片在远端是**计费**的，
// 不取消就会一直留着（这也是"上传失败后远端残留"的常见成因）。
func (c *Client) uploadMultipart(ctx context.Context, f *os.File, size int64, key string, progress ProgressFunc) (ObjectInfo, error) {
	var info ObjectInfo
	partSize := c.opt.PartSizeBytes
	if n := (size + partSize - 1) / partSize; n > MaxParts {
		// 分片数超限：抬高分片大小而不是报错。
		partSize = roundUpMiB((size + MaxParts - 1) / MaxParts)
		if partSize > MaxPartSizeBytes {
			return info, fmt.Errorf("r2: 文件 %d 字节超过分片上传可覆盖的范围", size)
		}
	}
	parts := int((size + partSize - 1) / partSize)

	uploadID, err := c.createMultipart(ctx, key)
	if err != nil {
		return info, err
	}
	// Abort 必须用一个**已经脱离取消**的 context：ctx 被取消（超时/退出）时
	// 若沿用同一个 ctx，取消请求本身会立刻失败，远端分片就永久留下了。
	abort := func() {
		actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if aerr := c.abortMultipart(actx, key, uploadID); aerr != nil {
			// 这里只能记一句：调用方拿不到这个错误，但它关系到计费，必须可见。
			fmt.Fprintf(os.Stderr, "[r2] 警告：取消分片上传失败（远端可能残留分片）：%v\n", aerr)
		}
	}

	completed := make([]completePartXML, 0, parts)
	for i := 1; i <= parts; i++ {
		off := int64(i-1) * partSize
		n := partSize
		if remain := size - off; remain < n {
			n = remain
		}
		// 每个分片单独计算整片 SHA-256。这一步会额外读一遍分片数据——
		// 代价是两倍磁盘读，换来的是不依赖服务端的 UNSIGNED-PAYLOAD 支持。
		sum, herr := hashFileRegion(f, off, n)
		if herr != nil {
			abort()
			return info, herr
		}
		sec := newRegionReader(f, off, n)
		resp, serr := c.send(ctx, request{
			op:            fmt.Sprintf("UploadPart#%d", i),
			method:        http.MethodPut,
			url:           c.objectURLRaw(key, buildQuery([2]string{"partNumber", fmt.Sprintf("%d", i)}, [2]string{"uploadId", uploadID})),
			payloadHash:   sum,
			body:          sec,
			length:        n,
			progress:      progress,
			progressBase:  off,
			progressTotal: size,
		})
		if serr != nil {
			abort()
			return info, serr
		}
		if resp.StatusCode/100 != 2 {
			e := parseAPIError(fmt.Sprintf("UploadPart#%d", i), key, resp)
			abort()
			return info, e
		}
		etag := strings.Trim(resp.Header.Get("ETag"), `"`)
		drainAndClose(resp)
		if etag == "" {
			abort()
			return info, fmt.Errorf("r2: 第 %d 片上传成功但响应缺少 ETag", i)
		}
		completed = append(completed, completePartXML{PartNumber: i, ETag: etag})
	}

	body, err := xml.Marshal(completeMultipartRequestXML{Parts: completed})
	if err != nil {
		abort()
		return info, fmt.Errorf("r2: 序列化完成请求失败: %w", err)
	}
	sum := sha256.Sum256(body)
	resp, err := c.send(ctx, request{
		op:          "CompleteMultipartUpload",
		method:      http.MethodPost,
		url:         c.objectURLRaw(key, buildQuery([2]string{"uploadId", uploadID})),
		headers:     map[string]string{"Content-Type": "application/xml"},
		payloadHash: hex.EncodeToString(sum[:]),
		body:        newBytesReadSeeker(body),
		length:      int64(len(body)),
	})
	if err != nil {
		abort()
		return info, err
	}
	if resp.StatusCode/100 != 2 {
		e := parseAPIError("CompleteMultipartUpload", key, resp)
		abort()
		return info, e
	}
	drainAndClose(resp)
	// 走到这里远端对象已经成立，不能再 abort（abort 会把上传成功的对象一并撤掉）。
	if progress != nil {
		progress(size, size)
	}
	return ObjectInfo{Key: key, Size: size, LastModified: c.now()}, nil
}

func (c *Client) createMultipart(ctx context.Context, key string) (string, error) {
	resp, err := c.send(ctx, request{
		op:          "CreateMultipartUpload",
		method:      http.MethodPost,
		url:         c.objectURLRaw(key, "uploads"),
		payloadHash: emptyPayloadSHA256,
	})
	if err != nil {
		return "", err
	}
	if resp.StatusCode/100 != 2 {
		return "", parseAPIError("CreateMultipartUpload", key, resp)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("r2: 读取 CreateMultipartUpload 响应失败: %w", err)
	}
	var parsed initiateMultipartXML
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("r2: 解析 CreateMultipartUpload 响应失败: %w", err)
	}
	if parsed.UploadID == "" {
		return "", errors.New("r2: 服务端未返回 UploadId")
	}
	return parsed.UploadID, nil
}

func (c *Client) abortMultipart(ctx context.Context, key, uploadID string) error {
	resp, err := c.send(ctx, request{
		op:          "AbortMultipartUpload",
		method:      http.MethodDelete,
		url:         c.objectURLRaw(key, buildQuery([2]string{"uploadId", uploadID})),
		payloadHash: emptyPayloadSHA256,
	})
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 && resp.StatusCode != http.StatusNoContent {
		return parseAPIError("AbortMultipartUpload", key, resp)
	}
	drainAndClose(resp)
	return nil
}

// Head 探测对象是否存在及其大小。
func (c *Client) Head(ctx context.Context, key string) (ObjectInfo, error) {
	var info ObjectInfo
	resp, err := c.send(ctx, request{
		op:          "HeadObject",
		method:      http.MethodHead,
		url:         c.objectURL(key, nil),
		payloadHash: emptyPayloadSHA256,
	})
	if err != nil {
		return info, err
	}
	if resp.StatusCode/100 != 2 {
		return info, parseAPIError("HeadObject", key, resp)
	}
	drainAndClose(resp)
	info = ObjectInfo{
		Key:  key,
		Size: parseContentLength(resp),
		ETag: strings.Trim(resp.Header.Get("ETag"), `"`),
	}
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		if t, perr := http.ParseTime(lm); perr == nil {
			info.LastModified = t
		}
	}
	return info, nil
}

// List 列举以 prefix 开头的对象，最多返回 limit 个（limit<=0 表示不限）。
// 自动翻页，结果按 Key 升序。
func (c *Client) List(ctx context.Context, prefix string, limit int) ([]ObjectInfo, error) {
	var out []ObjectInfo
	token := ""
	for {
		pairs := [][2]string{
			{"list-type", "2"},
			{"prefix", prefix},
		}
		if token != "" {
			pairs = append(pairs, [2]string{"continuation-token", token})
		}
		if limit > 0 {
			remain := limit - len(out)
			if remain <= 0 {
				return out, nil
			}
			pairs = append(pairs, [2]string{"max-keys", fmt.Sprintf("%d", minInt(remain, 1000))})
		}
		resp, err := c.send(ctx, request{
			op:          "ListObjectsV2",
			method:      http.MethodGet,
			url:         c.objectURLRaw("", buildQuery(pairs...)),
			payloadHash: emptyPayloadSHA256,
		})
		if err != nil {
			return nil, err
		}
		if resp.StatusCode/100 != 2 {
			return nil, parseAPIError("ListObjectsV2", prefix, resp)
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		drainAndClose(resp)
		if rerr != nil {
			return nil, fmt.Errorf("r2: 读取列举响应失败: %w", rerr)
		}
		var parsed listBucketResultXML
		if err := xml.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("r2: 解析列举响应失败: %w", err)
		}
		for _, o := range parsed.Contents {
			if o.Key == "" {
				continue
			}
			info := ObjectInfo{Key: o.Key, Size: o.Size, ETag: strings.Trim(o.ETag, `"`)}
			if o.LastModified != "" {
				if t, perr := time.Parse(time.RFC3339, o.LastModified); perr == nil {
					info.LastModified = t
				}
			}
			out = append(out, info)
		}
		if !parsed.IsTruncated || parsed.NextContinuationToken == "" {
			break
		}
		token = parsed.NextContinuationToken
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Download 下载对象到本地文件。
//
// 先写 `.part` 再改名：中途失败时不会留下一个"看起来完整"的半截文件。
// 写完会核对字节数与响应声明的长度，不一致按失败处理。
func (c *Client) Download(ctx context.Context, key, localPath string, progress ProgressFunc) (ObjectInfo, error) {
	var info ObjectInfo
	resp, err := c.send(ctx, request{
		op:          "GetObject",
		method:      http.MethodGet,
		url:         c.objectURL(key, nil),
		payloadHash: emptyPayloadSHA256,
	})
	if err != nil {
		return info, err
	}
	if resp.StatusCode/100 != 2 {
		return info, parseAPIError("GetObject", key, resp)
	}
	defer drainAndClose(resp)

	total := parseContentLength(resp)
	if total < 0 {
		total = 0
	}
	if progress != nil {
		progress(0, total)
	}

	tmp := localPath + ".part"
	out, err := os.OpenFile(fsutil.LongPath(tmp), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return info, fmt.Errorf("r2: 创建本地文件失败: %w", err)
	}
	var written int64
	if progress != nil {
		written, err = io.Copy(out, &progressReader{r: resp.Body, cb: progress, tot: total})
	} else {
		written, err = io.Copy(out, resp.Body)
	}
	closeErr := out.Close()
	if err != nil {
		_ = os.Remove(fsutil.LongPath(tmp))
		return info, fmt.Errorf("r2: 下载中断: %w", err)
	}
	if closeErr != nil {
		_ = os.Remove(fsutil.LongPath(tmp))
		return info, fmt.Errorf("r2: 写入本地文件失败: %w", closeErr)
	}
	if total > 0 && written != total {
		_ = os.Remove(fsutil.LongPath(tmp))
		return info, fmt.Errorf("r2: 下载长度不符（收到 %d 字节，声明 %d 字节），已丢弃", written, total)
	}
	if err := os.Rename(fsutil.LongPath(tmp), fsutil.LongPath(localPath)); err != nil {
		_ = os.Remove(fsutil.LongPath(tmp))
		return info, fmt.Errorf("r2: 保存下载文件失败: %w", err)
	}
	if progress != nil {
		progress(written, written)
	}
	return ObjectInfo{
		Key:          key,
		Size:         written,
		ETag:         strings.Trim(resp.Header.Get("ETag"), `"`),
		LastModified: parseLastModified(resp),
	}, nil
}

// Delete 删除远端对象。
func (c *Client) Delete(ctx context.Context, key string) error {
	resp, err := c.send(ctx, request{
		op:          "DeleteObject",
		method:      http.MethodDelete,
		url:         c.objectURL(key, nil),
		payloadHash: emptyPayloadSHA256,
	})
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 && resp.StatusCode != http.StatusNoContent {
		return parseAPIError("DeleteObject", key, resp)
	}
	drainAndClose(resp)
	return nil
}

// ---- 权限自检 ----

// ListBuckets 列举该凭据可见的全部桶（`GET /`）。
//
// 存在的唯一目的是**权限过大检测**，不是给人用来浏览桶的。
//
// R2 控制台能签发的长效 API token 只有四档权限：
//
//	Admin Read & Write / Admin Read only / Object Read & Write / Object Read only
//
// 后两档是**桶级**的，调 ListBuckets 会被拒（403）；前两档是**账户级**的，
// 才能列举出桶。所以"能列举桶"这一个事实，就等价于
// "这份 token 的权限远超上传备份所需要的最小权限"。
//
// 因此调用方应当把 403 当作**通过**：那是期望中的结果。
func (c *Client) ListBuckets(ctx context.Context) ([]string, error) {
	u := *c.base
	u.Path = "/"
	u.RawPath = "/"
	resp, err := c.send(ctx, request{
		op:          "ListBuckets",
		method:      http.MethodGet,
		url:         &u,
		payloadHash: emptyPayloadSHA256,
	})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, parseAPIError("ListBuckets", "/", resp)
	}
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	drainAndClose(resp)
	if rerr != nil {
		return nil, fmt.Errorf("r2: 读取桶列表失败: %w", rerr)
	}
	var parsed listAllMyBucketsResultXML
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("r2: 解析桶列表失败: %w", err)
	}
	var names []string
	for _, b := range parsed.Buckets.Bucket {
		if b.Name != "" {
			names = append(names, b.Name)
		}
	}
	return names, nil
}

// ---- 内部工具 ----

// objectURLRaw 用**已经编码好的**查询串构造 URL。
//
// 为什么不用 url.Values：`url.Values.Encode()` 会把空格编成 `+`，
// 而 SigV4 要求 `%20`；两者不一致会让含空格的参数拒签。
// 这里统一由 buildQuery 用 uriEncode 生成，发出去的和参与签名的是同一串字节。
func (c *Client) objectURLRaw(key, rawQuery string) *url.URL {
	u := c.objectURL(key, nil)
	u.RawQuery = rawQuery
	return u
}

// buildQuery 生成规范查询串：URI 编码后按键名（再按值）排序。
func buildQuery(pairs ...[2]string) string {
	type kv struct{ k, v string }
	list := make([]kv, 0, len(pairs))
	for _, p := range pairs {
		if p[0] == "" {
			continue
		}
		list = append(list, kv{uriEncode(p[0], true), uriEncode(p[1], true)})
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

// hashReader 从头读 len 字节计算 SHA-256，读完把游标交还给调用方（由 send 重置）。
func hashReader(r io.ReadSeeker, size int64) (string, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("r2: 定位请求体失败: %w", err)
	}
	h := sha256.New()
	if _, err := io.CopyN(h, r, size); err != nil {
		return "", fmt.Errorf("r2: 计算载荷摘要失败: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// hashFileRegion 计算文件 [off, off+n) 区间的 SHA-256。
func hashFileRegion(f io.ReadSeeker, off, n int64) (string, error) {
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return "", fmt.Errorf("r2: 定位分片失败: %w", err)
	}
	h := sha256.New()
	if _, err := io.CopyN(h, f, n); err != nil {
		return "", fmt.Errorf("r2: 计算分片摘要失败: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// regionReader 把文件的 [start, end) 区间当成独立请求体。
//
// 用 ReadAt 而不是共享的文件游标：hashFileRegion 会在同一个 *os.File 上移动游标，
// 两者共用游标就会互相踩。ReadAt 自带偏移，天然隔离。
type regionReader struct {
	f     *os.File
	start int64
	end   int64
	pos   int64
}

func newRegionReader(f *os.File, off, n int64) *regionReader {
	return &regionReader{f: f, start: off, end: off + n, pos: off}
}

func (r *regionReader) Read(b []byte) (int, error) {
	if r.pos >= r.end {
		return 0, io.EOF
	}
	if int64(len(b)) > r.end-r.pos {
		b = b[:r.end-r.pos]
	}
	n, err := r.f.ReadAt(b, r.pos)
	r.pos += int64(n)
	if r.pos >= r.end {
		// 恰好读到区间末尾：本次正常返回，EOF 留给下一次 Read。
		return n, nil
	}
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return n, err
	}
	return n, nil
}

// Seek 支持按需回绕：send 在每次尝试前会 Seek(0, SeekStart)，
// 这里翻译成"回到区间起点"，使得重试能重发完整分片。
func (r *regionReader) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		r.pos = r.start + offset
	case io.SeekCurrent:
		r.pos += offset
	case io.SeekEnd:
		r.pos = r.end + offset
	default:
		return 0, errors.New("r2: 非法的 Seek whence")
	}
	if r.pos < r.start || r.pos > r.end {
		return 0, fmt.Errorf("r2: Seek 越出分片范围（%d 不在 [%d, %d]）", r.pos, r.start, r.end)
	}
	return r.pos, nil
}

// bytesReadSeeker 把内存字节当成可回绕的读入源。
type bytesReadSeeker struct {
	b   []byte
	pos int64
}

func newBytesReadSeeker(b []byte) *bytesReadSeeker { return &bytesReadSeeker{b: b} }

func (s *bytesReadSeeker) Read(p []byte) (int, error) {
	if s.pos >= int64(len(s.b)) {
		return 0, io.EOF
	}
	n := copy(p, s.b[s.pos:])
	s.pos += int64(n)
	return n, nil
}

func (s *bytesReadSeeker) Seek(offset int64, whence int) (int64, error) {
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = s.pos + offset
	case io.SeekEnd:
		abs = int64(len(s.b)) + offset
	default:
		return 0, errors.New("r2: 非法的 Seek whence")
	}
	if abs < 0 {
		return 0, errors.New("r2: Seek 到负偏移")
	}
	s.pos = abs
	return abs, nil
}

func parseContentLength(resp *http.Response) int64 {
	if resp.ContentLength >= 0 {
		return resp.ContentLength
	}
	if v := resp.Header.Get("Content-Length"); v != "" {
		var n int64
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	}
	return -1
}

func parseLastModified(resp *http.Response) time.Time {
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		if t, err := http.ParseTime(lm); err == nil {
			return t
		}
	}
	return time.Time{}
}

// roundUpMiB 向上取整到 MiB，避免出现非整的分片大小。
func roundUpMiB(n int64) int64 {
	const mib = 1 << 20
	if n <= 0 {
		return mib
	}
	return ((n + mib - 1) / mib) * mib
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
