package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/immml/UsbBackUP-R2/internal/config"
	"github.com/immml/UsbBackUP-R2/internal/cred"
	"github.com/immml/UsbBackUP-R2/internal/fsutil"
	"github.com/immml/UsbBackUP-R2/internal/keystore"
	"github.com/immml/UsbBackUP-R2/internal/r2"
	"github.com/immml/UsbBackUP-R2/internal/winvol"
)

// stubUploader 是可控的上传实现，用来只测**编排逻辑**。
//
// 真实 S3 协议（签名、分片、重试）由 internal/r2 的假 S3 服务端覆盖；
// 这里关心的是另一件事：流水线有没有在正确的时机传、传对了键、
// 核对结果之后怎么处置本地文件。
type stubUploader struct {
	mu sync.Mutex
	// uploaded 记录每次 UploadFile 的 (key, 字节数, 本地路径)。
	uploaded []uploadCall
	// headSize 是 Head 返回的远端大小；为 nil 时回显最后一次上传的字节数。
	headSize *int64
	// uploadErr / headErr 是注入的失败。
	uploadErr error
	headErr   error
	// headCalls 计 Head 调用次数，用于验证"核对不一致重传一次"。
	headCalls int
}

type uploadCall struct {
	key   string
	bytes int64
	local string
}

func (s *stubUploader) UploadFile(_ context.Context, localPath, key string, progress r2.ProgressFunc) (r2.ObjectInfo, error) {
	st, err := os.Stat(fsutil.LongPath(localPath))
	if err != nil {
		return r2.ObjectInfo{}, err
	}
	if progress != nil {
		progress(st.Size(), st.Size())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uploadErr != nil {
		return r2.ObjectInfo{}, s.uploadErr
	}
	s.uploaded = append(s.uploaded, uploadCall{key: key, bytes: st.Size(), local: localPath})
	return r2.ObjectInfo{Key: key, Size: st.Size(), ETag: "etag-stub"}, nil
}

func (s *stubUploader) Head(_ context.Context, key string) (r2.ObjectInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.headCalls++
	if s.headErr != nil {
		return r2.ObjectInfo{}, s.headErr
	}
	sz := int64(0)
	if len(s.uploaded) > 0 {
		sz = s.uploaded[len(s.uploaded)-1].bytes
	}
	if s.headSize != nil {
		sz = *s.headSize
	}
	return r2.ObjectInfo{Key: key, Size: sz, ETag: "etag-stub"}, nil
}

func (s *stubUploader) calls() []uploadCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]uploadCall, len(s.uploaded))
	copy(out, s.uploaded)
	return out
}

func (s *stubUploader) heads() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.headCalls
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

// writeProductFile 造一个假的"已加密产物"文件，返回路径与大小。
func writeProductFile(t *testing.T, dir string, size int) (string, int64) {
	t.Helper()
	p := filepath.Join(dir, "MyUSB.zip.usbk")
	body := make([]byte, size)
	for i := range body {
		body[i] = byte(i % 251)
	}
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return p, int64(size)
}

// ---- prepareUpload ----

func TestPrepareUploadDisabledReturnsNil(t *testing.T) {
	// 没开上传时返回 nil，而不是"一个空的上传通道"：
	// 调用方据此把结论写成 not-enabled，而不是"尝试过但失败"。
	cfg := config.Default()
	cfg.Upload.Enabled = false
	if plan := prepareUpload(cfg, Deps{Cfg: cfg}, discardLogger()); plan != nil {
		t.Fatalf("未开启上传应返回 nil，实际 %+v", plan)
	}
	if plan := prepareUpload(nil, Deps{}, discardLogger()); plan != nil {
		t.Fatal("配置为 nil 时应返回 nil")
	}
}

func TestPrepareUploadUnavailableExplainsCandidates(t *testing.T) {
	// 凭据找不到时必须报错**且列全候选路径**。现场最常见的问题是
	// "client.json 放错目录"，只说一句"凭据不存在"会让人来回试。
	appData := t.TempDir()
	t.Setenv("LOCALAPPDATA", appData)

	cfg := config.Default()
	cfg.Upload.Enabled = true
	cfg.Upload.CredentialFile = filepath.Join(t.TempDir(), "nope.json")

	deps := Deps{Cfg: cfg}
	plan := prepareUpload(cfg, deps, discardLogger())
	if plan == nil {
		t.Fatal("开启上传后不应返回 nil（要能报出原因）")
	}
	if plan.client != nil {
		t.Fatal("凭据不存在时不应有可用客户端")
	}
	if plan.reason == "" {
		t.Fatal("必须给出不可用的原因")
	}
	for _, want := range []string{CredentialFileName, appData} {
		if !strings.Contains(plan.reason, want) {
			t.Errorf("原因里应包含候选信息 %q，实际 %q", want, plan.reason)
		}
	}
}

func TestPrepareUploadInjectedUploaderSkipsCredential(t *testing.T) {
	// 注入实现（联调/测试）优先，且不要求本机存在 DPAPI 凭据文件。
	cfg := config.Default()
	cfg.Upload.Enabled = true
	stub := &stubUploader{}
	plan := prepareUpload(cfg, Deps{Cfg: cfg, Uploader: stub}, discardLogger())
	if plan == nil || plan.client == nil {
		t.Fatal("注入的 Uploader 应被采用")
	}
	if plan.prefix != cred.DefaultPrefix {
		t.Errorf("未给前缀时应回落到默认前缀 %q，实际 %q", cred.DefaultPrefix, plan.prefix)
	}
	plan.Close() // creds 为空，应是安全的空操作
}

// ---- uploadProduct ----

func TestUploadProductUsesGivenKeyAndVerifiesSize(t *testing.T) {
	dir := t.TempDir()
	path, size := writeProductFile(t, dir, 4096)
	stub := &stubUploader{}
	plan := &uploadPlan{client: stub, bucket: "b", endpoint: "https://x"}

	cfg := config.Default()
	cfg.Upload.UploadTimeoutMin = 0

	res, err := uploadProduct(context.Background(), cfg, plan, discardLogger(), path, "usb/k.zip.usbk", size)
	if err != nil {
		t.Fatalf("上传应成功: %v", err)
	}
	if !res.OK || res.Result != Uploaded {
		t.Fatalf("结论应为 uploaded，实际 %+v", res)
	}
	if res.Bytes != size || res.ETag != "etag-stub" {
		t.Fatalf("结果字段不符: %+v", res)
	}
	calls := stub.calls()
	if len(calls) != 1 || calls[0].key != "usb/k.zip.usbk" {
		t.Fatalf("应以给定键上传一次，实际 %+v", calls)
	}
	if stub.heads() != 1 {
		t.Fatalf("应核对一次远端大小，实际 %d 次", stub.heads())
	}
}

func TestUploadProductRetriesOnceWhenRemoteSizeMismatches(t *testing.T) {
	// 远端大小与本地不一致 = 传输链路出了问题。直接判失败会让人以为
	// "再跑一次就行"；重传一次的成本远低于一次误判。
	dir := t.TempDir()
	path, size := writeProductFile(t, dir, 2048)
	wrong := size - 100
	stub := &stubUploader{headSize: &wrong}
	plan := &uploadPlan{client: stub, bucket: "b"}

	res, _ := uploadProduct(context.Background(), config.Default(), plan, discardLogger(),
		path, "k", size)

	// 每次核对都返回同一个错误大小 → 两次都没通过，结论为失败。
	if res.OK {
		t.Fatal("远端大小始终不符时不应判成功")
	}
	if res.Result != UploadFailed {
		t.Fatalf("结论应为 failed，实际 %q", res.Result)
	}
	if len(stub.calls()) != 2 {
		t.Fatalf("应重传一次（共两次），实际 %d 次", len(stub.calls()))
	}
	if !strings.Contains(res.Err, "大小不符") {
		t.Fatalf("错误信息应点明大小不符，实际 %q", res.Err)
	}

	// 第二次核对一致 → 应判成功，且仍然只重传一次。
	stub2 := &stubUploader{}
	plan2 := &uploadPlan{client: stub2, bucket: "b"}
	if _, err := uploadProduct(context.Background(), config.Default(), plan2, discardLogger(),
		path, "k", size); err != nil {
		t.Fatalf("大小一致时应成功: %v", err)
	}
	if len(stub2.calls()) != 1 {
		t.Fatalf("大小一致时不应重传，实际 %d 次", len(stub2.calls()))
	}
}

func TestUploadProductReportsForbiddenWithoutRetrying(t *testing.T) {
	dir := t.TempDir()
	path, size := writeProductFile(t, dir, 128)
	forbidden := &r2.APIError{StatusCode: http.StatusForbidden, Code: "AccessDenied", Message: "denied"}
	stub := &stubUploader{uploadErr: fmt.Errorf("put: %w", forbidden)}
	plan := &uploadPlan{client: stub, bucket: "b"}

	res, err := uploadProduct(context.Background(), config.Default(), plan, discardLogger(), path, "k", size)
	if err == nil {
		t.Fatal("被拒绝时应返回错误")
	}
	if res.Result != UploadFailed {
		t.Fatalf("结论应为 failed，实际 %q", res.Result)
	}
	// 403 是权限问题，重试没有意义。
	if len(stub.calls()) != 0 {
		t.Fatalf("权限错误不应产生成功记录，实际 %+v", stub.calls())
	}
	if !r2.IsForbidden(err) {
		t.Fatal("错误链里应能识别出 403，供调用方给出针对性提示")
	}
}

// ---- applyLocalPolicy ----

func TestApplyLocalPolicyMatrix(t *testing.T) {
	cases := []struct {
		name        string
		uploadOK    bool
		attempted   bool
		deleteAfter bool
		keepOnFail  bool
		wantAction  string
		wantGone    bool
	}{
		{"上传成功且配置删除", true, true, true, true, "deleted", true},
		{"上传成功但配置保留", true, true, false, true, "kept", false},
		{"上传失败默认保留", false, true, true, true, "kept", false},
		{"上传失败且明确关掉保留", false, true, true, false, "deleted", true},
		{"根本没尝试（凭据不可用）", false, false, true, true, "kept", false},
		{"根本没尝试且配置要删也不删", false, false, true, false, "kept", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path, _ := writeProductFile(t, dir, 64)
			cfg := config.Default()
			cfg.Upload.DeleteLocalAfterUpload = tc.deleteAfter
			cfg.Upload.KeepLocalOnFailure = tc.keepOnFail

			res := &UploadResult{OK: tc.uploadOK, Attempted: tc.attempted}
			applyLocalPolicy(cfg, Deps{}, res, path, discardLogger())

			if res.LocalAction != tc.wantAction {
				t.Fatalf("LocalAction = %q，期望 %q", res.LocalAction, tc.wantAction)
			}
			_, err := os.Stat(path)
			gone := errors.Is(err, os.ErrNotExist)
			if gone != tc.wantGone {
				t.Fatalf("文件是否被删 = %v，期望 %v", gone, tc.wantGone)
			}
		})
	}
}

func TestApplyLocalPolicyNeverDeletesInDryRun(t *testing.T) {
	dir := t.TempDir()
	path, _ := writeProductFile(t, dir, 64)
	cfg := config.Default()
	cfg.Upload.DeleteLocalAfterUpload = true

	res := &UploadResult{OK: true, Attempted: true}
	applyLocalPolicy(cfg, Deps{DryRun: true}, res, path, discardLogger())
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("dry-run 绝不能删文件: %v", err)
	}
}

// ---- 辅助函数 ----

func TestSanitizeObjectNameStripsSeparators(t *testing.T) {
	// 净化只保证"名字部分是单一组件"：不含任何路径分隔符、不是空串、不是 . / ..
	// 分隔符会被替换成下划线（fsutil.SanitizeName 的既定行为），
	// 残留的 ".." 因为已经没有层级而失去逃逸能力。
	cases := map[string]string{
		"MyUSB.zip.usbk":    "MyUSB.zip.usbk",
		"a/b/c.usbk":        "a_b_c.usbk",
		`C:\Windows\x.usbk`: "C__Windows_x.usbk",
		"  .zip.usbk  ":     "zip.usbk",
		"....":              "backup.usbk",
		"":                  "backup.usbk",
		".":                 "backup.usbk",
		"..":                "backup.usbk",
	}
	for in, want := range cases {
		got := sanitizeObjectName(in)
		if got != want {
			t.Errorf("sanitizeObjectName(%q) = %q，期望 %q", in, got, want)
		}
		if strings.ContainsAny(got, `/\`) {
			t.Errorf("净化结果 %q 仍含路径分隔符", got)
		}
		if got == ".." || got == "." || strings.TrimSpace(got) == "" {
			t.Errorf("净化结果 %q 是危险或空的名字", got)
		}
	}
}

// ObjectKey 的名字部分来自卷标（人可以随便起），必须永远是单组件。
//
// 注意 ObjectKey 内部先走 filepath.Base 再净化，所以真正的入口
// ProductName 已经削过一层。这里测的是**纵深防御**：即使有人绕过前者，
// 对象键也不能跑到前缀之外。
func TestObjectKeyStaysInsidePrefix(t *testing.T) {
	at := time.Date(2026, 9, 18, 13, 40, 0, 0, time.UTC)
	for _, bad := range []string{
		`..\..\evil.usbk`, "../../evil.usbk", `C:\Windows\x.usbk`, "a/b/c.usbk", "..", ".",
	} {
		got := ObjectKey("usb/", bad, at)
		if !strings.HasPrefix(got, "usb/") {
			t.Errorf("对象键 %q 未落在前缀内（输入 %q）", got, bad)
		}
		rest := strings.TrimPrefix(got, "usb/")
		if strings.ContainsAny(rest, `/\`) {
			t.Errorf("对象键名字部分 %q 含分隔符（输入 %q）", rest, bad)
		}
		if rest == ".." || rest == "." {
			t.Errorf("对象键名字部分 %q 有穿越嫌疑（输入 %q）", rest, bad)
		}
	}
}

func TestResolveCredentialPathPrefersConfiguredFile(t *testing.T) {
	appData := t.TempDir()
	t.Setenv("LOCALAPPDATA", appData)

	dir := t.TempDir()
	cfg := config.Default()
	cfg.Upload.CredentialFile = filepath.Join(dir, "custom.json")

	// 指定文件不存在 → 回落到 LOCALAPPDATA 下的标准名。
	fallback := filepath.Join(appData, "usbbackup-r2", CredentialFileName)
	if err := os.MkdirAll(filepath.Dir(fallback), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fallback, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, cands := ResolveCredentialPath(cfg)
	if got != fallback {
		t.Fatalf("应回落到 %s，实际 %q（候选 %v）", fallback, got, cands)
	}

	// 指定文件存在 → 优先命中它。
	if err := os.WriteFile(cfg.Upload.CredentialFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, _ = ResolveCredentialPath(cfg)
	if got != cfg.Upload.CredentialFile {
		t.Fatalf("应优先命中显式配置的路径，实际 %q", got)
	}
}

func TestResolveCredentialPathResolvesRelativeToExeDir(t *testing.T) {
	// 客户端场景：生成器把 client.json 与 client.exe 放一起，
	// 配置里写的是**相对名**。相对名必须按"可执行文件同目录"解析，
	// 否则现场只拷了 exe 时会静默退回本地模式。
	cfg := config.Default()
	cfg.Upload.CredentialFile = "client.json"

	exe, err := os.Executable()
	if err != nil {
		t.Skip("取不到可执行文件路径")
	}
	target := filepath.Join(filepath.Dir(exe), "client.json")
	if _, err := os.Stat(target); err == nil {
		t.Skip("测试二进制同目录已存在 client.json，跳过以免污染")
	}
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Skipf("无法在测试二进制目录写文件: %v", err)
	}
	defer os.Remove(target)

	got, _ := ResolveCredentialPath(cfg)
	if got != target {
		t.Fatalf("相对名应按 exe 同目录解析为 %s，实际 %q", target, got)
	}
}

// ---- 端到端：subst 造卷 + 真实 r2 客户端 + 记录型服务端 ----

// recordingS3 是一个"只记录"的 S3 假服务端。
//
// 它**不校验签名**——签名与分片协议的正确性由 internal/r2 的假 S3 服务端
// 用独立实现交叉验证。这里要证的是另一件事：流水线把正确的对象键、
// 正确的字节数送了出去，并按核对结果处置了本地文件。
type recordingS3 struct {
	mu       sync.Mutex
	puts     []putRecord
	headSize map[string]int64
}

type putRecord struct {
	path string
	size int64
}

func (s *recordingS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut:
		n, _ := io.Copy(io.Discard, r.Body)
		s.mu.Lock()
		s.puts = append(s.puts, putRecord{path: r.URL.Path, size: n})
		if s.headSize == nil {
			s.headSize = map[string]int64{}
		}
		s.headSize[r.URL.Path] = n
		s.mu.Unlock()
		w.Header().Set("ETag", `"rec-etag"`)
		w.WriteHeader(http.StatusOK)
	case http.MethodHead:
		s.mu.Lock()
		size, ok := s.headSize[r.URL.Path]
		s.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(size))
		w.Header().Set("ETag", `"rec-etag"`)
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *recordingS3) records() []putRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]putRecord, len(s.puts))
	copy(out, s.puts)
	return out
}

// substDrive 把目录挂成一个新盘符（本机没有可移动介质时的既定做法）。
// 返回盘符（如 "X:"）与清理函数；失败时返回错误由调用方 Skip。
func substDrive(t *testing.T, dir string) (string, func()) {
	t.Helper()
	// 挑一个当前不存在的盘符，避免踩到真实磁盘。
	for _, letter := range "XYZWVUTSRQ" {
		drive := string(letter) + ":"
		if _, err := os.Stat(drive + `\`); err == nil {
			continue // 已被占用
		}
		cmd := exec.Command("subst", drive, dir)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", nil
		}
		_ = out
		if _, err := os.Stat(drive + `\`); err != nil {
			continue
		}
		return drive, func() {
			_ = exec.Command("subst", drive, "/D").Run()
		}
	}
	return "", nil
}

func TestRunUploadsProductAndRemovesLocalCopy(t *testing.T) {
	// 这条是"自动上传"这条需求的端到端证据：
	// subst 造一块可写卷 → 流水线打包加密 → 真实 r2 客户端上传 → 核对 → 删本地。
	//
	// 本机没有可移动介质时 subst 会失败，此时跳过（README 里另有手工验证步骤）。
	srcRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcRoot, "a.txt"), []byte("hello world"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(srcRoot, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcRoot, "sub", "b.bin"), []byte(strings.Repeat("x", 5000)), 0o600); err != nil {
		t.Fatal(err)
	}

	drive, cleanup := substDrive(t, srcRoot)
	if drive == "" {
		t.Skip("本机无法用 subst 造卷（或所有候选盘符都被占用），跳过端到端上传验证")
	}
	defer cleanup()

	// 密钥：只生成公钥用于加密（本测试不解密）。
	keyDir := t.TempDir()
	kp, err := keystore.Generate(keystore.GenerateOptions{Bits: 2048, OutDir: keyDir})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := keystore.LoadPublicKey(kp.PublicPath)
	if err != nil {
		t.Fatal(err)
	}

	// 假服务端 + 凭据文件（走真实的 cred.Load → r2.New 路径）。
	rec := &recordingS3{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	credPath := filepath.Join(t.TempDir(), "client.json")
	if err := cred.Save(credPath, cred.Credentials{
		AccountID:       "acct",
		Bucket:          "mybucket",
		Endpoint:        srv.URL,
		Region:          "auto",
		Prefix:          "usb/",
		Scope:           cred.ScopeUpload,
		AccessKeyID:     []byte("AKIDEXAMPLE"),
		SecretAccessKey: []byte("secret-example-key"),
	}); err != nil {
		t.Fatalf("写凭据文件失败: %v", err)
	}

	outDir := t.TempDir()
	cfg := config.Default()
	cfg.OutputDir = outDir
	cfg.AuditFile = filepath.Join(t.TempDir(), "audit.jsonl")
	cfg.PublicKeyPath = kp.PublicPath
	cfg.Gate.UsedThresholdBytes = 1 << 62 // subst 卷报的是宿主盘容量，必须放宽门控
	cfg.Gate.MaxTotalBytes = 0
	cfg.Retention.KeepPerVolume = 5
	cfg.Upload.Enabled = true
	cfg.Upload.CredentialFile = credPath
	cfg.Upload.DeleteLocalAfterUpload = true
	cfg.Upload.KeepLocalOnFailure = true
	cfg.Upload.UploadTimeoutMin = 0

	deps := Deps{
		Cfg:               cfg,
		Log:               discardLogger(),
		AllowFixed:        true, // subst 卷是 DRIVE_FIXED
		EmbeddedPublicKey: pub,
	}

	res, err := Run(context.Background(), deps, drive)
	if err != nil {
		t.Fatalf("作业失败: %v（branch=%s err=%s）", err, res.Branch, res.Err)
	}
	if res.Branch != BranchArchive {
		t.Fatalf("应走 archive-encrypt 分支，实际 %s（原因 %s）", res.Branch, res.SkipReason)
	}
	if !res.OK {
		t.Fatalf("作业应成功: %+v", res)
	}
	if res.Upload.Result != Uploaded {
		t.Fatalf("应上传成功，实际 %q（err=%s）", res.Upload.Result, res.Upload.Err)
	}
	if res.Upload.Bytes != res.Encrypt.CipherBytes {
		t.Fatalf("上传字节数 %d 应等于密文长度 %d", res.Upload.Bytes, res.Encrypt.CipherBytes)
	}

	recs := rec.records()
	if len(recs) != 1 {
		t.Fatalf("服务端应收到一次 PUT，实际 %d 次: %+v", len(recs), recs)
	}
	// 键形如 /mybucket/usb/<UTC时间戳>_<产物名>：前缀锁定落点，
	// 时间戳保证同一块盘的多次采集不会在远端静默覆盖。
	wantRest := filepath.Base(res.ProductPath)
	gotPath := recs[0].path
	if !strings.HasPrefix(gotPath, "/mybucket/usb/") || !strings.HasSuffix(gotPath, "_"+wantRest) {
		t.Fatalf("对象路径 = %q，应以 /mybucket/usb/ 开头并以 _%s 结尾", gotPath, wantRest)
	}
	stamp := strings.TrimSuffix(strings.TrimPrefix(gotPath, "/mybucket/usb/"), "_"+wantRest)
	if len(stamp) != 16 || !strings.HasSuffix(stamp, "Z") {
		t.Fatalf("对象键里的时间戳格式不对: %q（整键 %q）", stamp, gotPath)
	}
	if recs[0].size != res.Encrypt.CipherBytes {
		t.Fatalf("服务端收到的字节数 %d 与密文长度 %d 不符", recs[0].size, res.Encrypt.CipherBytes)
	}

	// 上传核对通过 + 配置删除 → 本地不应再留一份。
	if _, err := os.Stat(res.ProductPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("上传成功后本地产物应被删除: %v", err)
	}
	if res.Upload.LocalAction != "deleted" {
		t.Fatalf("LocalAction 应为 deleted，实际 %q", res.Upload.LocalAction)
	}

	// 审计里要能看出"传到哪儿了"，且不得出现凭据材料。
	raw, err := os.ReadFile(cfg.AuditFile)
	if err != nil {
		t.Fatal(err)
	}
	line := string(raw)
	for _, want := range []string{`"upload_result":"uploaded"`, `"r2_bucket":"mybucket"`, `"r2_object_key":"usb/`} {
		if !strings.Contains(line, want) {
			t.Errorf("审计缺少 %s：%s", want, line)
		}
	}
	for _, forbidden := range []string{"secret-example-key", "AKIDEXAMPLE", "aws4_request", "signature"} {
		if strings.Contains(line, forbidden) {
			t.Errorf("审计泄露了敏感内容 %q：%s", forbidden, line)
		}
	}
}

func TestRunKeepsLocalProductWhenUploadDisabled(t *testing.T) {
	// 不开上传时：产物必须留在本地，且结论不能写成"上传失败"。
	srcRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcRoot, "a.txt"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	drive, cleanup := substDrive(t, srcRoot)
	if drive == "" {
		t.Skip("本机无法用 subst 造卷，跳过")
	}
	defer cleanup()

	keyDir := t.TempDir()
	kp, err := keystore.Generate(keystore.GenerateOptions{Bits: 2048, OutDir: keyDir})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := keystore.LoadPublicKey(kp.PublicPath)
	if err != nil {
		t.Fatal(err)
	}

	outDir := t.TempDir()
	cfg := config.Default()
	cfg.OutputDir = outDir
	cfg.AuditFile = filepath.Join(t.TempDir(), "audit.jsonl")
	cfg.PublicKeyPath = kp.PublicPath
	cfg.Gate.UsedThresholdBytes = 1 << 62
	cfg.Gate.MaxTotalBytes = 0
	cfg.Upload.Enabled = false

	deps := Deps{Cfg: cfg, Log: discardLogger(), AllowFixed: true, EmbeddedPublicKey: pub}
	res, err := Run(context.Background(), deps, drive)
	if err != nil {
		t.Fatalf("作业失败: %v", err)
	}
	if res.Upload.Result != UploadNotEnabled {
		t.Fatalf("结论应为 %q，实际 %q", UploadNotEnabled, res.Upload.Result)
	}
	if res.Upload.Attempted {
		t.Fatal("未开启上传时不应算作尝试过")
	}
	if res.Upload.LocalAction != "kept" {
		t.Fatalf("本地应保留，实际 %q", res.Upload.LocalAction)
	}
	if _, err := os.Stat(res.ProductPath); err != nil {
		t.Fatalf("本地产物应存在: %v", err)
	}
	if !res.OK {
		t.Fatalf("作业应成功: %+v", res)
	}
}

func TestRunKeepsLocalProductWhenUploadFails(t *testing.T) {
	// 上传失败**不能**把整次作业判成失败（D-19）：本地已经有一份完好的密文，
	// 真正的处置是保留本地 + 记审计 + 事后补传。
	srcRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcRoot, "a.txt"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	drive, cleanup := substDrive(t, srcRoot)
	if drive == "" {
		t.Skip("本机无法用 subst 造卷，跳过")
	}
	defer cleanup()

	keyDir := t.TempDir()
	kp, err := keystore.Generate(keystore.GenerateOptions{Bits: 2048, OutDir: keyDir})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := keystore.LoadPublicKey(kp.PublicPath)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.OutputDir = t.TempDir()
	cfg.AuditFile = filepath.Join(t.TempDir(), "audit.jsonl")
	cfg.PublicKeyPath = kp.PublicPath
	cfg.Gate.UsedThresholdBytes = 1 << 62
	cfg.Gate.MaxTotalBytes = 0
	cfg.Upload.Enabled = true
	cfg.Upload.DeleteLocalAfterUpload = true
	cfg.Upload.KeepLocalOnFailure = true

	deps := Deps{
		Cfg: cfg, Log: discardLogger(), AllowFixed: true, EmbeddedPublicKey: pub,
		Uploader: &stubUploader{uploadErr: errors.New("network unreachable")},
	}
	res, err := Run(context.Background(), deps, drive)
	if err != nil {
		t.Fatalf("作业本身不应因上传失败而报错: %v", err)
	}
	if !res.OK {
		t.Fatalf("作业应判成功（本地产物完好），实际 %+v", res)
	}
	if res.Upload.Result != UploadFailed {
		t.Fatalf("上传结论应为 failed，实际 %q", res.Upload.Result)
	}
	if _, err := os.Stat(res.ProductPath); err != nil {
		t.Fatalf("上传失败时必须保留本地产物以便补传: %v", err)
	}
}

func TestRunSkipsBeforeAnyUploadAttemptOnExemptVolume(t *testing.T) {
	// 授权标记豁免必须发生在**任何打包动作之前**：这块盘上可能有私钥，
	// 一旦先打包再判定，私钥就已经离开介质了。
	srcRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(srcRoot, "keys"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcRoot, "keys", "usbbackup-r2.key.pem"),
		[]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcRoot, ".usbbackup-allow"), []byte("fingerprint=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	drive, cleanup := substDrive(t, srcRoot)
	if drive == "" {
		t.Skip("本机无法用 subst 造卷，跳过")
	}
	defer cleanup()

	keyDir := t.TempDir()
	kp, err := keystore.Generate(keystore.GenerateOptions{Bits: 2048, OutDir: keyDir})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := keystore.LoadPublicKey(kp.PublicPath)
	if err != nil {
		t.Fatal(err)
	}

	outDir := t.TempDir()
	stub := &stubUploader{}
	cfg := config.Default()
	cfg.OutputDir = outDir
	cfg.AuditFile = filepath.Join(t.TempDir(), "audit.jsonl")
	cfg.PublicKeyPath = kp.PublicPath
	cfg.Gate.UsedThresholdBytes = 1 << 62
	cfg.Gate.MaxTotalBytes = 0
	cfg.Upload.Enabled = true
	cfg.Collect.Policy = "all" // 哪怕策略是全采，也必须豁免

	deps := Deps{
		Cfg: cfg, Log: discardLogger(), AllowFixed: true,
		EmbeddedPublicKey: pub, Uploader: stub,
	}
	res, err := Run(context.Background(), deps, drive)
	if err != nil {
		t.Fatalf("作业不应报错: %v", err)
	}
	if res.Branch != BranchSkipped || res.SkipReason != SkipReasonExemptMarker {
		t.Fatalf("应因授权标记跳过，实际 branch=%s reason=%s", res.Branch, res.SkipReason)
	}
	if res.Zip.Files != 0 || res.Encrypt.CipherBytes != 0 {
		t.Fatalf("豁免时不应打包任何东西: %+v", res.Zip)
	}
	if len(stub.calls()) != 0 {
		t.Fatal("豁免时不应发起任何上传")
	}
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("豁免时输出目录必须为空，实际 %d 个文件", len(entries))
	}
}

// 复现多分区介质的真实情形（2026-09-20 部署实测踩到的那次）：
// 本次作业的卷**自己没有任何标记**，但同一块物理磁盘上的另一个卷根带着磁盘级标记
// —— 比如 Ventoy 盘的固件分区 vs 数据分区。必须整盘豁免，且豁免发生在任何打包动作之前。
func TestRunSkipsWhenSiblingVolumeCarriesDiskMarker(t *testing.T) {
	jobRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(jobRoot, "firmware.bin"), []byte("EFI PART"), 0o600); err != nil {
		t.Fatal(err)
	}
	markerRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(markerRoot, ".usbbackup-allow-disk"),
		[]byte("fingerprint=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	drive, cleanup := substDrive(t, jobRoot)
	if drive == "" {
		t.Skip("本机无法用 subst 造卷，跳过")
	}
	defer cleanup()

	keyDir := t.TempDir()
	kp, err := keystore.Generate(keystore.GenerateOptions{Bits: 2048, OutDir: keyDir})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := keystore.LoadPublicKey(kp.PublicPath)
	if err != nil {
		t.Fatal(err)
	}

	outDir := t.TempDir()
	auditFile := filepath.Join(t.TempDir(), "audit.jsonl")
	stub := &stubUploader{}
	cfg := config.Default()
	cfg.OutputDir = outDir
	cfg.AuditFile = auditFile
	cfg.PublicKeyPath = kp.PublicPath
	cfg.Gate.UsedThresholdBytes = 1 << 62
	cfg.Gate.MaxTotalBytes = 0
	cfg.Upload.Enabled = true
	cfg.Collect.Policy = "all" // 哪怕策略是全采，也必须豁免

	deps := Deps{
		Cfg: cfg, Log: discardLogger(), AllowFixed: true,
		EmbeddedPublicKey: pub, Uploader: stub,
		// 注入"这两个卷根同属一块物理磁盘"。真机上的实现由 winvol 负责。
		SameDiskRoots: func(string) ([]string, error) {
			return []string{markerRoot, drive}, nil
		},
	}
	res, err := Run(context.Background(), deps, drive)
	if err != nil {
		t.Fatalf("作业不应报错: %v", err)
	}
	if res.Branch != BranchSkipped || res.SkipReason != SkipReasonExemptDiskMarker {
		t.Fatalf("应因同盘磁盘级标记跳过，实际 branch=%s reason=%s", res.Branch, res.SkipReason)
	}
	if res.Collect.ExemptMarkerFound || !res.Collect.ExemptDiskMarkerFound {
		t.Fatalf("应记录为磁盘级豁免（而非卷级）：%+v", res.Collect)
	}
	if res.Collect.ExemptDiskMarkerRoot != markerRoot {
		t.Fatalf("审计要能说清凭什么豁免，命中的卷根 = %q，期望 %q",
			res.Collect.ExemptDiskMarkerRoot, markerRoot)
	}
	if res.Zip.Files != 0 || res.Encrypt.CipherBytes != 0 {
		t.Fatalf("豁免时不应打包任何东西: %+v", res.Zip)
	}
	if len(stub.calls()) != 0 {
		t.Fatal("豁免时不应发起任何上传")
	}
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("豁免时输出目录必须为空，实际 %d 个文件", len(entries))
	}

	// 审计记录必须能与卷级豁免区分开：复盘时要能回答"为什么这一卷也跳过了"。
	raw, err := os.ReadFile(auditFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"exempt_disk_marker":true`) {
		t.Fatalf("审计未标记磁盘级豁免：%s", string(raw))
	}
	if !strings.Contains(string(raw), `"skip_reason":"`+SkipReasonExemptDiskMarker+`"`) {
		t.Fatalf("审计未记录磁盘级跳过原因：%s", string(raw))
	}
}

func TestRunPolicyOffSkipsWithoutReading(t *testing.T) {
	srcRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcRoot, "a.txt"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	drive, cleanup := substDrive(t, srcRoot)
	if drive == "" {
		t.Skip("本机无法用 subst 造卷，跳过")
	}
	defer cleanup()

	keyDir := t.TempDir()
	kp, err := keystore.Generate(keystore.GenerateOptions{Bits: 2048, OutDir: keyDir})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := keystore.LoadPublicKey(kp.PublicPath)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.OutputDir = t.TempDir()
	cfg.AuditFile = filepath.Join(t.TempDir(), "audit.jsonl")
	cfg.PublicKeyPath = kp.PublicPath
	cfg.Gate.UsedThresholdBytes = 1 << 62
	cfg.Gate.MaxTotalBytes = 0
	cfg.Collect.Policy = "off"

	deps := Deps{Cfg: cfg, Log: discardLogger(), AllowFixed: true, EmbeddedPublicKey: pub}
	res, err := Run(context.Background(), deps, drive)
	if err != nil {
		t.Fatal(err)
	}
	if res.Branch != BranchSkipped || res.SkipReason != SkipReasonCollectDisabled {
		t.Fatalf("应因策略 off 跳过，实际 branch=%s reason=%s", res.Branch, res.SkipReason)
	}
	if res.Zip.Files != 0 {
		t.Fatal("off 档位下不应读取任何文件")
	}
}

func TestRunMarkerOnlyRequiresCollectMarker(t *testing.T) {
	// marker_only 档位：没有采集标记就零读取跳过；
	// 有采集标记才放行到容量门控（这里用极小阈值把门控卡住，
	// 借"跳过原因不同"来证明准入确实放行了）。
	srcRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcRoot, "a.txt"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	drive, cleanup := substDrive(t, srcRoot)
	if drive == "" {
		t.Skip("本机无法用 subst 造卷，跳过")
	}
	defer cleanup()

	keyDir := t.TempDir()
	kp, err := keystore.Generate(keystore.GenerateOptions{Bits: 2048, OutDir: keyDir})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := keystore.LoadPublicKey(kp.PublicPath)
	if err != nil {
		t.Fatal(err)
	}

	newCfg := func() *config.Config {
		cfg := config.Default()
		cfg.OutputDir = t.TempDir()
		cfg.AuditFile = filepath.Join(t.TempDir(), "audit.jsonl")
		cfg.PublicKeyPath = kp.PublicPath
		cfg.Gate.UsedThresholdBytes = 1 // 一定会被门控挡住
		cfg.Gate.MaxTotalBytes = 0
		cfg.Collect.Policy = "marker_only"
		return cfg
	}

	// 无采集标记 → 准入阶段就跳过。
	cfg := newCfg()
	deps := Deps{Cfg: cfg, Log: discardLogger(), AllowFixed: true, EmbeddedPublicKey: pub}
	res, err := Run(context.Background(), deps, drive)
	if err != nil {
		t.Fatal(err)
	}
	if res.SkipReason != SkipReasonNoCollectMarker {
		t.Fatalf("无采集标记时应报 %s，实际 %s", SkipReasonNoCollectMarker, res.SkipReason)
	}
	if !res.Collect.MarkerChecked || res.Collect.MarkerFound {
		t.Fatalf("应记录「查过采集标记且未命中」，实际 %+v", res.Collect)
	}

	// 放上采集标记 → 准入放行，被容量门控挡住。
	if err := os.WriteFile(filepath.Join(srcRoot, ".usbbackup-collect"), []byte("ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg2 := newCfg()
	deps2 := Deps{Cfg: cfg2, Log: discardLogger(), AllowFixed: true, EmbeddedPublicKey: pub}
	res2, err := Run(context.Background(), deps2, drive)
	if err != nil {
		t.Fatal(err)
	}
	if res2.SkipReason != winvol.PolicyCodeOverThreshold {
		t.Fatalf("有采集标记时应放行到容量门控（期望 %s），实际 %s",
			winvol.PolicyCodeOverThreshold, res2.SkipReason)
	}
	if !res2.Collect.MarkerFound {
		t.Fatalf("应记录采集标记命中，实际 %+v", res2.Collect)
	}
}

var _ = time.Second
