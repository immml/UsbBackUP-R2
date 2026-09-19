package backup

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// newTestProgress 造一个把日志写进 buffer 的进度记录器。
func newTestProgress(t *testing.T, total int64) (*progressLogger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	return newProgressLogger(log, "VOL_X.zip.usbk", total), &buf
}

// 收尾那次 (size, size) 是重复上报：传输层写到最后一个字节已经报过一次，
// 调用方紧跟着又补报一次。原来每个文件都会多打一行一模一样的 100%。
func TestProgressLoggerDedupesFinalReport(t *testing.T) {
	const size = 9_490
	p, buf := newTestProgress(t, size)

	p.report(size, size)
	p.report(size, size)
	p.report(size, size)

	if n := strings.Count(buf.String(), "上传中"); n != 1 {
		t.Errorf("末尾重复上报应只打一行，实际 %d 行：\n%s", n, buf.String())
	}
}

// 真的推进不能被吃掉：done 变了就必须打。
func TestProgressLoggerKeepsRealProgress(t *testing.T) {
	const size = 64 << 20
	p, buf := newTestProgress(t, size)

	p.report(size/4, size)
	p.report(size/2, size)
	p.report(size, size)

	got := strings.Count(buf.String(), "上传中")
	if got != 3 {
		t.Errorf("三次不同进度应各打一行，实际 %d 行：\n%s", got, buf.String())
	}
}

// 去重不能过头：首次到达 100% 必须打得出来。
// （done=0 那种早期上报本来就被节流挡掉，属既有行为，与去重无关。）
func TestProgressLoggerFirstCompletionStillLogs(t *testing.T) {
	const size = 9_490
	p, buf := newTestProgress(t, size)

	p.report(size, size)

	if n := strings.Count(buf.String(), "上传中"); n != 1 {
		t.Errorf("首次完成应打一行，实际 %d 行：\n%s", n, buf.String())
	}
	if !strings.Contains(buf.String(), "percent=100%") {
		t.Errorf("应标出 100%%，实际：\n%s", buf.String())
	}
}
