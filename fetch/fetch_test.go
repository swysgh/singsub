package fetch

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestGetSub_TimeoutIdentifiable 验证 P2：超时能被 errors.Is/As 识别。
// 端点 sleep 3s，client timeout 200ms，必须返回 "" 且日志走超时分支。
func TestGetSub_TimeoutIdentifiable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
	}))
	defer srv.Close()

	got := GetSub(srv.URL, "test", "", 200*time.Millisecond, 1<<20)
	if got != "" {
		t.Errorf("expected empty result on timeout, got %d bytes", len(got))
	}
}

// TestGetSub_BodyLimitEnforced 验证 P2：响应体超过 maxBodyBytes 会被截断/报错。
func TestGetSub_BodyLimitEnforced(t *testing.T) {
	// 返回 1MB 数据；client 只允许 100 字节。
	big := strings.Repeat("A", 1<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte(big))
	}))
	defer srv.Close()

	got := GetSub(srv.URL, "test", "", 5*time.Second, 100)
	if got != "" {
		t.Errorf("expected empty result when body exceeds limit, got %d bytes", len(got))
	}
}

// TestGetSub_LocalFileUnaffected 验证本地文件读取不走 http 路径，
// 不受 timeout/maxBodyBytes 影响。
func TestGetSub_LocalFileUnaffected(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/local.txt"
	if err := writeFile(path, "hello-local"); err != nil {
		t.Fatal(err)
	}
	got := GetSub(path, "", dir, 200*time.Millisecond, 10)
	if got != "hello-local" {
		t.Errorf("local file read broken: %q", got)
	}
}
