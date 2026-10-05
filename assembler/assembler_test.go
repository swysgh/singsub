package assembler

import (
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"singsub/common"
)

// TestLazySubs_OnlyUsedSubIsFetched 验证 P0：未使用的订阅根本不会被抓取。
// 关键证据：构造两个 httptest 端点，一个会被脚本读、一个不会，请求结束后
// 断言未读取的那一个 count == 0。
func TestLazySubs_OnlyUsedSubIsFetched(t *testing.T) {
	// detect.DetectAndParse 能识别成至少一个 outbound 的最小 sing-box JSON。
	const nodeJSON = `{"outbounds":[{"type":"vless","tag":"vless-node","server":"1.2.3.4","server_port":443,"uuid":"u"}]}`

	var usedCount, unusedCount int32
	used := newCountingServer(t, &usedCount, nodeJSON)
	defer used.Close()
	unused := newCountingServer(t, &unusedCount, nodeJSON)
	defer unused.Close()

	subs := map[string]string{
		"used":   used.URL,
		"unused": unused.URL,
	}
	asm := NewAssembler(subs, "", "", time.Second, time.Second, 1<<20)

	src := `
function assemble(context) {
    const used = context.subs["used"];
    const u = used.outbounds.length;
    const keys = context.subs.keys();
    return { used_len: u, keys: keys };
}
`
	out := writeScript(t, src)
	defer removeFile(t, out)

	cfg, err := asm.RunScript(out, nil)
	if err != nil {
		t.Fatalf("RunScript failed: %v", err)
	}

	if got := atomic.LoadInt32(&usedCount); got != 1 {
		t.Errorf("used sub should be fetched exactly once, got %d", got)
	}
	if got := atomic.LoadInt32(&unusedCount); got != 0 {
		t.Errorf("unused sub must not be fetched (P0), got %d fetches", got)
	}

	m, ok := cfg["keys"].([]string)
	if !ok {
		t.Fatalf("expected keys []string, got %T", cfg["keys"])
	}
	if !containsStringRaw(m, "used") || !containsStringRaw(m, "unused") {
		t.Errorf("keys should include all sub names, got %v", m)
	}
}

// TestLazySubs_RepeatedAccessFetchesOnce 验证同一请求内重复访问同一订阅只抓一次。
func TestLazySubs_RepeatedAccessFetchesOnce(t *testing.T) {
	const nodeJSON = `{"outbounds":[{"type":"vless","tag":"vless-node","server":"1.2.3.4","server_port":443,"uuid":"u"}]}`

	var fetchCount int32
	srv := newCountingServer(t, &fetchCount, nodeJSON)
	defer srv.Close()

	subs := map[string]string{"s": srv.URL}
	asm := NewAssembler(subs, "", "", time.Second, time.Second, 1<<20)

	src := `
function assemble(context) {
    const a = context.subs["s"];
    const c = context.subs.get("s");
    const k = context.subs.keys();
    return { a: a.outbounds.length, c: c.outbounds.length, klen: k.length };
}
`
	out := writeScript(t, src)
	defer removeFile(t, out)

	if _, err := asm.RunScript(out, nil); err != nil {
		t.Fatalf("RunScript failed: %v", err)
	}

	if got := atomic.LoadInt32(&fetchCount); got != 1 {
		t.Errorf("same sub should be fetched exactly once across multiple accesses, got %d", got)
	}
}

// TestLazySubs_UnknownSubReturnsEmptyPair 验证访问未配置订阅名拿到空对而不是 panic/undefined。
func TestLazySubs_UnknownSubReturnsEmptyPair(t *testing.T) {
	asm := NewAssembler(map[string]string{}, "", "", time.Second, time.Second, 1<<20)
	src := `
function assemble(context) {
    const x = context.subs["不存在的"];
    if (!x) throw new Error("expected empty pair, got falsy");
    const o = x.outbounds;
    const e = x.endpoints;
    if (!Array.isArray(o) || o.length !== 0) throw new Error("outbounds not empty");
    if (!Array.isArray(e) || e.length !== 0) throw new Error("endpoints not empty");
    return { ok: true };
}
`
	out := writeScript(t, src)
	defer removeFile(t, out)

	if _, err := asm.RunScript(out, nil); err != nil {
		t.Fatalf("RunScript failed: %v", err)
	}
}

// TestScriptTimeout 验证 P1：死循环脚本在 script_timeout 内被打断，
// 且错误可被 errors.Is 识别为 errScriptTimeout。
func TestScriptTimeout(t *testing.T) {
	asm := NewAssembler(map[string]string{}, "", "", 200*time.Millisecond, time.Second, 1<<20)
	src := `
function assemble(context) {
    while (true) {}
    return {};
}
`
	out := writeScript(t, src)
	defer removeFile(t, out)

	start := time.Now()
	_, err := asm.RunScript(out, nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !isTimeoutErr(err) {
		t.Errorf("expected timeout err, got: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("timeout fired too late: %s", elapsed)
	}
}

// ---- helpers ----

// newCountingServer 起一个本地 HTTP 服务，每次被请求就把 *count 加一，
// 并返回 body 内容。这是隔离实验的标准工具：不依赖任何外网订阅。
func newCountingServer(t *testing.T, count *int32, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(count, 1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}))
	return srv
}

// writeScript 把 JS 写到临时文件并返回路径。Assembler 用 mtime 做缓存，
// 临时文件每次都是新创建因此 mtime 不会复用。
func writeScript(t *testing.T, src string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "script-*.js")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if _, err := f.WriteString(src); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	f.Close()
	return f.Name()
}

func removeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Logf("remove %s: %v", path, err)
	}
}

func containsString(xs []any, want string) bool {
	for _, x := range xs {
		if s, ok := x.(string); ok && s == want {
			return true
		}
	}
	return false
}

func containsStringRaw(xs []string, want string) bool {
	for _, s := range xs {
		if s == want {
			return true
		}
	}
	return false
}

func init() {
	common.SetupLogging("ERROR")
}
