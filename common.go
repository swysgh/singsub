package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"
)

// logger 统一使用标准库 log，带时间戳和级别前缀。
// 简单够用，避免引入额外依赖。

var logLevel = "INFO"

// 级别顺序，用于级别过滤
var levelOrder = map[string]int{
	"DEBUG":   0,
	"INFO":    1,
	"WARNING": 2,
	"ERROR":   3,
}

func setupLogging(level string) {
	logLevel = strings.ToUpper(level)
	log.SetFlags(log.LstdFlags) // 日期 + 时间
}

func levelEnabled(level string) bool {
	cur, ok := levelOrder[logLevel]
	if !ok {
		cur = levelOrder["INFO"]
	}
	want, ok := levelOrder[level]
	if !ok {
		want = levelOrder["INFO"]
	}
	return want >= cur
}

func logDebug(format string, v ...any) {
	if levelEnabled("DEBUG") {
		log.Printf("[DEBUG] "+format, v...)
	}
}
func logInfo(format string, v ...any) {
	if levelEnabled("INFO") {
		log.Printf("[INFO]  "+format, v...)
	}
}
func logWarn(format string, v ...any) {
	if levelEnabled("WARNING") {
		log.Printf("[WARN]  "+format, v...)
	}
}
func logError(format string, v ...any) {
	if levelEnabled("ERROR") {
		log.Printf("[ERROR] "+format, v...)
	}
}

// requestLogger 记录 HTTP 请求摘要，带耗时
type requestLogger struct {
	start    time.Time
	method   string
	path     string
}

func newRequestLogger(method, path string) *requestLogger {
	return &requestLogger{start: time.Now(), method: method, path: path}
}

func (r *requestLogger) done(code int, bodyLen int) {
	logInfo("请求完成: %s %s [%d] (%.2fs, %d 字节)", r.method, r.path, code, time.Since(r.start).Seconds(), bodyLen)
}

// dict2json 把任意值序列化成 JSON 字符串（保留中文等非 ASCII 字符，缩进 2 空格）。
// 对应 Python 版 common.dict2json。
// 注意：关闭 HTML 转义，避免 tag 里的 < > & 被转成 \u003c \u003e \u0026（Python json.dumps 默认不转义）。
func dict2json(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	// Encode 会追加一个换行，去掉以与原行为一致
	s := buf.String()
	return strings.TrimRight(s, "\n"), nil
}

// dict2jsonCompact 生成紧凑 JSON（无缩进），用于 vmess 等场景。
func dict2jsonCompact(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimRight(buf.String(), "\n"), nil
}

// parseQuery 把 ?a=b&c=d 解析成 map[string]string（取每个参数的第一个值）。
// 对应 Python 版 common.parse_query。
func parseQuery(query string) map[string]string {
	values, err := url.ParseQuery(query)
	if err != nil {
		return map[string]string{}
	}
	result := make(map[string]string, len(values))
	for k, vs := range values {
		if len(vs) > 0 {
			result[k] = vs[0]
		}
	}
	return result
}

// toString 把任意值转为字符串（用于宽松比较）。
func toString(v any) string {
	if v == nil {
		return ""
	}
	switch s := v.(type) {
	case string:
		return s
	case fmt.Stringer:
		return s.String()
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}
