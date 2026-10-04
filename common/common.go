package common

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// --- 日志 ---

var logLevel = "INFO"

var levelOrder = map[string]int{
	"DEBUG":   0,
	"INFO":    1,
	"WARNING": 2,
	"ERROR":   3,
}

func SetupLogging(level string) {
	logLevel = strings.ToUpper(level)
	log.SetFlags(log.LstdFlags)
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

func LogDebug(format string, v ...any) {
	if levelEnabled("DEBUG") {
		log.Printf("[DEBUG] "+format, v...)
	}
}
func LogInfo(format string, v ...any) {
	if levelEnabled("INFO") {
		log.Printf("[INFO]  "+format, v...)
	}
}
func LogWarn(format string, v ...any) {
	if levelEnabled("WARNING") {
		log.Printf("[WARN]  "+format, v...)
	}
}
func LogError(format string, v ...any) {
	if levelEnabled("ERROR") {
		log.Printf("[ERROR] "+format, v...)
	}
}

// RequestLogger 记录 HTTP 请求摘要，带耗时
type RequestLogger struct {
	start  time.Time
	method string
	path   string
	client string
}

func NewRequestLogger(method, path, client string) *RequestLogger {
	return &RequestLogger{start: time.Now(), method: method, path: path, client: client}
}

func (r *RequestLogger) Done(code int, bodyLen int) {
	LogInfo("请求完成: %s %s [%d] client=%s (%.2fs, %d 字节)", r.method, r.path, code, r.client, time.Since(r.start).Seconds(), bodyLen)
}

// --- JSON ---

func Dict2JSON(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimRight(buf.String(), "\n"), nil
}

func Dict2JSONCompact(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func JSONUnmarshal(data string, v any) error {
	return json.Unmarshal([]byte(data), v)
}

// --- YAML ---

func YAMLUnmarshal(data string, out any) error {
	return yaml.Unmarshal([]byte(data), out)
}

func YAMLEncode(v any) ([]byte, error) {
	return yaml.Marshal(v)
}

// --- Base64 ---

func B64EncodeStd(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func B64DecodeStd(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			b, err = base64.RawStdEncoding.DecodeString(s)
			if err != nil {
				return "", err
			}
		}
	}
	return string(b), nil
}

// --- 类型转换 ---

func ToString(v any) string {
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

func ToBool(v any) bool {
	switch b := v.(type) {
	case bool:
		return b
	case string:
		s := strings.ToLower(strings.TrimSpace(b))
		return s == "true" || s == "1"
	case float64:
		return b != 0
	case int:
		return b != 0
	}
	return false
}

func CheckFalse(v any) bool {
	if v == nil {
		return false
	}
	s := strings.ToLower(strings.TrimSpace(ToString(v)))
	return s == "false"
}

func CheckTrue(v any) bool {
	if v == nil {
		return false
	}
	s := strings.ToLower(strings.TrimSpace(ToString(v)))
	return s == "true"
}

func ToInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	case string:
		i, _ := strconv.Atoi(n)
		return i
	}
	return 0
}

func ToIntDefault(v any, def int) int {
	if v == nil {
		return def
	}
	i := ToInt(v)
	if i == 0 && def != 0 {
		return i
	}
	return i
}

func ToIntStr(s string) int {
	i, _ := strconv.Atoi(strings.TrimSpace(s))
	return i
}

// --- 字符串工具 ---

func JoinAny(v any, sep string) string {
	switch val := v.(type) {
	case string:
		return val
	case []any:
		parts := make([]string, 0, len(val))
		for _, p := range val {
			parts = append(parts, ToString(p))
		}
		return strings.Join(parts, sep)
	case []string:
		return strings.Join(val, sep)
	}
	return ToString(v)
}

func FirstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

func SplitLastColon(s string) (string, string) {
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return s, ""
	}
	return s[:idx], s[idx+1:]
}

func Itoa(i int) string {
	if i == 0 {
		return "0"
	}
	b := [20]byte{}
	pos := len(b)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}

// --- URI 编码 ---

func QuoteAll(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '_' || r == '.' || r == '-' || r == '~' {
			b.WriteRune(r)
		} else {
			for _, c := range []byte(string(r)) {
				b.WriteString("%")
				b.WriteString(strings.ToUpper(hex2(c)))
			}
		}
	}
	return b.String()
}

func hex2(c byte) string {
	const hexd = "0123456789abcdef"
	return string([]byte{hexd[c>>4], hexd[c&0xf]})
}

// --- 解析 ---

func ParseQuery(query string) map[string]string {
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

func ResolvePath(path, baseDir string) string {
	if filepath.IsAbs(path) {
		return path
	}
	if baseDir == "" {
		return path
	}
	return filepath.Join(baseDir, path)
}
