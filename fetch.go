package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// isURL 判断字符串是否是 http/https URL。
func isURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

// readLocalFile 读取本地文件，相对路径相对 baseDir 解析。
func readLocalFile(path, baseDir string) (string, error) {
	full := path
	if !filepath.IsAbs(path) {
		full = filepath.Join(baseDir, path)
	}
	b, err := os.ReadFile(full)
	if err != nil {
		if os.IsNotExist(err) {
			logError("本地文件不存在: %s", full)
		} else {
			logError("读取本地文件失败: %s (%s)", full, err)
		}
		return "", err
	}
	logInfo("成功读取本地文件: %s", full)
	return string(b), nil
}

// getsub 获取订阅内容：URL 用 HTTP 拉取，否则按本地文件读取。
// 对应 Python 版 fetch.getsub。
func getsub(rawURL, ua, baseDir string) string {
	if !isURL(rawURL) {
		content, err := readLocalFile(rawURL, baseDir)
		if err != nil {
			return ""
		}
		return content
	}

	if ua == "" {
		ua = "Mihomo"
	}

	logInfo("开始拉取订阅: %s (UA=%s)", rawURL, ua)

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		logError("请求 %s 构造失败: %s", rawURL, err)
		return ""
	}
	req.Header.Set("User-Agent", ua)

	resp, err := client.Do(req)
	if err != nil {
		if isTimeout(err) {
			logError("请求 %s 超时，请检查网络连接或目标服务器响应速度", rawURL)
		} else {
			logError("无法连接到 %s: %s", rawURL, err)
		}
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logError("HTTP 错误：请求 %s 失败，状态码 %d", rawURL, resp.StatusCode)
		return ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logError("读取 %s 响应失败: %s", rawURL, err)
		return ""
	}

	logInfo("成功获取订阅: %s (状态码=%d, %d 字节)", rawURL, resp.StatusCode, len(body))
	return string(body)
}

// isTimeout 判断错误是否为超时。
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "timeout") || strings.Contains(s, "DeadlineExceeded") ||
		strings.Contains(s, "context deadline exceeded")
}

// resolvePath 解析相对路径（相对 baseDir），绝对路径直接返回。
func resolvePath(path, baseDir string) string {
	if filepath.IsAbs(path) {
		return path
	}
	if baseDir == "" {
		return path
	}
	return filepath.Join(baseDir, path)
}

// _ 避免未使用导入（占位）
var _ = fmt.Sprintf
