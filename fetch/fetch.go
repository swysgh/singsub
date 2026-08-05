package fetch

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"singsub/common"
)

func IsURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

func readLocalFile(path, baseDir string) (string, error) {
	full := path
	if !filepath.IsAbs(path) {
		full = filepath.Join(baseDir, path)
	}
	b, err := os.ReadFile(full)
	if err != nil {
		if os.IsNotExist(err) {
			common.LogError("本地文件不存在: %s", full)
		} else {
			common.LogError("读取本地文件失败: %s (%s)", full, err)
		}
		return "", err
	}
	common.LogInfo("成功读取本地文件: %s", full)
	return string(b), nil
}

func GetSub(rawURL, ua, baseDir string) string {
	if !IsURL(rawURL) {
		content, err := readLocalFile(rawURL, baseDir)
		if err != nil {
			return ""
		}
		return content
	}

	if ua == "" {
		ua = "Mihomo"
	}

	common.LogInfo("开始拉取订阅: %s (UA=%s)", rawURL, ua)

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		common.LogError("请求 %s 构造失败: %s", rawURL, err)
		return ""
	}
	req.Header.Set("User-Agent", ua)

	resp, err := client.Do(req)
	if err != nil {
		if isTimeout(err) {
			common.LogError("请求 %s 超时，请检查网络连接或目标服务器响应速度", rawURL)
		} else {
			common.LogError("无法连接到 %s: %s", rawURL, err)
		}
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		common.LogError("HTTP 错误：请求 %s 失败，状态码 %d", rawURL, resp.StatusCode)
		return ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		common.LogError("读取 %s 响应失败: %s", rawURL, err)
		return ""
	}

	common.LogInfo("成功获取订阅: %s (状态码=%d, %d 字节)", rawURL, resp.StatusCode, len(body))
	return string(body)
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "timeout") || strings.Contains(s, "DeadlineExceeded") ||
		strings.Contains(s, "context deadline exceeded")
}