package fetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
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

// 包级共享 HTTP 客户端：复用连接，避免每次请求都新建 TCP + TLS 握手。
// Transport 调优保证空闲连接及时释放、连接数足够并发订阅请求复用。
var (
	sharedClientOnce sync.Once
	sharedClient     *http.Client
)

func sharedHTTPClient() *http.Client {
	sharedClientOnce.Do(func() {
		transport := &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   16,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
		sharedClient = &http.Client{Transport: transport}
	})
	return sharedClient
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

// GetSub 抓取一个订阅。失败返回空字符串，成功返回原始 body。
//
// 失败时调用方拿不到原因，只能自己编一个（或者干脆什么都不做）——
// 需要把原因给用户看的地方请用 GetSubWithErr。
func GetSub(rawURL, ua, baseDir string, fetchTimeout time.Duration, maxBodyBytes int64) string {
	content, _ := GetSubWithErr(rawURL, ua, baseDir, fetchTimeout, maxBodyBytes)
	return content
}

// GetSubWithErr 与 GetSub 相同，但把失败原因一并返回。
//
// 为什么需要它：失败只写进日志时，调用方无法把原因传到客户端，只能当作
// 「这个订阅没有节点」处理 —— 结果是一份带空分组的配置发出去，客户端
// sing-box check 报 `initialize outbound[N]: missing tags` 整份失败，
// 而日志里的真正原因（DNS 解析失败、403、超时）在客户端完全看不到。
//
// fetchTimeout 是整个请求（含 body 读取）的最大允许时间；<=0 时使用 15s 默认。
// maxBodyBytes 是 body 读取的上限；<=0 时使用 32 MiB 默认。超限报错并记日志。
func GetSubWithErr(rawURL, ua, baseDir string, fetchTimeout time.Duration, maxBodyBytes int64) (string, error) {
	if !IsURL(rawURL) {
		content, err := readLocalFile(rawURL, baseDir)
		if err != nil {
			if os.IsNotExist(err) {
				return "", fmt.Errorf("本地文件不存在: %s", rawURL)
			}
			return "", fmt.Errorf("读取本地文件失败: %s (%s)", rawURL, err)
		}
		return content, nil
	}

	if ua == "" {
		ua = "Mihomo"
	}

	if fetchTimeout <= 0 {
		fetchTimeout = 15 * time.Second
	}
	if maxBodyBytes <= 0 {
		maxBodyBytes = 32 << 20 // 32 MiB
	}

	common.LogInfo("开始拉取订阅: %s (UA=%s, timeout=%s, max=%dB)", rawURL, ua, fetchTimeout, maxBodyBytes)

	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		common.LogError("请求 %s 构造失败: %s", rawURL, err)
		return "", fmt.Errorf("请求构造失败: %s", err)
	}
	req.Header.Set("User-Agent", ua)

	client := sharedHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		if isTimeoutErr(err) {
			common.LogError("请求 %s 超时 (timeout=%s)，请检查网络连接或目标服务器响应速度", rawURL, fetchTimeout)
			return "", fmt.Errorf("请求超时 (timeout=%s)", fetchTimeout)
		}
		common.LogError("无法连接到 %s: %s", rawURL, err)
		return "", fmt.Errorf("无法连接: %s", stripURL(err))
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		common.LogError("HTTP 错误：请求 %s 失败，状态码 %d", rawURL, resp.StatusCode)
		return "", fmt.Errorf("HTTP 状态码 %d", resp.StatusCode)
	}

	// 用 LimitReader 限制 body 上游，防止恶意/异常响应吃光内存。
	limited := io.LimitReader(resp.Body, maxBodyBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		if isTimeoutErr(err) {
			common.LogError("请求 %s 读取 body 超时 (timeout=%s)", rawURL, fetchTimeout)
			return "", fmt.Errorf("读取响应超时 (timeout=%s)", fetchTimeout)
		}
		common.LogError("读取 %s 响应失败: %s", rawURL, err)
		return "", fmt.Errorf("读取响应失败: %s", err)
	}
	if int64(len(body)) > maxBodyBytes {
		common.LogError("请求 %s 响应体超过 %d 字节上限，已截断/拒绝", rawURL, maxBodyBytes)
		return "", fmt.Errorf("响应体超过 %d 字节上限", maxBodyBytes)
	}

	common.LogInfo("成功获取订阅: %s (状态码=%d, %d 字节)", rawURL, resp.StatusCode, len(body))
	return string(body), nil
}

// stripURL 去掉 *url.Error 外壳。
//
// 它的 Error() 会把整个 URL 拼进消息里（订阅 URL 带 token），而这个原因要写进
// 给客户端看的节点 tag —— 不该把 token 带到客户端的节点列表里。
func stripURL(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) && uerr.Err != nil {
		return uerr.Err
	}
	return err
}

// isTimeoutErr 标准方式识别超时：context.DeadlineExceeded 或 net.Error.Timeout。
// 不再用脆弱的字符串匹配。
func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return false
}
