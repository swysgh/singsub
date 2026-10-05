package main

import (
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"singsub/assembler"
	"singsub/common"
	"singsub/config"
	"singsub/detect"
	"singsub/fetch"
	"singsub/sb2uri"
)

var (
	gConfig    *config.Config
	gConfigDir string
)

func main() {
	configPath := flag.String("config", "config.json", "配置文件路径")
	host := flag.String("host", "0.0.0.0", "监听地址")
	port := flag.Int("port", 8080, "监听端口")
	logLevel := flag.String("log-level", "INFO", "日志级别：DEBUG / INFO / WARNING / ERROR")
	flag.Parse()

	common.SetupLogging(*logLevel)

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		common.LogError("%s", err)
		os.Exit(1)
	}
	gConfig = cfg
	gConfigDir = config.ConfigDir(*configPath)

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleHTTP)

	addr := fmt.Sprintf("%s:%d", *host, *port)
	common.LogInfo("singsub 服务已启动: http://%s/<token>?name=<订阅名>|script=<脚本名>&format=singbox|uri", addr)
	common.LogInfo("已加载订阅: %s", strings.Join(mapKeys(cfg.Subs), ", "))
	if len(cfg.Scripts) > 0 {
		common.LogInfo("已加载脚本: %s", strings.Join(mapKeys(cfg.Scripts), ", "))
	}
	if len(cfg.Shares) > 0 {
		parts := make([]string, 0, len(cfg.Shares))
		for k, v := range cfg.Shares {
			parts = append(parts, k+" -> "+v)
		}
		common.LogInfo("已加载分享链接: %s", strings.Join(parts, ", "))
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		common.LogError("服务启动失败: %s", err)
		os.Exit(1)
	}
}

// clientIP 从 X-Real-IP / X-Forwarded-For 提取真实客户端 IP，适用于反向代理场景。
// 信任顺序: X-Real-IP > X-Forwarded-For 第一个 > RemoteAddr
func clientIP(r *http.Request) string {
	if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	cip := clientIP(r)
	rl := common.NewRequestLogger(r.Method, r.URL.Path, cip)
	common.LogInfo("收到请求: %s %s (client=%s)", r.Method, r.URL.Path, cip)

	path := strings.TrimPrefix(r.URL.Path, "/")
	segments := strings.Split(path, "/")
	var segs []string
	for _, s := range segments {
		if s != "" {
			segs = append(segs, s)
		}
	}
	if len(segs) == 0 {
		writeText(w, http.StatusOK, "singsub running\n")
		return
	}

	// 浏览器自动请求 favicon.ico，直接返回 404 且不产生 token 告警日志
	if segs[0] == "favicon.ico" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	key := segs[0]
	qs := common.ParseQuery(r.URL.RawQuery)
	fmtStr := qs["format"]
	if fmtStr == "" {
		fmtStr = "singbox"
	}
	if fmtStr != "singbox" && fmtStr != "uri" {
		writeText(w, http.StatusBadRequest, "format 只能是 singbox 或 uri\n")
		return
	}
	ua := qs["ua"]

	if gConfig.Shares != nil {
		if scriptName, ok := gConfig.Shares[key]; ok {
			common.LogInfo("分享链接命中: %s -> script=%s", key, scriptName)
			handleScript(w, scriptName, qs, fmtStr, ua, rl)
			return
		}
	}

	expectToken := gConfig.Token
	if expectToken == "" || subtle.ConstantTimeCompare([]byte(key), []byte(expectToken)) != 1 {
		common.LogWarn("token 验证失败: %s", cip)
		writeText(w, http.StatusForbidden, "Forbidden: token 错误\n")
		return
	}

	if scriptName := qs["script"]; scriptName != "" {
		handleScript(w, scriptName, qs, fmtStr, ua, rl)
		return
	}

	subs := gConfig.Subs
	name := qs["name"]
	var targets [][2]string
	if name != "" {
		url, ok := subs[name]
		if !ok {
			writeText(w, http.StatusNotFound, fmt.Sprintf("未知订阅: %s\n", name))
			return
		}
		targets = append(targets, [2]string{name, url})
		common.LogInfo("请求指定订阅: %s", name)
	} else {
		for n, url := range subs {
			targets = append(targets, [2]string{n, url})
		}
		common.LogInfo("请求合并所有订阅 (%d 个)", len(targets))
	}

	if len(targets) == 0 {
		writeText(w, http.StatusNotFound, "配置文件未定义任何订阅\n")
		return
	}

	var allOutbounds []map[string]any
	var allEndpoints []map[string]any
	var failed []string
	for _, t := range targets {
		subName, url := t[0], t[1]
		origin := fetch.GetSub(url, ua, gConfigDir, gConfig.FetchTimeout(), gConfig.MaxBodyLimit())
		if origin == "" {
			failed = append(failed, subName)
			continue
		}
		outbounds, endpoints := detect.DetectAndParse(origin)
		if len(outbounds) > 0 || len(endpoints) > 0 {
			allOutbounds = append(allOutbounds, outbounds...)
			allEndpoints = append(allEndpoints, endpoints...)
			common.LogInfo("订阅 %s: 解析到 %d outbound + %d endpoint", subName, len(outbounds), len(endpoints))
		} else {
			common.LogWarn("订阅 %s 解析无节点", subName)
		}
	}

	if len(allOutbounds) == 0 && len(allEndpoints) == 0 {
		writeText(w, http.StatusUnprocessableEntity, "解析失败，未得到任何节点\n")
		return
	}

	contentType, body := detect.RenderNodes(allOutbounds, allEndpoints, fmtStr)
	if len(failed) > 0 {
		common.LogWarn("部分订阅获取失败: %s", strings.Join(failed, ", "))
	}
	common.LogInfo("转换完成: %d outbound + %d endpoint -> %s", len(allOutbounds), len(allEndpoints), fmtStr)
	writeBody(w, http.StatusOK, contentType, body+"\n", rl)
}

func handleScript(w http.ResponseWriter, scriptName string, qs map[string]string, fmtStr, ua string, rl *common.RequestLogger) {
	if gConfig.Scripts == nil {
		writeText(w, http.StatusNotFound, fmt.Sprintf("未知脚本: %s\n", scriptName))
		return
	}
	entry, ok := gConfig.Scripts[scriptName]
	if !ok {
		writeText(w, http.StatusNotFound, fmt.Sprintf("未知脚本: %s\n", scriptName))
		return
	}

	reserved := map[string]bool{"script": true, "format": true, "ua": true, "name": true}
	args := map[string]string{}
	for k, v := range qs {
		if !reserved[k] {
			args[k] = v
		}
	}

	common.LogInfo("执行脚本: %s (args=%v)", scriptName, args)

	asm := assembler.NewAssembler(gConfig.Subs, gConfigDir, ua,
		gConfig.ScriptTimeout(), gConfig.FetchTimeout(), gConfig.MaxBodyLimit())

	config, err := asm.RunScript(entry, args)
	if err != nil {
		var se *assembler.ScriptError
		if errors.As(err, &se) {
			if errors.Is(err, os.ErrNotExist) {
				writeText(w, http.StatusNotFound, fmt.Sprintf("%s\n", err))
				return
			}
		}
		common.LogError("脚本 %s 执行异常: %s", scriptName, err)
		writeText(w, http.StatusInternalServerError, fmt.Sprintf("脚本执行失败: %s\n", err))
		return
	}

	if fmtStr == "uri" {
		var proxyNodes []any
		for _, key := range []string{"outbounds", "endpoints"} {
			nodes, _ := config[key].([]any)
			for _, o := range nodes {
				if m, ok := o.(map[string]any); ok && isProxyNode(m) {
					proxyNodes = append(proxyNodes, m)
				}
			}
		}
		if len(proxyNodes) == 0 {
			writeText(w, http.StatusUnprocessableEntity, "装配结果无代理节点可转 URI\n")
			return
		}
		common.LogInfo("脚本 %s 完成: %d 代理节点转 URI", scriptName, len(proxyNodes))
		writeText(w, http.StatusOK, sb2uri.Singbox2URI(proxyNodes)+"\n")
		return
	}

	common.LogInfo("脚本 %s 完成: 返回 sing-box 配置", scriptName)
	body, err := common.Dict2JSON(config)
	if err != nil {
		common.LogError("JSON 序列化失败: %s", err)
		writeText(w, http.StatusInternalServerError, "JSON 序列化失败\n")
		return
	}
	writeBody(w, http.StatusOK, "application/json; charset=utf-8", body+"\n", rl)
}

// isProxyNode 判断装配结果是否为可转 URI 的代理节点：常规 outbound 带 server，
// wireguard endpoint 无 server，但其 peers[0] 承载地址与端口
func isProxyNode(node map[string]any) bool {
	if server, ok := node["server"].(string); ok && server != "" {
		return true
	}
	peers, _ := node["peers"].([]any)
	return len(peers) > 0
}

func writeText(w http.ResponseWriter, code int, body string) {
	writeBody(w, code, "text/plain; charset=utf-8", body, nil)
}

func writeBody(w http.ResponseWriter, code int, contentType, body string, rl *common.RequestLogger) {
	data := []byte(body)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.WriteHeader(code)
	w.Write(data)
	if rl != nil {
		rl.Done(code, len(data))
	}
}

func mapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
