package main

import (
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// 全局配置，启动 HTTP 服务时由 --config 加载
var (
	gConfig    *Config
	gConfigDir string
)

func main() {
	fs := flag.NewFlagSet("singsub", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	config := fs.String("config", "config.json", "配置文件路径")
	host := fs.String("host", "0.0.0.0", "监听地址")
	port := fs.Int("port", 8080, "监听端口")
	logLevel := fs.String("log-level", "INFO", "日志级别：DEBUG / INFO / WARNING / ERROR")
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	setupLogging(*logLevel)

	cfg, err := loadConfig(*config)
	if err != nil {
		logError("%s", err)
		os.Exit(1)
	}
	gConfig = cfg
	gConfigDir = configDir(*config)

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleHTTP)

	addr := fmt.Sprintf("%s:%d", *host, *port)
	logInfo("singsub 服务已启动: http://%s/<token>?name=<订阅名>|script=<脚本名>&format=singbox|uri", addr)
	logInfo("已加载订阅: %s", strings.Join(mapKeys(cfg.Subs), ", "))
	if len(cfg.Scripts) > 0 {
		logInfo("已加载脚本: %s", strings.Join(mapKeys(cfg.Scripts), ", "))
	}
	if len(cfg.Shares) > 0 {
		parts := make([]string, 0, len(cfg.Shares))
		for k, v := range cfg.Shares {
			parts = append(parts, k+" -> "+v)
		}
		logInfo("已加载分享链接: %s", strings.Join(parts, ", "))
	}

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
		// 读超时留长一些，订阅拉取可能慢
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		logError("服务启动失败: %s", err)
		os.Exit(1)
	}
}

// handleHTTP 处理所有 HTTP 请求
func handleHTTP(w http.ResponseWriter, r *http.Request) {
	rl := newRequestLogger(r.Method, r.URL.Path)
	logInfo("收到请求: %s %s", r.Method, r.URL.Path)

	// 首页：无 token，仅作存活探测
	path := strings.TrimPrefix(r.URL.Path, "/")
	segments := strings.Split(path, "/")
	// 过滤空段
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

	key := segs[0]
	qs := parseQuery(r.URL.RawQuery)
	fmtStr := qs["format"]
	if fmtStr == "" {
		fmtStr = "singbox"
	}
	if fmtStr != "singbox" && fmtStr != "uri" {
		writeText(w, http.StatusBadRequest, "format 只能是 singbox 或 uri\n")
		return
	}
	ua := qs["ua"]

	// 分享链接：key 匹配 shares
	if gConfig.Shares != nil {
		if scriptName, ok := gConfig.Shares[key]; ok {
			logInfo("分享链接命中: %s -> script=%s", key, scriptName)
			handleScript(w, scriptName, qs, fmtStr, ua, rl)
			return
		}
	}

	// token 验证
	expectToken := gConfig.Token
	if expectToken == "" || subtle.ConstantTimeCompare([]byte(key), []byte(expectToken)) != 1 {
		logWarn("token 验证失败: %s", r.RemoteAddr)
		writeText(w, http.StatusForbidden, "Forbidden: token 错误\n")
		return
	}

	// 优先走脚本装配
	if scriptName := qs["script"]; scriptName != "" {
		handleScript(w, scriptName, qs, fmtStr, ua, rl)
		return
	}

	// 指定订阅 / 合并所有订阅
	subs := gConfig.Subs
	name := qs["name"]
	var targets [][2]string // [(name, url)]
	if name != "" {
		url, ok := subs[name]
		if !ok {
			writeText(w, http.StatusNotFound, fmt.Sprintf("未知订阅: %s\n", name))
			return
		}
		targets = append(targets, [2]string{name, url})
		logInfo("请求指定订阅: %s", name)
	} else {
		for n, url := range subs {
			targets = append(targets, [2]string{n, url})
		}
		logInfo("请求合并所有订阅 (%d 个)", len(targets))
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
		origin := getsub(url, ua, gConfigDir)
		if origin == "" {
			failed = append(failed, subName)
			continue
		}
		outbounds, endpoints := detectAndParse(origin)
		if len(outbounds) > 0 || len(endpoints) > 0 {
			allOutbounds = append(allOutbounds, outbounds...)
			allEndpoints = append(allEndpoints, endpoints...)
			logInfo("订阅 %s: 解析到 %d outbound + %d endpoint", subName, len(outbounds), len(endpoints))
		} else {
			logWarn("订阅 %s 解析无节点", subName)
		}
	}

	if len(allOutbounds) == 0 && len(allEndpoints) == 0 {
		writeText(w, http.StatusUnprocessableEntity, "解析失败，未得到任何节点\n")
		return
	}

	contentType, body := renderNodes(allOutbounds, allEndpoints, fmtStr)
	if len(failed) > 0 {
		logWarn("部分订阅获取失败: %s", strings.Join(failed, ", "))
	}
	logInfo("转换完成: %d outbound + %d endpoint -> %s", len(allOutbounds), len(allEndpoints), fmtStr)
	writeBody(w, http.StatusOK, contentType, body+"\n", rl)
}

// handleScript 处理脚本装配请求
func handleScript(w http.ResponseWriter, scriptName string, qs map[string]string, fmtStr, ua string, rl *requestLogger) {
	if gConfig.Scripts == nil {
		writeText(w, http.StatusNotFound, fmt.Sprintf("未知脚本: %s\n", scriptName))
		return
	}
	entry, ok := gConfig.Scripts[scriptName]
	if !ok {
		writeText(w, http.StatusNotFound, fmt.Sprintf("未知脚本: %s\n", scriptName))
		return
	}

	// 额外查询参数（去掉保留字段）传给脚本
	reserved := map[string]bool{"script": true, "format": true, "ua": true, "name": true}
	args := map[string]string{}
	for k, v := range qs {
		if !reserved[k] {
			args[k] = v
		}
	}

	logInfo("执行脚本: %s (args=%v)", scriptName, args)

	// 每次请求用一个新的 Assembler，保证 UA 隔离
	asm := NewAssembler(gConfig.Subs, gConfigDir, ua)

	config, err := asm.RunScript(entry, args)
	if err != nil {
		var se *ScriptError
		if errors.As(err, &se) {
			if errors.Is(err, os.ErrNotExist) {
				writeText(w, http.StatusNotFound, fmt.Sprintf("%s\n", err))
				return
			}
		}
		logError("脚本 %s 执行异常: %s", scriptName, err)
		writeText(w, http.StatusInternalServerError, fmt.Sprintf("脚本执行失败: %s\n", err))
		return
	}

	if fmtStr == "uri" {
		// 抽真实代理节点（有 server 字段）转 URI。
		// sing-box 不区分 outbounds 和 endpoints 的 tag，所以从两者都取。
		var proxyNodes []any
		for _, key := range []string{"outbounds", "endpoints"} {
			if nodes, ok := config[key].([]any); ok {
				for _, o := range nodes {
					if m, ok := o.(map[string]any); ok {
						if _, ok := m["server"]; ok {
							proxyNodes = append(proxyNodes, m)
						}
					}
				}
			}
		}
		if len(proxyNodes) == 0 {
			writeText(w, http.StatusUnprocessableEntity, "装配结果无代理节点可转 URI\n")
			return
		}
		logInfo("脚本 %s 完成: %d 代理节点转 URI", scriptName, len(proxyNodes))
		writeText(w, http.StatusOK, singbox2uri(proxyNodes)+"\n")
		return
	}

	logInfo("脚本 %s 完成: 返回 sing-box 配置", scriptName)
	body, err := dict2json(config)
	if err != nil {
		logError("JSON 序列化失败: %s", err)
		writeText(w, http.StatusInternalServerError, "JSON 序列化失败\n")
		return
	}
	writeBody(w, http.StatusOK, "application/json; charset=utf-8", body+"\n", rl)
}

// --- HTTP 响应辅助 ---

func writeText(w http.ResponseWriter, code int, body string) {
	writeBody(w, code, "text/plain; charset=utf-8", body, nil)
}

func writeBody(w http.ResponseWriter, code int, contentType, body string, rl *requestLogger) {
	data := []byte(body)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.WriteHeader(code)
	w.Write(data)
	if rl != nil {
		rl.done(code, len(data))
	}
}

// mapKeys 返回 map 的键列表
func mapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
