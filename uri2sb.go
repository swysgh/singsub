package main

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// uri2singbox 把 URI 列表（或整体 base64）解析成 sing-box 节点列表。
// 对应 Python 版 uri2sb.uri2singbox。
func uri2singbox(originData string) []map[string]any {
	if originData == "" {
		logWarn("订阅内容为空，请检查链接或网络！")
		return nil
	}

	text := strings.TrimSpace(originData)
	lines := strings.Split(text, "\n")

	// 探测是否整体 base64：如果没有任何行以已知 scheme 开头，则尝试 base64 解码
	isPlain := false
	schemes := []string{"ss://", "vmess://", "vless://", "trojan://", "wireguard://", "wg://"}
	for _, l := range lines {
		l = strings.TrimSpace(l)
		for _, sc := range schemes {
			if strings.HasPrefix(l, sc) {
				isPlain = true
				break
			}
		}
		if isPlain {
			break
		}
	}

	if !isPlain {
		// 整体 base64 解码
		cleaned := strings.ReplaceAll(text, "\n", "")
		cleaned = strings.ReplaceAll(cleaned, "\r", "")
		decoded, err := base64.URLEncoding.DecodeString(cleaned)
		if err != nil {
			// 尝试 RawURLEncoding（无 padding）
			decoded, err = base64.RawURLEncoding.DecodeString(cleaned)
			if err != nil {
				// 尝试标准 base64
				decoded, err = base64.StdEncoding.DecodeString(cleaned)
				if err != nil {
					// 解码失败就按明文处理
					decoded = []byte(cleaned)
				}
			}
		}
		lines = strings.Split(string(decoded), "\n")
	}

	var allnode []map[string]any
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		matched := false
		for _, sc := range schemes {
			if strings.HasPrefix(line, sc) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		var node map[string]any
		var err error
		switch {
		case strings.HasPrefix(line, "vmess://"):
			node, err = parseVmess(line)
		case strings.HasPrefix(line, "ss://"):
			node, err = parseSS(line)
		case strings.HasPrefix(line, "vless://"):
			node, err = parseVless(line)
		case strings.HasPrefix(line, "wireguard://"), strings.HasPrefix(line, "wg://"):
			node, err = parseWireguard(line)
		default:
			node, err = parseTrojan(line)
		}
		if err != nil {
			preview := line
			if len(preview) > 20 {
				preview = preview[:20]
			}
			logWarn("解析 %s URI 失败，跳过: %s", preview, err)
			continue
		}
		if node != nil {
			allnode = append(allnode, node)
		}
	}
	return allnode
}

// b64decodeURLSafe 解码 URL-safe base64（兼容有/无 padding）。
func b64decodeURLSafe(s string) ([]byte, error) {
	// 补齐 padding
	if pad := len(s) % 4; pad != 0 {
		s += strings.Repeat("=", 4-pad)
	}
	if d, err := base64.URLEncoding.DecodeString(s); err == nil {
		return d, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

// parseVmess 解析 vmess://base64(json) URI
func parseVmess(uri string) (map[string]any, error) {
	raw, err := b64decodeURLSafe(uri[len("vmess://"):])
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nil
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}

	tag, _ := cfg["ps"].(string)
	if tag == "" {
		tag, _ = cfg["add"].(string)
	}
	port := toInt(cfg["port"])

	node := map[string]any{
		"tag":         tag,
		"type":        "vmess",
		"server":      cfg["add"],
		"server_port": port,
		"uuid":        cfg["id"],
		"alter_id":    toIntDefault(cfg["aid"], 0),
	}

	if scy, ok := cfg["scy"].(string); ok && scy != "" {
		node["security"] = scy
	}

	net, _ := cfg["net"].(string)
	switch net {
	case "ws":
		transport := map[string]any{"type": "ws"}
		path, _ := cfg["path"].(string)
		if path == "" {
			path = "/"
		}
		transport["path"] = path
		if host, ok := cfg["host"].(string); ok && host != "" {
			transport["headers"] = map[string]any{"Host": host}
		}
		node["transport"] = transport
	case "grpc":
		transport := map[string]any{"type": "grpc"}
		if path, ok := cfg["path"].(string); ok && path != "" {
			transport["service_name"] = path
		}
		node["transport"] = transport
	case "h2", "tcp":
		// tcp 默认；h2 在 vmess base64 里少见
	}

	tls := map[string]any{}
	switch t := cfg["tls"].(type) {
	case string:
		if t == "tls" {
			tls["enabled"] = true
		}
	case bool:
		if t {
			tls["enabled"] = true
		}
	}
	if sni, ok := cfg["sni"].(string); ok && sni != "" {
		tls["server_name"] = sni
	}
	if alpn, ok := cfg["alpn"].(string); ok && alpn != "" {
		tls["alpn"] = strings.Split(alpn, ",")
	} else if alpn, ok := cfg["alpn"].([]any); ok {
		tls["alpn"] = alpn
	}
	if verify, ok := cfg["verify"].(string); ok {
		if strings.ToLower(verify) == "false" || verify == "0" {
			tls["insecure"] = true
		}
	} else if verify, ok := cfg["verify"].(bool); ok && !verify {
		tls["insecure"] = true
	}
	if len(tls) > 0 {
		node["tls"] = tls
	}
	return node, nil
}

// parseSS 解析 ss:// URI（SIP002 和旧式）
func parseSS(uri string) (map[string]any, error) {
	body := uri[len("ss://"):]
	var name string
	if idx := strings.Index(body, "#"); idx >= 0 {
		name = body[idx+1:]
		name, _ = url.QueryUnescape(name)
		body = body[:idx]
	}
	query := map[string]string{}
	if idx := strings.Index(body, "?"); idx >= 0 {
		query = parseQuery(body[idx+1:])
		body = body[:idx]
	}

	var method, password, host, port string

	if strings.Contains(body, "@") {
		// SIP002: userinfo@host:port
		atIdx := strings.LastIndex(body, "@")
		userinfo := body[:atIdx]
		hostport := body[atIdx+1:]
		if !strings.Contains(userinfo, ":") {
			// userinfo 可能是 base64
			decoded, err := b64decodeURLSafe(userinfo)
			if err == nil && strings.Contains(string(decoded), ":") {
				userinfo = string(decoded)
			}
		}
		if !strings.Contains(hostport, ":") {
			return nil, nil
		}
		host, port = splitLastColon(hostport)
		parts := strings.SplitN(userinfo, ":", 2)
		if len(parts) != 2 {
			return nil, nil
		}
		method, password = parts[0], parts[1]
	} else {
		// 旧式: ss://base64(method:password@host:port)
		decoded, err := b64decodeURLSafe(body)
		if err != nil || !strings.Contains(string(decoded), "@") {
			return nil, err
		}
		s := string(decoded)
		atIdx := strings.LastIndex(s, "@")
		userinfo := s[:atIdx]
		hostport := s[atIdx+1:]
		parts := strings.SplitN(userinfo, ":", 2)
		if len(parts) != 2 {
			return nil, nil
		}
		method, password = parts[0], parts[1]
		host, port = splitLastColon(hostport)
	}

	method, _ = url.QueryUnescape(method)
	password, _ = url.QueryUnescape(password)

	node := map[string]any{
		"tag":         firstNonEmpty(name, host),
		"type":        "shadowsocks",
		"server":      host,
		"server_port": toIntStr(port),
		"method":      method,
		"password":    password,
	}
	if query["uot"] == "1" || query["uot"] == "true" {
		node["udp_over_tcp"] = true
	}
	return node, nil
}

// parseUserinfoHost 通用解析 scheme://user@host:port?query#name
func parseUserinfoHost(uri, scheme string) (uuid, host string, port int, query map[string]string, name string, err error) {
	body := uri[len(scheme)+3:]
	if idx := strings.Index(body, "#"); idx >= 0 {
		name, _ = url.QueryUnescape(body[idx+1:])
		body = body[:idx]
	}
	query = map[string]string{}
	if idx := strings.Index(body, "?"); idx >= 0 {
		query = parseQuery(body[idx+1:])
		body = body[:idx]
	}
	atIdx := strings.LastIndex(body, "@")
	if atIdx < 0 {
		return "", "", 0, nil, "", errParse("missing @")
	}
	userinfo := body[:atIdx]
	hostport := body[atIdx+1:]
	host, ports := splitLastColon(hostport)
	port = toIntStr(ports)
	return userinfo, host, port, query, name, nil
}

type errParse string

func (e errParse) Error() string { return string(e) }

// parseVless 解析 vless:// URI
func parseVless(uri string) (map[string]any, error) {
	uuid, host, port, query, name, err := parseUserinfoHost(uri, "vless")
	if err != nil {
		return nil, err
	}
	node := map[string]any{
		"tag":         firstNonEmpty(name, host),
		"type":        "vless",
		"server":      host,
		"server_port": port,
		"uuid":        uuid,
	}
	if flow := query["flow"]; flow != "" {
		node["flow"] = flow
	}

	net := query["type"]
	if net == "" {
		net = "tcp"
	}
	switch net {
	case "ws":
		transport := map[string]any{"type": "ws"}
		path := query["path"]
		if path == "" {
			path = "/"
		}
		transport["path"] = path
		if h := query["host"]; h != "" {
			transport["headers"] = map[string]any{"Host": h}
		}
		if ed := firstNonEmpty(query["ed"], query["earlyData"]); ed != "" {
			transport["max_early_data"] = toIntStr(ed)
		}
		node["transport"] = transport
	case "grpc":
		transport := map[string]any{"type": "grpc"}
		if sn := query["serviceName"]; sn != "" {
			transport["service_name"] = sn
		}
		node["transport"] = transport
	case "http":
		transport := map[string]any{"type": "http"}
		path := query["path"]
		if path == "" {
			path = "/"
		}
		transport["path"] = path
		if h := query["host"]; h != "" {
			transport["host"] = strings.Split(h, ",")
		}
		node["transport"] = transport
	}

	tls := map[string]any{}
	if query["security"] == "tls" {
		tls["enabled"] = true
		if sni := firstNonEmpty(query["sni"], query["servername"]); sni != "" {
			tls["server_name"] = sni
		}
		if alpn := query["alpn"]; alpn != "" {
			tls["alpn"] = strings.Split(alpn, ",")
		}
		if fp := query["fp"]; fp != "" {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
		}
		if query["allowInsecure"] == "1" || query["allowInsecure"] == "true" {
			tls["insecure"] = true
		}
	} else if query["security"] == "reality" {
		tls["enabled"] = true
		reality := map[string]any{"enabled": true}
		if sni := firstNonEmpty(query["sni"], query["servername"]); sni != "" {
			tls["server_name"] = sni
		}
		if pbk := query["pbk"]; pbk != "" {
			reality["public_key"] = pbk
		}
		if sid := query["sid"]; sid != "" {
			reality["short_id"] = sid
		}
		tls["reality"] = reality
		if fp := query["fp"]; fp != "" {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
		}
	}
	if len(tls) > 0 {
		node["tls"] = tls
	}
	return node, nil
}

// parseTrojan 解析 trojan:// URI
func parseTrojan(uri string) (map[string]any, error) {
	password, host, port, query, name, err := parseUserinfoHost(uri, "trojan")
	if err != nil {
		return nil, err
	}
	pwd, _ := url.QueryUnescape(password)
	node := map[string]any{
		"tag":         firstNonEmpty(name, host),
		"type":        "trojan",
		"server":      host,
		"server_port": port,
		"password":    pwd,
	}

	net := query["type"]
	if net == "" {
		net = "tcp"
	}
	switch net {
	case "ws":
		transport := map[string]any{"type": "ws"}
		path := query["path"]
		if path == "" {
			path = "/"
		}
		transport["path"] = path
		if h := query["host"]; h != "" {
			transport["headers"] = map[string]any{"Host": h}
		}
		node["transport"] = transport
	case "grpc":
		transport := map[string]any{"type": "grpc"}
		if sn := query["serviceName"]; sn != "" {
			transport["service_name"] = sn
		}
		node["transport"] = transport
	}

	tls := map[string]any{"enabled": true} // trojan 强制 TLS
	if sni := query["sni"]; sni != "" {
		tls["server_name"] = sni
	}
	if alpn := query["alpn"]; alpn != "" {
		tls["alpn"] = strings.Split(alpn, ",")
	}
	if fp := query["fp"]; fp != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	if query["allowInsecure"] == "1" || query["allowInsecure"] == "true" {
		tls["insecure"] = true
	}
	node["tls"] = tls
	return node, nil
}

// parseWireguard 解析 wireguard:// URI
func parseWireguard(uri string) (map[string]any, error) {
	body := uri
	if idx := strings.Index(body, "://"); idx >= 0 {
		body = body[idx+3:]
	}
	var name string
	if idx := strings.Index(body, "#"); idx >= 0 {
		name, _ = url.QueryUnescape(body[idx+1:])
		body = body[:idx]
	}
	query := map[string]string{}
	if idx := strings.Index(body, "?"); idx >= 0 {
		query = parseQuery(body[idx+1:])
		body = body[:idx]
	}
	atIdx := strings.LastIndex(body, "@")
	if atIdx < 0 {
		return nil, errParse("wireguard: missing @")
	}
	publicKey := body[:atIdx]
	hostport := body[atIdx+1:]
	host, ports := splitLastColon(hostport)
	port := toIntStr(ports)

	peer := map[string]any{
		"address":    host,
		"port":       port,
		"public_key": publicKey,
	}

	node := map[string]any{
		"tag":          firstNonEmpty(name, host),
		"type":         "wireguard",
		"server":       host,
		"server_port":  port,
		"local_address": []any{},
		"private_key":  query["private_key"],
		"peers":        []any{peer},
	}

	if addr := query["address"]; addr != "" {
		node["local_address"] = strings.Split(addr, ",")
	}

	allowed := query["allowed_ips"]
	if allowed == "" {
		allowed = "0.0.0.0/0,::/0"
	}
	peer["allowed_ips"] = strings.Split(allowed, ",")

	if psk := query["pre_shared_key"]; psk != "" {
		peer["pre_shared_key"] = psk
	}
	if ka := firstNonEmpty(query["persistent_keepalive"], query["persistent_keepalive_interval"]); ka != "" {
		peer["persistent_keepalive_interval"] = toIntStr(ka)
	}
	if r := query["reserved"]; r != "" {
		parts := strings.Split(r, ",")
		var reserved []any
		for _, p := range parts {
			reserved = append(reserved, toIntStr(p))
		}
		node["reserved"] = reserved
	}
	if mtu := query["mtu"]; mtu != "" {
		node["mtu"] = toIntStr(mtu)
	}
	if workers := query["workers"]; workers != "" {
		node["workers"] = toIntStr(workers)
	}
	if dns := query["dns"]; dns != "" {
		node["dns"] = strings.Split(dns, ",")
	}
	return node, nil
}

// --- 辅助函数 ---

// toInt 把 any 转成 int（json.Number / float64 / string）。
func toInt(v any) int {
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

func toIntDefault(v any, def int) int {
	if v == nil {
		return def
	}
	i := toInt(v)
	if i == 0 && def != 0 {
		// 字符串 "0" 会返回 0，保留
	}
	return i
}

// toIntStr 把字符串转 int（用于 port 等字段）
func toIntStr(s string) int {
	i, _ := strconv.Atoi(strings.TrimSpace(s))
	return i
}

// splitLastColon 按最后一个冒号分割（host:port）。
func splitLastColon(s string) (string, string) {
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return s, ""
	}
	return s[:idx], s[idx+1:]
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

// 确保 regexp 被引用（某些未来扩展可能用到）
var _ = regexp.MustCompile
