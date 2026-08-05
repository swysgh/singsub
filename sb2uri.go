package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// quoteAll 等价于 Python 的 urllib.parse.quote(s, safe='')：
// 除了字母、数字、_.-~ 之外，其余字符全部 percent-encode。
// 用于 URI 各组件（userinfo / query value / fragment）的编码。
func quoteAll(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '_' || r == '.' || r == '-' || r == '~' {
			b.WriteRune(r)
		} else {
			// 多字节字符按 UTF-8 字节逐个编码
			for _, c := range []byte(string(r)) {
				b.WriteString("%")
				b.WriteString(strings.ToUpper(hex2(c)))
			}
		}
	}
	return b.String()
}

// hex2 返回字节 c 的大写十六进制表示
func hex2(c byte) string {
	const hexd = "0123456789abcdef"
	return string([]byte{hexd[c>>4], hexd[c&0xf]})
}

// singbox2uri 把 sing-box 节点转成 URI 字符串（多节点用换行分隔）。
// 支持 dict / list / 含 outbounds 的完整配置。
// 对应 Python 版 sb2uri.singbox2uri。
func singbox2uri(data any) string {
	var nodes []any
	switch v := data.(type) {
	case map[string]any:
		if ob, ok := v["outbounds"]; ok {
			if list, ok := ob.([]any); ok {
				nodes = list
			}
		} else {
			nodes = []any{v}
		}
	case []any:
		nodes = v
	default:
		logWarn("singbox2uri: 输入类型不支持 (%T)", data)
		return ""
	}

	var lines []string
	for _, n := range nodes {
		node, ok := n.(map[string]any)
		if !ok {
			continue
		}
		uri := nodeToURI(node)
		if uri != "" {
			lines = append(lines, uri)
		} else {
			logWarn("singbox2uri: 跳过不支持的节点 %s (type=%s)", toString(node["tag"]), toString(node["type"]))
		}
	}
	return strings.Join(lines, "\n")
}

// nodeToURI 把单个 sing-box 节点转成 URI 字符串。
func nodeToURI(node map[string]any) string {
	ntype, _ := node["type"].(string)
	server, _ := node["server"].(string)
	port := toInt(node["server_port"])
	tag, _ := node["tag"].(string)

	fragment := ""
	if tag != "" {
		// 用 PathEscape 保持与 Python urllib.parse.quote 一致（空格 -> %20）
		fragment = "#" + quoteAll(tag)
	}

	switch ntype {
	case "shadowsocks":
		return ssToURI(node, server, port, fragment)
	case "vmess":
		return vmessToURI(node, server, port, tag)
	case "vless":
		return vlessToURI(node, server, port, fragment)
	case "trojan":
		return trojanToURI(node, server, port, fragment)
	case "wireguard":
		return wireguardToURI(node, server, port, fragment)
	}
	return ""
}

// queryBuilder 用于构建 query string
type queryBuilder struct {
	pairs [][2]string
}

func (q *queryBuilder) add(k, v string) { q.pairs = append(q.pairs, [2]string{k, v}) }
func (q *queryBuilder) String() string {
	if len(q.pairs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(q.pairs))
	for _, p := range q.pairs {
		// 用 PathEscape 保持与 Python urllib.parse.quote(v, safe='') 一致
		parts = append(parts, p[0]+"="+quoteAll(p[1]))
	}
	return "?" + strings.Join(parts, "&")
}

// buildTLSQuery 从 node["tls"] 重建 TLS query 参数
func buildTLSQuery(q *queryBuilder, tlsMap map[string]any) {
	if tlsMap == nil {
		return
	}
	if reality, ok := tlsMap["reality"].(map[string]any); ok && toBool(reality["enabled"]) {
		q.add("security", "reality")
		if sni, ok := tlsMap["server_name"].(string); ok && sni != "" {
			q.add("sni", sni)
		}
		if pbk, ok := reality["public_key"].(string); ok && pbk != "" {
			q.add("pbk", pbk)
		}
		if sid, ok := reality["short_id"].(string); ok && sid != "" {
			q.add("sid", sid)
		}
	} else if toBool(tlsMap["enabled"]) {
		q.add("security", "tls")
		if sni, ok := tlsMap["server_name"].(string); ok && sni != "" {
			q.add("sni", sni)
		}
		if toBool(tlsMap["insecure"]) {
			q.add("allowInsecure", "1")
		}
	}
	if alpn := tlsMap["alpn"]; alpn != nil {
		q.add("alpn", joinAny(alpn, ","))
	}
	if utls, ok := tlsMap["utls"].(map[string]any); ok {
		if fp, ok := utls["fingerprint"].(string); ok && fp != "" {
			q.add("fp", fp)
		}
	}
}

// buildTransportQuery 从 node["transport"] 重建传输层 query 参数
func buildTransportQuery(q *queryBuilder, transport map[string]any) {
	if transport == nil {
		return
	}
	ttype, _ := transport["type"].(string)
	switch ttype {
	case "ws":
		q.add("type", "ws")
		path, _ := transport["path"].(string)
		if path == "" {
			path = "/"
		}
		q.add("path", path)
		if headers, ok := transport["headers"].(map[string]any); ok {
			if host, ok := headers["Host"].(string); ok && host != "" {
				q.add("host", host)
			}
		}
		if ed := transport["max_early_data"]; ed != nil {
			q.add("ed", toString(ed))
		}
	case "grpc":
		q.add("type", "grpc")
		if sn, ok := transport["service_name"].(string); ok && sn != "" {
			q.add("serviceName", sn)
		}
	case "http":
		q.add("type", "http")
		if path, ok := transport["path"].(string); ok && path != "" {
			q.add("path", path)
		}
		if host := transport["host"]; host != nil {
			q.add("host", joinAny(host, ","))
		}
	}
}

func ssToURI(node map[string]any, server string, port int, fragment string) string {
	method, _ := node["method"].(string)
	password, _ := node["password"].(string)
	userinfo := quoteAll(method) + ":" + quoteAll(password)

	q := &queryBuilder{}
	if v, ok := node["udp_over_tcp"]; ok && toBool(v) {
		q.add("uot", "1")
	}
	return "ss://" + userinfo + "@" + server + ":" + itoa(port) + q.String() + fragment
}

func vmessToURI(node map[string]any, server string, port int, tag string) string {
	cfg := map[string]any{
		"v":   "2",
		"ps":  tag,
		"add": server,
		"port": itoa(port),
		"id":  toString(node["uuid"]),
		"aid": itoa(toIntDefault(node["alter_id"], 0)),
		"net": "tcp",
	}
	if sec, ok := node["security"].(string); ok && sec != "" {
		cfg["scy"] = sec
	}
	if transport, ok := node["transport"].(map[string]any); ok {
		ttype, _ := transport["type"].(string)
		switch ttype {
		case "ws":
			cfg["net"] = "ws"
			path, _ := transport["path"].(string)
			if path == "" {
				path = "/"
			}
			cfg["path"] = path
			if headers, ok := transport["headers"].(map[string]any); ok {
				if host, ok := headers["Host"].(string); ok && host != "" {
					cfg["host"] = host
				}
			}
		case "grpc":
			cfg["net"] = "grpc"
			if sn, ok := transport["service_name"].(string); ok && sn != "" {
				cfg["path"] = sn
			}
		case "http":
			cfg["net"] = "h2"
		}
	}
	if tls, ok := node["tls"].(map[string]any); ok && toBool(tls["enabled"]) {
		cfg["tls"] = "tls"
		if sni, ok := tls["server_name"].(string); ok && sni != "" {
			cfg["sni"] = sni
		}
		if toBool(tls["insecure"]) {
			cfg["verify"] = false
		}
		if alpn := tls["alpn"]; alpn != nil {
			cfg["alpn"] = joinAny(alpn, ",")
		}
	}

	raw, _ := dict2jsonCompact(cfg)
	encoded := base64.URLEncoding.EncodeToString([]byte(raw))
	return "vmess://" + encoded
}

func vlessToURI(node map[string]any, server string, port int, fragment string) string {
	uuid, _ := node["uuid"].(string)
	q := &queryBuilder{}
	if transport, ok := node["transport"].(map[string]any); ok {
		buildTransportQuery(q, transport)
	}
	if tls, ok := node["tls"].(map[string]any); ok {
		buildTLSQuery(q, tls)
	}
	if flow, ok := node["flow"].(string); ok && flow != "" {
		q.add("flow", flow)
	}
	return "vless://" + uuid + "@" + server + ":" + itoa(port) + q.String() + fragment
}

func trojanToURI(node map[string]any, server string, port int, fragment string) string {
	password, _ := node["password"].(string)
	userinfo := quoteAll(password)
	q := &queryBuilder{}
	if transport, ok := node["transport"].(map[string]any); ok {
		buildTransportQuery(q, transport)
	}
	if tls, ok := node["tls"].(map[string]any); ok {
		buildTLSQuery(q, tls)
	}
	return "trojan://" + userinfo + "@" + server + ":" + itoa(port) + q.String() + fragment
}

func wireguardToURI(node map[string]any, server string, port int, fragment string) string {
	peers, _ := node["peers"].([]any)
	if len(peers) == 0 {
		return ""
	}
	peer, _ := peers[0].(map[string]any)
	publicKey, _ := peer["public_key"].(string)

	q := &queryBuilder{}
	if pk, ok := node["private_key"].(string); ok && pk != "" {
		q.add("private_key", pk)
	}
	if la, ok := node["local_address"].([]any); ok && len(la) > 0 {
		q.add("address", joinAny(la, ","))
	}
	if allowed, ok := peer["allowed_ips"].([]any); ok && len(allowed) > 0 {
		q.add("allowed_ips", joinAny(allowed, ","))
	}
	if psk, ok := peer["pre_shared_key"].(string); ok && psk != "" {
		q.add("pre_shared_key", psk)
	}
	if ka := peer["persistent_keepalive_interval"]; ka != nil {
		q.add("persistent_keepalive", toString(ka))
	}
	if r := node["reserved"]; r != nil {
		q.add("reserved", joinAny(r, ","))
	}
	if mtu := node["mtu"]; mtu != nil {
		q.add("mtu", toString(mtu))
	}
	if workers := node["workers"]; workers != nil {
		q.add("workers", toString(workers))
	}
	if dns := node["dns"]; dns != nil {
		q.add("dns", joinAny(dns, ","))
	}
	return "wireguard://" + quoteAll(publicKey) + "@" + server + ":" + itoa(port) + q.String() + fragment
}

// --- 辅助函数 ---

// toBool 宽松的真值判断（对应 Python checktrue）
func toBool(v any) bool {
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
	case json.Number:
		s := b.String()
		return s != "0" && s != ""
	}
	return false
}

// joinAny 把 any（string 或 []any）用 sep 连接成字符串
func joinAny(v any, sep string) string {
	switch val := v.(type) {
	case string:
		return val
	case []any:
		parts := make([]string, 0, len(val))
		for _, p := range val {
			parts = append(parts, toString(p))
		}
		return strings.Join(parts, sep)
	case []string:
		return strings.Join(val, sep)
	}
	return toString(v)
}

// itoa int -> string
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	return json.Number(itoaInt(i)).String()
}

func itoaInt(i int) string {
	// 避免引入 strconv 的简单实现（strconv 更快，但这里保持一致）
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
