package main

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// clash2singbox 把 Clash YAML 配置转成 sing-box 节点列表。
// 对应 Python 版 clash.clash2singbox。
func clash2singbox(originData string) []map[string]any {
	if originData == "" {
		logWarn("订阅内容为空，请检查链接或网络！")
		return nil
	}

	var data map[string]any
	if err := yaml.Unmarshal([]byte(originData), &data); err != nil {
		logError("Clash YAML 解析失败: %s", err)
		return nil
	}

	proxies, ok := data["proxies"].([]any)
	if !ok {
		return nil
	}

	var allnode []map[string]any
	for _, p := range proxies {
		onenode, ok := p.(map[string]any)
		if !ok {
			continue
		}
		node := clashNodeToSingbox(onenode)
		if node != nil {
			allnode = append(allnode, node)
		}
	}
	return allnode
}

// checkFalse 对应 Python checkfalse：字符串 "false" 视为假
func checkFalse(v any) bool {
	if v == nil {
		return false
	}
	s := strings.ToLower(strings.TrimSpace(toString(v)))
	return s == "false"
}

// checkTrue 对应 Python checktrue：字符串 "true" 视为真
func checkTrue(v any) bool {
	if v == nil {
		return false
	}
	s := strings.ToLower(strings.TrimSpace(toString(v)))
	return s == "true"
}

// toIntAny 从 any 取 int（yaml 解析出的可能是 int / int64 / float64）
func toIntAny(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case string:
		return toIntStr(n)
	}
	return 0
}

// pemOrPath 判断值是 PEM 内容还是文件路径
func pemOrPath(value any) (pem, path string) {
	s := toString(value)
	if strings.HasPrefix(strings.TrimLeft(s, " "), "-----BEGIN") {
		return s, ""
	}
	return "", s
}

// dialFields 处理 smux / brutal / detour 等拨号相关字段
func dialFields(onenode, node map[string]any) {
	if checkFalse(onenode["udp"]) {
		node["network"] = "tcp"
	}
	if smux, ok := onenode["smux"].(map[string]any); ok {
		if !checkFalse(smux["enabled"]) {
			node["smux"] = map[string]any{
				"enabled":         true,
				"protocol":        firstNonEmpty(toString(smux["protocol"]), "smux"),
				"max_connections": toIntAnyDefault(smux["max-connections"], 4),
				"min_streams":     toIntAnyDefault(smux["min-streams"], 4),
				"max_streams":     toIntAnyDefault(smux["max-streams"], 0),
				"padding":         checkTrue(smux["padding"]),
			}
			if checkTrue(onenode["padding"]) {
				node["padding"] = true
			}
			if brutal, ok := smux["brutal-opts"].(map[string]any); ok {
				if checkTrue(brutal["enabled"]) {
					node["brutal"] = map[string]any{
						"enabled":  true,
						"up_mbps":  toIntAnyDefault(brutal["up"], 100),
						"down_mbps": toIntAnyDefault(brutal["down"], 100),
					}
				}
			}
		}
	}
	if detour := toString(onenode["dialer-proxy"]); detour != "" {
		node["detour"] = detour
	}
}

func toIntAnyDefault(v any, def int) int {
	if v == nil {
		return def
	}
	i := toIntAny(v)
	return i
}

// clashTLS 处理 TLS 相关字段
func clashTLS(onenode, node map[string]any) {
	tls := map[string]any{}
	if checkTrue(onenode["tls"]) {
		tls["enabled"] = true
	}
	if sn := toString(onenode["servername"]); sn != "" {
		tls["server_name"] = sn
	}
	if alpn := onenode["alpn"]; alpn != nil {
		tls["alpn"] = alpn
	}
	if checkTrue(onenode["skip-cert-verify"]) {
		tls["insecure"] = true
	}
	if utls := toString(onenode["client-fingerprint"]); utls != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": utls}
	}
	if reality, ok := onenode["reality-opts"].(map[string]any); ok {
		tls["reality"] = map[string]any{
			"enabled":    true,
			"public_key": toString(reality["public-key"]),
			"short_id":   toString(reality["short-id"]),
		}
	}
	if cert := onenode["certificate"]; cert != nil {
		pem, path := pemOrPath(cert)
		if pem != "" {
			tls["certificate"] = []string{pem}
		} else {
			tls["certificate_path"] = path
		}
	}
	if privkey := onenode["private-key"]; privkey != nil {
		pem, path := pemOrPath(privkey)
		if pem != "" {
			tls["key"] = []string{pem}
		} else {
			tls["key_path"] = path
		}
	}
	if len(tls) > 0 {
		node["tls"] = tls
	}
}

// clashV2RayTransport 处理传输层（ws/grpc/h2/http）
func clashV2RayTransport(onenode, node map[string]any) {
	network, _ := onenode["network"].(string)
	switch network {
	case "tcp", "":
		return
	case "ws":
		wsOpts, _ := onenode["ws-opts"].(map[string]any)
		if wsOpts == nil {
			wsOpts = map[string]any{}
		}
		transport := map[string]any{"type": "ws"}
		path, _ := wsOpts["path"].(string)
		if path == "" {
			path = "/"
		}
		transport["path"] = path
		if headers := wsOpts["headers"]; headers != nil {
			transport["headers"] = headers
		}
		if ed := wsOpts["max-early-data"]; ed != nil {
			transport["max_early_data"] = toIntAny(ed)
		}
		if h := toString(wsOpts["early-data-header-name"]); h != "" {
			transport["early_data_header_name"] = h
		}
		node["transport"] = transport
	case "grpc":
		grpcOpts, _ := onenode["grpc-opts"].(map[string]any)
		if grpcOpts == nil {
			grpcOpts = map[string]any{}
		}
		transport := map[string]any{"type": "grpc"}
		if sn := toString(grpcOpts["grpc-service-name"]); sn != "" {
			transport["service_name"] = sn
		}
		node["transport"] = transport
	case "h2", "http":
		var opts map[string]any
		if o, ok := onenode["h2-opts"].(map[string]any); ok {
			opts = o
		} else if o, ok := onenode["http-opts"].(map[string]any); ok {
			opts = o
		} else {
			opts = map[string]any{}
		}
		transport := map[string]any{"type": "http"}
		if host := opts["host"]; host != nil {
			switch h := host.(type) {
			case string:
				transport["host"] = []string{h}
			default:
				transport["host"] = h
			}
		}
		if path := toString(opts["path"]); path != "" {
			transport["path"] = path
		}
		if method := toString(opts["method"]); method != "" {
			transport["method"] = method
		}
		if headers := opts["headers"]; headers != nil {
			transport["headers"] = headers
		}
		node["transport"] = transport
	}
}

// clashNodeToSingbox 把单个 clash 节点转成 sing-box 节点
func clashNodeToSingbox(onenode map[string]any) map[string]any {
	ntype, _ := onenode["type"].(string)
	name, _ := onenode["name"].(string)
	server, _ := onenode["server"].(string)
	port := toIntAny(onenode["port"])

	switch ntype {
	case "ss":
		node := map[string]any{
			"tag":         name,
			"type":        "shadowsocks",
			"server":      server,
			"server_port": port,
			"method":      toString(onenode["cipher"]),
			"password":    toString(onenode["password"]),
		}
		if checkTrue(onenode["udp-over-tcp"]) {
			version := onenode["udp-over-tcp-version"]
			verStr := toString(version)
			if verStr == "1" || verStr == "2" {
				node["udp_over_tcp"] = map[string]any{"enabled": true, "version": toIntAny(version)}
			} else {
				node["udp_over_tcp"] = true
			}
		}
		dialFields(onenode, node)
		return node

	case "vless":
		node := map[string]any{
			"tag":         name,
			"type":        "vless",
			"server":      server,
			"server_port": port,
			"uuid":        toString(onenode["uuid"]),
		}
		if flow := toString(onenode["flow"]); flow != "" {
			node["flow"] = flow
		}
		if pe := onenode["packet_encoding"]; pe != nil {
			node["packet_encoding"] = pe
		}
		dialFields(onenode, node)
		clashTLS(onenode, node)
		clashV2RayTransport(onenode, node)
		return node

	case "vmess":
		node := map[string]any{
			"tag":         name,
			"type":        "vmess",
			"server":      server,
			"server_port": port,
			"uuid":        toString(onenode["uuid"]),
			"alter_id":    toIntAnyDefault(onenode["alter-id"], 0),
		}
		if pe := onenode["packet_encoding"]; pe != nil {
			node["packet_encoding"] = pe
		}
		if cipher := toString(onenode["cipher"]); cipher != "" {
			node["security"] = cipher
		}
		dialFields(onenode, node)
		clashTLS(onenode, node)
		clashV2RayTransport(onenode, node)
		return node

	case "trojan":
		node := map[string]any{
			"tag":         name,
			"type":        "trojan",
			"server":      server,
			"server_port": port,
			"password":    toString(onenode["password"]),
		}
		dialFields(onenode, node)
		clashTLS(onenode, node)
		clashV2RayTransport(onenode, node)
		return node

	case "wireguard":
		return clashWireguardToSingbox(onenode, name, server, port)
	}
	return nil
}

// clashWireguardToSingbox 处理 wireguard 节点
func clashWireguardToSingbox(onenode map[string]any, name, server string, port int) map[string]any {
	node := map[string]any{
		"tag":         name,
		"type":        "wireguard",
		"server":      server,
		"server_port": port,
	}

	privateKey := firstNonEmpty(toString(onenode["private-key"]), toString(onenode["private_key"]))
	if privateKey != "" {
		node["private_key"] = privateKey
	}

	// local_address
	var ip any
	if v, ok := onenode["ip"]; ok {
		ip = v
	} else if v, ok := onenode["ip-address"]; ok {
		ip = v
	} else if v, ok := onenode["local_address"]; ok {
		ip = v
	}
	if ip != nil {
		switch v := ip.(type) {
		case string:
			node["local_address"] = []string{v}
		case []any:
			node["local_address"] = v
		default:
			node["local_address"] = []any{v}
		}
	} else {
		node["local_address"] = []any{}
	}

	publicKey := firstNonEmpty(toString(onenode["public-key"]), toString(onenode["public_key"]))
	if publicKey == "" {
		return nil
	}

	peer := map[string]any{
		"address":    server,
		"port":       port,
		"public_key": publicKey,
	}

	// allowed_ips
	var allowed any
	if v, ok := onenode["allowed-ips"]; ok {
		allowed = v
	} else if v, ok := onenode["allowed_ips"]; ok {
		allowed = v
	} else {
		allowed = []string{"0.0.0.0/0", "::/0"}
	}
	switch v := allowed.(type) {
	case string:
		peer["allowed_ips"] = []string{v}
	case []any:
		peer["allowed_ips"] = v
	default:
		peer["allowed_ips"] = []any{v}
	}

	if psk := firstNonEmpty(toString(onenode["pre-shared-key"]), toString(onenode["pre_shared_key"])); psk != "" {
		peer["pre_shared_key"] = psk
	}
	if keepalive := firstNonEmpty(toString(onenode["keepalive"]), toString(onenode["persistent_keepalive_interval"])); keepalive != "" {
		peer["persistent_keepalive_interval"] = toIntStr(keepalive)
	}

	node["peers"] = []any{peer}

	if reserved := onenode["reserved"]; reserved != nil {
		switch v := reserved.(type) {
		case []any:
			var rs []any
			for _, r := range v {
				rs = append(rs, toIntAny(r))
			}
			node["reserved"] = rs
		case string:
			parts := strings.Split(v, ",")
			var rs []any
			for _, p := range parts {
				rs = append(rs, toIntStr(p))
			}
			node["reserved"] = rs
		}
	}
	if mtu := onenode["mtu"]; mtu != nil {
		node["mtu"] = toIntAny(mtu)
	}
	if workers := onenode["workers"]; workers != nil {
		node["workers"] = toIntAny(workers)
	}
	if dns := onenode["dns"]; dns != nil {
		switch v := dns.(type) {
		case string:
			node["dns"] = []string{v}
		case []any:
			node["dns"] = v
		default:
			node["dns"] = []any{v}
		}
	}
	return node
}

// 确保 os 被引用（未来扩展可能用）
var _ = os.Getenv
