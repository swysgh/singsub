package clash

import (
	"strings"

	"singsub/common"
)

func Clash2Singbox(originData string) []map[string]any {
	if originData == "" {
		common.LogWarn("订阅内容为空，请检查链接或网络！")
		return nil
	}

	var data map[string]any
	if err := common.YAMLUnmarshal(originData, &data); err != nil {
		common.LogError("Clash YAML 解析失败: %s", err)
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

func toIntAny(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case string:
		return common.ToIntStr(n)
	}
	return 0
}

func toIntAnyDefault(v any, def int) int {
	if v == nil {
		return def
	}
	i := toIntAny(v)
	return i
}

func pemOrPath(value any) (pem, path string) {
	s := common.ToString(value)
	if len(s) > 0 && s[0] == '-' {
		return s, ""
	}
	return "", s
}

func dialFields(onenode, node map[string]any) {
	if common.CheckFalse(onenode["udp"]) {
		node["network"] = "tcp"
	}
	if smux, ok := onenode["smux"].(map[string]any); ok {
		if !common.CheckFalse(smux["enabled"]) {
			node["smux"] = map[string]any{
				"enabled":         true,
				"protocol":        common.FirstNonEmpty(common.ToString(smux["protocol"]), "smux"),
				"max_connections": toIntAnyDefault(smux["max-connections"], 4),
				"min_streams":     toIntAnyDefault(smux["min-streams"], 4),
				"max_streams":     toIntAnyDefault(smux["max-streams"], 0),
				"padding":         common.CheckTrue(smux["padding"]),
			}
			if common.CheckTrue(onenode["padding"]) {
				node["padding"] = true
			}
			if brutal, ok := smux["brutal-opts"].(map[string]any); ok {
				if common.CheckTrue(brutal["enabled"]) {
					node["brutal"] = map[string]any{
						"enabled":    true,
						"up_mbps":    toIntAnyDefault(brutal["up"], 100),
						"down_mbps": toIntAnyDefault(brutal["down"], 100),
					}
				}
			}
		}
	}
	if detour := common.ToString(onenode["dialer-proxy"]); detour != "" {
		node["detour"] = detour
	}
}

func clashTLS(onenode, node map[string]any) {
	tls := map[string]any{}
	if common.CheckTrue(onenode["tls"]) {
		tls["enabled"] = true
	}
	if sn := common.ToString(onenode["servername"]); sn != "" {
		tls["server_name"] = sn
	}
	if alpn := onenode["alpn"]; alpn != nil {
		tls["alpn"] = alpn
	}
	if common.CheckTrue(onenode["skip-cert-verify"]) {
		tls["insecure"] = true
	}
	if utls := common.ToString(onenode["client-fingerprint"]); utls != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": utls}
	}
	if reality, ok := onenode["reality-opts"].(map[string]any); ok {
		tls["reality"] = map[string]any{
			"enabled":    true,
			"public_key": common.ToString(reality["public-key"]),
			"short_id":   common.ToString(reality["short-id"]),
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
		if h := common.ToString(wsOpts["early-data-header-name"]); h != "" {
			transport["early_data_header_name"] = h
		}
		node["transport"] = transport
	case "grpc":
		grpcOpts, _ := onenode["grpc-opts"].(map[string]any)
		if grpcOpts == nil {
			grpcOpts = map[string]any{}
		}
		transport := map[string]any{"type": "grpc"}
		if sn := common.ToString(grpcOpts["grpc-service-name"]); sn != "" {
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
		if path := common.ToString(opts["path"]); path != "" {
			transport["path"] = path
		}
		if method := common.ToString(opts["method"]); method != "" {
			transport["method"] = method
		}
		if headers := opts["headers"]; headers != nil {
			transport["headers"] = headers
		}
		node["transport"] = transport
	}
}

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
			"method":      common.ToString(onenode["cipher"]),
			"password":    common.ToString(onenode["password"]),
		}
		if common.CheckTrue(onenode["udp-over-tcp"]) {
			version := onenode["udp-over-tcp-version"]
			verStr := common.ToString(version)
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
			"uuid":        common.ToString(onenode["uuid"]),
		}
		if flow := common.ToString(onenode["flow"]); flow != "" {
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
			"uuid":        common.ToString(onenode["uuid"]),
			"alter_id":    toIntAnyDefault(onenode["alter-id"], 0),
		}
		if pe := onenode["packet_encoding"]; pe != nil {
			node["packet_encoding"] = pe
		}
		if cipher := common.ToString(onenode["cipher"]); cipher != "" {
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
			"password":    common.ToString(onenode["password"]),
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

func clashWireguardToSingbox(onenode map[string]any, name, server string, port int) map[string]any {
	node := map[string]any{
		"tag":         name,
		"type":        "wireguard",
		"server":      server,
		"server_port": port,
	}

	privateKey := common.FirstNonEmpty(common.ToString(onenode["private-key"]), common.ToString(onenode["private_key"]))
	if privateKey != "" {
		node["private_key"] = privateKey
	}

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

	publicKey := common.FirstNonEmpty(common.ToString(onenode["public-key"]), common.ToString(onenode["public_key"]))
	if publicKey == "" {
		return nil
	}

	peer := map[string]any{
		"address":    server,
		"port":       port,
		"public_key": publicKey,
	}

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

	if psk := common.FirstNonEmpty(common.ToString(onenode["pre-shared-key"]), common.ToString(onenode["pre_shared_key"])); psk != "" {
		peer["pre_shared_key"] = psk
	}
	if keepalive := common.FirstNonEmpty(common.ToString(onenode["keepalive"]), common.ToString(onenode["persistent_keepalive_interval"])); keepalive != "" {
		peer["persistent_keepalive_interval"] = common.ToIntStr(keepalive)
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
				rs = append(rs, common.ToIntStr(p))
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