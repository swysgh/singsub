package sb2uri

import (
	"encoding/base64"
	"strings"

	"singsub/internal/common"
)

func Singbox2URI(data any) string {
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
		common.LogWarn("singbox2uri: 输入类型不支持 (%T)", data)
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
			common.LogWarn("singbox2uri: 跳过不支持的节点 %s (type=%s)", common.ToString(node["tag"]), common.ToString(node["type"]))
		}
	}
	return strings.Join(lines, "\n")
}

func nodeToURI(node map[string]any) string {
	ntype, _ := node["type"].(string)
	server, _ := node["server"].(string)
	port := common.ToInt(node["server_port"])
	tag, _ := node["tag"].(string)

	fragment := ""
	if tag != "" {
		fragment = "#" + common.QuoteAll(tag)
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
		parts = append(parts, p[0]+"="+common.QuoteAll(p[1]))
	}
	return "?" + strings.Join(parts, "&")
}

func buildTLSQuery(q *queryBuilder, tlsMap map[string]any) {
	if tlsMap == nil {
		return
	}
	if reality, ok := tlsMap["reality"].(map[string]any); ok && common.ToBool(reality["enabled"]) {
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
	} else if common.ToBool(tlsMap["enabled"]) {
		q.add("security", "tls")
		if sni, ok := tlsMap["server_name"].(string); ok && sni != "" {
			q.add("sni", sni)
		}
		if common.ToBool(tlsMap["insecure"]) {
			q.add("allowInsecure", "1")
		}
	}
	if alpn := tlsMap["alpn"]; alpn != nil {
		q.add("alpn", common.JoinAny(alpn, ","))
	}
	if utls, ok := tlsMap["utls"].(map[string]any); ok {
		if fp, ok := utls["fingerprint"].(string); ok && fp != "" {
			q.add("fp", fp)
		}
	}
}

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
			q.add("ed", common.ToString(ed))
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
			q.add("host", common.JoinAny(host, ","))
		}
	}
}

func ssToURI(node map[string]any, server string, port int, fragment string) string {
	method, _ := node["method"].(string)
	password, _ := node["password"].(string)
	userinfo := common.QuoteAll(method) + ":" + common.QuoteAll(password)

	q := &queryBuilder{}
	if v, ok := node["udp_over_tcp"]; ok && common.ToBool(v) {
		q.add("uot", "1")
	}
	return "ss://" + userinfo + "@" + server + ":" + common.Itoa(port) + q.String() + fragment
}

func vmessToURI(node map[string]any, server string, port int, tag string) string {
	cfg := map[string]any{
		"v":   "2",
		"ps":  tag,
		"add": server,
		"port": common.Itoa(port),
		"id":  common.ToString(node["uuid"]),
		"aid": common.Itoa(common.ToIntDefault(node["alter_id"], 0)),
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
	if tls, ok := node["tls"].(map[string]any); ok && common.ToBool(tls["enabled"]) {
		cfg["tls"] = "tls"
		if sni, ok := tls["server_name"].(string); ok && sni != "" {
			cfg["sni"] = sni
		}
		if common.ToBool(tls["insecure"]) {
			cfg["verify"] = false
		}
		if alpn := tls["alpn"]; alpn != nil {
			cfg["alpn"] = common.JoinAny(alpn, ",")
		}
	}

	raw, _ := common.Dict2JSONCompact(cfg)
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
	return "vless://" + uuid + "@" + server + ":" + common.Itoa(port) + q.String() + fragment
}

func trojanToURI(node map[string]any, server string, port int, fragment string) string {
	password, _ := node["password"].(string)
	userinfo := common.QuoteAll(password)
	q := &queryBuilder{}
	if transport, ok := node["transport"].(map[string]any); ok {
		buildTransportQuery(q, transport)
	}
	if tls, ok := node["tls"].(map[string]any); ok {
		buildTLSQuery(q, tls)
	}
	return "trojan://" + userinfo + "@" + server + ":" + common.Itoa(port) + q.String() + fragment
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
		q.add("address", common.JoinAny(la, ","))
	}
	if allowed, ok := peer["allowed_ips"].([]any); ok && len(allowed) > 0 {
		q.add("allowed_ips", common.JoinAny(allowed, ","))
	}
	if psk, ok := peer["pre_shared_key"].(string); ok && psk != "" {
		q.add("pre_shared_key", psk)
	}
	if ka := peer["persistent_keepalive_interval"]; ka != nil {
		q.add("persistent_keepalive", common.ToString(ka))
	}
	if r := node["reserved"]; r != nil {
		q.add("reserved", common.JoinAny(r, ","))
	}
	if mtu := node["mtu"]; mtu != nil {
		q.add("mtu", common.ToString(mtu))
	}
	if workers := node["workers"]; workers != nil {
		q.add("workers", common.ToString(workers))
	}
	if dns := node["dns"]; dns != nil {
		q.add("dns", common.JoinAny(dns, ","))
	}
	return "wireguard://" + common.QuoteAll(publicKey) + "@" + server + ":" + common.Itoa(port) + q.String() + fragment
}