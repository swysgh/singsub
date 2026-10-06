package detect

import (
	"encoding/json"
	"strings"

	"singsub/clash"
	"singsub/common"
	"singsub/sb2uri"
	"singsub/uri2sb"
)

func DetectAndParse(originData string) (outbounds, endpoints []map[string]any) {
	stripped := strings.TrimLeft(originData, " \t\r\n")

	if strings.HasPrefix(stripped, "{") {
		var config map[string]any
		if err := json.Unmarshal([]byte(originData), &config); err == nil {
			_, hasOutbounds := config["outbounds"]
			_, hasEndpoints := config["endpoints"]
			if hasOutbounds || hasEndpoints {
				outbounds = toMapSlice(config["outbounds"])
				endpoints = toMapSlice(config["endpoints"])
				ensureRealityUTLS(outbounds)
				return outbounds, endpoints
			}
		}
	}

	if nodes := tryClash(originData); nodes != nil {
		ensureRealityUTLS(nodes)
		return nodes, nil
	}

	nodes := uri2sb.URI2Singbox(originData)
	if nodes == nil {
		return nil, nil
	}
	ensureRealityUTLS(nodes)
	return nodes, nil
}

// 兼容订阅里没写指纹的 REALITY 节点。
//
// sing-box 的 REALITY 客户端**强制要求 uTLS**,没有它 `sing-box check` 直接失败:
//
//	FATAL[0000] initialize outbound[41]: uTLS is required by reality client
//
// REALITY 的伪装本就是照着某个真实浏览器的样子握手 —— 缺指纹时补 chrome 是唯一安全的取值,
// 换成别的浏览器反而会把 SNI 与指纹的匹配关系弄拧。这里补上是为了让订阅侧漏写指纹时
// 仍能产出可用配置,而不是让整份配置在客户端校验阶段整块失败。
const defaultRealityFingerprint = "chrome"

func ensureRealityUTLS(nodes []map[string]any) {
	for _, node := range nodes {
		tls, ok := node["tls"].(map[string]any)
		if !ok || tls == nil {
			continue
		}
		reality, ok := tls["reality"].(map[string]any)
		if !ok || reality == nil || !common.ToBool(reality["enabled"]) {
			continue
		}
		if utls, ok := tls["utls"].(map[string]any); ok && common.ToBool(utls["enabled"]) &&
			common.ToString(utls["fingerprint"]) != "" {
			continue
		}
		common.LogWarn("节点 %q 缺少 uTLS 指纹,REALITY 客户端必须有 uTLS,已补默认指纹 %s",
			common.ToString(node["tag"]), defaultRealityFingerprint)
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": defaultRealityFingerprint}
	}
}

func tryClash(originData string) []map[string]any {
	var parsed map[string]any
	if err := common.YAMLUnmarshal(originData, &parsed); err != nil {
		return nil
	}
	if _, ok := parsed["proxies"]; !ok {
		return nil
	}
	return clash.Clash2Singbox(originData)
}

func toMapSlice(v any) []map[string]any {
	if v == nil {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	var result []map[string]any
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			result = append(result, m)
		}
	}
	return result
}

func RenderNodes(outbounds, endpoints []map[string]any, fmtStr string) (string, string) {
	if fmtStr == "uri" {
		all := make([]any, 0, len(outbounds)+len(endpoints))
		for _, o := range outbounds {
			all = append(all, o)
		}
		for _, e := range endpoints {
			all = append(all, e)
		}
		return "text/plain; charset=utf-8", sb2uri.Singbox2URI(all)
	}
	config := map[string]any{"outbounds": outbounds}
	if len(endpoints) > 0 {
		config["endpoints"] = endpoints
	}
	body, err := common.Dict2JSON(config)
	if err != nil {
		common.LogError("JSON 序列化失败: %s", err)
		return "text/plain; charset=utf-8", "{}"
	}
	return "application/json; charset=utf-8", body
}
