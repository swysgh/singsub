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
				return outbounds, endpoints
			}
		}
	}

	if nodes := tryClash(originData); nodes != nil {
		return nodes, nil
	}

	nodes := uri2sb.URI2Singbox(originData)
	if nodes == nil {
		return nil, nil
	}
	return nodes, nil
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
