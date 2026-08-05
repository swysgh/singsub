package main

import (
	"encoding/json"
	"strings"
)

// detectAndParse 自动识别订阅格式，提取节点列表。
// 返回 (outbounds, endpoints)。
// wireguard 节点在 sing-box 中属于 endpoint，不放在 outbounds 中。
// clash / URI 输入：全部视为 outbounds，endpoints 为空。
// 对应 Python 版 singsub.detect_and_parse。
func detectAndParse(originData string) (outbounds, endpoints []map[string]any) {
	stripped := strings.TrimLeft(originData, " \t\r\n")

	// sing-box JSON：以 { 开头且含 outbounds 字段
	if strings.HasPrefix(stripped, "{") {
		var config map[string]any
		if err := json.Unmarshal([]byte(originData), &config); err == nil {
			if _, ok := config["outbounds"]; ok {
				outbounds = toMapSlice(config["outbounds"])
				endpoints = toMapSlice(config["endpoints"])
				return outbounds, endpoints
			}
		}
	}

	// Clash YAML：尝试解析，带 proxies 字段的就是 Clash 配置
	if nodes := tryClash(originData); nodes != nil {
		return nodes, nil
	}

	// 否则按 URI 订阅处理
	nodes := uri2singbox(originData)
	if nodes == nil {
		return nil, nil
	}
	return nodes, nil
}

// tryClash 尝试用 yaml 解析并检查是否是 Clash 配置
func tryClash(originData string) []map[string]any {
	// 用 yaml 解析（不依赖 clash2singbox 内部重复解析）
	var parsed map[string]any
	if err := yamlUnmarshal(originData, &parsed); err != nil {
		return nil
	}
	if _, ok := parsed["proxies"]; !ok {
		return nil
	}
	return clash2singbox(originData)
}

// toMapSlice 把 any 转成 []map[string]any，非 map 元素跳过。
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

// renderNodes 把 outbounds/endpoints 渲染成 (contentType, body)。
// uri 格式同时输出 outbounds 和 endpoints（sing-box 不区分两者 tag）。
func renderNodes(outbounds, endpoints []map[string]any, fmtStr string) (string, string) {
	if fmtStr == "uri" {
		// sb2uri 接受 []any，合并 outbounds + endpoints
		all := make([]any, 0, len(outbounds)+len(endpoints))
		for _, o := range outbounds {
			all = append(all, o)
		}
		for _, e := range endpoints {
			all = append(all, e)
		}
		return "text/plain; charset=utf-8", singbox2uri(all)
	}
	config := map[string]any{"outbounds": outbounds}
	if len(endpoints) > 0 {
		config["endpoints"] = endpoints
	}
	body, err := dict2json(config)
	if err != nil {
		logError("JSON 序列化失败: %s", err)
		return "text/plain; charset=utf-8", "{}"
	}
	return "application/json; charset=utf-8", body
}
