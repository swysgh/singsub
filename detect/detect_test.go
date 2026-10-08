package detect

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// REALITY 节点缺 uTLS 时必须补上:sing-box 的 reality 客户端强制要求 uTLS,
// 订阅侧漏写 fp 时整份配置会在客户端 check 阶段整块失败。
func TestEnsureRealityUTLSFillsMissing(t *testing.T) {
	nodes := []map[string]any{
		{
			"tag": "缺指纹的 reality 节点",
			"tls": map[string]any{
				"enabled": true,
				"reality": map[string]any{"enabled": true, "public_key": "abc", "short_id": "1234"},
			},
		},
	}
	ensureRealityUTLS(nodes)

	utls, ok := nodes[0]["tls"].(map[string]any)["utls"].(map[string]any)
	if !ok {
		t.Fatalf("没有补上 utls: %#v", nodes[0])
	}
	if utls["fingerprint"] != defaultRealityFingerprint || utls["enabled"] != true {
		t.Fatalf("补出来的 utls 不对: %#v", utls)
	}
}

// 已有指纹的节点不能被覆盖(订阅里写 qq / firefox 是有意的)
func TestEnsureRealityUTLSKeepsExisting(t *testing.T) {
	nodes := []map[string]any{
		{
			"tag": "已有指纹",
			"tls": map[string]any{
				"enabled": true,
				"reality": map[string]any{"enabled": true},
				"utls":    map[string]any{"enabled": true, "fingerprint": "qq"},
			},
		},
	}
	ensureRealityUTLS(nodes)

	utls := nodes[0]["tls"].(map[string]any)["utls"].(map[string]any)
	if utls["fingerprint"] != "qq" {
		t.Fatalf("覆盖了已有指纹: %#v", utls)
	}
}

// utls 存在但指纹为空等于没写,同样要补
func TestEnsureRealityUTLSFillsEmptyFingerprint(t *testing.T) {
	nodes := []map[string]any{
		{
			"tag": "空指纹",
			"tls": map[string]any{
				"reality": map[string]any{"enabled": true},
				"utls":    map[string]any{"enabled": true, "fingerprint": ""},
			},
		},
	}
	ensureRealityUTLS(nodes)

	utls := nodes[0]["tls"].(map[string]any)["utls"].(map[string]any)
	if utls["fingerprint"] != defaultRealityFingerprint {
		t.Fatalf("空指纹没补上: %#v", utls)
	}
}

// 非 reality 节点、没有 tls 的节点、reality 未 enabled 的节点都不该被动
func TestEnsureRealityUTLSSkipsOthers(t *testing.T) {
	nodes := []map[string]any{
		{"tag": "普通 tls", "tls": map[string]any{"enabled": true, "server_name": "a.com"}},
		{"tag": "裸节点"},
		{"tag": "reality 关闭", "tls": map[string]any{"reality": map[string]any{"enabled": false}}},
	}
	ensureRealityUTLS(nodes)

	for i, node := range nodes {
		tls, _ := node["tls"].(map[string]any)
		if tls == nil {
			continue
		}
		if _, ok := tls["utls"]; ok {
			t.Fatalf("不该动节点 %d: %#v", i, node)
		}
	}
}

// 端到端一小段:真实形态的 vless reality URI(不带 fp=)过一遍 URI2Singbox 风格入口
func TestDetectAndParseFixesURIRealityWithoutFP(t *testing.T) {
	uri := "vless://11111111-2222-3333-4444-555555555555@example.com:443" +
		"?security=reality&sni=www.vercel.com&pbk=1xPsxGhI_90Aykk0DyfBH0xbvuRjzMlZZRgnlMl9snI" +
		"&sid=aea1a90f6f53&type=tcp&encryption=none#%E9%A6%99%E6%B8%AF%20PreDirect"

	outbounds, _ := DetectAndParse(uri)
	if len(outbounds) == 0 {
		t.Fatal("没解析出节点")
	}
	tls, ok := outbounds[0]["tls"].(map[string]any)
	if !ok {
		t.Fatalf("节点没有 tls: %#v", outbounds[0])
	}
	if _, ok := tls["reality"].(map[string]any); !ok {
		t.Fatalf("没有解析出 reality: %#v", tls)
	}
	utls, ok := tls["utls"].(map[string]any)
	if !ok || utls["fingerprint"] != defaultRealityFingerprint {
		t.Fatalf("reality 节点没补上 uTLS: %#v", tls)
	}
}

// 走 Clash 入口的 reality 节点(client-fingerprint 缺失)同样要补
func TestDetectAndParseFixesClashReality(t *testing.T) {
	yamlSrc := `
proxies:
  - name: "hkg-predirect"
    type: vless
    server: example.com
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    tls: true
    servername: www.vercel.com
    network: tcp
    reality-opts:
      public-key: 1xPsxGhI_90Aykk0DyfBH0xbvuRjzMlZZRgnlMl9snI
      short-id: aea1a90f6f53
`
	var probe map[string]any
	if err := yaml.Unmarshal([]byte(yamlSrc), &probe); err != nil {
		t.Fatalf("测试用 YAML 不合法: %s", err)
	}
	outbounds, _ := DetectAndParse(yamlSrc)
	if len(outbounds) == 0 {
		t.Fatal("Clash 入口没解析出节点")
	}
	tls, _ := outbounds[0]["tls"].(map[string]any)
	if tls == nil {
		t.Fatalf("节点没有 tls: %#v", outbounds[0])
	}
	if _, ok := tls["reality"].(map[string]any); !ok {
		t.Fatalf("没解析出 reality: %#v", tls)
	}
	utls, ok := tls["utls"].(map[string]any)
	if !ok || utls["fingerprint"] != defaultRealityFingerprint {
		t.Fatalf("clash reality 节点没补上 uTLS: %#v", tls)
	}
}
