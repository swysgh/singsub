package main

import (
	"encoding/base64"
	"encoding/json"
)

// jsonUnmarshal 包装 json.Unmarshal。
func jsonUnmarshal(data string, v any) error {
	return json.Unmarshal([]byte(data), v)
}

// yamlMarshal 包装 yaml.Marshal。
func yamlMarshal(v any) ([]byte, error) {
	return yamlMarshalImpl(v)
}

// b64encodeStd 标准基类编码（兼容 Sub-Store 的 b64e）。
func b64encodeStd(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// b64decodeStd 标准基类解码（兼容 Sub-Store 的 b64d）。
func b64decodeStd(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		// 尝试 URL-safe
		b, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			// 尝试无 padding
			b, err = base64.RawStdEncoding.DecodeString(s)
			if err != nil {
				return "", err
			}
		}
	}
	return string(b), nil
}
