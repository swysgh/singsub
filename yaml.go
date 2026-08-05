package main

import "gopkg.in/yaml.v3"

// yamlUnmarshal 包装 yaml.Unmarshal，便于统一替换实现。
func yamlUnmarshal(data string, out any) error {
	return yaml.Unmarshal([]byte(data), out)
}

// yamlMarshalImpl 包装 yaml.Marshal。
func yamlMarshalImpl(v any) ([]byte, error) {
	return yaml.Marshal(v)
}
