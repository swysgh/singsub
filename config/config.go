package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"singsub/common"
)

type Config struct {
	Token           string            `json:"token"`
	Subs            map[string]string `json:"subs"`
	Scripts         map[string]string `json:"scripts"`
	Shares          map[string]string `json:"shares"`
	ScriptTimeoutMs int               `json:"script_timeout_ms"`
	FetchTimeoutMs  int               `json:"fetch_timeout_ms"`
	MaxBodyBytes    int64             `json:"max_body_bytes"`
}

const (
	DefaultScriptTimeoutMs = 5000
	DefaultFetchTimeoutMs  = 15000
	DefaultMaxBodyBytes    = 32 << 20 // 32 MiB
)

func (c *Config) ScriptTimeout() time.Duration {
	if c.ScriptTimeoutMs <= 0 {
		return time.Duration(DefaultScriptTimeoutMs) * time.Millisecond
	}
	return time.Duration(c.ScriptTimeoutMs) * time.Millisecond
}

func (c *Config) FetchTimeout() time.Duration {
	if c.FetchTimeoutMs <= 0 {
		return time.Duration(DefaultFetchTimeoutMs) * time.Millisecond
	}
	return time.Duration(c.FetchTimeoutMs) * time.Millisecond
}

func (c *Config) MaxBodyLimit() int64 {
	if c.MaxBodyBytes <= 0 {
		return DefaultMaxBodyBytes
	}
	return c.MaxBodyBytes
}

func LoadConfig(path string) (*Config, error) {
	common.LogInfo("加载配置文件: %s", path)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	if cfg.Token == "" {
		return nil, fmt.Errorf("配置文件需配置非空 token 字符串")
	}
	if cfg.Subs == nil {
		return nil, fmt.Errorf("配置文件需包含 subs 对象")
	}
	for key, spath := range cfg.Scripts {
		if spath == "" {
			return nil, fmt.Errorf("脚本 %s 的值需为脚本路径字符串", key)
		}
	}
	for key, scriptName := range cfg.Shares {
		if scriptName == "" {
			return nil, fmt.Errorf("分享 %s 的值需为脚本名字符串", key)
		}
		if cfg.Scripts != nil {
			if _, ok := cfg.Scripts[scriptName]; !ok {
				common.LogWarn("分享 %s 引用的脚本 %s 未在 scripts 中定义", key, scriptName)
			}
		}
	}

	common.LogInfo("配置文件加载成功，订阅: %d 个，脚本: %d 个，分享链接: %d 个",
		len(cfg.Subs), len(cfg.Scripts), len(cfg.Shares))
	return &cfg, nil
}

func ConfigDir(configPath string) string {
	abs, err := filepath.Abs(configPath)
	if err != nil {
		return filepath.Dir(configPath)
	}
	return filepath.Dir(abs)
}
