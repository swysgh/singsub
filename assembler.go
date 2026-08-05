package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
)

// Assembler 管理 JS 脚本的加载（带 mtime 缓存）和执行。
// 兼容 Sub-Store 脚本风格：
//   - $content: 初始为 null，脚本读模板后赋值；脚本结束后作为最终输出
//   - $arguments: 查询参数对象（Sub-Store 风格）
//   - $files / $options: Sub-Store 占位
//   - produceArtifact({type, name, platform, produceType}): 返回订阅节点数组
//   - require("fs") / fs.readFileSync: 读本地文件
//   - 顶层 await: 脚本中可直接 await produceArtifact(...)
//
// 同时保留 singsub 原有的 assemble(context) 契约的等价 JS 形式：
// 脚本可定义 function assemble(context) 并返回配置 dict。
// 优先级：$content 模式 > assemble 函数。
type Assembler struct {
	configDir string
	subs      map[string]string
	ua        string
}

// 全局脚本源码缓存（跨请求共享，基于 mtime 失效）
var (
	scriptCacheMu    sync.Mutex
	scriptCacheStore = map[string]scriptCacheEntry{}
)

type scriptCacheEntry struct {
	mtime time.Time
	src   string
}

// NewAssembler 创建一个脚本装配器。
func NewAssembler(subs map[string]string, configDir, ua string) *Assembler {
	return &Assembler{
		configDir: configDir,
		subs:      subs,
		ua:        ua,
	}
}

// RunScript 加载并执行脚本，返回最终的 sing-box 配置 dict。
func (a *Assembler) RunScript(scriptPath string, args map[string]string) (map[string]any, error) {
	path := resolvePath(scriptPath, a.configDir)

	src, err := a.loadScript(path)
	if err != nil {
		return nil, err
	}

	vm := goja.New()
	a.injectAPI(vm, path, args)

	// 包装成 async IIFE 以支持顶层 await。
	// 同时把脚本内可能定义的 assemble 函数暴露到全局（IIFE 内的 function 声明是局部的）。
	// 通过在脚本末尾追加 `globalThis.assemble = assemble` 实现——但如果 assemble 未定义会报错，
	// 所以用 typeof 守卫。
	wrapped := "(async function() {\n" + src + "\n;if (typeof assemble !== 'undefined') { globalThis.assemble = assemble; }\n})()"
	v, err := vm.RunScript(filepath.Base(path), wrapped)
	if err != nil {
		return nil, &ScriptError{Path: path, Err: err}
	}

	// 检查顶层 promise 状态（goja 同步 resolve 时此处已完成）
	if obj, ok := v.(*goja.Object); ok {
		if p, ok := obj.Export().(*goja.Promise); ok {
			switch p.State() {
			case goja.PromiseStateRejected:
				return nil, &ScriptError{Path: path, Err: errors.New(toString(p.Result()))}
			}
		}
	}

	// 优先：$content 模式（Sub-Store 风格）
	if contentVal := vm.Get("$content"); contentVal != nil && !goja.IsUndefined(contentVal) && !goja.IsNull(contentVal) {
		contentStr := contentVal.String()
		if contentStr != "" {
			var config map[string]any
			if err := jsonUnmarshal(contentStr, &config); err == nil {
				return config, nil
			}
			// $content 不是 JSON：返回包了一层的 config
			return map[string]any{"_content": contentStr}, nil
		}
	}

	// 兼容：脚本定义了 assemble(context) 函数
	if assembleVal := vm.Get("assemble"); assembleVal != nil && !goja.IsUndefined(assembleVal) {
		if fn, ok := goja.AssertFunction(assembleVal); ok {
			context := map[string]any{
				"subs":       buildLazySubsObject(vm, a.subs, a.ua, a.configDir),
				"args":       args,
				"config_dir": a.configDir,
			}
			ret, err := fn(goja.Undefined(), vm.ToValue(context))
			if err != nil {
				return nil, &ScriptError{Path: path, Err: err}
			}
			if ret == nil || goja.IsUndefined(ret) || goja.IsNull(ret) {
				return nil, &ScriptError{Path: path, Err: errors.New("assemble 返回了空值")}
			}
			if config, ok := ret.Export().(map[string]any); ok {
				return config, nil
			}
			// JSON 往返兜底
			if jsonStr, err := dict2jsonCompact(ret.Export()); err == nil {
				var config map[string]any
				if err := jsonUnmarshal(jsonStr, &config); err == nil {
					return config, nil
				}
			}
			return nil, &ScriptError{Path: path, Err: errors.New("assemble 返回类型无法识别为配置 dict")}
		}
	}

	return nil, &ScriptError{Path: path, Err: errors.New("脚本既未设置 $content 也未定义 assemble(context)")}
}

// loadScript 按 mtime 缓存加载脚本源码。
func (a *Assembler) loadScript(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", &ScriptError{Path: path, Err: errors.New("脚本不存在: " + path)}
		}
		return "", &ScriptError{Path: path, Err: err}
	}

	scriptCacheMu.Lock()
	defer scriptCacheMu.Unlock()

	if cached, ok := scriptCacheStore[path]; ok && cached.mtime.Equal(fi.ModTime()) {
		return cached.src, nil
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return "", &ScriptError{Path: path, Err: err}
	}
	src := string(b)
	scriptCacheStore[path] = scriptCacheEntry{mtime: fi.ModTime(), src: src}
	logInfo("已加载脚本: %s", path)
	return src, nil
}

// ScriptError 包装脚本执行错误，带路径信息。
type ScriptError struct {
	Path string
	Err  error
}

func (e *ScriptError) Error() string { return e.Err.Error() }
func (e *ScriptError) Unwrap() error { return e.Err }

// injectAPI 注入 Sub-Store 兼容的全局 API。
func (a *Assembler) injectAPI(vm *goja.Runtime, scriptPath string, args map[string]string) {
	// $content: 初始为 null，脚本负责赋值
	vm.Set("$content", nil)

	// $arguments: 查询参数对象
	vm.Set("$arguments", args)

	// $files / $options: Sub-Store 占位
	vm.Set("$files", []any{})
	vm.Set("$options", map[string]any{})

	// fs 模块
	fsObj := vm.NewObject()
	fsObj.Set("readFileSync", func(call goja.FunctionCall) goja.Value {
		p := call.Argument(0).String()
		// 相对路径相对脚本所在目录解析
		if !filepath.IsAbs(p) {
			p = filepath.Join(filepath.Dir(scriptPath), p)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			panic(vm.ToValue("fs.readFileSync 失败: " + err.Error()))
		}
		return vm.ToValue(string(b))
	})
	fsObj.Set("writeFileSync", func(call goja.FunctionCall) goja.Value {
		p := call.Argument(0).String()
		if !filepath.IsAbs(p) {
			p = filepath.Join(filepath.Dir(scriptPath), p)
		}
		content := call.Argument(1).String()
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			panic(vm.ToValue("fs.writeFileSync 失败: " + err.Error()))
		}
		return goja.Undefined()
	})
	fsObj.Set("existsSync", func(call goja.FunctionCall) goja.Value {
		p := call.Argument(0).String()
		if !filepath.IsAbs(p) {
			p = filepath.Join(filepath.Dir(scriptPath), p)
		}
		_, err := os.Stat(p)
		return vm.ToValue(err == nil)
	})
	vm.Set("fs", fsObj)

	// require: 仅支持 "fs"
	vm.Set("require", func(call goja.FunctionCall) goja.Value {
		mod := call.Argument(0).String()
		if mod == "fs" {
			return vm.ToValue(fsObj)
		}
		panic(vm.ToValue("不支持的模块: " + mod))
	})

	// produceArtifact: Sub-Store 核心 API，返回订阅节点数组（Promise）。
	// opts: {type, name, platform, produceType}
	// 注意：goja runtime 不是线程安全的，所以这里同步拉取订阅后 resolve，
	// 保证 promise 在 RunScript 返回前就已完成（goja 同步 resolve 语义）。
	// 网络拉取会阻塞 runtime，但对订阅转换场景可接受。
	vm.Set("produceArtifact", func(call goja.FunctionCall) goja.Value {
		opts := call.Argument(0).Export()
		name := ""
		artifactType := "subscription"
		if m, ok := opts.(map[string]any); ok {
			if v, ok := m["name"].(string); ok {
				name = v
			}
			if v, ok := m["type"].(string); ok && v != "" {
				artifactType = v
			}
		}

		p, resolve, reject := vm.NewPromise()

		// 同步拉取（goja runtime 单线程，goroutine 会导致线程安全问题）
		nodes, err := a.produceArtifact(artifactType, name)
		if err != nil {
			reject(err.Error())
		} else {
			resolve(nodes)
		}

		return vm.ToValue(p)
	})

	// console.log 等：转发到日志
	stringifyFn := vm.Get("JSON").ToObject(vm).Get("stringify")
	stringify, _ := goja.AssertFunction(stringifyFn)
	consoleLog := func(level func(string, ...any), args []goja.Value) {
		logFn := level
		_ = logFn
		parts := make([]string, 0, len(args))
		for _, a := range args {
			if a == nil || goja.IsUndefined(a) {
				parts = append(parts, "undefined")
				continue
			}
			if goja.IsNull(a) {
				parts = append(parts, "null")
				continue
			}
			if s, ok := a.Export().(string); ok {
				parts = append(parts, s)
				continue
			}
			if stringify != nil {
				if v, err := stringify(goja.Undefined(), a); err == nil && v != nil && !goja.IsUndefined(v) {
					parts = append(parts, v.String())
					continue
				}
			}
			parts = append(parts, a.String())
		}
		level("[script] %s", strings.Join(parts, " "))
	}
	consoleObj := vm.NewObject()
	consoleObj.Set("log", func(call goja.FunctionCall) goja.Value {
		consoleLog(logInfo, call.Arguments)
		return goja.Undefined()
	})
	consoleObj.Set("info", func(call goja.FunctionCall) goja.Value {
		consoleLog(logInfo, call.Arguments)
		return goja.Undefined()
	})
	consoleObj.Set("warn", func(call goja.FunctionCall) goja.Value {
		consoleLog(logWarn, call.Arguments)
		return goja.Undefined()
	})
	consoleObj.Set("error", func(call goja.FunctionCall) goja.Value {
		consoleLog(logError, call.Arguments)
		return goja.Undefined()
	})
	vm.Set("console", consoleObj)

	// ProxyUtils: Sub-Store 节点工具的简化占位（提供 yaml）
	proxyUtils := vm.NewObject()
	yamlObj := vm.NewObject()
	yamlObj.Set("safeLoad", func(call goja.FunctionCall) goja.Value {
		s := call.Argument(0).String()
		var out any
		if err := yamlUnmarshal(s, &out); err != nil {
			panic(vm.ToValue("yaml 解析失败: " + err.Error()))
		}
		return vm.ToValue(out)
	})
	yamlObj.Set("load", func(call goja.FunctionCall) goja.Value {
		s := call.Argument(0).String()
		var out any
		if err := yamlUnmarshal(s, &out); err != nil {
			panic(vm.ToValue("yaml 解析失败: " + err.Error()))
		}
		return vm.ToValue(out)
	})
	yamlObj.Set("safeDump", func(call goja.FunctionCall) goja.Value {
		v := call.Argument(0).Export()
		b, err := yamlMarshal(v)
		if err != nil {
			panic(vm.ToValue("yaml 序列化失败: " + err.Error()))
		}
		return vm.ToValue(string(b))
	})
	yamlObj.Set("dump", func(call goja.FunctionCall) goja.Value {
		v := call.Argument(0).Export()
		b, err := yamlMarshal(v)
		if err != nil {
			panic(vm.ToValue("yaml 序列化失败: " + err.Error()))
		}
		return vm.ToValue(string(b))
	})
	proxyUtils.Set("yaml", yamlObj)
	proxyUtils.Set("produce", func(call goja.FunctionCall) goja.Value {
		v := call.Argument(0).Export()
		s, _ := dict2jsonCompact(v)
		return vm.ToValue(s)
	})
	vm.Set("ProxyUtils", proxyUtils)

	// 兼容 Sub-Store 的 b64e / b64d
	vm.Set("b64e", func(call goja.FunctionCall) goja.Value {
		s := call.Argument(0).String()
		return vm.ToValue(b64encodeStd(s))
	})
	vm.Set("b64d", func(call goja.FunctionCall) goja.Value {
		s := call.Argument(0).String()
		out, err := b64decodeStd(s)
		if err != nil {
			return goja.Undefined()
		}
		return vm.ToValue(out)
	})
}

// produceArtifact 实际拉取订阅并转成 sing-box 节点数组。
// collection 类型：name 可以是逗号分隔的多个订阅名。
func (a *Assembler) produceArtifact(artifactType, name string) ([]any, error) {
	if name == "" {
		return nil, errors.New("produceArtifact: name 为空")
	}

	if artifactType == "collection" {
		names := strings.Split(name, ",")
		var all []any
		for _, n := range names {
			n = strings.TrimSpace(n)
			if n == "" {
				continue
			}
			nodes, err := a.fetchSubNodes(n)
			if err != nil {
				return nil, err
			}
			all = append(all, nodes...)
		}
		return all, nil
	}

	return a.fetchSubNodes(name)
}

// fetchSubNodes 拉取单个订阅，返回 sing-box outbounds 节点列表。
// 返回 []any 以便 goja 包装为原生 JS 数组（[]map[string]any 会被当成对象）。
func (a *Assembler) fetchSubNodes(name string) ([]any, error) {
	url, ok := a.subs[name]
	if !ok {
		return nil, errors.New("未知订阅: " + name)
	}
	origin := getsub(url, a.ua, a.configDir)
	if origin == "" {
		return nil, errors.New("订阅获取失败: " + name)
	}
	outbounds, _ := detectAndParse(origin)
	// 转成 []any 以便 goja 识别为 JS 数组
	nodes := make([]any, len(outbounds))
	for i, o := range outbounds {
		nodes[i] = o
	}
	logInfo("订阅 %s: 解析到 %d 节点", name, len(nodes))
	return nodes, nil
}

// buildLazySubsObject 构造一个 JS 对象，作为 assemble(context) 契约里的 context.subs。
// 预计算所有订阅，返回 map[name] -> {outbounds, endpoints}（sing-box 格式），
// 同时提供 get(name) 和 keys() 方法。
// （懒加载在 Sub-Store 风格脚本中通过 produceArtifact 实现，此处预计算可接受。）
func buildLazySubsObject(_ *goja.Runtime, subs map[string]string, ua, configDir string) map[string]any {
	result := map[string]any{}
	cache := map[string]map[string]any{}
	for name, url := range subs {
		pair := fetchSubConfig(url, ua, configDir)
		cache[name] = pair
		result[name] = pair
	}
	// get 方法：兼容不存在的订阅，返回空 sing-box 配置 {outbounds:[], endpoints:[]}
	result["get"] = func(name string) map[string]any {
		if pair, ok := cache[name]; ok {
			return pair
		}
		return map[string]any{"outbounds": []any{}, "endpoints": []any{}}
	}
	// keys 方法
	result["keys"] = func() []string {
		keys := make([]string, 0, len(subs))
		for k := range subs {
			keys = append(keys, k)
		}
		return keys
	}
	return result
}

// fetchSubConfig 拉取订阅，返回 {outbounds, endpoints}（sing-box 配置格式）。
func fetchSubConfig(url, ua, configDir string) map[string]any {
	origin := getsub(url, ua, configDir)
	if origin == "" {
		return map[string]any{"outbounds": []any{}, "endpoints": []any{}}
	}
	outbounds, endpoints := detectAndParse(origin)
	// 转成 []any 以便 JS 访问
	obAny := make([]any, len(outbounds))
	for i, o := range outbounds {
		obAny[i] = o
	}
	epAny := make([]any, len(endpoints))
	for i, e := range endpoints {
		epAny[i] = e
	}
	return map[string]any{"outbounds": obAny, "endpoints": epAny}
}
