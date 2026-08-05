package assembler

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"

	"singsub/internal/common"
	"singsub/internal/detect"
	"singsub/internal/fetch"
)

type Assembler struct {
	configDir string
	subs      map[string]string
	ua        string
}

var (
	scriptCacheMu    sync.Mutex
	scriptCacheStore = map[string]scriptCacheEntry{}
)

type scriptCacheEntry struct {
	mtime time.Time
	src   string
}

func NewAssembler(subs map[string]string, configDir, ua string) *Assembler {
	return &Assembler{
		configDir: configDir,
		subs:      subs,
		ua:        ua,
	}
}

func (a *Assembler) RunScript(scriptPath string, args map[string]string) (map[string]any, error) {
	path := common.ResolvePath(scriptPath, a.configDir)

	src, err := a.loadScript(path)
	if err != nil {
		return nil, err
	}

	vm := goja.New()
	a.injectAPI(vm, path, args)

	wrapped := "(async function() {\n" + src + "\n;if (typeof assemble !== 'undefined') { globalThis.assemble = assemble; }\n})()"
	v, err := vm.RunScript(filepath.Base(path), wrapped)
	if err != nil {
		return nil, &ScriptError{Path: path, Err: err}
	}

	if obj, ok := v.(*goja.Object); ok {
		if p, ok := obj.Export().(*goja.Promise); ok {
			switch p.State() {
			case goja.PromiseStateRejected:
				return nil, &ScriptError{Path: path, Err: errors.New(common.ToString(p.Result()))}
			}
		}
	}

	if contentVal := vm.Get("$content"); contentVal != nil && !goja.IsUndefined(contentVal) && !goja.IsNull(contentVal) {
		contentStr := contentVal.String()
		if contentStr != "" {
			var config map[string]any
			if err := common.JSONUnmarshal(contentStr, &config); err == nil {
				return config, nil
			}
			return map[string]any{"_content": contentStr}, nil
		}
	}

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
			if jsonStr, err := common.Dict2JSONCompact(ret.Export()); err == nil {
				var config map[string]any
				if err := common.JSONUnmarshal(jsonStr, &config); err == nil {
					return config, nil
				}
			}
			return nil, &ScriptError{Path: path, Err: errors.New("assemble 返回类型无法识别为配置 dict")}
		}
	}

	return nil, &ScriptError{Path: path, Err: errors.New("脚本既未设置 $content 也未定义 assemble(context)")}
}

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
	common.LogInfo("已加载脚本: %s", path)
	return src, nil
}

type ScriptError struct {
	Path string
	Err  error
}

func (e *ScriptError) Error() string { return e.Err.Error() }
func (e *ScriptError) Unwrap() error { return e.Err }

func (a *Assembler) injectAPI(vm *goja.Runtime, scriptPath string, args map[string]string) {
	vm.Set("$content", nil)
	vm.Set("$arguments", args)
	vm.Set("$files", []any{})
	vm.Set("$options", map[string]any{})

	fsObj := vm.NewObject()
	fsObj.Set("readFileSync", func(call goja.FunctionCall) goja.Value {
		p := call.Argument(0).String()
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

	vm.Set("require", func(call goja.FunctionCall) goja.Value {
		mod := call.Argument(0).String()
		if mod == "fs" {
			return vm.ToValue(fsObj)
		}
		panic(vm.ToValue("不支持的模块: " + mod))
	})

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

		nodes, err := a.produceArtifact(artifactType, name)
		if err != nil {
			reject(err.Error())
		} else {
			resolve(nodes)
		}

		return vm.ToValue(p)
	})

	stringifyFn := vm.Get("JSON").ToObject(vm).Get("stringify")
	stringify, _ := goja.AssertFunction(stringifyFn)
	consoleLog := func(level func(string, ...any), args []goja.Value) {
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
		consoleLog(common.LogInfo, call.Arguments)
		return goja.Undefined()
	})
	consoleObj.Set("info", func(call goja.FunctionCall) goja.Value {
		consoleLog(common.LogInfo, call.Arguments)
		return goja.Undefined()
	})
	consoleObj.Set("warn", func(call goja.FunctionCall) goja.Value {
		consoleLog(common.LogWarn, call.Arguments)
		return goja.Undefined()
	})
	consoleObj.Set("error", func(call goja.FunctionCall) goja.Value {
		consoleLog(common.LogError, call.Arguments)
		return goja.Undefined()
	})
	vm.Set("console", consoleObj)

	proxyUtils := vm.NewObject()
	yamlObj := vm.NewObject()
	yamlObj.Set("safeLoad", func(call goja.FunctionCall) goja.Value {
		s := call.Argument(0).String()
		var out any
		if err := common.YAMLUnmarshal(s, &out); err != nil {
			panic(vm.ToValue("yaml 解析失败: " + err.Error()))
		}
		return vm.ToValue(out)
	})
	yamlObj.Set("load", func(call goja.FunctionCall) goja.Value {
		s := call.Argument(0).String()
		var out any
		if err := common.YAMLUnmarshal(s, &out); err != nil {
			panic(vm.ToValue("yaml 解析失败: " + err.Error()))
		}
		return vm.ToValue(out)
	})
	yamlObj.Set("safeDump", func(call goja.FunctionCall) goja.Value {
		v := call.Argument(0).Export()
		b, err := common.YAMLEncode(v)
		if err != nil {
			panic(vm.ToValue("yaml 序列化失败: " + err.Error()))
		}
		return vm.ToValue(string(b))
	})
	yamlObj.Set("dump", func(call goja.FunctionCall) goja.Value {
		v := call.Argument(0).Export()
		b, err := common.YAMLEncode(v)
		if err != nil {
			panic(vm.ToValue("yaml 序列化失败: " + err.Error()))
		}
		return vm.ToValue(string(b))
	})
	proxyUtils.Set("yaml", yamlObj)
	proxyUtils.Set("produce", func(call goja.FunctionCall) goja.Value {
		v := call.Argument(0).Export()
		s, _ := common.Dict2JSONCompact(v)
		return vm.ToValue(s)
	})
	vm.Set("ProxyUtils", proxyUtils)

	vm.Set("b64e", func(call goja.FunctionCall) goja.Value {
		s := call.Argument(0).String()
		return vm.ToValue(common.B64EncodeStd(s))
	})
	vm.Set("b64d", func(call goja.FunctionCall) goja.Value {
		s := call.Argument(0).String()
		out, err := common.B64DecodeStd(s)
		if err != nil {
			return goja.Undefined()
		}
		return vm.ToValue(out)
	})
}

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

func (a *Assembler) fetchSubNodes(name string) ([]any, error) {
	url, ok := a.subs[name]
	if !ok {
		return nil, errors.New("未知订阅: " + name)
	}
	origin := fetch.GetSub(url, a.ua, a.configDir)
	if origin == "" {
		return nil, errors.New("订阅获取失败: " + name)
	}
	outbounds, _ := detect.DetectAndParse(origin)
	nodes := make([]any, len(outbounds))
	for i, o := range outbounds {
		nodes[i] = o
	}
	common.LogInfo("订阅 %s: 解析到 %d 节点", name, len(nodes))
	return nodes, nil
}

func buildLazySubsObject(_ *goja.Runtime, subs map[string]string, ua, configDir string) map[string]any {
	result := map[string]any{}
	cache := map[string]map[string]any{}
	for name, url := range subs {
		pair := fetchSubConfig(url, ua, configDir)
		cache[name] = pair
		result[name] = pair
	}
	result["get"] = func(name string) map[string]any {
		if pair, ok := cache[name]; ok {
			return pair
		}
		return map[string]any{"outbounds": []any{}, "endpoints": []any{}}
	}
	result["keys"] = func() []string {
		keys := make([]string, 0, len(subs))
		for k := range subs {
			keys = append(keys, k)
		}
		return keys
	}
	return result
}

func fetchSubConfig(url, ua, configDir string) map[string]any {
	origin := fetch.GetSub(url, ua, configDir)
	if origin == "" {
		return map[string]any{"outbounds": []any{}, "endpoints": []any{}}
	}
	outbounds, endpoints := detect.DetectAndParse(origin)
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