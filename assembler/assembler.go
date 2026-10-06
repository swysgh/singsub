package assembler

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"

	"singsub/common"
	"singsub/detect"
	"singsub/fetch"
)

// errScriptTimeout 是脚本执行超时的错误标识。
// goja.Runtime.Interrupt() 会把此值装进 *goja.InterruptedError，
// 后者实现了 Unwrap()，因此 errors.Is(err, errScriptTimeout) 能正确识别。
var errScriptTimeout = errors.New("script execution timeout")

type Assembler struct {
	configDir     string
	subs          map[string]string
	ua            string
	scriptTimeout time.Duration
	fetchTimeout  time.Duration
	maxBodyBytes  int64

	// per-request 订阅缓存：保证同一请求内重复访问只抓一次。
	// Assembler 每次请求 NewAssembler 新建，所以此处天然 per-request。
	subCache   map[string]map[string]any
	subCacheMu sync.Mutex
}

var (
	scriptCacheMu    sync.Mutex
	scriptCacheStore = map[string]scriptCacheEntry{}
)

type scriptCacheEntry struct {
	mtime time.Time
	src   string
}

func NewAssembler(subs map[string]string, configDir, ua string, scriptTimeout, fetchTimeout time.Duration, maxBodyBytes int64) *Assembler {
	return &Assembler{
		configDir:     configDir,
		subs:          subs,
		ua:            ua,
		scriptTimeout: scriptTimeout,
		fetchTimeout:  fetchTimeout,
		maxBodyBytes:  maxBodyBytes,
		subCache:      map[string]map[string]any{},
	}
}

func (a *Assembler) RunScript(scriptPath string, args map[string]string) (map[string]any, error) {
	path := common.ResolvePath(scriptPath, a.configDir)

	src, err := a.loadScript(path)
	if err != nil {
		return nil, err
	}

	vm := goja.New()

	// 脚本执行超时：通过 goja.Runtime.Interrupt() 在 JS 代码执行中触发中断。
	// Interrupt() 不能打断原生 Go 函数，所以 JSONUnmarshal、ReadFile 等
	// 系统调用不在中断范围之内；这正是我们想要的（避免破坏文件系统一致性）。
	timeout := a.scriptTimeout
	var timer *time.Timer
	if timeout > 0 {
		timer = time.AfterFunc(timeout, func() {
			vm.Interrupt(errScriptTimeout)
		})
		defer timer.Stop()
	}

	a.injectAPI(vm, path, args)

	wrapped := "(async function() {\n" + src + "\n;if (typeof assemble !== 'undefined') { globalThis.assemble = assemble; }\n})()"
	v, err := vm.RunScript(filepath.Base(path), wrapped)
	if err != nil {
		if isTimeoutErr(err) {
			return nil, &ScriptError{Path: path, Err: fmt.Errorf("%w (timeout=%s)", errScriptTimeout, timeout)}
		}
		return nil, &ScriptError{Path: path, Err: err}
	}

	if obj, ok := v.(*goja.Object); ok {
		if p, ok := obj.Export().(*goja.Promise); ok {
			switch p.State() {
			case goja.PromiseStateRejected:
				rejErr := errors.New(common.ToString(p.Result()))
				if isTimeoutErr(rejErr) {
					return nil, &ScriptError{Path: path, Err: fmt.Errorf("%w (timeout=%s)", errScriptTimeout, timeout)}
				}
				return nil, &ScriptError{Path: path, Err: rejErr}
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
			subsObj := a.buildLazySubsObject(vm)
			context := map[string]any{
				"subs":       subsObj,
				"args":       args,
				"config_dir": a.configDir,
			}
			ret, err := fn(goja.Undefined(), vm.ToValue(context))
			if err != nil {
				if isTimeoutErr(err) {
					return nil, &ScriptError{Path: path, Err: fmt.Errorf("%w (timeout=%s)", errScriptTimeout, timeout)}
				}
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

// isTimeoutErr 识别因 Interrupt() 触发的超时。
// goja.InterruptedError 实现了 Unwrap()，因此 errors.Is 能穿透到 errScriptTimeout。
func isTimeoutErr(err error) bool {
	return errors.Is(err, errScriptTimeout)
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

// fetchSubNodes 是 produceArtifact 走的子路。
// 复用 per-request 缓存，保证同一请求内 produceArtifact(name) 多次调用只抓一次。
func (a *Assembler) fetchSubNodes(name string) ([]any, error) {
	pair, err := a.fetchSubPair(name)
	if err != nil {
		return nil, err
	}
	outbounds, _ := pair["outbounds"].([]any)
	nodes := make([]any, len(outbounds))
	for i, o := range outbounds {
		nodes[i] = o
	}
	common.LogInfo("订阅 %s: 解析到 %d 节点", name, len(nodes))
	return nodes, nil
}

// fetchSubPair 返回 {outbounds, endpoints}，per-request 缓存。
//
// 订阅拉取失败时**不返回空对**：脚本照常装配，客户端就会拿到一份带空分组的
// 配置，sing-box check 报 `initialize outbound[N]: missing tags` 整份失败
// （实测：机场订阅一次 DNS 解析失败，就让桌面连续两次更新失败）。
// 改成塞一条 direct 占位节点、tag 直接写明是哪个订阅、为什么失败 ——
// 配置能正常启动，失败原因也摆在客户端的节点列表里，不用翻服务端日志。
func (a *Assembler) fetchSubPair(name string) (map[string]any, error) {
	if _, ok := a.subs[name]; !ok {
		return nil, errors.New("未知订阅: " + name)
	}
	a.subCacheMu.Lock()
	if cached, ok := a.subCache[name]; ok {
		a.subCacheMu.Unlock()
		return cached, nil
	}
	a.subCacheMu.Unlock()

	url := a.subs[name]
	origin, err := fetch.GetSubWithErr(url, a.ua, a.configDir, a.fetchTimeout, a.maxBodyBytes)
	if err != nil {
		pair := failedSubPair(name, err)
		a.subCacheMu.Lock()
		a.subCache[name] = pair
		a.subCacheMu.Unlock()
		return pair, nil
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
	pair := map[string]any{"outbounds": obAny, "endpoints": epAny}

	a.subCacheMu.Lock()
	a.subCache[name] = pair
	a.subCacheMu.Unlock()
	return pair, nil
}

// failedSubPair 造一个「订阅拉取失败」的占位订阅：一条 direct 出站，tag 写明订阅名和失败原因。
//
// 用 direct 是因为失败时用户最可能想的就是「先直连顶着」，而不是把流量丢给别的节点；
// 原因写进 tag 则是因为客户端只认配置、看不到服务端日志。
func failedSubPair(name string, err error) map[string]any {
	tag := fmt.Sprintf("❌ %s 拉取失败: %s", name, truncateRunes(err.Error(), 120))
	common.LogWarn("订阅 %q 拉取失败: %s（已用一条 direct 占位节点代替，tag=%q）", name, err, tag)
	return map[string]any{
		"outbounds": []any{map[string]any{"type": "direct", "tag": tag}},
		"endpoints": []any{},
	}
}

// truncateRunes 按字符（不是字节）截断，避免把多字节字符切成乱码。
func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

// lazySubs 是真正的惰性订阅代理：被 JS 访问时才抓取，同一请求内只抓一次。
//
// 对 root（key=""）：
//   - Get("get")  -> JS 函数：function(name)
//   - Get("keys") -> JS 函数：function()
//   - Get(<订阅名>) -> 该订阅的 {outbounds, endpoints}（惰性抓取 + 缓存）
//   - Get(其他)   -> 空对（不抛 TypeError）
//   - Has/Get 同上语义
//   - Keys() 返回所有订阅名 + get + keys
type lazySubs struct {
	a  *Assembler
	vm *goja.Runtime
}

func (l *lazySubs) Get(key string) goja.Value {
	switch key {
	case "get":
		return l.vm.ToValue(func(call goja.FunctionCall) goja.Value {
			name := call.Argument(0).String()
			pair, err := l.a.fetchSubPair(name)
			if err != nil {
				common.LogWarn("脚本访问未配置订阅 %q: %s", name, err)
				return l.a.emptyPairObject(l.vm)
			}
			return l.vm.ToValue(pair)
		})
	case "keys":
		return l.vm.ToValue(func(call goja.FunctionCall) goja.Value {
			keys := make([]string, 0, len(l.a.subs))
			for k := range l.a.subs {
				keys = append(keys, k)
			}
			return l.vm.ToValue(keys)
		})
	}
	// 视为订阅名访问
	pair, err := l.a.fetchSubPair(key)
	if err != nil {
		common.LogWarn("脚本访问未配置订阅 %q: %s", key, err)
		return l.a.emptyPairObject(l.vm)
	}
	return l.vm.ToValue(pair)
}

func (l *lazySubs) Set(string, goja.Value) bool { return false }
func (l *lazySubs) Has(key string) bool {
	if key == "get" || key == "keys" {
		return true
	}
	_, ok := l.a.subs[key]
	return ok
}
func (l *lazySubs) Delete(string) bool { return false }
func (l *lazySubs) Keys() []string {
	keys := make([]string, 0, len(l.a.subs)+2)
	for k := range l.a.subs {
		keys = append(keys, k)
	}
	keys = append(keys, "get", "keys")
	return keys
}

// buildLazySubsObject 返回真正的惰性订阅对象：
// 访问某个订阅名时才去抓取+解析，且同一请求内重复访问只抓一次。
func (a *Assembler) buildLazySubsObject(vm *goja.Runtime) *goja.Object {
	return vm.NewDynamicObject(&lazySubs{a: a, vm: vm})
}

// emptyPairObject 在未知订阅名时返回一个空对对象 {outbounds:[], endpoints:[]}，
// 确保脚本写 subs["xxx"].outbounds 时不抛 TypeError。
func (a *Assembler) emptyPairObject(vm *goja.Runtime) goja.Value {
	pair := map[string]any{
		"outbounds": []any{},
		"endpoints": []any{},
	}
	return vm.ToValue(pair)
}
