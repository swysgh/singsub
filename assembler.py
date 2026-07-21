"""模板装配引擎：加载用户脚本，把订阅节点转成 sing-box 后放进 context 交给脚本处理。

参考 substore 模式：引擎负责抓订阅 + 转换，脚本负责选模板、装配、返回最终配置。

脚本契约：定义 `def assemble(context)`，返回 sing-box 配置 dict。
- context["subs"]  : 懒加载映射，subs["自建"] 触发抓取+转换并缓存，
                     返回 (outbounds, endpoints) 元组。
                     取 outbounds 用 subs["自建"][0]，取 endpoints 用 subs["自建"][1]。
- context["args"]  : 查询参数 dict（除 script/format/ua/name 外的字段）
- context["config_dir"] : 配置文件所在目录（脚本可用它定位模板）
"""
import importlib.util
import os
import sys
import traceback

from common import get_logger
from fetch import getsub

logger = get_logger(__name__)


class LazySubs:
    """按名懒加载订阅节点，抓取+解析结果缓存。

    subs['自建']    -> 触发 getsub+detect_and_parse，返回 (outbounds, endpoints) 元组
                       （不存在则 KeyError）
    subs.get('名')  -> 不存在返回 None
    """

    def __init__(self, subs_config, ua=None, config_dir=None):
        self._subs = subs_config or {}
        self._ua = ua
        self._config_dir = config_dir
        self._cache = {}

    def _fetch(self, name):
        url = self._subs.get(name)
        if url is None:
            return None
        origin = getsub(url, self._ua, self._config_dir)
        if not origin:
            return ([], [])
        # 延迟导入避免循环依赖（singsub 导入 assembler）
        from singsub import detect_and_parse
        outbounds, endpoints = detect_and_parse(origin)
        return (outbounds or [], endpoints or [])

    def __getitem__(self, name):
        if name not in self._cache:
            if name not in self._subs:
                raise KeyError(name)
            self._cache[name] = self._fetch(name)
        return self._cache[name]

    def get(self, name, default=None):
        if name not in self._subs:
            return default
        if name not in self._cache:
            self._cache[name] = self._fetch(name)
        return self._cache[name]

    def keys(self):
        return self._subs.keys()


# 脚本模块缓存：path -> (mtime, module)
_SCRIPT_CACHE = {}


def _load_script(path):
    """按 mtime 缓存动态加载脚本模块；文件改了自动重载。"""
    try:
        mtime = os.path.getmtime(path)
    except OSError as e:
        raise FileNotFoundError(f"脚本不存在: {path} ({e})")

    cached = _SCRIPT_CACHE.get(path)
    if cached and cached[0] == mtime:
        return cached[1]

    mod_name = f"_singsub_script_{abs(hash(path))}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"无法加载脚本: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)
    _SCRIPT_CACHE[path] = (mtime, module)
    return module


def run_script(script_path, subs_config, args=None, config_dir=None, ua=None):
    """加载脚本并调用 assemble(context)，返回最终 config dict。

    script_path: 脚本路径（相对 config_dir 或绝对）
    subs_config: CONFIG["subs"]，订阅名 -> 订阅链接
    args:        传给脚本的查询参数 dict
    config_dir:  配置文件所在目录，用于解析相对脚本路径，也透传给脚本定位模板
    """
    path = script_path if os.path.isabs(script_path) else os.path.join(config_dir or "", script_path)
    module = _load_script(path)
    assemble = getattr(module, "assemble", None)
    if assemble is None:
        raise AttributeError(f"脚本 {path} 未定义 assemble(context)")

    context = {
        "subs": LazySubs(subs_config, ua, config_dir),
        "args": args or {},
        "config_dir": config_dir or "",
    }
    try:
        result = assemble(context)
    except Exception:
        logger.error("脚本 %s 执行失败:\n%s", path, traceback.format_exc())
        raise
    return result
