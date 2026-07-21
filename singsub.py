#!/usr/bin/python3
import argparse
import hmac
import json
import logging
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from fetch import getsub
from common import setup_logging, get_logger, dict2json
from clash import clash2singbox
from uri2sb import uri2singbox
from sb2uri import singbox2uri
from assembler import run_script

import yaml

logger = get_logger(__name__)


# 启动 HTTP 服务时由 --config 加载
CONFIG = {}
CONFIG_DIR = ""


def detect_and_parse(origin_data):
    """自动识别订阅格式，提取节点列表。

    返回 (outbounds, endpoints) 元组。
    wireguard 节点在 sing-box 中属于 endpoint，不放在 outbounds 中。
    clash / URI 输入：全部视为 outbounds，endpoints 为空。
    """
    stripped = origin_data.lstrip()
    # sing-box 配置是 JSON 且顶层含 outbounds：分别取 outbounds / endpoints
    if stripped.startswith("{"):
        try:
            config = json.loads(origin_data)
            if isinstance(config, dict) and "outbounds" in config:
                outbounds = config["outbounds"] or []
                endpoints = config.get("endpoints") or []
                return (outbounds, endpoints)
        except json.JSONDecodeError:
            pass
    # clash yaml：尝试用 yaml 解析，带 proxies 字段的就是 Clash 配置
    try:
        parsed = yaml.safe_load(origin_data)
        if isinstance(parsed, dict) and "proxies" in parsed:
            nodes = clash2singbox(origin_data)
            return (nodes or [], [])
    except yaml.YAMLError:
        pass
    # 否则按 URI 订阅处理
    try:
        nodes = uri2singbox(origin_data)
        return (nodes or [], [])
    except Exception as e:
        logger.error("URI 解析失败，订阅格式无法识别: %s", e)
        return ([], [])


def render_nodes(outbounds, endpoints, fmt):
    """把 outbounds / endpoints 渲染成 (content_type, body)。

    uri 格式只输出 outbounds（wireguard 不支持转 URI）。
    """
    if fmt == "uri":
        return "text/plain; charset=utf-8", singbox2uri(outbounds)
    config = {"outbounds": outbounds}
    if endpoints:
        config["endpoints"] = endpoints
    return "application/json; charset=utf-8", dict2json(config)


def convert(origin_data, fmt):
    """把单份订阅原文转成目标格式的 (content_type, body)。失败返回 None。"""
    outbounds, endpoints = detect_and_parse(origin_data)
    if not outbounds and not endpoints:
        return None
    return render_nodes(outbounds, endpoints, fmt)


def render(origin_data, fmt):
    """命令行用：返回结果字符串。失败返回 None。"""
    result = convert(origin_data, fmt)
    return result[1] if result else None


# ----------------------- HTTP 服务 -----------------------

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        """重写 BaseHTTPRequestHandler 的 log_message，改用 singsub 的 logger。
        
        原始格式：`self.address_string() - - [date] "request" status size`
        这里简化记录：method path status size
        """
        logger.info("HTTP %s %s -> %s %s", self.command, self.path, fmt % args, "")

    def _log_request(self, code, body_len):
        """记录请求摘要：方法、路径、状态码、耗时、响应大小。"""
        elapsed = time.time() - self._start_time
        logger.info("请求完成: %s %s [%d] (%.2fs, %d 字节)", self.command, self.path, code, elapsed, body_len)

    def _respond(self, code, content_type, body):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        self._log_request(code, len(data))

    def do_GET(self):
        self._start_time = time.time()
        parsed = urlparse(self.path)
        segments = [s for s in parsed.path.split("/") if s] # 过滤切割后的空字符串

        logger.info("收到请求: %s %s", self.command, self.path)

        # 首页：无 token，仅作存活探测
        if not segments:
            self._respond(200, "text/plain; charset=utf-8", "singsub running\n")
            return

        # 路径首段即验证密码
        token = segments[0]
        expect_token = CONFIG.get("token", "")
        if not expect_token or not hmac.compare_digest(token, expect_token):
            logger.warning("token 验证失败: %s", self.address_string())
            self._respond(403, "text/plain; charset=utf-8", "Forbidden: token 错误\n")
            return

        qs = parse_qs(parsed.query)
        fmt = qs.get("format", ["singbox"])[0]
        if fmt not in ("singbox", "uri"):
            self._respond(400, "text/plain; charset=utf-8", "format 只能是 singbox 或 uri\n")
            return
        ua = qs.get("ua", [None])[0]

        # 优先走脚本装配：?script=<name>
        script_name = qs.get("script", [None])[0]
        if script_name:
            self._handle_script(script_name, qs, fmt, ua)
            return

        subs = CONFIG.get("subs") or {}
        name = qs.get("name", [None])[0]
        if name:
            if name not in subs:
                self._respond(404, "text/plain; charset=utf-8", f"未知订阅: {name}\n")
                return
            targets = [(name, subs[name])]
            logger.info("请求指定订阅: %s", name)
        else:
            # 不指定 name：合并所有订阅
            targets = list(subs.items())
            logger.info("请求合并所有订阅 (%d 个)", len(targets))

        if not targets:
            self._respond(404, "text/plain; charset=utf-8", "配置文件未定义任何订阅\n")
            return

        all_outbounds = []
        all_endpoints = []
        failed = []
        for sub_name, url in targets:
            origin = getsub(url, ua, CONFIG_DIR)
            if not origin:
                failed.append(sub_name)
                continue
            outbounds, endpoints = detect_and_parse(origin)
            if outbounds or endpoints:
                all_outbounds.extend(outbounds)
                all_endpoints.extend(endpoints)
                logger.info("订阅 %s: 解析到 %d outbound + %d endpoint", sub_name, len(outbounds), len(endpoints))
            else:
                logger.warning("订阅 %s 解析无节点", sub_name)

        if not all_outbounds and not all_endpoints:
            self._respond(422, "text/plain; charset=utf-8", "解析失败，未得到任何节点\n")
            return

        result = render_nodes(all_outbounds, all_endpoints, fmt)

        if failed:
            logger.warning("部分订阅获取失败: %s", ", ".join(failed))

        content_type, body = result
        logger.info("转换完成: %d outbound + %d endpoint -> %s", len(all_outbounds), len(all_endpoints), fmt)
        self._respond(200, content_type, body + "\n")

    def _handle_script(self, script_name, qs, fmt, ua):
        scripts = CONFIG.get("scripts") or {}
        entry = scripts.get(script_name)
        if not entry:
            self._respond(404, "text/plain; charset=utf-8", f"未知脚本: {script_name}\n")
            return

        # 额外查询参数（去掉保留字段）传给脚本
        reserved = {"script", "format", "ua", "name"}
        args = {k: v[0] for k, v in qs.items() if k not in reserved}

        logger.info("执行脚本: %s (args=%s)", script_name, args)
        try:
            config = run_script(entry, CONFIG.get("subs") or {}, args, CONFIG_DIR, ua)
        except FileNotFoundError as e:
            self._respond(404, "text/plain; charset=utf-8", f"{e}\n")
            return
        except Exception as e:
            logger.exception("脚本 %s 执行异常", script_name)
            self._respond(500, "text/plain; charset=utf-8", f"脚本执行失败: {e}\n")
            return

        if fmt == "uri":
            # 抽真实代理节点（有 server 字段）转 URI
            proxy_nodes = [o for o in config.get("outbounds", []) if isinstance(o, dict) and "server" in o]
            if not proxy_nodes:
                self._respond(422, "text/plain; charset=utf-8", "装配结果无代理节点可转 URI\n")
                return
            logger.info("脚本 %s 完成: %d 代理节点转 URI", script_name, len(proxy_nodes))
            self._respond(200, "text/plain; charset=utf-8", singbox2uri(proxy_nodes) + "\n")
        else:
            logger.info("脚本 %s 完成: 返回 sing-box 配置", script_name)
            self._respond(200, "application/json; charset=utf-8", dict2json(config) + "\n")


def load_config(path):
    logger.info("加载配置文件: %s", path)
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    if "token" not in cfg or not isinstance(cfg["token"], str) or not cfg["token"]:
        logger.critical("配置文件需配置非空 token 字符串")
        sys.exit(1)
    if "subs" not in cfg or not isinstance(cfg["subs"], dict):
        logger.critical("配置文件需包含 subs 对象")
        sys.exit(1)
    scripts = cfg.get("scripts")
    if scripts is not None:
        if not isinstance(scripts, dict):
            logger.critical("配置文件 scripts 需为对象：脚本名 -> 脚本路径")
            sys.exit(1)
        for key, spath in scripts.items():
            if not isinstance(spath, str):
                logger.critical("脚本 %s 的值需为脚本路径字符串", key)
                sys.exit(1)
    logger.info("配置文件加载成功，订阅: %d 个，脚本: %d 个", len(cfg.get("subs", {})), len(cfg.get("scripts", {})))
    return cfg

def cmd_serve(args):
    global CONFIG, CONFIG_DIR
    CONFIG = load_config(args.config)
    CONFIG_DIR = os.path.dirname(os.path.abspath(args.config))
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    logger.info("singsub 服务已启动: http://%s:%s/<token>?name=<订阅名>|script=<脚本名>&format=singbox|uri", args.host, args.port)
    logger.info("已加载订阅: %s", ", ".join(CONFIG["subs"].keys()))
    if CONFIG.get("scripts"):
        logger.info("已加载脚本: %s", ", ".join(CONFIG["scripts"].keys()))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("收到中断信号，停止服务")
        server.shutdown()


# ----------------------- 命令行转换 -----------------------

def cmd_convert(args):
    logger.info("开始转换: %s -> %s", args.url, args.format)
    origin_data = getsub(args.url, args.user_agent)
    if not origin_data:
        sys.exit(1)

    result = render(origin_data, args.format)
    if result is None:
        logger.error("解析失败，未得到任何节点。")
        sys.exit(1)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(result + "\n")
        logger.info("转换结果已写入: %s", args.output)
    else:
        print(result)


# ----------------------- 参数解析 -----------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="订阅转换：clash/URI/sing-box 订阅 -> sing-box 配置 / URI"
    )
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help="日志级别，默认 INFO")

    sub = parser.add_subparsers(dest="command", required=True)

    # convert: 命令行直接转换
    p_conv = sub.add_parser("convert", help="命令行直接转换订阅")
    p_conv.add_argument("url", help="订阅链接 (http/https)")
    p_conv.add_argument(
        "-f", "--format", choices=["singbox", "uri"], default="singbox",
        help="输出格式：singbox (默认) 或 uri",
    )
    p_conv.add_argument("-u", "--user-agent", default=None, help="请求订阅的 User-Agent，默认 Mihomo")
    p_conv.add_argument("-o", "--output", default=None, help="输出到文件，默认打印到标准输出")
    p_conv.set_defaults(func=cmd_convert)

    # serve: HTTP 服务
    p_serve = sub.add_parser("serve", help="启动 HTTP 转换服务")
    p_serve.add_argument("--config", default="config.json", help="配置文件路径，默认 config.json")
    p_serve.add_argument("--host", default="0.0.0.0", help="监听地址，默认 0.0.0.0")
    p_serve.add_argument("--port", type=int, default=8080, help="监听端口，默认 8080")
    p_serve.set_defaults(func=cmd_serve)

    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging(getattr(logging, args.log_level.upper(), logging.INFO))
    args.func(args)


if __name__ == "__main__":
    main()
