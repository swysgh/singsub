"""desktop 装配脚本（参考移植自 desktop.js）。

契约：定义 assemble(context)，引擎抓订阅并转换成 sing-box 节点后传入。
- context["subs"]["自建"]    对应原 JS getProxies('自建')
- context["subs"]["客户"]    对应原 JS getProxies('客户')
- context["subs"]["rtx.al"]  对应原 JS getProxies('rtx.al')
- context["subs"]["ikuuu"]   对应原 JS getProxies('ikuuu')
- context["args"]            查询参数
模板由脚本自己选、自己读（路径相对本脚本）。
"""
import json
import os
import re

TEMPLATE = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "../template/desktop.json")
)

UNLOCK_TAGS = ["google", "ai", "spotify", "github", "youtube"]
UNLOCK_NODES = ["hkt", "webnx", "grsg", "ynkr", "ynus", "iptw"]


def add_dns(config, tags):
    """给每个 tag 添加一个走该组的 DNS 服务器。"""
    for tag in tags:
        dns_tag = f"dns-{tag}"
        config["dns"]["servers"].append({
            "type": "udp",
            "tag": dns_tag,
            "server": "8.8.8.8",
            "server_port": 53,
            "detour": tag,
        })


def add_selector(config, tags):
    """添加 selector 类型的出站分组（可传单个字符串或列表）。"""
    if isinstance(tags, str):
        tags = [tags]
    for tag in tags:
        config["outbounds"].append({
            "type": "selector",
            "tag": tag,
            "outbounds": [],
        })


def add_urltest(config, tags):
    """添加 urltest 类型的出站分组。"""
    for tag in tags:
        config["outbounds"].append({
            "type": "urltest",
            "tag": tag,
            "outbounds": [],
            "url": "https://cp.cloudflare.com/",
        })


def assemble(context):
    subs = context["subs"]

    with open(TEMPLATE, "r", encoding="utf-8") as f:
        config = json.load(f)

    self_built = subs.get("自建", [])
    # 筛选掉带 流量/套餐 字样的节点（信息节点，非代理）
    rtxal = [p for p in subs.get("rtx.al", []) if not re.search(r"(流量|套餐)", p["tag"])]
    ikuuu = subs.get("ikuuu", [])
    client = subs.get("客户", [])

    # 添加分组：dns → selector → urltest
    add_dns(config, UNLOCK_TAGS)
    add_selector(config, UNLOCK_TAGS)
    add_selector(config, ["客户", "机场", "rtx.al", "ikuuu", "pre2", "home"])
    add_urltest(config, ["ikuuu-auto"])
    config["outbounds"].append({
        "type": "urltest",
        "tag": "home-auto",
        "outbounds": [],
        "url": "http://10.1.0.2/",
        "interval": "5s",
        "tolerance": 5,
    })

    # 将节点插入 outbounds 末尾
    config["outbounds"].extend(self_built)
    config["outbounds"].extend(client)
    config["outbounds"].extend(rtxal)
    config["outbounds"].extend(ikuuu)

    # 各订阅 tag 列表
    self_built_tags = [p["tag"] for p in self_built]
    rtxal_tags = [p["tag"] for p in rtxal]
    ikuuu_tags = [p["tag"] for p in ikuuu]
    client_tags = [p["tag"] for p in client]

    # 处理各个分组
    for o in config["outbounds"]:
        tag = o.get("tag")

        if tag == "select":
            o["outbounds"].extend([
                "pre",
                *[t for t in self_built_tags if not re.search(r"(homeserver|txsh-ss)", t)],
                "客户",
                "direct",
            ])
            o["default"] = "pre"

        elif tag == "pre":
            o["outbounds"].append("机场")
            o["outbounds"].extend([
                t for t in self_built_tags
                if re.search(r"(claw|dmithk|alihk|dmitjp|sthk|dmitus)", t)
                and not re.search(r"(pre)", t)
            ])

        elif tag == "pre2":
            o["outbounds"].append("机场")
            o["outbounds"].extend([
                t for t in self_built_tags
                if re.search(r"(claw|dmithk|alihk|dmitjp|sthk|dmitus)", t)
                and not re.search(r"(pre)", t)
            ])

        elif tag == "cn":
            o["outbounds"].extend([
                "direct",
                "home",
                "txsh-ss",
                "select",
                *[t for t in self_built_tags if not re.search(r"(us|homeserver|txsh-ss|alihz-ss)", t)],
            ])

        elif tag == "home":
            o["outbounds"].extend([
                "home-auto",
                *[t for t in self_built_tags if re.search(r"(homeserver|sthk)", t, re.I)],
                "direct",
            ])

        elif tag == "home-auto":
            o["outbounds"].extend([
                *[t for t in self_built_tags if re.search(r"(homeserver)", t, re.I)],
                "direct",
            ])

        elif tag == "机场":
            o["outbounds"].extend(["rtx.al", "ikuuu"])

        elif tag == "rtx.al":
            o["outbounds"].extend(rtxal_tags)

        elif tag == "ikuuu":
            o["outbounds"].extend(["ikuuu-auto", *ikuuu_tags])

        elif tag == "ikuuu-auto":
            o["outbounds"].extend(ikuuu_tags)

        elif tag == "客户":
            o["outbounds"].extend(
                t for t in client_tags if not re.search(r"(国外前置|国内前置)", t)
            )

        else:
            if tag in UNLOCK_TAGS:
                matching = [t for t in self_built_tags
                            if any(kw in t for kw in UNLOCK_NODES)]
                o["outbounds"].extend(["select", "客户", "机场", *matching])

    return config