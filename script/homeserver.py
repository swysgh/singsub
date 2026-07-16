"""homeserver 装配脚本（参考移植自 homeserver.js）。

契约：定义 assemble(context)，引擎抓订阅并转换成 sing-box 节点后传入。
- context["subs"]["自建"]   对应原 JS getProxies('自建')，返回节点 list
- context["subs"]["ikuuu"]  对应原 JS getProxies('ikuuu')
- context["args"]           查询参数
模板由脚本自己选、自己读（路径相对本脚本）。
"""
import json
import os
import re

# 模板就在主目录的template/下
TEMPLATE = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "../template/homeserver.json")
)

# 与原 JS 同名节点一起过滤掉
FILTER_REGEX = re.compile(r"(us|pre|homeserver|-ss|nbix)")


def assemble(context):
    subs = context["subs"]

    with open(TEMPLATE, "r", encoding="utf-8") as f:
        config = json.load(f)

    self_built = subs["自建"]
    ikuuu = subs["ikuuu"]

    # 过滤掉 tag 匹配正则的自建节点
    self_built_filtered = [p for p in self_built if not FILTER_REGEX.search(p["tag"])]

    # 将节点插入 outbounds 末尾
    config["outbounds"].extend(self_built_filtered)
    config["outbounds"].extend(ikuuu)

    # 自建（过滤后）和 ikuuu 的 tag 列表，用于填充各分组
    self_built_tags = [p["tag"] for p in self_built_filtered]
    ikuuu_tags = [p["tag"] for p in ikuuu]

    # 遍历 outbounds，处理 auto/select/claude 分组
    for o in config["outbounds"]:
        tag = o.get("tag")
        if tag in ("auto", "select", "claude"):
            o["outbounds"].extend(self_built_tags)
            o["outbounds"].extend(ikuuu_tags)
        if tag == "select":
            o["outbounds"].insert(0, "auto")
            o["outbounds"].append("direct")
        if tag == "claude":
            o["outbounds"].insert(0, "select")
            o["outbounds"].append("direct")

    return config
