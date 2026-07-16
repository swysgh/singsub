import json
import urllib.parse


def dict2json(data, indent=2, ensure_ascii=False):
    """把 dict / list 序列化成 JSON 字符串。

    默认 ensure_ascii=False：保留中文等非 ASCII 字符，避免 tag 被转成 \\uXXXX。
    indent=2 与 sing-box 官方配置风格一致；传 None 可得到紧凑输出。
    """
    return json.dumps(data, indent=indent, ensure_ascii=ensure_ascii)


def parse_query(query):
    """把 ?a=b&c=d 解析成 dict，值不解码列表"""
    return {k: v[0] for k, v in urllib.parse.parse_qs(query, keep_blank_values=True).items()}
