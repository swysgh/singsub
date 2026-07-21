import json
import logging
import urllib.parse


def setup_logging(level=logging.INFO):
    """统一配置日志格式：时间戳 / 级别 / 模块 / 消息。

    仅当没有已配置的 handler 时设置，避免重复调用覆盖。
    """
    logger = logging.getLogger("singsub")
    if logger.handlers:
        return  # 已有 handler，不重复配置
    logger.setLevel(level)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        "[%(asctime)s] [%(levelname)-5s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(handler)
    # 让 urllib3 等第三方库安静一点
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def get_logger(name):
    """获取 singsub 命名空间下的子 logger。

    使用方式：logger = get_logger(__name__)
    """
    return logging.getLogger(f"singsub.{name}")


def dict2json(data, indent=2, ensure_ascii=False):
    """把 dict / list 序列化成 JSON 字符串。

    默认 ensure_ascii=False：保留中文等非 ASCII 字符，避免 tag 被转成 \\uXXXX。
    indent=2 与 sing-box 官方配置风格一致；传 None 可得到紧凑输出。
    """
    return json.dumps(data, indent=indent, ensure_ascii=ensure_ascii)


def parse_query(query):
    """把 ?a=b&c=d 解析成 dict，值不解码列表"""
    return {k: v[0] for k, v in urllib.parse.parse_qs(query, keep_blank_values=True).items()}
