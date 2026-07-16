import os
from urllib.parse import urlparse

import requests


def _is_url(s):
    return urlparse(s).scheme in ("http", "https")


def _read_local_file(path, base_dir):
    # 相对路径相对 base_dir（配置文件所在目录）解析，绝对路径直接用
    full = path if os.path.isabs(path) else os.path.join(base_dir or "", path)
    try:
        with open(full, "r", encoding="utf-8") as f:
            content = f.read()
        print(f"成功读取本地文件: {full}")
        return content
    except FileNotFoundError:
        print(f"错误：本地文件不存在: {full}")
    except OSError as e:
        print(f"错误：读取本地文件失败: {full} ({e})")
    return None


def getsub(url, ua, base_dir=None):
    # 本地文件路径（非 http/https）：直接读文件
    if not _is_url(url):
        return _read_local_file(url, base_dir)

    # 如果 ua 为空字符串或 None，则赋予默认值
    if not ua:
        ua = "Mihomo"

    headers = {'User-Agent': ua}

    try:
        # 推荐加上 timeout（超时限制，比如 10 秒），防止请求因网络问题无限期卡死
        response = requests.get(url, headers=headers, timeout=10)

        # 这一步很关键：如果 HTTP 状态码不是 2xx（例如 404, 500 等），它会直接抛出 HTTPError 异常
        response.raise_for_status()

        # 修正了原代码的格式化打印
        print(f"成功获取: {url}")
        return response.text

    except requests.exceptions.Timeout:
        print(f"错误：请求 {url} 超时，请检查网络连接或目标服务器响应速度。")
    except requests.exceptions.ConnectionError:
        print(f"错误：无法连接到 {url}，请确认网址是否正确或网络是否通畅。")
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP 错误：请求失败，状态码为 {response.status_code}。错误信息：{http_err}")
    except requests.exceptions.RequestException as err:
        # 捕获其他所有 requests 相关的异常（如代理错误、SSL证书问题等）
        print(f"请求发生未知错误: {err}")

    # 如果发生异常导致未成功获取，则返回 None
    return None
