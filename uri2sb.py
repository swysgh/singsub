import base64
import json
import logging
import urllib.parse

from common import parse_query


def uri2singbox(origin_data):
    if not origin_data:
        logging.warning("订阅内容为空，请检查链接或网络！")
        return None
    # 探测是否整体 base64：非 base64 直接当明文按行处理
    text = origin_data.strip()
    lines = text.splitlines()
    is_plain = any(l.strip().startswith(("ss://", "vmess://", "vless://", "trojan://")) for l in lines)
    if not is_plain:
        decoded = base64.urlsafe_b64decode(text.replace("\n", "").replace("\r", "")).decode("utf-8")
        if decoded:
            lines = decoded.splitlines()

    allnode = []
    for line in lines:
        line = line.strip()
        if not line or not line.startswith(("ss://", "vmess://", "vless://", "trojan://")):
            continue
        try:
            if line.startswith("vmess://"):
                node = parse_vmess(line)
            elif line.startswith("ss://"):
                node = parse_ss(line)
            elif line.startswith("vless://"):
                node = parse_vless(line)
            else:
                node = parse_trojan(line)
            if node:
                allnode.append(node)
        except Exception as e:
            logging.warning(f"解析失败，跳过该行: {e}")
    return allnode

def parse_vmess(uri):
    raw = base64.urlsafe_b64decode(uri[len("vmess://"):]).decode("utf-8")
    if not raw:
        return None
    cfg = json.loads(raw)
    node = {
        "tag": cfg.get("ps") or cfg.get("add"),
        "type": "vmess",
        "server": cfg["add"],
        "server_port": int(cfg["port"]),
        "uuid": cfg["id"],
        "alter_id": int(cfg.get("aid", 0)),
    }
    scy = cfg.get("scy")
    if scy:
        node["security"] = scy
    net = cfg.get("net")
    if net == "ws":
        transport = {"type": "ws", "path": cfg.get("path", "/")}
        host = cfg.get("host")
        if host:
            transport["headers"] = {"Host": host}
        node["transport"] = transport
    elif net == "grpc":
        transport = {"type": "grpc"}
        if cfg.get("path"):
            transport["service_name"] = cfg["path"]
        node["transport"] = transport
    elif net == "h2" or net == "tcp":
        pass  # tcp 默认；h2 在 vmess base64 里少见
    tls = {}
    if cfg.get("tls") in ("tls", True, "true"):
        tls["enabled"] = True
    sni = cfg.get("sni")
    if sni:
        tls["server_name"] = sni
    alpn = cfg.get("alpn")
    if alpn:
        tls["alpn"] = alpn.split(",") if isinstance(alpn, str) else alpn
    if str(cfg.get("verify", "")).lower() in ("false", "0"):
        tls["insecure"] = True
    if tls:
        node["tls"] = tls
    return node

def parse_ss(uri):
    # SIP002: ss://base64(method:password)@host:port?query#name
    #         或明文 method:password（可能被 percent-encode）
    # 旧式:   ss://base64(method:password@host:port)#name
    body = uri[len("ss://"):]
    name = None
    if "#" in body:
        body, name = body.split("#", 1)
        name = urllib.parse.unquote(name)
    query = {}
    if "?" in body:
        body, q = body.split("?", 1)
        query = parse_query(q)
    if "@" in body:
        # SIP002: userinfo 可能是明文 method:password，也可能 base64
        userinfo, hostport = body.rsplit("@", 1)
        if ":" not in userinfo:
            decoded = base64.urlsafe_b64decode(userinfo).decode("utf-8")
            if decoded and ":" in decoded:
                userinfo = decoded
        if ":" not in hostport:
            return None
        host, port = hostport.rsplit(":", 1)
        method, password = userinfo.split(":", 1)
    else:
        # 旧式: ss://base64(method:password@host:port)
        decoded = base64.urlsafe_b64decode(body)
        if not decoded or "@" not in decoded:
            return None
        userinfo, hostport = decoded.rsplit("@", 1)
        method, password = userinfo.split(":", 1)
        host, port = hostport.rsplit(":", 1)
    node = {
        "tag": name or host,
        "type": "shadowsocks",
        "server": host,
        "server_port": int(port),
        "method": urllib.parse.unquote(method),
        # password 可能被 percent-encode（如 %3D%3D -> ==）
        "password": urllib.parse.unquote(password),
    }
    # uot=1 表示 udp over tcp
    if query.get("uot") in ("1", "true"):
        node["udp_over_tcp"] = True
    return node

def _parse_userinfo_host(uri, scheme):
    """处理 vless/trojan 这种 scheme://user@host:port?query#name 的通用解析"""
    body = uri[len(scheme) + 3:]
    name = None
    if "#" in body:
        body, name = body.split("#", 1)
        name = urllib.parse.unquote(name)
    query = {}
    if "?" in body:
        body, q = body.split("?", 1)
        query = parse_query(q)
    userinfo, hostport = body.rsplit("@", 1)
    host, port = hostport.rsplit(":", 1)
    return userinfo, host, int(port), query, name

def parse_vless(uri):
    uuid, host, port, query, name = _parse_userinfo_host(uri, "vless")
    node = {
        "tag": name or host,
        "type": "vless",
        "server": host,
        "server_port": port,
        "uuid": uuid,
    }
    flow = query.get("flow")
    if flow:
        node["flow"] = flow
    # 传输层
    net = query.get("type", "tcp")
    if net == "ws":
        transport = {"type": "ws", "path": query.get("path", "/")}
        host_h = query.get("host")
        if host_h:
            transport["headers"] = {"Host": host_h}
        ed = query.get("ed") or query.get("earlyData")
        if ed:
            transport["max_early_data"] = int(ed)
        node["transport"] = transport
    elif net == "grpc":
        transport = {"type": "grpc"}
        if query.get("serviceName"):
            transport["service_name"] = query["serviceName"]
        node["transport"] = transport
    elif net == "http":
        transport = {"type": "http", "path": query.get("path", "/")}
        if query.get("host"):
            transport["host"] = query["host"].split(",")
        node["transport"] = transport
    # TLS
    tls = {}
    if query.get("security") == "tls":
        tls["enabled"] = True
        if query.get("sni"):
            tls["server_name"] = query["sni"]
        alpn = query.get("alpn")
        if alpn:
            tls["alpn"] = alpn.split(",")
        if query.get("fp"):
            tls["utls"] = {"enabled": True, "fingerprint": query["fp"]}
        if query.get("allowInsecure") in ("1", "true"):
            tls["insecure"] = True
    elif query.get("security") == "reality":
        tls["reality"] = {"enabled": True}
        if query.get("sni"):
            tls["server_name"] = query["sni"]
        if query.get("pbk"):
            tls["reality"]["public_key"] = query["pbk"]
        if query.get("sid"):
            tls["reality"]["short_id"] = query["sid"]
        if query.get("fp"):
            tls["utls"] = {"enabled": True, "fingerprint": query["fp"]}
    if tls:
        node["tls"] = tls
    return node

def parse_trojan(uri):
    password, host, port, query, name = _parse_userinfo_host(uri, "trojan")
    node = {
        "tag": name or host,
        "type": "trojan",
        "server": host,
        "server_port": port,
        "password": urllib.parse.unquote(password),
    }
    net = query.get("type", "tcp")
    if net == "ws":
        transport = {"type": "ws", "path": query.get("path", "/")}
        host_h = query.get("host")
        if host_h:
            transport["headers"] = {"Host": host_h}
        node["transport"] = transport
    elif net == "grpc":
        transport = {"type": "grpc"}
        if query.get("serviceName"):
            transport["service_name"] = query["serviceName"]
        node["transport"] = transport
    tls = {"enabled": True}  # trojan 强制 TLS
    if query.get("sni"):
        tls["server_name"] = query["sni"]
    alpn = query.get("alpn")
    if alpn:
        tls["alpn"] = alpn.split(",")
    if query.get("fp"):
        tls["utls"] = {"enabled": True, "fingerprint": query["fp"]}
    if query.get("allowInsecure") in ("1", "true"):
        tls["insecure"] = True
    node["tls"] = tls
    return node
