import base64
import json
import logging
import urllib.parse


def _node_to_uri(node):
    """把单个 sing-box 节点 dict 转成 URI 字符串。不支持的类型返回 None。"""
    ntype = node.get("type")
    server = node["server"]
    port = node["server_port"]
    tag = node.get("tag")
    fragment = "#" + urllib.parse.quote(tag, safe="") if tag else ""
    query = []

    def build_tls(tls):
        """从 node["tls"] 重建 query 参数（vless/trojan 通用）。"""
        if not tls:
            return
        if tls.get("reality", {}).get("enabled"):
            query.append(("security", "reality"))
            if tls.get("server_name"):
                query.append(("sni", tls["server_name"]))
            if tls["reality"].get("public_key"):
                query.append(("pbk", tls["reality"]["public_key"]))
            if tls["reality"].get("short_id"):
                query.append(("sid", tls["reality"]["short_id"]))
        elif tls.get("enabled"):
            query.append(("security", "tls"))
            if tls.get("server_name"):
                query.append(("sni", tls["server_name"]))
            if tls.get("insecure"):
                query.append(("allowInsecure", "1"))
        if tls.get("alpn"):
            alpn = tls["alpn"]
            query.append(("alpn", ",".join(alpn) if isinstance(alpn, list) else alpn))
        if tls.get("utls", {}).get("fingerprint"):
            query.append(("fp", tls["utls"]["fingerprint"]))

    def build_transport(transport):
        """从 node["transport"] 重建 query 参数（vless/trojan 通用）。"""
        if not transport:
            return
        ttype = transport.get("type")
        if ttype == "ws":
            query.append(("type", "ws"))
            query.append(("path", transport.get("path", "/")))
            host = (transport.get("headers") or {}).get("Host")
            if host:
                query.append(("host", host))
            ed = transport.get("max_early_data")
            if ed:
                query.append(("ed", str(ed)))
        elif ttype == "grpc":
            query.append(("type", "grpc"))
            if transport.get("service_name"):
                query.append(("serviceName", transport["service_name"]))
        elif ttype == "http":
            query.append(("type", "http"))
            if transport.get("path"):
                query.append(("path", transport["path"]))
            if transport.get("host"):
                host = transport["host"]
                query.append(("host", ",".join(host) if isinstance(host, list) else host))
        # tcp 不输出 type，保持默认

    def qs():
        if not query:
            return ""
        return "?" + "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in query)

    if ntype == "shadowsocks":
        method = node.get("method", "")
        password = node.get("password", "")
        userinfo = f"{urllib.parse.quote(method, safe='')}:{urllib.parse.quote(password, safe='')}"
        if node.get("udp_over_tcp") in (True, "true", 1):
            query.append(("uot", "1"))
        return f"ss://{userinfo}@{server}:{port}{qs()}{fragment}"

    if ntype == "vmess":
        cfg = {
            "v": "2",
            "ps": tag or "",
            "add": server,
            "port": str(port),
            "id": node.get("uuid", ""),
            "aid": str(node.get("alter_id", 0)),
            "net": "tcp",
        }
        if node.get("security"):
            cfg["scy"] = node["security"]
        transport = node.get("transport")
        if transport:
            ttype = transport.get("type")
            if ttype == "ws":
                cfg["net"] = "ws"
                cfg["path"] = transport.get("path", "/")
                host = (transport.get("headers") or {}).get("Host")
                if host:
                    cfg["host"] = host
            elif ttype == "grpc":
                cfg["net"] = "grpc"
                if transport.get("service_name"):
                    cfg["path"] = transport["service_name"]
            elif ttype == "http":
                cfg["net"] = "h2"
        tls = node.get("tls")
        if tls and tls.get("enabled"):
            cfg["tls"] = "tls"
            if tls.get("server_name"):
                cfg["sni"] = tls["server_name"]
            if tls.get("insecure"):
                cfg["verify"] = False
            if tls.get("alpn"):
                alpn = tls["alpn"]
                cfg["alpn"] = ",".join(alpn) if isinstance(alpn, list) else alpn
        raw = json.dumps(cfg, ensure_ascii=False, separators=(",", ":"))
        encoded = base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")
        return f"vmess://{encoded}"

    if ntype == "vless":
        userinfo = node.get("uuid", "")
        build_transport(node.get("transport"))
        build_tls(node.get("tls"))
        if node.get("flow"):
            query.append(("flow", node["flow"]))
        return f"vless://{userinfo}@{server}:{port}{qs()}{fragment}"

    if ntype == "trojan":
        userinfo = urllib.parse.quote(node.get("password", ""), safe="")
        build_transport(node.get("transport"))
        build_tls(node.get("tls"))
        return f"trojan://{userinfo}@{server}:{port}{qs()}{fragment}"

    if ntype == "wireguard":
        return _wireguard_to_uri(node, server, port, tag)

    return None

def _wireguard_to_uri(node, server, port, tag):
    """把 sing-box wireguard endpoint 节点转成 wireguard:// URI 字符串。"""
    query = []
    fragment = "#" + urllib.parse.quote(tag, safe="") if tag else ""

    # public_key 从 peers[0] 获取
    peers = node.get("peers", [])
    if not peers:
        return None
    peer0 = peers[0]
    public_key = peer0.get("public_key", "")

    # private_key（顶层字段）
    if node.get("private_key"):
        query.append(("private_key", node["private_key"]))

    # local_address：address=10.0.0.2/32,fd00::2/128
    local_addr = node.get("local_address", [])
    if local_addr:
        query.append(("address", ",".join(local_addr)))

    # allowed_ips
    allowed_ips = peer0.get("allowed_ips", [])
    if allowed_ips:
        query.append(("allowed_ips", ",".join(allowed_ips)))

    # pre_shared_key
    if peer0.get("pre_shared_key"):
        query.append(("pre_shared_key", peer0["pre_shared_key"]))

    # persistent_keepalive_interval
    keepalive = peer0.get("persistent_keepalive_interval")
    if keepalive:
        query.append(("persistent_keepalive", str(keepalive)))

    # reserved
    reserved = node.get("reserved")
    if reserved:
        query.append(("reserved", ",".join(str(x) for x in reserved)))

    # mtu
    mtu = node.get("mtu")
    if mtu:
        query.append(("mtu", str(mtu)))

    # workers
    workers = node.get("workers")
    if workers:
        query.append(("workers", str(workers)))

    # dns
    dns = node.get("dns")
    if dns:
        query.append(("dns", ",".join(dns) if isinstance(dns, list) else dns))

    qs = "?" + "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in query) if query else ""
    return f"wireguard://{urllib.parse.quote(public_key, safe='')}@{server}:{port}{qs}{fragment}"

def singbox2uri(data):
    """把 sing-box 节点（dict / 列表 / 含 outbounds 的配置 dict）转成 URI 字符串。

    多个节点用换行分隔；无法转换的节点会被跳过并记日志。
    """
    if isinstance(data, dict):
        if "outbounds" in data:
            nodes = data["outbounds"]
        else:
            nodes = [data]
    elif isinstance(data, list):
        nodes = data
    else:
        logging.warning("singbox2uri: 输入类型不支持")
        return None

    lines = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        uri = _node_to_uri(node)
        if uri:
            lines.append(uri)
        else:
            logging.warning(f"singbox2uri: 跳过不支持的节点类型 {node.get('type')}")
    return "\n".join(lines)
