import logging
import yaml


def clash2singbox(origin_data):
    if not origin_data:
        logging.warning("订阅内容为空，请检查链接或网络！")
        return None
    data = yaml.safe_load(origin_data)
    origin_node = data["proxies"]
    def checkfalse(origin):
        return str(origin).strip().lower() == "false"
    def checktrue(origin):
        return str(origin).strip().lower() == "true"
    def dial_fields(onenode, node):
        if checkfalse(onenode.get("udp")):
            node["network"] = "tcp"
        smux_opts = onenode.get("smux")
        if isinstance(smux_opts, dict):
            if not checkfalse(smux_opts.get("enabled")):
                node["smux"] = {
                    "enabled": True,
                    "protocol": smux_opts.get("protocol", "smux"),
                    "max_connections": int(smux_opts.get("max-connections", 4)),
                    "min_streams": int(smux_opts.get("min-streams", 4)),
                    "max_streams": int(smux_opts.get("max-streams", 0)),
                    "padding": checktrue(smux_opts.get("padding"))
                }
                if checktrue(onenode.get("padding")):
                    node["padding"] = True
                brutal_opts = smux_opts.get("brutal-opts")
                if isinstance(brutal_opts, dict):
                    if checktrue(brutal_opts.get("enabled")):
                        node["brutal"] = {
                            "enabled": True,
                            "up_mbps": int(brutal_opts.get("up", 100)),
                            "down_mbps": int(brutal_opts.get("down", 100))
                        }
        detour = onenode.get("dialer-proxy")
        if detour:
            node["detour"] = detour
    def tls(onenode, node):
        def pem_or_path(value):
            if str(value).lstrip().startswith("-----BEGIN"):
                return value, None
            return None, value
        tls = {}
        if checktrue(onenode.get("tls")):
            tls["enabled"] = True
        server_name = onenode.get("servername")
        if server_name:
            tls["server_name"] = server_name
        alpn = onenode.get("alpn")
        if alpn:
            tls["alpn"] = alpn
        insecure = onenode.get("skip-cert-verify")
        if checktrue(insecure):
            tls["insecure"] = True
        utls = onenode.get("client-fingerprint")
        if utls:
            tls["utls"] = {"enabled": True, "fingerprint": utls}
        reality = onenode.get("reality-opts")
        if reality:
            tls["reality"] = {"enabled": True, "public_key": reality["public-key"], "short_id": reality["short-id"]}

        cert = onenode.get("certificate")
        if cert:
            pem, path = pem_or_path(cert)
            if pem:
                tls["certificate"] = [pem]
            else:
                tls["certificate_path"] = path
        privkey = onenode.get("private-key")
        if privkey:
            pem, path = pem_or_path(privkey)
            if pem:
                tls["key"] = [pem]
            else:
                tls["key_path"] = path
        if tls:
            node["tls"] = tls
    def v2ray_transport(onenode, node):
        network = onenode.get("network")
        match network:
            case "tcp" | None:
                return
            case "ws":
                ws_opts = onenode.get("ws-opts") or {}
                transport = {"type": "ws", "path": ws_opts.get("path", "/")}
                headers = ws_opts.get("headers")
                if headers:
                    transport["headers"] = headers
                max_early_data = ws_opts.get("max-early-data")
                if max_early_data:
                    transport["max_early_data"] = int(max_early_data)
                early_data_header = ws_opts.get("early-data-header-name")
                if early_data_header:
                    transport["early_data_header_name"] = early_data_header
                node["transport"] = transport
            case "grpc":
                grpc_opts = onenode.get("grpc-opts") or {}
                transport = {"type": "grpc"}
                service_name = grpc_opts.get("grpc-service-name")
                if service_name:
                    transport["service_name"] = service_name
                node["transport"] = transport
            case "h2" | "http":
                opts = onenode.get("h2-opts") or onenode.get("http-opts") or {}
                transport = {"type": "http"}
                host = opts.get("host")
                if host:
                    transport["host"] = host if isinstance(host, list) else [host]
                path = opts.get("path")
                if path:
                    transport["path"] = path
                method = opts.get("method")
                if method:
                    transport["method"] = method
                headers = opts.get("headers")
                if headers:
                    transport["headers"] = headers
                node["transport"] = transport
    allnode = []
    for onenode in origin_node:
        match onenode["type"]:
            case "ss":
                node = {"tag": onenode["name"], "type": "shadowsocks", "server": onenode["server"], "server_port": int(onenode["port"]), "method": onenode["cipher"], "password": onenode["password"]}
                if checktrue(onenode.get("udp-over-tcp")):
                    version = onenode.get("udp-over-tcp-version")
                    if version in ["1", "2", 1, 2]:
                        node["udp_over_tcp"] = {"enabled": True, "version": int(version)}
                    else:
                        node["udp_over_tcp"] = True
                dial_fields(onenode, node)
                allnode.append(node)
            case "vless":
                node = {"tag": onenode["name"], "type": "vless", "server": onenode["server"], "server_port": int(onenode["port"]), "uuid": onenode["uuid"]}
                flow = onenode.get("flow")
                if flow:
                    node["flow"] = flow
                packet_encoding = onenode.get("packet_encoding")
                if packet_encoding:
                    node["packet_encoding"] = packet_encoding
                dial_fields(onenode, node)
                tls(onenode, node)
                v2ray_transport(onenode, node)
                allnode.append(node)
            case "vmess":
                node = {"tag": onenode["name"], "type": "vmess", "server": onenode["server"], "server_port": int(onenode["port"]), "uuid": onenode["uuid"]}
                node["alter_id"] = int(onenode.get("alter-id", 0))
                packet_encoding = onenode.get("packet_encoding")
                if packet_encoding:
                    node["packet_encoding"] = packet_encoding
                cipher = onenode.get("cipher")
                if cipher:
                    node["security"] = cipher
                dial_fields(onenode, node)
                tls(onenode, node)
                v2ray_transport(onenode, node)
                allnode.append(node)
            case "trojan":
                node = {"tag": onenode["name"], "type": "trojan", "server": onenode["server"], "server_port": int(onenode["port"]), "password": onenode["password"]}
                dial_fields(onenode, node)
                tls(onenode, node)
                v2ray_transport(onenode, node)
                allnode.append(node)
    return allnode
