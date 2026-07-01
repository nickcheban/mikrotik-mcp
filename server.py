import os
import json
import socket
import hashlib
import struct
import ipaddress
from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import JSONResponse
from fastapi.concurrency import run_in_threadpool

MIKROTIK_HOST = os.getenv("MIKROTIK_HOST", "192.168.1.1")
MIKROTIK_PORT = int(os.getenv("MIKROTIK_PORT", "8728"))
MIKROTIK_USER = os.getenv("MIKROTIK_USER", "ai-mcp")
MIKROTIK_PASS = os.getenv("MIKROTIK_PASS", "")
MCP_SECRET    = os.getenv("MCP_SECRET", "")
DOMAIN        = os.getenv("DOMAIN", "mikrotik-mcp.example.com")

app = FastAPI()

# ─── RouterOS API клиент ───────────────────────────────────────────────────────

class RouterOSAPI:
    """Минимальный синхронный клиент RouterOS API (порт 8728)."""

    def __init__(self, host, port, username, password, timeout=10):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.timeout = timeout
        self.sock = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))
        self._login()

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()

    # ── кодирование длин ──────────────────────────────────────────────────────

    def _encode_length(self, length):
        if length < 0x80:
            return bytes([length])
        elif length < 0x4000:
            length |= 0x8000
            return struct.pack("!H", length)
        elif length < 0x200000:
            length |= 0xC00000
            return struct.pack("!I", length)[1:]
        elif length < 0x10000000:
            length |= 0xE0000000
            return struct.pack("!I", length)
        else:
            return b'\xF0' + struct.pack("!I", length)

    def _decode_length(self):
        b = self._recv_exact(1)
        first = b[0]
        if first < 0x80:
            return first
        elif first < 0xC0:
            second = self._recv_exact(1)[0]
            return ((first & 0x3F) << 8) | second
        elif first < 0xE0:
            rest = self._recv_exact(2)
            return ((first & 0x1F) << 16) | (rest[0] << 8) | rest[1]
        elif first < 0xF0:
            rest = self._recv_exact(3)
            return ((first & 0x0F) << 24) | (rest[0] << 16) | (rest[1] << 8) | rest[2]
        else:
            rest = self._recv_exact(4)
            return struct.unpack("!I", rest)[0]

    def _recv_exact(self, n):
        """Гарантированно читает ровно n байт или выбрасывает исключение."""
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("RouterOS API: соединение закрыто")
            data += chunk
        return data

    # ── протокол ──────────────────────────────────────────────────────────────

    def _write_sentence(self, words):
        data = b""
        for word in words:
            encoded = word.encode("utf-8")
            data += self._encode_length(len(encoded)) + encoded
        data += b"\x00"
        self.sock.sendall(data)

    def _read_sentence(self):
        words = []
        while True:
            length = self._decode_length()
            if length == 0:
                break
            word = self._recv_exact(length).decode("utf-8", errors="replace")
            words.append(word)
        return words

    def _login(self):
        self._write_sentence(["/login", f"=name={self.username}", f"=password={self.password}"])
        response = self._read_sentence()
        if response and response[0] == "!done":
            return
        # Старый challenge-based логин
        challenge = None
        for word in response:
            if word.startswith("=ret="):
                challenge = bytes.fromhex(word[5:])
        if challenge:
            md5 = hashlib.md5()
            md5.update(b"\x00")
            md5.update(self.password.encode("utf-8"))
            md5.update(challenge)
            self._write_sentence(["/login", f"=name={self.username}", f"=response=00{md5.hexdigest()}"])
            self._read_sentence()

    def _read_records(self):
        """Читает !re-записи до !done. Общий цикл для query() и query_words()."""
        results = []
        while True:
            sentence = self._read_sentence()
            if not sentence:
                break
            tag = sentence[0]
            if tag == "!re":
                obj = {}
                for word in sentence[1:]:
                    if word.startswith("="):
                        parts = word[1:].split("=", 1)
                        if len(parts) == 2:
                            obj[parts[0]] = parts[1]
                results.append(obj)
            elif tag == "!done":
                break
            elif tag in ("!trap", "!fatal"):
                raise Exception(f"RouterOS error: {' '.join(sentence[1:])}")
        return results

    def query(self, command, params=None, filters=None):
        """Выполнить команду и вернуть список словарей."""
        words = [command]
        if params:
            for k, v in params.items():
                words.append(f"={k}={v}")
        if filters:
            for f in filters:
                words.append(f"?{f}")
        self._write_sentence(words)
        return self._read_records()

    def query_words(self, words):
        """Как query(), но принимает уже готовый список слов — нужно для команд
        с флагами без значения (например 'once' у /interface/monitor-traffic)."""
        self._write_sentence(words)
        return self._read_records()

    def run(self, command, params=None):
        """Выполнить команду без возврата данных (add/remove/set)."""
        words = [command]
        if params:
            for k, v in params.items():
                words.append(f"={k}={v}")
        self._write_sentence(words)
        while True:
            sentence = self._read_sentence()
            if not sentence:
                break
            tag = sentence[0]
            if tag == "!done":
                break
            elif tag in ("!trap", "!fatal"):
                raise Exception(f"RouterOS error: {' '.join(sentence[1:])}")


def get_api():
    return RouterOSAPI(MIKROTIK_HOST, MIKROTIK_PORT, MIKROTIK_USER, MIKROTIK_PASS)


# ─── Описание инструментов ────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "system_info",
        "description": "Информация о системе: модель, версия RouterOS, uptime, CPU, RAM",
        "inputSchema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "get_interfaces",
        "description": "Список сетевых интерфейсов с их статусом и комментариями",
        "inputSchema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "get_dhcp_leases",
        "description": "Список DHCP lease — кто подключён к сети. Можно фильтровать по серверу.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "server": {"type": "string", "description": "Имя DHCP сервера. Если не указан — все."}
            },
            "required": []
        }
    },
    {
        "name": "get_firewall_rules",
        "description": "Правила файрвола (filter). Можно фильтровать по chain (input/forward/output).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "chain": {"type": "string", "description": "Цепочка: input, forward, output. Если не указана — все."}
            },
            "required": []
        }
    },
    {
        "name": "get_nat_rules",
        "description": "Правила NAT (dstnat и srcnat)",
        "inputSchema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "get_address_lists",
        "description": "Содержимое address-list. Можно указать конкретный список.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "list": {"type": "string", "description": "Имя списка, например blocked, allowed_internet. Если не указан — все."}
            },
            "required": []
        }
    },
    {
        "name": "get_queues",
        "description": "Simple Queues — ограничения скорости для устройств и интерфейсов",
        "inputSchema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "get_routes",
        "description": "Таблица маршрутизации",
        "inputSchema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "add_to_address_list",
        "description": "Добавить IP адрес в address-list на Микротике",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "IP адрес или подсеть, например 1.2.3.4 или 192.168.1.0/24"},
                "list": {"type": "string", "description": "Имя списка, например blocked"},
                "comment": {"type": "string", "description": "Комментарий (необязательно)"},
                "timeout": {"type": "string", "description": "Время жизни записи, например 1h, 1d (необязательно)"}
            },
            "required": ["address", "list"]
        }
    },
    {
        "name": "remove_from_address_list",
        "description": "Удалить IP адрес из address-list на Микротике",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "IP адрес для удаления"},
                "list": {"type": "string", "description": "Имя списка"}
            },
            "required": ["address", "list"]
        }
    },
    {
        "name": "get_logs",
        "description": "Последние записи из лога Микротика",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "number", "description": "Количество записей (по умолчанию 50)"}
            },
            "required": []
        }
    },
    {
        "name": "execute_command",
        "description": "Выполнить RouterOS команду для чтения/диагностики. Только read-only команды. Например: /ip/firewall/filter/print или /ping address=8.8.8.8 count=3",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "RouterOS команда"}
            },
            "required": ["command"]
        }
    },
    {
        "name": "get_wireguard",
        "description": "WireGuard: список интерфейсов (listen-port, public-key) и пиров (endpoint, allowed-address, последний handshake, rx/tx)",
        "inputSchema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "get_dns_static",
        "description": "Список статических DNS-записей (/ip/dns/static) на Микротике",
        "inputSchema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "get_interface_traffic",
        "description": "Мгновенный снимок текущей загрузки интерфейсов (бит/с, пакетов/с) — для диагностики 'почему тормозит интернет прямо сейчас'",
        "inputSchema": {
            "type": "object",
            "properties": {
                "interface": {"type": "string", "description": "Имя интерфейса или список через запятую, например ether1,wlan1. Если не указано — все активные интерфейсы (максимум 8)."}
            },
            "required": []
        }
    },
    {
        "name": "config_snapshot",
        "description": "JSON-снимок ключевых разделов конфигурации (интерфейсы, firewall filter/NAT, address-lists, DHCP lease, маршруты, WireGuard, статический DNS) — для сравнения 'было/стало' до и после изменений. Это не бинарный RouterOS-бэкап, а читаемый JSON-снимок.",
        "inputSchema": {"type": "object", "properties": {}, "required": []}
    }
]


# ─── Логика инструментов ──────────────────────────────────────────────────────

# Whitelist разрешённых корневых команд для execute_command
ALLOWED_READ_COMMANDS = {
    "/ip/firewall/filter/print",
    "/ip/firewall/nat/print",
    "/ip/firewall/address-list/print",
    "/ip/firewall/mangle/print",
    "/ip/route/print",
    "/ip/address/print",
    "/ip/dhcp-server/lease/print",
    "/ip/dhcp-server/print",
    "/ip/dns/print",
    "/ip/dns/static/print",
    "/interface/print",
    "/interface/ethernet/print",
    "/interface/bridge/print",
    "/interface/bridge/port/print",
    "/interface/vlan/print",
    "/interface/wireguard/print",
    "/interface/wireguard/peers/print",
    "/queue/simple/print",
    "/queue/type/print",
    "/system/resource/print",
    "/system/identity/print",
    "/system/routerboard/print",
    "/system/clock/print",
    "/log/print",
    "/ping",
    "/tool/ping",
}

def validate_ip(address):
    """Проверяет что адрес — валидный IP или подсеть."""
    try:
        ipaddress.ip_network(address, strict=False)
    except ValueError:
        raise ValueError(f"Некорректный IP адрес или подсеть: {address}")


def run_tool(name, args):
    with get_api() as api:

        if name == "system_info":
            res   = api.query("/system/resource/print")
            board = api.query("/system/routerboard/print")
            idn   = api.query("/system/identity/print")
            info  = res[0]   if res   else {}
            rb    = board[0] if board else {}
            ident = idn[0]   if idn   else {}
            cpu   = info.get("cpu-load")
            return {
                "identity":         ident.get("name", ""),
                "model":            rb.get("model", info.get("board-name", "")),
                "routeros_version": info.get("version", ""),
                "uptime":           info.get("uptime", ""),
                "cpu_load":         f"{cpu}%" if cpu is not None else "N/A",
                "free_memory":      info.get("free-memory", ""),
                "total_memory":     info.get("total-memory", ""),
                "architecture":     info.get("architecture-name", ""),
            }

        elif name == "get_interfaces":
            ifaces = api.query("/interface/print")
            return {
                "interfaces": [
                    {
                        "name":        i.get("name", ""),
                        "type":        i.get("type", ""),
                        "running":     i.get("running", ""),
                        "disabled":    i.get("disabled", ""),
                        "comment":     i.get("comment", ""),
                        "mac_address": i.get("mac-address", ""),
                    }
                    for i in ifaces
                ],
                "count": len(ifaces)
            }

        elif name == "get_dhcp_leases":
            server_filter = args.get("server", "")
            leases = api.query("/ip/dhcp-server/lease/print")
            result = [
                {
                    "address":       lease.get("address", ""),
                    "mac":           lease.get("mac-address", ""),
                    "hostname":      lease.get("host-name", ""),
                    "comment":       lease.get("comment", ""),
                    "server":        lease.get("server", ""),
                    "status":        lease.get("status", ""),
                    "last_seen":     lease.get("last-seen", ""),
                    "expires_after": lease.get("expires-after", ""),
                }
                for lease in leases
                if not server_filter or lease.get("server", "") == server_filter
            ]
            return {"leases": result, "count": len(result)}

        elif name == "get_firewall_rules":
            chain = args.get("chain", "")
            rules = api.query("/ip/firewall/filter/print")
            result = [
                {
                    "chain":        r.get("chain", ""),
                    "action":       r.get("action", ""),
                    "comment":      r.get("comment", ""),
                    "src_address":  r.get("src-address", ""),
                    "dst_address":  r.get("dst-address", ""),
                    "protocol":     r.get("protocol", ""),
                    "dst_port":     r.get("dst-port", ""),
                    "in_interface": r.get("in-interface", ""),
                    "disabled":     r.get("disabled", "false"),
                    "bytes":        r.get("bytes", "0"),
                    "packets":      r.get("packets", "0"),
                }
                for r in rules
                if not chain or r.get("chain", "") == chain
            ]
            return {"rules": result, "count": len(result)}

        elif name == "get_nat_rules":
            rules = api.query("/ip/firewall/nat/print")
            return {
                "rules": [
                    {
                        "chain":        r.get("chain", ""),
                        "action":       r.get("action", ""),
                        "comment":      r.get("comment", ""),
                        "src_address":  r.get("src-address", ""),
                        "dst_address":  r.get("dst-address", ""),
                        "protocol":     r.get("protocol", ""),
                        "dst_port":     r.get("dst-port", ""),
                        "to_addresses": r.get("to-addresses", ""),
                        "to_ports":     r.get("to-ports", ""),
                        "disabled":     r.get("disabled", "false"),
                    }
                    for r in rules
                ],
                "count": len(rules)
            }

        elif name == "get_address_lists":
            list_filter = args.get("list", "")
            entries = api.query("/ip/firewall/address-list/print")
            result = [
                {
                    "list":     e.get("list", ""),
                    "address":  e.get("address", ""),
                    "comment":  e.get("comment", ""),
                    "timeout":  e.get("timeout", ""),
                    "disabled": e.get("disabled", "false"),
                }
                for e in entries
                if not list_filter or e.get("list", "") == list_filter
            ]
            return {"entries": result, "count": len(result)}

        elif name == "get_queues":
            queues = api.query("/queue/simple/print")
            return {
                "queues": [
                    {
                        "name":            q.get("name", ""),
                        "target":          q.get("target", ""),
                        "max_limit":       q.get("max-limit", ""),
                        "burst_limit":     q.get("burst-limit", ""),
                        "burst_threshold": q.get("burst-threshold", ""),
                        "burst_time":      q.get("burst-time", ""),
                        "disabled":        q.get("disabled", "false"),
                        "comment":         q.get("comment", ""),
                    }
                    for q in queues
                ],
                "count": len(queues)
            }

        elif name == "get_routes":
            routes = api.query("/ip/route/print")
            return {
                "routes": [
                    {
                        "dst_address": r.get("dst-address", ""),
                        "gateway":     r.get("gateway", ""),
                        "distance":    r.get("distance", ""),
                        "active":      r.get("active", ""),
                        "comment":     r.get("comment", ""),
                    }
                    for r in routes
                ],
                "count": len(routes)
            }

        elif name == "add_to_address_list":
            address = args["address"]
            lst     = args["list"]
            comment = args.get("comment", "added by ai-mcp")
            timeout = args.get("timeout", "")
            validate_ip(address)
            params = {"address": address, "list": lst, "comment": comment}
            if timeout:
                params["timeout"] = timeout
            api.run("/ip/firewall/address-list/add", params)
            return {"status": "ok", "address": address, "list": lst}

        elif name == "remove_from_address_list":
            address = args["address"]
            lst     = args["list"]
            validate_ip(address)
            entries = api.query("/ip/firewall/address-list/print")
            removed = 0
            for entry in entries:
                if entry.get("address") == address and entry.get("list") == lst:
                    entry_id = entry.get(".id", "")
                    if entry_id:
                        api.run("/ip/firewall/address-list/remove", {".id": entry_id})
                        removed += 1
            return {"status": "ok", "removed": removed, "address": address, "list": lst}

        elif name == "get_logs":
            limit = int(args.get("limit", 50))
            logs  = api.query("/log/print")
            return {
                "logs": [
                    {
                        "time":    log.get("time", ""),
                        "topics":  log.get("topics", ""),
                        "message": log.get("message", ""),
                    }
                    for log in logs[-limit:]
                ],
                "count": min(limit, len(logs))
            }

        elif name == "execute_command":
            command = args["command"].strip()
            # Определяем базовую команду (первое слово)
            base_cmd = command.split()[0].rstrip("/")
            # Нормализуем: /ping → /ping, /ip/firewall/filter/print → /ip/firewall/filter/print
            normalized = "/" + base_cmd.lstrip("/")

            if normalized not in ALLOWED_READ_COMMANDS:
                return {
                    "error": f"Команда не в whitelist: {normalized}",
                    "allowed": sorted(ALLOWED_READ_COMMANDS)
                }

            # Парсим аргументы: ключ=значение → словарь params
            words  = command.split()
            params = {}
            for word in words[1:]:
                if "=" in word:
                    k, v = word.split("=", 1)
                    params[k] = v

            result = api.query(normalized, params if params else None)
            return {"command": command, "result": result, "count": len(result)}

        elif name == "get_wireguard":
            ifaces = api.query("/interface/wireguard/print")
            peers  = api.query("/interface/wireguard/peers/print")
            return {
                "interfaces": [
                    {
                        "name":        i.get("name", ""),
                        "listen_port": i.get("listen-port", ""),
                        "public_key":  i.get("public-key", ""),
                        "running":     i.get("running", ""),
                        "disabled":    i.get("disabled", "false"),
                    }
                    for i in ifaces
                ],
                "peers": [
                    {
                        "name":            p.get("name", ""),
                        "interface":       p.get("interface", ""),
                        "public_key":      p.get("public-key", ""),
                        "allowed_address": p.get("allowed-address", ""),
                        "endpoint":        p.get("current-endpoint-address", p.get("endpoint-address", "")),
                        "endpoint_port":   p.get("current-endpoint-port", p.get("endpoint-port", "")),
                        "last_handshake":  p.get("last-handshake", ""),
                        "rx":              p.get("rx", ""),
                        "tx":              p.get("tx", ""),
                        "disabled":        p.get("disabled", "false"),
                        "comment":         p.get("comment", ""),
                    }
                    for p in peers
                ],
            }

        elif name == "get_dns_static":
            entries = api.query("/ip/dns/static/print")
            return {
                "entries": [
                    {
                        "name":     e.get("name", ""),
                        "type":     e.get("type", "A"),
                        "address":  e.get("address", ""),
                        "cname":    e.get("cname", ""),
                        "ttl":      e.get("ttl", ""),
                        "disabled": e.get("disabled", "false"),
                        "comment":  e.get("comment", ""),
                    }
                    for e in entries
                ],
                "count": len(entries)
            }

        elif name == "get_interface_traffic":
            iface = args.get("interface", "").strip()
            if not iface:
                ifaces = api.query("/interface/print")
                names = [i.get("name") for i in ifaces if i.get("disabled", "false") != "true" and i.get("name")]
                iface = ",".join(names[:8])
            if not iface:
                return {"error": "Нет доступных интерфейсов для снимка трафика"}
            records = api.query_words(["/interface/monitor-traffic", f"=interface={iface}", "=once="])
            return {
                "interfaces": [
                    {
                        "name":                   r.get("name", ""),
                        "rx_bits_per_second":     r.get("rx-bits-per-second", ""),
                        "tx_bits_per_second":     r.get("tx-bits-per-second", ""),
                        "rx_packets_per_second":  r.get("rx-packets-per-second", ""),
                        "tx_packets_per_second":  r.get("tx-packets-per-second", ""),
                    }
                    for r in records
                ],
                "count": len(records)
            }

        elif name == "config_snapshot":
            ifaces      = api.query("/interface/print")
            fw_filter   = api.query("/ip/firewall/filter/print")
            fw_nat      = api.query("/ip/firewall/nat/print")
            addr_lists  = api.query("/ip/firewall/address-list/print")
            dhcp_leases = api.query("/ip/dhcp-server/lease/print")
            routes      = api.query("/ip/route/print")
            wg_ifaces   = api.query("/interface/wireguard/print")
            wg_peers    = api.query("/interface/wireguard/peers/print")
            dns_static  = api.query("/ip/dns/static/print")
            return {
                "note": "JSON-снимок ключевых разделов конфигурации (не бинарный RouterOS backup)",
                "interfaces":         ifaces,
                "firewall_filter":    fw_filter,
                "firewall_nat":       fw_nat,
                "address_lists":      addr_lists,
                "dhcp_leases":        dhcp_leases,
                "routes":             routes,
                "wireguard_interfaces": wg_ifaces,
                "wireguard_peers":    wg_peers,
                "dns_static":         dns_static,
            }

        else:
            return {"error": f"Unknown tool: {name}"}


# ─── FastAPI endpoints ────────────────────────────────────────────────────────

STATIC_TOKEN = os.getenv("MCP_SECRET", "")

def check_auth(request: Request):
    if not MCP_SECRET:
        return  # В dev-режиме без секрета — пропускаем
    auth = request.headers.get("Authorization", "")
    allowed = {f"Bearer {MCP_SECRET}", f"Bearer {STATIC_TOKEN}"}
    if auth not in allowed:
        raise HTTPException(status_code=401, detail="Unauthorized")

ALLOWED_REDIRECT_HOSTS = {"claude.ai", "anthropic.com", "console.anthropic.com"}

def validate_redirect_uri(uri: str):
    from urllib.parse import urlparse
    parsed = urlparse(uri)
    host = (parsed.hostname or "").lower()
    is_local = host in ("localhost", "127.0.0.1")
    is_trusted = host in ALLOWED_REDIRECT_HOSTS or any(host.endswith("." + h) for h in ALLOWED_REDIRECT_HOSTS)
    ok = (parsed.scheme == "http" and is_local) or (parsed.scheme == "https" and (is_local or is_trusted))
    if not ok:
        raise HTTPException(status_code=400, detail=f"redirect_uri not allowed: {uri}")


@app.get("/")
async def root():
    return {"status": "mikrotik-mcp running", "version": "1.1.0", "host": MIKROTIK_HOST}


@app.get("/mcp")
async def mcp_info(request: Request):
    check_auth(request)
    return {
        "protocolVersion": "2024-11-05",
        "capabilities": {"tools": {}},
        "serverInfo": {"name": "mikrotik-mcp", "version": "1.1.0"}
    }


@app.post("/mcp")
async def mcp_handler(request: Request):
    check_auth(request)
    body   = await request.json()
    method = body.get("method")
    req_id = body.get("id")

    if method == "initialize":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "mikrotik-mcp", "version": "1.1.0"}
        }})

    elif method == "notifications/initialized":
        return Response(status_code=204)

    elif method == "tools/list":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}})

    elif method == "tools/call":
        params    = body.get("params", {})
        tool_name = params.get("name")
        tool_args = params.get("arguments", {})
        try:
            # Синхронный run_tool выполняется в thread pool, не блокируя event loop
            result = await run_in_threadpool(run_tool, tool_name, tool_args)
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {
                "content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False, indent=2)}]
            }})
        except Exception as e:
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {
                "code": -32603,
                "message": str(e)
            }})

    else:
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {
            "code": -32601,
            "message": f"Method not found: {method}"
        }})


# ─── OAuth заглушка (требуется для подключения через claude.ai) ───────────────

@app.get("/.well-known/oauth-authorization-server")
async def oauth_metadata():
    return {
        "issuer":                    f"https://{DOMAIN}",
        "authorization_endpoint":    f"https://{DOMAIN}/oauth/authorize",
        "token_endpoint":            f"https://{DOMAIN}/oauth/token",
        "response_types_supported":  ["code"],
        "grant_types_supported":     ["authorization_code"]
    }

@app.get("/oauth/authorize")
async def oauth_authorize(request: Request):
    from fastapi.responses import RedirectResponse
    params      = dict(request.query_params)
    redirect_uri = params.get("redirect_uri", "")
    state        = params.get("state", "")
    if not redirect_uri:
        raise HTTPException(status_code=400, detail="redirect_uri required")
    validate_redirect_uri(redirect_uri)
    return RedirectResponse(url=f"{redirect_uri}?code=mikrotik-mcp-static-code&state={state}")

@app.post("/oauth/token")
async def oauth_token(request: Request):
    form = await request.form()
    if STATIC_TOKEN and form.get("client_secret") != STATIC_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid client_secret")
    return {
        "access_token": STATIC_TOKEN,
        "token_type":   "bearer",
        "expires_in":   86400
    }
