# mikrotik-mcp

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)

MCP server for MikroTik RouterOS. Talks to the router directly over the binary RouterOS API (port 8728) — a minimal hand-rolled implementation of the protocol (length encoding, sentence-based exchange, MD5-challenge login for older versions), no third-party RouterOS API library.

**Intentionally read-only** (with one exception — managing entries in a single address-list, see below). This is a deliberate architectural choice: the router is the most sensitive node in the network, and an LLM shouldn't be able to change firewall/NAT/routing directly.

## Tools

| Tool | Description |
|---|---|
| `system_info` | Model, RouterOS version, uptime, CPU, RAM |
| `get_interfaces` | List of network interfaces with status |
| `get_dhcp_leases` | DHCP leases — who's connected to the network |
| `get_firewall_rules` | Firewall filter rules, filterable by chain |
| `get_nat_rules` | NAT rules (dstnat/srcnat) |
| `get_address_lists` | Contents of an address-list |
| `get_queues` | Simple Queues — bandwidth limits |
| `get_routes` | Routing table |
| `add_to_address_list` / `remove_from_address_list` | The only write operations — add/remove an IP from an address-list (e.g. for blocking) |
| `get_logs` | Recent log entries |
| `execute_command` | Arbitrary read-only RouterOS command — **only** from an explicit whitelist in the code (`ALLOWED_READ_COMMANDS`) |
| `get_wireguard` | WireGuard interfaces and peers (endpoint, handshake, rx/tx) |
| `get_dns_static` | Router's static DNS entries |
| `get_interface_traffic` | Instant per-interface throughput snapshot (`/interface/monitor-traffic ... once`) |
| `config_snapshot` | JSON snapshot of key config sections — for diffing before/after manual changes |

## Setup

```bash
git clone <this-repo> mikrotik-mcp && cd mikrotik-mcp
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env       # fill in MIKROTIK_HOST/USER/PASS, MCP_SECRET
uvicorn server:app --host 0.0.0.0 --port 8001
```

Systemd unit example: [`deploy/mikrotik-mcp.service`](deploy/mikrotik-mcp.service).

**Docker:**

```bash
docker build -t mikrotik-mcp .
docker run -p 8001:8001 --env-file .env mikrotik-mcp
```

**On the router:** create a dedicated user in a read-only group (`/user group add name=ai-mcp-group policy=read,api,!write,!policy,!test,!winbox,!password,!web,!reboot,!ftp,!sniff,!sensitive,!romon`), don't grant `write`/`policy`. Even if the server itself is compromised, access stays limited at the RouterOS level.

## Security model

- Auth is an `Authorization: Bearer $MCP_SECRET` header. Empty `MCP_SECRET` = no check (local network/VPN only).
- `/.well-known/oauth-authorization-server` + `/oauth/authorize` + `/oauth/token` are a compatible stub for claude.ai custom connectors, which [don't support a static API key](https://claude.com/docs/connectors/building/authentication) — only full OAuth 2.1 or no auth at all. The actual protection is the Bearer token on `/mcp`, not this handshake. Via Claude Code CLI (`claude mcp add --header ...`) you don't need this stub at all.
- `redirect_uri` in `/oauth/authorize` is checked against an allowlist (`claude.ai`, `anthropic.com`, `console.anthropic.com`, `localhost`).
- `execute_command` runs strictly through a whitelist of root commands in the code — you cannot execute an arbitrary write command through this tool, even by trying.
- **Transport**: the server does not terminate TLS itself — it listens on plain HTTP. If it's reachable beyond localhost/a trusted LAN (and especially if you're connecting it as a custom connector in claude.ai, where HTTPS is required), put TLS termination in front of it: Cloudflare Tunnel, Tailscale Funnel, nginx/Caddy + Let's Encrypt, etc. Without that, the Bearer token (`MCP_SECRET`) in the `Authorization` header goes out in plaintext.

## Requirements

- MikroTik RouterOS 6.x/7.x with the API enabled (`/ip service enable api`, port 8728 by default).
- Python 3.11+.

## License

MIT — see [LICENSE](LICENSE).
