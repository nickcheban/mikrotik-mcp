# mikrotik-mcp

MCP-сервер для MikroTik RouterOS. Общается с роутером напрямую по бинарному RouterOS API (порт 8728) — минимальная самописная реализация протокола (кодирование длин, sentence-based обмен, MD5-challenge login для старых версий), без сторонних библиотек уровня RouterOS API.

**Намеренно read-only** (за исключением управления одним конкретным address-list — см. ниже). Это осознанное архитектурное решение: роутер — самый чувствительный узел сети, и LLM не должна иметь возможность менять firewall/NAT/маршрутизацию напрямую.

## Инструменты

| Инструмент | Описание |
|---|---|
| `system_info` | Модель, версия RouterOS, uptime, CPU, RAM |
| `get_interfaces` | Список сетевых интерфейсов со статусом |
| `get_dhcp_leases` | DHCP lease — кто подключён к сети |
| `get_firewall_rules` | Правила файрвола (filter), с фильтром по chain |
| `get_nat_rules` | Правила NAT (dstnat/srcnat) |
| `get_address_lists` | Содержимое address-list |
| `get_queues` | Simple Queues — ограничения скорости |
| `get_routes` | Таблица маршрутизации |
| `add_to_address_list` / `remove_from_address_list` | Единственные write-операции — добавить/убрать IP из address-list (например, для блокировки) |
| `get_logs` | Последние записи лога |
| `execute_command` | Произвольная read-only RouterOS-команда — **только** из явного whitelist в коде (`ALLOWED_READ_COMMANDS`) |
| `get_wireguard` | WireGuard-интерфейсы и пиры (endpoint, handshake, rx/tx) |
| `get_dns_static` | Статические DNS-записи роутера |
| `get_interface_traffic` | Мгновенный снимок скорости по интерфейсам (`/interface/monitor-traffic ... once`) |
| `config_snapshot` | JSON-снимок ключевых разделов конфига — для диффа «было/стало» до и после ручных изменений |

## Установка

```bash
git clone <this-repo> mikrotik-mcp && cd mikrotik-mcp
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env       # заполните MIKROTIK_HOST/USER/PASS, MCP_SECRET
uvicorn server:app --host 0.0.0.0 --port 8001
```

Systemd-юнит — пример в [`deploy/mikrotik-mcp.service`](deploy/mikrotik-mcp.service).

**На роутере:** создайте отдельного пользователя в read-only группе (`/user group add name=ai-mcp-group policy=read,api,!write,!policy,!test,!winbox,!password,!web,!reboot,!ftp,!sniff,!sensitive,!romon`), не выдавайте `write`/`policy`. Даже если сервер скомпрометируют, доступ будет ограничен на уровне самого RouterOS.

## Security model

- Авторизация — `Authorization: Bearer $MCP_SECRET`. Пустой `MCP_SECRET` = без проверки (только локальная сеть/VPN).
- `/.well-known/oauth-authorization-server` + `/oauth/authorize` + `/oauth/token` — совместимая заглушка для custom-коннекторов claude.ai, у которых [нет поддержки статического API-ключа](https://claude.com/docs/connectors/building/authentication) — только полноценный OAuth 2.1 или отсутствие авторизации вовсе. Реальную защиту даёт Bearer-токен на `/mcp`, а не этот хендшейк. Через Claude Code CLI (`claude mcp add --header ...`) эта заглушка не нужна вовсе.
- `redirect_uri` в `/oauth/authorize` — allowlist (`claude.ai`, `anthropic.com`, `console.anthropic.com`, `localhost`).
- `execute_command` работает строго через whitelist корневых команд в коде — нельзя выполнить произвольную write-команду через этот инструмент, даже если попытаться.

## Требования

- MikroTik RouterOS 6.x/7.x с включённым API (`/ip service enable api`, порт 8728 по умолчанию).
- Python 3.11+.

## Лицензия

MIT — см. [LICENSE](LICENSE).
