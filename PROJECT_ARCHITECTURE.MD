# PROJECT_ARCHITECTURE

## Цель
Сделать локальный Web UI на сервере, который повторяет логику официального клиента Amnezia: разворачивает и управляет контейнерами протоколов/сервисов, показывает мониторинг и выдаёт конфиги для синхронизации с приложением.

## Компоненты
1. **Backend (Go)**
   - Один бинарник, запускается на сервере
   - Управляет Docker напрямую (без SSH)
   - Отдаёт API для UI
   - Хранит состояние в SQLite

2. **Web UI (static)**
   - Одна страница (SPA‑стиль)
   - Экран контейнеров, логов, конфигов, установки протоколов
   - Модальные окна для редактирования конфигов и клиентов

3. **Docker‑контейнеры Amnezia**
   - AWG / WireGuard / OpenVPN / OpenVPN over Cloak / Shadowsocks / Xray / IPsec
   - Сервисы: AmneziaDNS / Socks5 / SFTP

## Текущий MVP
- List / start / stop / restart контейнеров
- Логи
- Редактор конфигов для известных контейнеров
- Экспорт конфигов (download / copy / QR)
- Установка/удаление протоколов и сервисов
- Мониторинг хоста
- Подсчёт активных подключений
- Плитка занятых портов
- Проверка конфликтов портов при установке
- Перезапуск сервера из UI
- SQLite хранилище (клиенты/конфиги/алерты)
- Клиенты (WireGuard/AWG) + экспорт `vpn://` + QR (MVP)
- Split‑tunnel (SQLite + применение в `vpn://`)
- Опционально: системный split‑tunnel через `nftables`

## Планируемые модули
- **Installer**: установка Docker, подготовка хоста, сеть `amnezia-dns-net`
- **Protocol Manager**: установка и удаление контейнеров протоколов
- **Config Exporter**: генерация `vpn://` (full access / connection)
- **Monitoring**: CPU/RAM/Net I/O, алерты, healthcheck
- **Client Manager**: управление клиентами для всех поддерживаемых протоколов
- **Split Tunneling Manager**: списки доменов/подсетей, режимы include/exclude, применение правил

## API (черновик)
- `/api/health`
- `/api/containers`
- `/api/containers/{name}/start|stop|restart|logs|config|export`
- `/api/protocols`
- `/api/protocols/{id}/install|remove`
- `/api/monitoring`
- `/api/ports`
- `/api/alerts`
- `/api/clients`
- `/api/clients/{id}/export`
- `/api/server/restart`
- `/api/export/vpn://` (будет)
- `/api/split-tunnel` (GET/POST)

## Контейнер → конфиг
- `amnezia-awg` → `/opt/amnezia/awg/wg0.conf`
- `amnezia-awg2` → `/opt/amnezia/awg/awg0.conf`
- `amnezia-wireguard` → `/opt/amnezia/wireguard/wg0.conf`
- `amnezia-openvpn` → `/opt/amnezia/openvpn/server.conf`
- `amnezia-openvpn-cloak` → `/opt/amnezia/openvpn/server.conf`
- `amnezia-shadowsocks` → `/opt/amnezia/openvpn/server.conf`
- `amnezia-xray` → `/opt/amnezia/xray/server.json`
- `amnezia-socks5proxy` → `/usr/local/3proxy/conf/3proxy.cfg`
- `amnezia-dns` → `/opt/amnezia/dns/unbound.conf` (может отличаться)
- `amnezia-sftp` → `/etc/ssh/sshd_config` (черновик)

## Безопасность
- Basic Auth на UI
- Локальная установка без публичных ключей/агентов
- В будущем: IP‑лист, TLS и audit‑лог

## Split‑tunnel (дизайн)
- **Цель**: дать UI список доменов/подсетей, которые проходят через VPN (include) или исключаются (exclude).
- **Режимы**:
  - `include` — только перечисленные домены/подсети через VPN.
  - `exclude` — всё через VPN, кроме перечисленных доменов/подсетей.
- **Хранение**: SQLite (`split_tunnel`).
- **Применение**:
  - домены резолвятся в IP/CIDR;
  - в `vpn://` добавляются поля `splitTunnelType` и `splitTunnelSites`;
  - при применении обновляются `amnezia_json` и `vpn://` для существующих клиентов.
- **Системное применение (опционально)**:
  - `nftables` sets + policy routing (tproxy);
  - включается `SPLIT_TUNNEL_SYSTEM=1`.
