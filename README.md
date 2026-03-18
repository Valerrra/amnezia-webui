# Amnezia WebUI

Локальная Web‑панель для управления контейнерами Amnezia на сервере. UI + API для мониторинга, управления протоколами/сервисами, работы с клиентами и экспорта конфигов.

## Возможности
- Список контейнеров и статусов
- `start / stop / restart` контейнеров
- Логи контейнеров
- Редактор конфигов для поддерживаемых контейнеров
- Экспорт конфигов (download / copy / QR)
- Установка/удаление протоколов и сервисов через UI
- Мониторинг хоста (CPU, RAM, uptime)
- Подсчёт активных подключений
- Плитка занятых портов
- Перезапуск сервера из UI
- Клиенты (WireGuard/AWG) + экспорт `vpn://`
- Split‑tunnel (SQLite + применение в `vpn://`)
- Опционально: системный split‑tunnel через `nftables`
- Basic Auth

## Требования
- Linux x86_64 (рекомендуется Ubuntu 20.04+)
- root/sudo доступ
- Docker
- systemd
- Открытый порт для UI (по умолчанию `8090`)

## Установка (для новичка, шаг за шагом)

### 1. Обновить систему и поставить зависимости
```bash
sudo apt update
sudo apt install -y ca-certificates curl git
```

### 2. Установить Docker
```bash
curl -fsSL https://get.docker.com | sudo sh
```

### 3. Скачать проект
```bash
sudo mkdir -p /opt/amnezia-webui
sudo chown -R $USER:$USER /opt/amnezia-webui

git clone https://github.com/Valerrra/amnezia-webui.git /opt/amnezia-webui
cd /opt/amnezia-webui
```

### 4. Собрать бинарник (без установки Go)
```bash
docker run --rm -v $PWD:/src -w /src -e CGO_ENABLED=0 golang:1.22 \
  bash -lc "export PATH=/usr/local/go/bin:$PATH; go build -o amnezia-webui ./cmd/server"
```

### 5. Создать файл окружения
```bash
sudo tee /etc/amnezia-webui.env > /dev/null <<'EOF'
WEBUI_PORT=8090
WEBUI_USER=admin
WEBUI_PASSWORD=change-me
SCRIPTS_DIR=/opt/amnezia-webui/scripts
DB_PATH=/opt/amnezia-webui/data/amnezia.db
# Включить системный split-tunnel (опционально)
# SPLIT_TUNNEL_SYSTEM=1
EOF
```

### 6. Создать systemd‑сервис
```bash
sudo tee /etc/systemd/system/amnezia-webui.service > /dev/null <<'EOF'
[Unit]
Description=Amnezia WebUI
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
EnvironmentFile=/etc/amnezia-webui.env
WorkingDirectory=/opt/amnezia-webui
ExecStart=/opt/amnezia-webui/amnezia-webui
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
```

### 7. Запустить сервис
```bash
sudo mkdir -p /opt/amnezia-webui/data
sudo systemctl daemon-reload
sudo systemctl enable --now amnezia-webui
sudo systemctl status amnezia-webui --no-pager
```

### 8. Открыть UI
Откройте в браузере:
```
http://<server-ip>:8090
```
Войдите по Basic Auth (логин/пароль из `/etc/amnezia-webui.env`).

## Обновление
```bash
cd /opt/amnezia-webui

git pull

docker run --rm -v $PWD:/src -w /src -e CGO_ENABLED=0 golang:1.22 \
  bash -lc "export PATH=/usr/local/go/bin:$PATH; go build -o amnezia-webui ./cmd/server"

sudo systemctl restart amnezia-webui
```

## Переменные окружения
- `WEBUI_PORT` — порт UI (по умолчанию `8090`)
- `WEBUI_USER` — логин Basic Auth (по умолчанию `admin`)
- `WEBUI_PASSWORD` — пароль Basic Auth
- `SCRIPTS_DIR` — путь к скриптам (по умолчанию `/opt/amnezia-webui/scripts`)
- `DB_PATH` — путь к SQLite (по умолчанию `/opt/amnezia-webui/data/amnezia.db`)
- `SPLIT_TUNNEL_SYSTEM=1` — включить системный split‑tunnel через `nftables`

## Примечания
- Для установки/удаления протоколов используются локальные скрипты из `scripts/`.
- Рекомендуется ограничить доступ к UI по IP‑фильтру/файрволу и задать сложный пароль.

## API (MVP)
- `GET /api/health`
- `GET /api/containers`
- `POST /api/containers/{name}/start|stop|restart`
- `GET /api/containers/{name}/logs?tail=200`
- `GET /api/containers/{name}/config`
- `POST /api/containers/{name}/config`
- `GET /api/containers/{name}/export`
- `GET /api/protocols`
- `POST /api/protocols/{id}/install|remove`
- `GET /api/monitoring`
- `GET /api/ports`
- `GET /api/alerts`
- `GET /api/clients`
- `POST /api/clients`
- `GET /api/clients/{id}/export`
- `POST /api/server/restart`
- `GET /api/split-tunnel`
- `POST /api/split-tunnel`

## Лицензия
TBD
