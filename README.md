# Скрипт установки VLESS REALITY

Скрипт `install.sh` поднимает VPN-сервер на базе Xray через Docker: `VLESS + REALITY` в одном из двух режимов транспорта:

- `xhttp` - новый режим по умолчанию
- `tcp` - старый режим с `flow=xtls-rprx-vision`, удобнее для клиентов/TUN-стеков, которые не поддерживают XHTTP

Фейковый веб-сервер больше не устанавливается.

Тестировалось на Ubuntu Server 22.04. На других Ubuntu-подобных системах может заработать, но это не гарантируется.

## Debian 12: сервер с 2 ГБ свободного диска

Используйте отдельный `install-debian12.sh` (только Debian 12 Bookworm):

```bash
sudo bash install-debian12.sh
```

Без вопросов, например TCP:

```bash
sudo REALITY_DOMAIN=dl.google.com XRAY_TRANSPORT=tcp XRAY_PORT=443 bash install-debian12.sh
```

Параметры подключения и режимы совпадают с `install.sh`. Повторный запуск генерирует новые ключи и пересоздаёт контейнер: параметры клиентов потребуется обновить.

Что сделано для небольшого диска:

- Docker устанавливается из официального репозитория Debian, без Buildx и рекомендуемых пакетов; зависимости устанавливаются автоматически.
- Кэш пакетов APT очищается перед установкой, после каждого этапа установки пакетов и в конце.
- До установки требуется минимум 1536 МиБ свободного места на файловых системах `/` и `/var`; перед загрузкой Xray — минимум 512 МиБ в хранилищах Docker/containerd. Это предварительные пороги, а не гарантия размера установки: он зависит от имеющихся пакетов и текущих образов.
- Для Xray включён драйвер Docker `local`: ротация при **2 МиБ**, максимум **3 файла**, сжатие архивов. Бюджет — примерно **6 МиБ** плюс служебные данные; старый файл удаляется при следующей ротации. При малом объёме записи логи могут храниться дольше суток: здесь ограничение по размеру.
- Access-логи Xray отключены, сохраняются только предупреждения и ошибки в stderr. Отдельные неограниченные файлы логов Xray не создаются.
- **Для всего системного журнала хоста** устанавливается лимит 32 МиБ на диске / 16 МиБ в RAM и срок хранения 1 сутки. Архивные журналы очищаются сразу при установке, затем таймером каждые 15 минут (с точностью около минуты). У journald лимит не является строгой квотой: активные файлы и метаданные могут давать превышение.

Изменения journald записываются в `/etc/systemd/journald.conf.d/99-xray-small-disk.conf`; таймер — `xray-journal-cleanup.timer`. Существующие архивные системные журналы сверх лимита/возраста удаляются. Логи других контейнеров и обычные файлы `/var/log` (например, от отдельно установленного rsyslog) эти настройки не ограничивают. Образы и тома других сервисов автоматически не удаляются.

Проверка после установки:

```bash
docker inspect --format '{{json .HostConfig.LogConfig}}' xray-reality
docker logs --tail=100 xray-reality
systemctl status xray-journal-cleanup.timer
journalctl --disk-usage
df -h / /var
docker system df
```

Этот вариант проверен локально на синтаксис и генерацию конфигураций; полный запуск на Debian 12 требует проверки на сервере.

## Быстрая установка (Ubuntu)

1. Скопируйте репозиторий на сервер.
2. Запустите скрипт от `root`:

```bash
sudo bash install.sh
```

Или скачайте скрипт напрямую с GitHub и сразу запустите его:

```bash
curl -fsSL https://raw.githubusercontent.com/nickolsky/vless_docker_install_scripts/refs/heads/main/install.sh | sudo bash
```

3. Ответьте на вопросы скрипта:
   - `REALITY_DOMAIN` - домен, который Xray будет имитировать, например `dl.google.com`
   - `XRAY_TRANSPORT` - транспорт `xhttp` или `tcp`, по умолчанию `xhttp`
   - `XRAY_PORT` - порт для Xray, по умолчанию `443`
   - `XHTTP_PATH` - путь транспорта XHTTP, по умолчанию `/xhttp`; спрашивается только для режима `xhttp`

4. После завершения скрипт выведет готовые параметры подключения и VLESS URL для импорта в клиент.

## Что делает скрипт

Скрипт автоматизирует установку и запуск Xray в режиме `VLESS + REALITY` через Docker.

В процессе он:

- проверяет, что запуск идет от `root`
- проверяет наличие Docker и Docker Compose Plugin, а при необходимости устанавливает их
- генерирует `UUID`, REALITY-ключи и `shortId`
- создает конфигурацию Xray в `/opt/xray`
- запускает контейнер `xray-reality`
- останавливает и удаляет старые контейнеры `nginx-web` и `certbot`, если они остались от предыдущей версии скрипта
- открывает порты в firewall: `22/tcp` и `XRAY_PORT/tcp`
- в конце показывает итоговые параметры клиента, VLESS URL и статус контейнеров

Скрипт больше не создает `/opt/nginx`, `/opt/www`, nginx-конфиги, certbot-конфиги и не пытается выпускать сертификаты Let's Encrypt.

## Что важно знать заранее

- Скрипт рассчитан на запуск на чистом или почти чистом сервере.
- Xray по умолчанию слушает `443/tcp`.
- Если `443/tcp` занят другим процессом, Xray не сможет стартовать; освободите порт или передайте другой `XRAY_PORT` явно.
- В режиме `xhttp` в клиенте нужно указать тот же `XHTTP_PATH`, который вы задали при установке, а `Flow` оставить пустым.
- В режиме `tcp` в клиенте нужно указать `Flow = xtls-rprx-vision`.
- Fingerprint по умолчанию выводится как `edge`.

## Какие данные спросит скрипт

### `REALITY_DOMAIN`

Домен, который будет использоваться в настройках REALITY как маскировка. По умолчанию используется `dl.google.com`.

### `XRAY_TRANSPORT`

Транспорт Xray. Возможные значения:

- `xhttp` - новый режим, по умолчанию
- `tcp` - старый режим с `xtls-rprx-vision`

### `XRAY_PORT`

Порт, на котором будет слушать Xray. По умолчанию `443`.

### `XHTTP_PATH`

Путь транспорта XHTTP. По умолчанию `/xhttp`. Если ввести путь без начального `/`, скрипт добавит его автоматически. Используется только при `XRAY_TRANSPORT=xhttp`.

## Что получится после установки

После успешного запуска будут созданы:

- `/opt/xray/docker-compose.yml`
- `/opt/xray/config.json`

Контейнер:

- `xray-reality`

## Проверка и логи

Проверить контейнеры:

```bash
docker ps
```

Посмотреть логи Xray:

```bash
docker logs -f xray-reality
```

## Пример запуска без вопросов

XHTTP режим:

```bash
sudo REALITY_DOMAIN=dl.google.com \
XRAY_TRANSPORT=xhttp \
XRAY_PORT=443 \
XHTTP_PATH=/xhttp \
bash install.sh
```

Старый TCP режим:

```bash
sudo REALITY_DOMAIN=dl.google.com \
XRAY_TRANSPORT=tcp \
XRAY_PORT=443 \
bash install.sh
```

Через GitHub напрямую, XHTTP режим:

```bash
curl -fsSL https://raw.githubusercontent.com/nickolsky/vless_docker_install_scripts/refs/heads/main/install.sh \
  | sudo REALITY_DOMAIN=dl.google.com XRAY_TRANSPORT=xhttp XRAY_PORT=443 XHTTP_PATH=/xhttp bash
```

Через GitHub напрямую, старый TCP режим:

```bash
curl -fsSL https://raw.githubusercontent.com/nickolsky/vless_docker_install_scripts/refs/heads/main/install.sh \
  | sudo REALITY_DOMAIN=dl.google.com XRAY_TRANSPORT=tcp XRAY_PORT=443 bash
```

## Клиентские параметры

Используйте параметры и VLESS URL, которые скрипт выведет в конце установки.

Общее:

- protocol: `vless`
- security: `reality`
- port: `443`, если вы не задавали другой `XRAY_PORT`
- encryption: `none`
- fingerprint: `edge`
- SNI: значение `REALITY_DOMAIN`
- public key: значение `PublicKey`
- short id: значение `ShortID`
- spiderX: `/`

Для `xhttp`:

- transport: `xhttp`
- flow: оставить пустым
- xhttp path: значение `XHTTP_PATH`
- xhttp mode: `auto`

Для `tcp`:

- transport: `tcp`
- flow: `xtls-rprx-vision`

## Ограничения

- Исходный `install.sh` явно ориентирован на Ubuntu и использует установку Docker через репозиторий Docker для Ubuntu.
- Внутри есть команды `apt-get`, `systemctl`, `ufw`, `firewall-cmd`, `iptables`, поэтому на других дистрибутивах поведение не гарантировано.
- В исходном `install.sh` блок `ensure_prereqs` сейчас фактически ничего не устанавливает, потому что команды установки зависимостей в нем закомментированы.
