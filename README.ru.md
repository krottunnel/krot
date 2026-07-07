<p align="center">
  <img src="assets/wordmark.svg" alt="krot — tunnels that dig" width="420"/>
</p>

<p align="center">
  <a href="https://github.com/krottunnel/krot/actions/workflows/ci.yml"><img src="https://github.com/krottunnel/krot/actions/workflows/ci.yml/badge.svg" alt="CI"/></a>
  <a href="https://github.com/krottunnel/krot/releases/latest"><img src="https://img.shields.io/github/v/release/krottunnel/krot?color=e89a9a&label=release" alt="Latest release"/></a>
  <a href="./LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg" alt="License"/></a>
  <img src="https://img.shields.io/badge/rust-stable-orange.svg" alt="Rust stable"/>
</p>

<p align="center">
  <a href="./README.md">English</a> · <b>Русский</b>
</p>

# krot

**Self-hosted ngrok на Rust. Zero-knowledge, thread-per-core, беспарольный.**

`krot` — open-source туннельный сервис: свой VPS, один Docker-контейнер,
никакой подписки и никакого доверия к чужому relay. HTTPS-трафик проходит через
сервер зашифрованным до конца туннеля, ключи авторизации — SSH-стиль
(`authorized_keys`), сертификат для apex-домена сервер получает и продлевает
сам через ACME.

Написан на стабильном Rust с `tokio`, `quinn` (QUIC) и `rustls`. Один
бинарь ~7 MB (release + LTO + strip), Docker-образ ~85 MB на debian-slim.

<details>
<summary><b>Оглавление</b></summary>

- [Что внутри](#что-внутри)
- [Установка](#установка)
- [Быстрый старт](#быстрый-старт)
- [CLI reference](#cli-reference)
- [Admin API](#admin-api)
- [Архитектура](#архитектура)
- [Federated relays](#federated-relays)
- [Безопасность](#безопасность)
- [Известные ограничения](#известные-ограничения)
- [Разработка](#разработка)
- [Контрибьютинг](#контрибьютинг)
- [Сообщения об уязвимостях](#сообщения-об-уязвимостях)
- [Лицензия](#лицензия)

</details>

---

## Что внутри

| | |
|---|---|
| **QUIC + TCP fallback** | Основной транспорт — QUIC на UDP. Клиенты за корпоративным NAT'ом с заблокированным UDP автоматически переключаются на TLS 1.3 over TCP с mini-mux'ом. Тот же порт, различаются по ALPN. |
| **Zero-knowledge apex TLS** | Сервер терминирует TLS **только** на apex (`krot.example`). Подключения на `alice.krot.example` идут SNI-passthrough — сервер видит только зашифрованный поток. Приватные ключи поддоменов у него никогда не появляются. |
| **Thread-per-core** | Каждое ядро получает изолированный `tokio` current-thread рантайм и собственный QUIC endpoint через `SO_REUSEPORT`. Rate-limit'ы разбиваются по-корово — каждый worker имеет свой bandwidth bucket, total cap соблюдается. |
| **Беспарольный Ed25519 bootstrap** | Клиент генерит Ed25519 ключ, стучится с одноразовым admin-токеном (32 байта энтропии, BLAKE3-хеш на диске, TTL 10 минут). Сервер добавляет публичный ключ в `authorized_keys`. |
| **ACME auto-renewal** | Встроенный HTTP-01 responder на порту 80. Сертификат Let's Encrypt для apex, обновление за 30 дней до истечения. Кэш в `data_dir/acme/` mode `0700`. |
| **Session resume** | Клиент упал → при переконнекте цепляется обратно к тому же `public_url` в течение 30-секундного grace period. Работает **между транспортами** — можно уронить QUIC-сессию и восстановить её через TCP fallback. |
| **Rate limiting** | Per-identity token-bucket через `governor` + period quota. Полностью распределяется по-корово, aggregate cap соблюдается. При исчерпании квоты сервер сообщает клиенту `retry_after_ms`. |
| **Passive HTTP inspector** | `--inspect` включает локальную веб-админку на `localhost:4040` — метод, путь, статус, длительность каждого запроса. |
| **Login-page auth** | `krot http --auth user:pass` показывает стилизованную страницу входа с бренд-марком крота; успешный логин ставит session cookie (`HttpOnly; SameSite=Lax`, 8h rolling TTL). Для машин — `--api-key SECRET` (`X-API-Key` / `Authorization: Bearer`). Файл/env-варианты для не-dev использования. Constant-time compare, не логирует секреты. |
| **Admin API** | `/admin/v1/{tunnels,keys,metrics}` HTTP endpoint на `127.0.0.1:9700`. Bearer-token auth, Prometheus metrics, revoke ключа за 1 секунду. |
| **Federated relays** | Мульти-relay setup: `federation=peer1,peer2` в `authorized_keys`. Клиент публикует один туннель на нескольких релеях, DNS/CDN разруливает failover. |
| **Hot-reload авторизации** | Ключ удалён из `authorized_keys` → активная сессия за <1 секунду получает уведомление о revoke через `notify` watcher. Тот же механизм для peer-list'а. |
| **Graceful shutdown** | `Ctrl+C` → корректный ServerBye во все открытые сессии, дожидается ACK, потом закрывает endpoint. Дедлайн 5 секунд. |

---

## Установка

Четыре способа получить бинари `krot-server` и `krot-client`.

### Готовые бинари (рекомендуется)

Скачай со страницы [последнего релиза](https://github.com/krottunnel/krot/releases/latest):

| Платформа | Архив |
|---|---|
| Linux · x86_64 | `krot-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz` |
| Linux · ARM64 | `krot-vX.Y.Z-aarch64-unknown-linux-musl.tar.gz` |
| macOS · Apple Silicon | `krot-vX.Y.Z-aarch64-apple-darwin.tar.gz` |
| Windows · 64-bit | `krot-vX.Y.Z-x86_64-pc-windows-msvc.zip` |
| Windows · 32-bit | `krot-vX.Y.Z-i686-pc-windows-msvc.zip` |

В каждом архиве `krot-server`, `krot` (клиент), `LICENSE-*`, `README.md`. Проверь `.sha256`, распакуй, положи бинари в `PATH`. Intel Mac: запусти `aarch64-apple-darwin` через Rosetta 2 либо ставь через `cargo install --git` (ниже).

### Через cargo

Нужен стабильный Rust toolchain (ставится через [rustup.rs](https://rustup.rs)):

```bash
cargo install --git https://github.com/krottunnel/krot krot-server krot-client
```

Бинари попадают в `~/.cargo/bin/` (unix) или `%USERPROFILE%\.cargo\bin\` (Windows).

### Через Docker (только сервер)

```bash
docker pull krottunnel/krot-server:latest
```

Multi-arch образ (`linux/amd64`, `linux/arm64`).

### Из исходников

```bash
git clone https://github.com/krottunnel/krot
cd krot
cargo build --release --workspace
# → target/release/krot-server, target/release/krot-client
```

---

## Быстрый старт

Prerequisites: VPS с публичным IP, свой домен, wildcard DNS `*.krot.example → <VPS IP>`, порты 80/443/7853 открыты.

### 1. Server

```bash
# готовый образ с Docker Hub — рекомендуется:
docker pull krottunnel/krot-server:latest
# либо собрать локально:
# docker build -t krottunnel/krot-server:dev .

docker run -d --name krot \
  -p 7853:7853/udp \
  -p 7853:7853/tcp \
  -p 80:80/tcp \
  -p 443:443/tcp \
  -v krot-data:/var/lib/krot \
  -v krot-config:/etc/krot \
  krottunnel/krot-server:latest \
  --domain krot.example \
  --acme-contact mailto:admin@krot.example \
  --acme-production \
  --tcp-fallback-bind 0.0.0.0:7853

# сервер печатает одноразовый admin-token:
docker logs krot | grep KROT_ADMIN_TOKEN
# KROT_ADMIN_TOKEN=R54VHZ9FD0JJ44GPDZFEJZ7DV8WFB77JHYHVPFF64BF677X7WX70
```

> **Root/privileges.** Дефолты `--http-bind 0.0.0.0:80` и `--https-bind 0.0.0.0:443` — привилегированные порты. Docker-контейнер выше запускается через `-p 80:80/tcp`, где Docker сам мапит. При запуске **без Docker** нужен либо `sudo`, либо `setcap 'cap_net_bind_service=+ep' target/release/krot-server`. Для локальной разработки перезадать на непривилегированные: `--http-bind 127.0.0.1:8080 --https-bind 127.0.0.1:8443`.

### 2. Client

```bash
krot init --server krot.example --admin-token R54VHZ9FD0JJ44...
# → enrolled at krot.example:7853
```

### 3. Публикуем локальный сервис

```bash
krot http 3000 --name alice --inspect
# → https://alice.krot.example
# → inspector: http://127.0.0.1:4040
```

Готово. Внешние запросы на `https://alice.krot.example` летят TLS-зашифрованными сквозь сервер до вашего клиента.

---

## CLI reference

### `krot-server`

| Флаг | Default | Что делает |
|---|---|---|
| `--domain <apex>` | — | Включает DomainMode. Без него — IpMode (только TCP-туннели, self-signed cert с pinned fingerprint). |
| `--acme-contact mailto:...` | — | Получить apex-сертификат через ACME (Let's Encrypt **staging** по умолчанию). |
| `--acme-production` | off | Переключить на LE production. |
| `--tls-cert / --tls-key` | — | Альтернатива ACME — принести свой PEM-сертификат. |
| `--bind` | `0.0.0.0:7853` | UDP-адрес QUIC endpoint'а. |
| `--tcp-fallback-bind <addr>` | disabled | TCP+TLS listener для клиентов с заблокированным UDP. |
| `--http-bind` / `--https-bind` | `0.0.0.0:80` / `:443` | Адреса для роутеров 80/443. |
| `--tcp-port-pool <lo-hi>` | `10000-19999` | Пул портов для TCP-туннелей. |
| `--cores N` | `available_parallelism()` | Число worker-потоков. `bw=` cap разбивается по-корово. |
| `--data-dir` | `/var/lib/krot` | Persistent state (identity cert, ACME cache, admin_token hash). |
| `--authorized-keys` | `/etc/krot/authorized_keys` | SSH-стилевой файл авторизованных ключей. Hot-reload. |
| `--peer-list` | `/etc/krot/peers.txt` | Статический список федеративных релеев (один apex/строка). Hot-reload. |
| `--admin-bind` | `127.0.0.1:9700` | Structured admin API. Пустое значение отключает. |
| `--issue-admin-token` | off | Выпустить новый admin-token, даже если `authorized_keys` не пуст. |

### `krot` (клиент)

| Подкоманда | Что делает |
|---|---|
| `krot init --server HOST --admin-token TOKEN [--fingerprint sha256:HEX]` | Сгенерировать identity, enroll'нуть публичный ключ. IpMode — с pinned fingerprint; DomainMode — с настоящим CA. |
| `krot tcp <port>` | Публиковать TCP-сервис (`ssh`, БД, minecraft, что угодно) как `tcp://<host>:<port>`. |
| `krot http <port> [flags]` | Публиковать HTTP-сервис как `https://<label>.<apex>`. См. auth flags ниже. |

**Client auth flags** (только для `krot http`, работает на plain-HTTP ветке; HTTPS-passthrough остаётся opaque):

| Флаг | Описание |
|---|---|
| `--auth <user:pass>` | Стилизованная login-страница + session cookie (`HttpOnly; SameSite=Lax`, 8h rolling TTL). Спец-пути `/__krot/login` и `/__krot/logout` перехватываются клиентом. Dev only — креденшелы светятся в `ps`. |
| `--auth-env <VAR>` | То же, но `user:pass` из env-переменной. |
| `--auth-file <path>` | То же, но `user:pass` из файла (single line, trims trailing newlines). |
| `--api-key <SECRET>` / `--api-key-env` / `--api-key-file` | Header-based auth для машин: `X-API-Key: <key>` или `Authorization: Bearer <key>`. 403 при mismatch. |
| `--auth-realm <string>` | Внутренняя строка, показывается только в диагностике API-key ветки. Default `"KROT Protected Tunnel"`. |
| `--name <label>` | Requested subdomain label (default случайный). |
| `--inspect` / `--inspect-bind <addr>` | Локальная веб-админка с историей запросов. |

### Автоматический fallback

Клиент пытается QUIC, при transport-level failure — retry TCP fallback. Прозрачно для пользователя.

---

## Admin API

Structured HTTP endpoint на `127.0.0.1:9700` для оператора. Bearer-token auth.

```bash
# Обменять enrollment admin_token на session_token (single-use):
curl -s http://127.0.0.1:9700/admin/v1/session \
  -H 'Content-Type: application/json' \
  -d '{"admin_token":"R54VHZ9FD0JJ44..."}'
# → {"session_token":"XXXX","expires_at_unix":1735000000}

TOKEN=XXXX

# Список туннелей
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9700/admin/v1/tunnels
# → [{"tunnel_id":1,"kind":"http","label":"alice","state":"live","inspect":false,...}]

# Список авторизованных ключей
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9700/admin/v1/keys

# Добавить ключ (append to authorized_keys)
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"line":"ed25519 AAAA... subdomain=bob conns=3"}' \
  http://127.0.0.1:9700/admin/v1/keys

# Ревокация: за <1s hot-reload убьёт активные сессии этого ключа
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:9700/admin/v1/keys/AAAA...=

# Prometheus метрики (~30 counter'ов + gauge'ов)
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9700/admin/v1/metrics
# → krot_uptime_seconds 42
# → krot_build_info{version="0.1.0"} 1
# → krot_tunnels_total 3
# → krot_handshake_auth_ok_total 12
# → krot_session_bye_total 8
# → krot_resume_reattached_total 3
# → krot_rate_limit_quota_exceeded_total 4
# → krot_transport_quic_accepted_total 20
# → krot_transport_tcp_fallback_accepted_total 5
# → krot_bytes_period_used{pubkey="AAAA..."} 1234567
```

**JSON logging** (для log-aggregation'а — Loki, Elastic, etc.):

```bash
KROT_LOG_FORMAT=json RUST_LOG=info krot-server ...
# → {"timestamp":"...","level":"INFO","fields":{"message":"..."},...}
```

Publicly-exposed admin API MUST быть за TLS reverse-proxy'ем (nginx / caddy). Loopback default безопасен.

---

## Архитектура

<p align="center">
  <img src="assets/architecture.svg" alt="krot architecture" width="900"/>
</p>

Workspace-крейты:

| Крейт | Роль |
|---|---|
| `krot-proto` | Wire-типы, framing, Ed25519 challenge-response, инспектор prelude. |
| `krot-transport` | Connection/stream wrapper'ы с двумя backend'ами: QUIC и mux-over-TCP. ALPN + keep-alive. |
| `krot-server` | Relay: registry, auth-handshake, ACME, SNI/Host routers, thread-per-core, admin API, peer registry, rate limiting. |
| `krot-client` | CLI + enroll flow + inspector + auto-fallback + login-page/API-key auth. |

---

## Federated relays

Один identity → несколько релеев одновременно. Live URL'ы работают со всех.

**Шаг 1** — на каждом релее прописать peer-list:

```bash
# на relay-1 (krot.us.example):
cat > /etc/krot/peers.txt <<EOF
krot.eu.example
krot.asia.example
EOF
# hot-reload сразу подхватит
```

**Шаг 2** — `authorized_keys` с `federation=`:

```
ed25519 AAAA... subdomain=alice federation=krot.eu.example,krot.asia.example
```

**Шаг 3** — клиент опрашивает список peer'ов и публикует на разрешённых:

```bash
krot http 3000 --name alice --federate
# → https://alice.krot.us.example
# → https://alice.krot.eu.example
# → https://alice.krot.asia.example
```

**Cross-relay collision detection.** При регистрации `label` сервер консультируется с соседними релеями:

- Если peer имеет `label` от **того же** identity → additional destination (allow, log).
- Если от **другого** identity → отказ `LABEL_UNAVAILABLE`.
- Peer unreachable → fail-open.

---

## Безопасность

| Угроза | Митигация |
|---|---|
| MITM клиент↔сервер | IpMode: SPKI SHA-256 pin через `--fingerprint sha256:...`. DomainMode: публичный CA. |
| Утечка приватного ключа поддомена | Сервер их **не хранит**. Клиент терминирует TLS сам или форвардит зашифрованный поток. |
| Кража identity | Identity в `~/.krot/identity` mode `0600`. Ротация = сгенерировать новый, `authorized_keys` удалить старую строку. Hot-reload убьёт активные сессии за <1s. |
| Replay challenge signature | Domain separator префиксом ко всем Ed25519-подписям. |
| Bruteforce admin-token | 32 байта энтропии + BLAKE3 constant-time compare + single-use + TTL 10 мин. |
| Bruteforce login-страницы туннеля | Rate-limit брут — на плечах operator'а через reverse-proxy. Wrong/missing креды возвращают одинаковую страницу с общим сообщением. Session cookie 32 байта энтропии из OsRng, in-memory store. |
| DoS через spoofed UDP | QUIC session tickets + per-identity bandwidth limits. Unknown identity не занимает места в rate table. |
| Frame parser panic | Bounded allocations (64 KiB frames, 8 KiB HTTP, 256 KiB mux). Property tests + fuzz targets. |
| Cross-relay label spoofing | Collision detection консультируется с peer'ами до allocate. Same-identity → additional destination, different → reject. |

---

## Известные ограничения

- **Continuous soak testing.** Есть `scripts/soak/` для ручного прогона на двух VDS; регулярный автоматический soak в CI пока не гоняется.
- **DomainMode multi-level subdomains** (`a.b.krot.example`) не проходят валидацию — только один уровень.
- **IPv6-only VPS** должен работать, но не тестировался в CI.

---

## Разработка

```bash
# Все крейты, все тесты.
cargo test --workspace

# Проверка стиля / lint'ов (соответствует CI).
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

# Deep proptest sweep (по умолчанию 256 cases, вручную можно больше):
PROPTEST_CASES=10000 cargo test --workspace

# Локальный сервер + клиент в двух терминалах:
cargo run -p krot-server -- \
    --data-dir /tmp/krot-server --authorized-keys /tmp/krot-server/authorized_keys \
    --peer-list /tmp/krot-server/peers.txt \
    --bind 127.0.0.1:7853 --tcp-port-pool 10000-10999 --cores 1 \
    --admin-bind 127.0.0.1:9700

# (из stdout скопировать KROT_ADMIN_TOKEN и KROT_SERVER_FINGERPRINT)

cargo run -p krot-client -- \
    --data-dir /tmp/krot-client init \
    --server 127.0.0.1:7853 --admin-token XXX --fingerprint sha256:YYY

cargo run -p krot-client -- --data-dir /tmp/krot-client tcp 3000
```

Changelog: [`CHANGELOG.md`](./CHANGELOG.md).

CI: [.github/workflows/ci.yml](./.github/workflows/ci.yml) — fmt/clippy/test на Linux+macOS, MSRV pin, `cargo audit`, 60s fuzz smoke per target.

---

## Контрибьютинг

Баг-репорты, feature-requests, патчи — welcome.

Перед пуллреквестом:

1. Прогнать `just ci` (fmt + clippy + тесты). Должно быть зелёное.
2. Для user-visible изменений — добавить строку в `CHANGELOG.md` под новую версию.
3. Один коммит — одно логическое изменение.

Впервые в Rust или в этом коде? Раздел `Разработка` выше показывает как поднять локальную пару server+client — самый быстрый способ вьехать в проект.

---

## Сообщения об уязвимостях

**Не открывай** публичный issue для security-уязвимостей.

Используй встроенную в GitHub [форму приватного security advisory](https://github.com/krottunnel/krot/security/advisories/new). Первый ответ — в течение 72 часов.

Coordinated disclosure: 90 дней от первого репорта, при обоюдном согласии срок может быть продлён.

---

## Лицензия

Лицензировано под одной из:

- **MIT** ([LICENSE-MIT](./LICENSE-MIT))
- **Apache License, Version 2.0** ([LICENSE-APACHE](./LICENSE-APACHE))

на твой выбор.

SPDX-License-Identifier: `MIT OR Apache-2.0`

Если явно не указано иное, любой контрибьюшн, отправленный в этот проект (в терминах Apache-2.0), будет автоматически лицензирован под обеими лицензиями без каких-либо дополнительных условий.
