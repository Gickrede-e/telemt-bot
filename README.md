# telemt-bot

Minimal **Telegram bot** that surfaces live status of a
[telemt](https://github.com/Gickrede-e/telemt_bb) MTProto-proxy instance:
DC connectivity, ME pool health, per-user traffic, handshake-failure
breakdowns, and any Prometheus metric on demand.

* Single file Python 3, **zero third-party dependencies** (stdlib only).
* Inline-keyboard main menu + slash-command autocomplete.
* Edit-in-place responses (no chat spam on refresh).
* Owner-whitelist by Telegram `chat_id` — non-owner messages are silently
  ignored.

## Screenshots / sample renders

```
🟢 telemt 3.4.16  ·  uptime 51m 53s
━━━━━━━━━━━━━━━━━━━━
Состояние
✅ ready: ready
✅ accept_new_connections
✅ me_runtime_ready
🔌 upstreams: 1/1  ·  route: middle
🧩 shards: 6 (per-source-IP isolation) — /shards
🌍 outbound: 6 source IPs · 1623 TG conns (см. /ips)

Трафик (с момента старта)
active conns              6 192  (1 users)
connections_total     1 436 734
bad_total                76 859
handshake_timeouts       38 089
accept_to                     0
```

```
🌐 Telegram DC Connectivity
━━━━━━━━━━━━━━━━━━━━

✅ DC -203  ·  rtt 28ms  ·  load 0.00
writers   3/3  (floor 1-3-10)
endpoints 1/1
coverage  100.0% ████████████
fresh     100.0% ████████████
```

## Commands

| Command | What it shows |
|---|---|
| `/menu` | Inline-keyboard main menu |
| `/status` | Version, uptime, ready state, active connections, **shard mode**, accept-permit-timeout |
| `/dc` | Compact per-DC table: id, RTT, writers, clients, health icon |
| `/dc <num>` | Detail view of one DC: floor, coverage, endpoints, top writers |
| `/dcall` | **Full** detail block for every DC in one response (no drill-down needed) |
| `/me` | Middle-proxy pool: writers, endpoints, hardswaps, quarantines (aggregated across shards) |
| `/shards` | Per-source-IP shard topology + balance check (telemt Phase 2 MePoolMux) |
| `/ips` | Outbound source-IP distribution from `/proc/net/tcp` |
| `/users` | All configured users with traffic + IP counts |
| `/user <name>` | Single-user detail + first 8 active IPs |
| `/online` | Total active connections + top-10 users |
| `/handshake` | Bad-handshake breakdown (by class, top 15) |
| `/metric <name>` | Raw value of any Prometheus metric series |
| `/refresh` | Re-fetch snapshot |
| `/help` | Help text |

### `/shards` — Phase 2 visibility

When telemt runs with `me_writer_bind_mode = "shard"` (per-source-IP
isolation, see telemt's `docs/PERFORMANCE_AND_ANTIDETECT.ru.md` §B+), the
bot surfaces the shard plan and a **balance check** computed from
`/proc/net/tcp`. Coefficient-of-variation across source IPs tells you at a
glance whether one shard is starving:

```
🧩 Шарды (MePoolMux)
━━━━━━━━━━━━━━━━━━━━
🧩 mode: shard · per-source-IP isolation
  configured: 6 bind addresses · live: 6 active source IPs

source IP          conns  balance
45.144.53.142        282  ████████████
45.144.53.77         280  ███████████░
45.144.53.124        271  ███████████░
45.144.53.100        264  ███████████░
45.144.53.143        264  ███████████░
45.144.53.36         262  ███████████░
TOTAL               1623

✓ баланс отличный (CV=2.71%)
```

The bot reads `/etc/telemt/telemt.toml` directly to know which mode is
configured — needs group-read access (default install.sh puts the bot
user in the `telemt` group).

## Requirements

* Python 3.10+ (uses `urllib`, `json`, `re`, `logging` only).
* A running `telemt` exposing the admin API (`127.0.0.1:9091`) and
  Prometheus metrics (`127.0.0.1:9090/metrics`). Both are enabled by
  default in upstream `telemt`'s `config.toml`.
* A Telegram bot token from [@BotFather](https://t.me/BotFather).
* Your Telegram `chat_id` (message [@userinfobot](https://t.me/userinfobot)
  to obtain it).

## Quick install (systemd)

```sh
# 1. Get the bot
sudo install -d -m 0750 /opt/telemt-bot
sudo curl -fsSL https://raw.githubusercontent.com/Gickrede-e/telemt-bot/main/bot.py \
    -o /opt/telemt-bot/bot.py
sudo chmod 0755 /opt/telemt-bot/bot.py

# 2. Dedicated user (least privilege)
sudo useradd -r -s /usr/sbin/nologin -d /opt/telemt-bot -c "Telemt Bot" telemt-bot
sudo chown -R telemt-bot:telemt-bot /opt/telemt-bot

# 3. Config (token + your chat_id)
sudo install -d -m 0750 -o root -g telemt-bot /etc/telemt-bot
sudo curl -fsSL https://raw.githubusercontent.com/Gickrede-e/telemt-bot/main/etc/telemt-bot/env.example \
    -o /etc/telemt-bot/env
sudo $EDITOR /etc/telemt-bot/env   # fill in TELEMT_BOT_TOKEN and TELEMT_BOT_OWNERS
sudo chmod 0640 /etc/telemt-bot/env
sudo chown root:telemt-bot /etc/telemt-bot/env

# 4. systemd unit
sudo curl -fsSL https://raw.githubusercontent.com/Gickrede-e/telemt-bot/main/systemd/telemt-bot.service \
    -o /etc/systemd/system/telemt-bot.service
sudo systemctl daemon-reload
sudo systemctl enable --now telemt-bot

# 5. Verify
systemctl status telemt-bot
journalctl -u telemt-bot -f
```

## Configuration

All settings come from environment variables (read by the systemd
`EnvironmentFile=/etc/telemt-bot/env`):

| Variable | Required | Default | Notes |
|---|---|---|---|
| `TELEMT_BOT_TOKEN` | yes | — | Token from @BotFather |
| `TELEMT_BOT_OWNERS` | yes | — | Comma-separated Telegram `chat_id`s (whitelist) |
| `TELEMT_API_BASE` | no | `http://127.0.0.1:9091` | telemt admin API base URL |
| `TELEMT_METRICS_URL` | no | `http://127.0.0.1:9090/metrics` | telemt Prometheus endpoint |
| `TELEMT_API_AUTH` | no | empty | `Authorization` header value if telemt's `[server.api].auth_header` is set |

### Multiple owners

```env
TELEMT_BOT_OWNERS=5136562786,77777777,123456789
```

Every owner sees the same admin-level data. Non-owners are silently
ignored — no acknowledgement, no error message, no log spam beyond a
single `INFO ignoring chat_id=...` line.

## Security model

* **Local-only data plane**: the bot only ever talks to `127.0.0.1`
  (telemt's admin API + `/metrics`) and `api.telegram.org`. It does not
  expose any HTTP listener of its own.
* **Owner whitelist** is enforced for both message commands and inline
  callback queries. Non-owner callback presses get an
  `🚫 not authorized` toast.
* **Hardening** (systemd unit): runs as a dedicated `telemt-bot` user
  with `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`,
  `PrivateTmp`, `ProtectKernelTunables`, `ProtectControlGroups`.
* **No write access** to telemt: the bot only calls `GET` endpoints.
  All `POST/PATCH/DELETE` endpoints on telemt's admin API are
  unreachable from this code path.

## Update workflow

```sh
sudo curl -fsSL https://raw.githubusercontent.com/Gickrede-e/telemt-bot/main/bot.py \
    -o /opt/telemt-bot/bot.py
sudo systemctl restart telemt-bot
```

The bot will re-register the `/` slash-command list on every startup, so
new commands appear in the Telegram client immediately.

## Development

```sh
git clone https://github.com/Gickrede-e/telemt-bot
cd telemt-bot
export TELEMT_BOT_TOKEN=...
export TELEMT_BOT_OWNERS=...
# Point at a remote telemt over an SSH tunnel if you don't have one local:
ssh -L 9091:127.0.0.1:9091 -L 9090:127.0.0.1:9090 root@your-telemt-host
export TELEMT_API_BASE=http://127.0.0.1:9091
export TELEMT_METRICS_URL=http://127.0.0.1:9090/metrics
python3 bot.py
```

## License

MIT — see [LICENSE](LICENSE).
