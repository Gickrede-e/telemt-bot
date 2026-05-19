#!/usr/bin/env python3
"""telemt-bot — Telegram-бот статистики telemt.

Источники данных: admin API (127.0.0.1:9091) + Prometheus metrics (127.0.0.1:9090).
Зависимости: только stdlib (urllib + json).

Required env:
    TELEMT_BOT_TOKEN   — токен от @BotFather
    TELEMT_BOT_OWNERS  — comma-separated chat_id из @userinfobot (whitelist)

Optional env:
    TELEMT_API_BASE     — default http://127.0.0.1:9091
    TELEMT_METRICS_URL  — default http://127.0.0.1:9090/metrics
    TELEMT_API_AUTH     — Authorization header value
"""

import html
import json
import logging
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

# ─── config ─────────────────────────────────────────────────────────────

BOT_TOKEN = os.environ.get("TELEMT_BOT_TOKEN", "").strip()
_OWNERS_RAW = os.environ.get("TELEMT_BOT_OWNERS", "").strip()
OWNERS = {int(x) for x in _OWNERS_RAW.split(",") if x.strip().lstrip("-").isdigit()}
API_BASE = os.environ.get("TELEMT_API_BASE", "http://127.0.0.1:9091").rstrip("/")
METRICS_URL = os.environ.get("TELEMT_METRICS_URL", "http://127.0.0.1:9090/metrics")
API_AUTH = os.environ.get("TELEMT_API_AUTH", "").strip()

TG_API = "https://api.telegram.org/bot{token}/{method}"
POLL_TIMEOUT = 30
HTTP_TIMEOUT = 5
TG_HTTP_TIMEOUT = POLL_TIMEOUT + 5

# Russian thin-space-style separators kept low-key so they render in any client.
HR = "━━━━━━━━━━━━━━━━━━━━"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("telemt-bot")


# ─── HTTP helpers ───────────────────────────────────────────────────────

def _http_get(url: str, timeout: int = HTTP_TIMEOUT, headers: Optional[Dict[str, str]] = None) -> bytes:
    hdrs = {"Accept": "application/json", "User-Agent": "telemt-bot/1"}
    if headers:
        hdrs.update(headers)
    if API_AUTH and url.startswith(API_BASE):
        hdrs["Authorization"] = API_AUTH
    req = urllib.request.Request(url, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def api(path: str) -> Any:
    raw = _http_get(f"{API_BASE}{path}")
    payload = json.loads(raw)
    if not payload.get("ok", False):
        err = payload.get("error", {})
        raise RuntimeError(f"api {path}: {err.get('code')}: {err.get('message')}")
    return payload.get("data")


def metrics_text() -> str:
    return _http_get(METRICS_URL).decode("utf-8", "replace")


_METRIC_LINE = re.compile(
    r"^(?P<name>\w+)(?:\{(?P<labels>[^}]*)\})?\s+(?P<value>[-+0-9eE.NaInf]+)\s*$"
)


def parse_metric(text: str, name: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        m = _METRIC_LINE.match(line)
        if not m or m.group("name") != name:
            continue
        labels: Dict[str, str] = {}
        if m.group("labels"):
            for pair in re.findall(r'(\w+)="([^"]*)"', m.group("labels")):
                labels[pair[0]] = pair[1]
        try:
            out.append({"labels": labels, "value": float(m.group("value"))})
        except ValueError:
            pass
    return out


def metric_one(text: str, name: str, labels: Optional[Dict[str, str]] = None) -> Optional[float]:
    for s in parse_metric(text, name):
        if not labels or all(s["labels"].get(k) == v for k, v in labels.items()):
            return s["value"]
    return None


# ─── /proc/net/tcp parsing (for outbound source-IP visibility) ──────────

# Telegram MTProto endpoint IP ranges (from core.telegram.org/resources/cidr.txt
# — the same list the per-IP shaper uses). Matching by prefix is good enough
# for counting outbound connections; we don't need RFC-perfect CIDR math.
TG_IP_PREFIXES = (
    "91.105.192.", "91.105.193.",
    "91.108.4.", "91.108.5.", "91.108.6.", "91.108.7.",
    "91.108.8.", "91.108.9.", "91.108.10.", "91.108.11.",
    "91.108.12.", "91.108.13.", "91.108.14.", "91.108.15.",
    "91.108.16.", "91.108.17.", "91.108.18.", "91.108.19.",
    "91.108.20.", "91.108.21.", "91.108.22.", "91.108.23.",
    "91.108.56.", "91.108.57.", "91.108.58.", "91.108.59.",
    "149.154.160.", "149.154.161.", "149.154.162.", "149.154.163.",
    "149.154.164.", "149.154.165.", "149.154.166.", "149.154.167.",
    "149.154.168.", "149.154.169.", "149.154.170.", "149.154.171.",
    "149.154.172.", "149.154.173.", "149.154.174.", "149.154.175.",
    "185.76.151.",
)


def _decode_hex_ipv4(hex_addr: str) -> Optional[str]:
    """/proc/net/tcp stores ipv4 as 8 hex chars in little-endian.
    e.g. '6435902D' (LE) -> 45.144.53.100."""
    if len(hex_addr) != 8:
        return None
    try:
        b = bytes.fromhex(hex_addr)
    except ValueError:
        return None
    return f"{b[3]}.{b[2]}.{b[1]}.{b[0]}"


def outbound_to_tg_by_source_ip() -> Dict[str, int]:
    """Read /proc/net/tcp and count ESTABLISHED outbound connections to
    Telegram MP/DC endpoints, grouped by our local source IP.

    Returns a dict {source_ip: connection_count}. Empty dict on read failure.
    /proc/net/tcp is world-readable in every namespace the bot can see, so
    this does not require CAP_NET_ADMIN. State 01 = ESTABLISHED.
    """
    counts: Dict[str, int] = {}
    try:
        with open("/proc/net/tcp", "r") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return counts
    # First line is the header.
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[1]
        remote = parts[2]
        state = parts[3]
        if state != "01":  # ESTABLISHED
            continue
        try:
            r_ip_hex, r_port_hex = remote.split(":")
            l_ip_hex, _ = local.split(":")
        except ValueError:
            continue
        r_ip = _decode_hex_ipv4(r_ip_hex)
        if not r_ip:
            continue
        if not any(r_ip.startswith(p) for p in TG_IP_PREFIXES):
            continue
        l_ip = _decode_hex_ipv4(l_ip_hex)
        if not l_ip:
            continue
        counts[l_ip] = counts.get(l_ip, 0) + 1
    return counts


# ─── shard topology helpers (Phase 2 MePoolMux) ─────────────────────────

# `/etc/telemt/telemt.toml` is group-readable (rw-r----- root:telemt). The
# bot runs as user `telemt-bot` who is in the `telemt` group via install.sh
# from PR #4, so this read normally succeeds. If it fails (permissions
# changed, file moved), the bot falls back to inferring shard mode purely
# from /proc/net/tcp source-IP topology so the UI still shows something
# useful instead of empty.
TELEMT_CONFIG_PATH = os.environ.get("TELEMT_CONFIG_PATH", "/etc/telemt/telemt.toml")


def read_shard_config() -> Dict[str, Any]:
    """Parse a few specific keys out of telemt.toml to expose shard config to
    the UI. Deliberately not a real TOML parser — we only care about three
    lines and the bot is stdlib-only.

    Returns {mode, multiplier, bind_count, error?}. mode is "shard" |
    "round_robin" | "unknown".
    """
    out: Dict[str, Any] = {"mode": "unknown", "multiplier": 1, "bind_count": 0}
    try:
        with open(TELEMT_CONFIG_PATH, "r") as fh:
            text = fh.read()
    except OSError as e:
        out["error"] = f"read {TELEMT_CONFIG_PATH}: {e.strerror}"
        return out
    m = re.search(r'^\s*me_writer_bind_mode\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if m:
        out["mode"] = m.group(1)
    else:
        # Field defaults to round_robin when absent in config — telemt's
        # MeWriterBindMode::default(). Reflect that here so the UI doesn't
        # report a false "unknown" for legacy single-pool deployments.
        out["mode"] = "round_robin"
    m = re.search(r'^\s*me_writer_bind_multiplier\s*=\s*(\d+)', text, re.MULTILINE)
    if m:
        out["multiplier"] = int(m.group(1))
    # bind_addresses lives on [[upstreams]] entries. We count entries on
    # any line of the form `bind_addresses = ["1.2.3.4", "5.6.7.8"]` — the
    # first such entry is the relevant one for shard count under the
    # current single-direct-upstream production config.
    m = re.search(r'^\s*bind_addresses\s*=\s*\[([^\]]*)\]', text, re.MULTILINE)
    if m:
        # Count quoted IPs inside the array; tolerates whitespace + trailing comma.
        out["bind_count"] = len(re.findall(r'"[^"]+"', m.group(1)))
    return out


def shard_topology() -> Dict[str, Any]:
    """Combine config-declared shard plan with the live /proc/net/tcp view.

    The interesting question for an operator after the Phase 2 deploy is
    "are my shards actually balanced?" — answered by comparing the
    per-source-IP outbound counts. Variance high → one shard is failing
    or a TG endpoint is rejecting one of our source IPs.
    """
    cfg = read_shard_config()
    counts = outbound_to_tg_by_source_ip()
    distinct_ips = len(counts)
    total = sum(counts.values())

    # Coefficient of variation as a balance metric: stdev/mean. Lower is
    # better; > 0.25 typically means one shard is materially underperforming.
    cv: Optional[float] = None
    if distinct_ips >= 2 and total > 0:
        mean = total / distinct_ips
        variance = sum((c - mean) ** 2 for c in counts.values()) / distinct_ips
        stdev = variance ** 0.5
        cv = stdev / mean if mean > 0 else None

    # Effective shard count: in shard mode, this is the configured bind
    # address count; in round_robin, it's effectively 1 (single pool).
    # We surface the LIVE observed value (distinct source IPs in use) and
    # the CONFIGURED value (bind_count) so a mismatch is obvious.
    return {
        "config_mode": cfg.get("mode", "unknown"),
        "config_bind_count": cfg.get("bind_count", 0),
        "config_multiplier": cfg.get("multiplier", 1),
        "config_error": cfg.get("error"),
        "live_source_ip_count": distinct_ips,
        "live_total_conns": total,
        "live_per_ip": counts,
        "balance_cv": cv,
    }


# ─── Telegram helpers ───────────────────────────────────────────────────

def tg(method: str, **kwargs: Any) -> Dict[str, Any]:
    url = TG_API.format(token=BOT_TOKEN, method=method)
    data: Dict[str, str] = {}
    for k, v in kwargs.items():
        if v is None:
            continue
        data[k] = json.dumps(v) if isinstance(v, (dict, list)) else str(v)
    encoded = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=encoded, method="POST")
    with urllib.request.urlopen(req, timeout=TG_HTTP_TIMEOUT) as r:
        return json.loads(r.read())


def esc(s: Any) -> str:
    return html.escape(str(s), quote=False)


# ─── inline-keyboard menus ──────────────────────────────────────────────

def main_menu() -> Dict[str, Any]:
    """The primary 2-column menu shown by /start and /menu."""
    return {
        "inline_keyboard": [
            [
                {"text": "📊 Статус", "callback_data": "status"},
                {"text": "🟢 Online", "callback_data": "online"},
            ],
            [
                {"text": "🌐 DC", "callback_data": "dc"},
                {"text": "🌐📋 All DCs", "callback_data": "dcall"},
            ],
            [
                {"text": "🔌 ME pool", "callback_data": "me"},
            ],
            [
                {"text": "🧩 Шарды", "callback_data": "shards"},
                {"text": "🌍 Outbound IPs", "callback_data": "ips"},
            ],
            [
                {"text": "👥 Пользователи", "callback_data": "users"},
                {"text": "🔐 Handshake", "callback_data": "handshake"},
            ],
            [
                {"text": "ℹ️ Помощь", "callback_data": "help"},
            ],
        ]
    }


def back_menu() -> Dict[str, Any]:
    """A single 🔙 button appended to every command-response so the user can
    return to the main menu without typing."""
    return {
        "inline_keyboard": [
            [
                {"text": "🔙 В меню", "callback_data": "menu"},
                {"text": "🔄 Перезапросить", "callback_data": "REFRESH"},
            ]
        ]
    }


def send(chat_id: int, text: str, reply_markup: Optional[Dict[str, Any]] = None) -> None:
    chunks = chunk_text(text, 3800)
    for i, chunk in enumerate(chunks):
        try:
            tg(
                "sendMessage",
                chat_id=chat_id,
                text=chunk,
                parse_mode="HTML",
                disable_web_page_preview=True,
                reply_markup=reply_markup if i == len(chunks) - 1 else None,
            )
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            log.warning("sendMessage HTTPError %s: %s", e.code, body[:300])


def edit(chat_id: int, message_id: int, text: str, reply_markup: Optional[Dict[str, Any]] = None) -> bool:
    """Try to edit a previous message in-place (used for callback responses).
    Returns True on success, False if the edit failed (e.g. message too old)."""
    try:
        tg(
            "editMessageText",
            chat_id=chat_id,
            message_id=message_id,
            text=text[:4000],
            parse_mode="HTML",
            disable_web_page_preview=True,
            reply_markup=reply_markup,
        )
        return True
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace") if hasattr(e, "read") else ""
        # 400 "message is not modified" is a no-op success.
        if "message is not modified" in body:
            return True
        log.info("edit failed (%s): %s", e.code, body[:200])
        return False


def chunk_text(text: str, max_size: int) -> List[str]:
    chunks: List[str] = []
    buf: List[str] = []
    size = 0
    for line in text.split("\n"):
        line_size = len(line) + 1
        if size + line_size > max_size and buf:
            chunks.append("\n".join(buf))
            buf, size = [], 0
        buf.append(line)
        size += line_size
    if buf:
        chunks.append("\n".join(buf))
    return chunks or [""]


# ─── formatters ─────────────────────────────────────────────────────────

def fmt_num(n: float) -> str:
    """Pretty integer with non-breaking thin spaces every 3 digits."""
    return f"{int(n):,}".replace(",", " ")


def fmt_bytes(n: float) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    v = float(n)
    for u in units:
        if v < 1024:
            return f"{v:.1f} {u}"
        v /= 1024
    return f"{v:.1f} EiB"


def fmt_secs(s: float) -> str:
    s = int(s)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    parts: List[str] = []
    if d: parts.append(f"{d}d")
    if h: parts.append(f"{h}h")
    if m or h or d: parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)


def progress_bar(pct: float, width: int = 12) -> str:
    """Simple unicode horizontal bar. 100% = '████████████'."""
    pct = max(0.0, min(100.0, pct))
    filled = int(pct / 100.0 * width)
    return "█" * filled + "░" * (width - filled)


# ─── command renderers ─────────────────────────────────────────────────

def cmd_help(_: str) -> str:
    return (
        f"<b>📡 telemt-bot</b>\n{HR}\n"
        "Статистика MTProto-прокси.\n\n"
        "<b>Кнопки</b> — для частых запросов.\n"
        "<b>Текстовые команды</b> — для конкретики:\n\n"
        "  <code>/user &lt;name&gt;</code> — детали по пользователю + первые 8 IP\n"
        "  <code>/metric &lt;name&gt;</code> — любая Prometheus-метрика\n"
        "  <code>/dc</code> — компактная таблица по DC; <code>/dc &lt;N&gt;</code> — детали одного DC\n"
        "  <code>/dcall</code> — полный блок по КАЖДОМУ DC в одном ответе\n"
        "  <code>/ips</code> — распределение outbound по source IP\n"
        "  <code>/shards</code> — режим шардирования + balance check (Phase 2)\n"
        "  <code>/menu</code> — показать главное меню\n"
        "  <code>/refresh</code> — обновить snapshot\n\n"
        "<i>Доступ ограничен whitelist'ом owner-ов.</i>"
    )


def cmd_status(_: str) -> str:
    sysinfo = api("/v1/system/info")
    ready = api("/v1/health/ready")
    gates = api("/v1/runtime/gates")
    summary = api("/v1/stats/summary")
    users = api("/v1/stats/users") or []

    active = sum(u.get("current_connections", 0) for u in users)
    active_users = sum(1 for u in users if u.get("current_connections", 0) > 0)

    accept_to = 0.0
    try:
        accept_to = metric_one(metrics_text(), "telemt_accept_permit_timeout_total") or 0.0
    except Exception:
        pass

    # Outbound source-IP count — surfaces multi-IP topology at a glance.
    ip_counts = outbound_to_tg_by_source_ip()
    ip_distinct = len(ip_counts)
    ip_total_conn = sum(ip_counts.values())

    # Shard mode — added in Phase 2. Determined by reading the live config
    # (or falling back to "unknown" if telemt.toml is unreadable). The
    # detail view lives in /shards; here we render only a one-liner so
    # /status stays scannable.
    shard_cfg = read_shard_config()
    shard_mode = shard_cfg.get("mode", "unknown")

    ready_ok = ready.get("ready", False)
    accept_ok = gates.get("accepting_new_connections", False)
    me_ok = gates.get("me_runtime_ready", False)

    health_icon = "🟢" if (ready_ok and accept_ok and me_ok) else ("🟡" if ready_ok else "🔴")
    ups_h = ready.get("healthy_upstreams", 0)
    ups_t = ready.get("total_upstreams", 0)

    ip_icon = "🌍" if ip_distinct > 1 else "🌐"
    if shard_mode == "shard":
        shard_line = (
            f"🧩 shards: <b>{shard_cfg.get('bind_count', '?')}</b> "
            f"(per-source-IP isolation) — /shards"
        )
    elif shard_mode == "round_robin" and shard_cfg.get("multiplier", 1) > 1:
        shard_line = (
            f"🔁 outbound mode: <b>round_robin ×{shard_cfg['multiplier']}</b> — /shards"
        )
    elif shard_mode == "round_robin":
        shard_line = "🔁 outbound mode: <b>round_robin</b> (single pool) — /shards"
    else:
        shard_line = "❓ outbound mode: <i>unknown</i> — /shards"

    return (
        f"{health_icon} <b>telemt {esc(sysinfo.get('version','?'))}</b>"
        f"  ·  uptime {esc(fmt_secs(sysinfo.get('uptime_seconds',0)))}\n"
        f"{HR}\n"
        f"<b>Состояние</b>\n"
        f"{'✅' if ready_ok else '❌'} ready: <code>{esc(ready.get('status','?'))}</code>\n"
        f"{'✅' if accept_ok else '⏸'} accept_new_connections\n"
        f"{'✅' if me_ok else '⏳'} me_runtime_ready\n"
        f"🔌 upstreams: <b>{ups_h}/{ups_t}</b>"
        f"  ·  route: <code>{esc(gates.get('route_mode','?'))}</code>\n"
        f"{shard_line}\n"
        f"{ip_icon} outbound: <b>{ip_distinct}</b> source IPs · "
        f"{ip_total_conn} TG conns (см. /ips)\n"
        f"\n<b>Трафик (с момента старта)</b>\n"
        f"<pre>"
        f"active conns       {fmt_num(active):>12}  ({active_users} users)\n"
        f"connections_total  {fmt_num(summary.get('connections_total',0)):>12}\n"
        f"bad_total          {fmt_num(summary.get('connections_bad_total',0)):>12}\n"
        f"handshake_timeouts {fmt_num(summary.get('handshake_timeouts_total',0)):>12}\n"
        f"accept_to          {fmt_num(accept_to):>12}"
        f"</pre>"
        f"<i>config:</i> <code>{esc(sysinfo.get('config_path',''))}</code> "
        f"(reload #{sysinfo.get('config_reload_count',0)})\n"
        f"<i>hash:</i> <code>{esc(str(sysinfo.get('config_hash',''))[:12])}</code>"
    )


def _dc_health(dc: Dict[str, Any]) -> Tuple[str, str]:
    """Return (icon, label) traffic-light for a DC.

    🟢 healthy (full coverage + writers + reasonable RTT)
    🟡 high-latency (full coverage + writers but RTT > 500ms)
    🟠 degraded (partial coverage or missing writers)
    🔴 unhealthy (no coverage)
    """
    cov = dc.get("coverage_pct", 0)
    alive = dc.get("alive_writers", 0)
    required = dc.get("required_writers", 0)
    rtt = dc.get("rtt_ms")
    if cov < 50 or alive == 0:
        return "🔴", "unhealthy"
    if cov < 100 or alive < required:
        return "🟠", "degraded"
    if rtt is not None and rtt > 500:
        return "🟡", "high latency"
    return "🟢", "healthy"


def cmd_dc(args: str) -> str:
    """Compact DC table; /dc <num> for one-DC detail view."""
    arg = args.strip()
    if arg:
        try:
            target = int(arg)
        except ValueError:
            return f"❌ номер DC должен быть числом: <code>{esc(arg)}</code>"
        return _cmd_dc_detail(target)

    dcs_data = api("/v1/stats/dcs")
    if not dcs_data.get("middle_proxy_enabled"):
        return f"🚫 middle proxy off: {esc(dcs_data.get('reason','?'))}"

    # Aggregate bound_clients per DC from the writers endpoint (the dcs API's
    # `load` field is a TG-internal queue metric, not actual client count).
    try:
        writers_data = api("/v1/stats/me-writers")
        clients_per_dc: Dict[int, int] = {}
        for w in writers_data.get("writers", []):
            clients_per_dc[w["dc"]] = clients_per_dc.get(w["dc"], 0) + w.get("bound_clients", 0)
    except Exception:
        clients_per_dc = {}

    dcs = list(dcs_data.get("dcs", []))
    total_writers = sum(d.get("alive_writers", 0) for d in dcs)
    total_required = sum(d.get("required_writers", 0) for d in dcs)
    total_clients = sum(clients_per_dc.values())
    busiest = max(clients_per_dc.values(), default=0)

    # Sort hottest first so the operator sees the DCs that matter at the top.
    dcs.sort(key=lambda d: (-clients_per_dc.get(d.get("dc", 0), 0), d.get("dc", 0)))

    lines = [
        f"🌐 <b>DC Connectivity</b>",
        (
            f"<i>{len(dcs)} DCs · {fmt_num(total_writers)} writers "
            f"({fmt_num(total_required)} required) · {fmt_num(total_clients)} clients</i>"
        ),
        HR,
        "<pre>",
        f"{'DC':>5}  {'RTT':>7}  {'writers':>8}  {'clients':>7}",
        "─────────────────────────────────────",
    ]
    degraded: List[int] = []
    for d in dcs:
        dc_id = d.get("dc", 0)
        rtt = d.get("rtt_ms")
        rtt_s = f"{rtt:>5.0f}ms" if rtt is not None else "     —"
        alive = d.get("alive_writers", 0)
        required = d.get("required_writers", 0)
        wr = f"{alive}/{required}"
        clients = clients_per_dc.get(dc_id, 0)
        icon, _ = _dc_health(d)
        if icon != "🟢":
            degraded.append(dc_id)
        # Mark hottest (only if there are actual clients to mark).
        marker = " 🔥" if busiest > 0 and clients == busiest else ""
        lines.append(
            f"{dc_id:>5}  {rtt_s:>7}  {wr:>8}  {fmt_num(clients):>7}  {icon}{marker}"
        )
    lines.append("</pre>")

    if degraded:
        lines.append(
            f"⚠️ degraded: <code>{', '.join(str(d) for d in degraded)}</code> — "
            f"посмотри <code>/dc &lt;номер&gt;</code> для деталей"
        )
    else:
        lines.append(
            "<i>Подсказка: <code>/dc &lt;номер&gt;</code> — endpoints + writers по DC</i>"
        )
    return "\n".join(lines)


def _cmd_dc_detail(target: int) -> str:
    """Detailed snapshot of one DC: floor, coverage, endpoints, top writers."""
    dcs_data = api("/v1/stats/dcs")
    dc = next(
        (d for d in dcs_data.get("dcs", []) if d.get("dc") == target),
        None,
    )
    if not dc:
        return f"❌ DC <code>{target}</code> не найден"

    # Single-DC view fetches writers separately; reuse the shared
    # renderer so format stays identical to /dcall per-DC blocks.
    try:
        writers_data = api("/v1/stats/me-writers")
        dc_writers = [
            w for w in writers_data.get("writers", []) if w.get("dc") == target
        ]
    except Exception:
        dc_writers = []

    return _render_dc_full_block(dc, dc_writers, include_writer_table=True)


def _render_dc_full_block(
    dc: Dict[str, Any],
    dc_writers: List[Dict[str, Any]],
    include_writer_table: bool,
) -> str:
    """Single-DC block used by both `/dc <num>` (with top-writer table)
    and `/dcall` (without — too large × 12 DCs). The first 4 sections
    (header / stats / endpoint list) match between the two so muscle
    memory transfers."""
    target = dc.get("dc", 0)
    icon, label = _dc_health(dc)
    cov = dc.get("coverage_pct", 0)
    fresh = dc.get("fresh_coverage_pct", 0)
    rtt = dc.get("rtt_ms")
    rtt_s = f"{rtt:.0f}ms" if rtt is not None else "—"
    alive = dc.get("alive_writers", 0)
    required = dc.get("required_writers", 0)
    f_min = dc.get("floor_min", 0)
    f_tgt = dc.get("floor_target", 0)
    f_max = dc.get("floor_max", 0)
    cap = " 🔒" if dc.get("floor_capped") else ""

    total_clients = sum(w.get("bound_clients", 0) for w in dc_writers)

    lines = [
        f"🌐 <b>DC {target}</b>  ·  {icon} {label}",
        HR,
        "<pre>",
        f"writers     {alive}/{required}",
        f"floor       {f_min}-{f_tgt}-{f_max}{cap}",
        f"coverage    {cov:5.1f}%  {progress_bar(cov)}",
        f"fresh       {fresh:5.1f}%  {progress_bar(fresh)}",
        f"endpoints   {dc.get('available_endpoints',0)}/{len(dc.get('endpoints',[]))}",
        f"rtt         {rtt_s}",
        f"clients     {fmt_num(total_clients)}",
        "</pre>",
    ]

    # Endpoints with their writer count.
    eps = dc.get("endpoints", []) or []
    ep_w = {
        e["endpoint"]: e.get("active_writers", 0)
        for e in dc.get("endpoint_writers", []) or []
    }
    if eps:
        lines.append("<b>Endpoints</b>")
        lines.append("<pre>")
        for ep in eps:
            lines.append(f"{ep:<25} {ep_w.get(ep, 0):>3} writers")
        lines.append("</pre>")

    # Top writers by client count — only on `/dc <num>` drill-down.
    # `/dcall` skips this because 12 DCs × 10 writers each blows past
    # Telegram's per-message limit even with chunking.
    if include_writer_table and dc_writers:
        lines.append(f"<b>Writers</b> ({len(dc_writers)})")
        lines.append("<pre>")
        for w in sorted(dc_writers, key=lambda x: -x.get("bound_clients", 0))[:10]:
            ep = (w.get("endpoint", "") or "")[:22]
            rtt_ema = w.get("rtt_ema_ms") or 0
            lines.append(
                f"#{w['writer_id']:<5} {ep:<22} "
                f"{w.get('bound_clients', 0):>5}c {rtt_ema:>4.0f}ms"
            )
        if len(dc_writers) > 10:
            lines.append(f"… ещё {len(dc_writers) - 10}")
        lines.append("</pre>")

    return "\n".join(lines)


def cmd_dcall(_: str) -> str:
    """Per-DC detail block for EVERY DC in one message.

    `/dc` (compact table) is best when you want "are any DCs sick?";
    `/dcall` is best when you want the full picture per DC without
    drilling into each one separately. Shares the per-DC renderer with
    `/dc <num>` so the format is identical — only difference is that
    `/dcall` skips the top-writers table (too large × 12 DCs).
    """
    dcs_data = api("/v1/stats/dcs")
    if not dcs_data.get("middle_proxy_enabled"):
        return f"🚫 middle proxy off: {esc(dcs_data.get('reason','?'))}"

    # One fetch, scoped per-DC inline. Avoids per-DC API roundtrips.
    try:
        writers_data = api("/v1/stats/me-writers")
        writers_by_dc: Dict[int, List[Dict[str, Any]]] = {}
        for w in writers_data.get("writers", []):
            writers_by_dc.setdefault(w.get("dc", 0), []).append(w)
    except Exception:
        writers_by_dc = {}

    dcs = list(dcs_data.get("dcs", []))
    # Sort by DC id ascending so the order is predictable across
    # invocations — operators scrolling want the same DC in the same
    # place each time. (`/dc` sorts by load; `/dcall` sorts by id.)
    dcs.sort(key=lambda d: d.get("dc", 0))

    total_writers = sum(d.get("alive_writers", 0) for d in dcs)
    total_required = sum(d.get("required_writers", 0) for d in dcs)
    total_clients = sum(
        sum(w.get("bound_clients", 0) for w in ws)
        for ws in writers_by_dc.values()
    )

    blocks = [
        f"🌐 <b>All DC details</b>",
        (
            f"<i>{len(dcs)} DCs · {fmt_num(total_writers)} writers "
            f"({fmt_num(total_required)} required) · "
            f"{fmt_num(total_clients)} clients</i>"
        ),
        "",
    ]
    for dc in dcs:
        dc_id = dc.get("dc", 0)
        blocks.append(
            _render_dc_full_block(
                dc,
                writers_by_dc.get(dc_id, []),
                include_writer_table=False,
            )
        )
        blocks.append("")  # blank line between DCs for visual separation

    return "\n".join(blocks)


def cmd_me(_: str) -> str:
    data = api("/v1/stats/me-writers")
    if not data.get("middle_proxy_enabled"):
        return f"🚫 middle proxy off: {esc(data.get('reason','?'))}"
    s = data.get("summary", {})
    quarantine = 0.0
    swaps = 0.0
    try:
        text = metrics_text()
        quarantine = metric_one(text, "telemt_me_endpoint_quarantine_total") or 0.0
        swaps = metric_one(text, "telemt_pool_swap_total") or 0.0
    except Exception:
        pass

    cov = s.get("coverage_pct", 0)
    fresh = s.get("fresh_coverage_pct", 0)
    avail_pct = s.get("available_pct", 0)

    # Shard-aware header. In shard mode the writers/required/fresh
    # numbers are aggregated across ALL shards by Phase 2c (MePoolMux
    # ::aggregate_status_snapshot) — so the figures match the system
    # total, not a single shard. Surface this so operators don't think
    # the system is over-provisioning. /shards has the per-shard breakdown.
    shard_cfg = read_shard_config()
    shard_header = ""
    if shard_cfg.get("mode") == "shard":
        n = shard_cfg.get("bind_count", 0)
        shard_header = (
            f"<i>🧩 aggregated across <b>{n}</b> shards (mux mode) — /shards</i>\n"
        )

    return (
        f"🔌 <b>Middle-proxy pool</b>\n{HR}\n"
        f"{shard_header}"
        f"<pre>"
        f"writers   alive {s.get('alive_writers',0):>5} / required {s.get('required_writers',0):>5}\n"
        f"          fresh {s.get('fresh_alive_writers',0):>5}\n"
        f"endpoints {s.get('available_endpoints',0):>3} / {s.get('configured_endpoints',0):<3}  ({avail_pct:5.1f}%)\n"
        f"dc_groups {s.get('configured_dc_groups',0)}\n"
        f"\n"
        f"coverage  {cov:5.1f}% {progress_bar(cov)}\n"
        f"fresh     {fresh:5.1f}% {progress_bar(fresh)}"
        f"</pre>"
        f"\n<b>Counters</b>\n"
        f"  🏥 quarantine_total: <b>{fmt_num(quarantine)}</b>\n"
        f"  🔄 pool_swap_total:  <b>{fmt_num(swaps)}</b>"
    )


def cmd_users(_: str) -> str:
    users = api("/v1/stats/users") or []
    if not users:
        return "👥 нет пользователей в runtime"
    rows = [f"👥 <b>Пользователи</b> ({len(users)})", HR]
    for u in sorted(users, key=lambda x: x.get("current_connections", 0), reverse=True):
        name = esc(u.get("username", "?"))
        conn = u.get("current_connections", 0)
        ips = u.get("active_unique_ips", 0)
        recent = u.get("recent_unique_ips", 0)
        octets = u.get("total_octets", 0)
        max_ips = u.get("max_unique_ips")
        max_conn = u.get("max_tcp_conns")
        quota = u.get("data_quota_bytes")

        # Status emoji: green if has active conns, dim if idle.
        icon = "🟢" if conn > 0 else "⚪"

        limits = []
        if max_conn: limits.append(f"max_conn=<b>{max_conn}</b>")
        if max_ips: limits.append(f"max_ips=<b>{max_ips}</b>")
        if quota: limits.append(f"quota=<b>{fmt_bytes(quota)}</b>")
        limits_s = "  " + " · ".join(limits) if limits else ""

        rows.append(
            f"\n{icon} <b>{name}</b>{limits_s}\n"
            f"<pre>"
            f"connections   {fmt_num(conn):>8}\n"
            f"unique IPs    {fmt_num(ips):>8}  (recent {fmt_num(recent)})\n"
            f"traffic       {fmt_bytes(octets):>12}"
            f"</pre>"
        )
    return "\n".join(rows)


def cmd_user(args: str) -> str:
    name = args.strip().split()[0] if args.strip() else ""
    if not name:
        return "Usage: <code>/user &lt;username&gt;</code>"
    try:
        u = api(f"/v1/users/{urllib.parse.quote(name)}")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return f"❌ user not found: <code>{esc(name)}</code>"
        raise
    ips = u.get("active_unique_ips_list", [])
    icon = "🟢" if u.get("current_connections", 0) > 0 else "⚪"
    return (
        f"{icon} <b>user {esc(u.get('username',''))}</b>\n{HR}\n"
        f"<pre>"
        f"in_runtime         {u.get('in_runtime')}\n"
        f"connections        {fmt_num(u.get('current_connections',0)):>8}\n"
        f"active_unique_ips  {fmt_num(u.get('active_unique_ips',0)):>8}\n"
        f"recent_unique_ips  {fmt_num(u.get('recent_unique_ips',0)):>8}\n"
        f"total_octets       {fmt_bytes(u.get('total_octets',0)):>12}\n"
        f"max_tcp_conns      {u.get('max_tcp_conns')}\n"
        f"max_unique_ips     {u.get('max_unique_ips')}\n"
        f"data_quota_bytes   {u.get('data_quota_bytes')}\n"
        f"expiration         {u.get('expiration_rfc3339')}\n"
        f"ad_tag             {u.get('user_ad_tag') or ''}"
        f"</pre>"
        f"<b>Первые 8 active IPs</b> ({len(ips)} всего)\n"
        + ("<pre>" + "\n".join(esc(ip) for ip in ips[:8]) + "</pre>" if ips else "  —")
    )


def cmd_online(_: str) -> str:
    users = api("/v1/stats/users") or []
    total = sum(u.get("current_connections", 0) for u in users)
    total_ips = sum(u.get("active_unique_ips", 0) for u in users)
    active_users = [u for u in users if u.get("current_connections", 0) > 0]
    rows = [
        f"🟢 <b>Online сейчас</b>",
        HR,
        f"<pre>"
        f"connections     {fmt_num(total):>10}\n"
        f"unique IPs      {fmt_num(total_ips):>10}\n"
        f"active users    {len(active_users):>10}"
        f"</pre>"
    ]
    if active_users:
        rows.append(f"<b>Топ по соединениям</b>")
        rows.append("<pre>")
        for i, u in enumerate(sorted(active_users, key=lambda x: x.get("current_connections", 0), reverse=True)[:10], 1):
            name = (u.get('username', '?') or '?')[:14].ljust(14)
            rows.append(
                f"{i:>2}. {name} {fmt_num(u.get('current_connections',0)):>7}c "
                f"{fmt_num(u.get('active_unique_ips',0)):>6}ip "
                f"{fmt_bytes(u.get('total_octets',0)):>10}"
            )
        rows.append("</pre>")
    return "\n".join(rows)


def cmd_handshake(_: str) -> str:
    summary = api("/v1/stats/summary")
    total = summary.get("connections_total", 0)
    bad = summary.get("connections_bad_total", 0)
    timeouts = summary.get("handshake_timeouts_total", 0)
    bad_pct = (bad / total * 100) if total > 0 else 0.0

    rows = [
        f"🔐 <b>Handshake breakdown</b>",
        HR,
        f"<pre>"
        f"total          {fmt_num(total):>12}\n"
        f"bad            {fmt_num(bad):>12}  ({bad_pct:.2f}%)\n"
        f"timeouts       {fmt_num(timeouts):>12}"
        f"</pre>"
    ]
    bad_classes = sorted(
        summary.get("connections_bad_by_class") or [],
        key=lambda c: c.get("total", 0), reverse=True,
    )
    if bad_classes:
        rows.append(f"<b>bad_by_class</b> (top 15)")
        rows.append("<pre>")
        for c in bad_classes[:15]:
            name = (c.get('class', '?') or '?')[:32].ljust(32)
            rows.append(f"{name} {fmt_num(c.get('total',0)):>8}")
        rows.append("</pre>")
    hf = summary.get("handshake_failures_by_class") or []
    if hf:
        rows.append(f"<b>handshake_failures_by_class</b> (top 10)")
        rows.append("<pre>")
        for c in sorted(hf, key=lambda c: c.get("total", 0), reverse=True)[:10]:
            name = (c.get('class', '?') or '?')[:32].ljust(32)
            rows.append(f"{name} {fmt_num(c.get('total',0)):>8}")
        rows.append("</pre>")
    return "\n".join(rows)


def cmd_metric(args: str) -> str:
    name = args.strip().split()[0] if args.strip() else ""
    if not name:
        return (
            "Usage: <code>/metric &lt;metric_name&gt;</code>\n\n"
            "Примеры:\n"
            "  <code>/metric telemt_me_endpoint_quarantine_total</code>\n"
            "  <code>/metric telemt_ip_tracker_users</code>\n"
            "  <code>/metric telemt_handshake_failures_by_class_total</code>"
        )
    if not re.fullmatch(r"[A-Za-z0-9_]+", name):
        return "❌ invalid metric name"
    series = parse_metric(metrics_text(), name)
    if not series:
        return f"❌ no series for <code>{esc(name)}</code>"
    rows = [f"📈 <b>{esc(name)}</b>", HR, f"({len(series)} series)", "<pre>"]
    for s in series[:25]:
        labels = ",".join(f"{k}={v}" for k, v in s["labels"].items())
        line = f"{labels[:48]:<48} {s['value']:>12g}"
        rows.append(line)
    rows.append("</pre>")
    if len(series) > 25:
        rows.append(f"… ещё {len(series) - 25}")
    return "\n".join(rows)


def cmd_ips(_: str) -> str:
    """Outbound source-IP distribution to Telegram endpoints.

    Useful for verifying multi-IP `bind_addresses` rotation and the new
    `me_writer_bind_multiplier` feature. Each established TCP session from
    one of our IPs to a TG endpoint counts toward that IP's bucket.
    """
    counts = outbound_to_tg_by_source_ip()
    if not counts:
        return (
            f"🌍 <b>Outbound IPs</b>\n{HR}\n"
            "Не удалось прочитать <code>/proc/net/tcp</code> или нет активных\n"
            "соединений к Telegram. Бот должен жить в том же netns что и telemt."
        )
    total = sum(counts.values())
    distinct = len(counts)

    # Visual bar relative to busiest IP, so disuse is immediately obvious.
    busiest = max(counts.values())

    rows = [f"🌍 <b>Outbound к Telegram</b>", HR]
    rows.append(
        f"  {distinct} active source IP · {total} ESTABLISHED connections"
    )
    rows.append("<pre>")
    rows.append(f"{'source IP':<18} {'conns':>6}  bar")
    # Sort: most-used first.
    for ip, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        bar_width = int(n / busiest * 12) if busiest else 0
        bar = "█" * bar_width + "░" * (12 - bar_width)
        rows.append(f"{ip:<18} {n:>6}  {bar}")
    rows.append("</pre>")

    # Hint about multi-IP scaling status.
    if distinct <= 1:
        rows.append(
            "<i>⚠️ только один source IP — для multi-IP outbound добавь</i>\n"
            "<i><code>[[upstreams]] bind_addresses = [...]</code></i>"
        )
    elif distinct >= 3:
        rows.append(
            f"<i>✓ multi-IP outbound: writers распределены по {distinct} source IP</i>"
        )
    return "\n".join(rows)


def cmd_shards(_: str) -> str:
    """Per-source-IP shard view (Phase 2 MePoolMux).

    Prefers the authoritative `/v1/stats/me-writers/by-shard` API (Phase
    2d) which returns the exact per-shard writer counts that the proxy
    itself sees. Falls back to /proc/net/tcp source-IP inference when
    that endpoint isn't available (older telemt, API disabled).

    Both paths surface the same balance check: a healthy shard mode has
    all source IPs within ~10-15% of each other. Big imbalance usually
    means one shard's writers are stuck quarantining a flaky endpoint
    that's fine for sibling shards — exactly the failure-isolation
    behaviour shard mode adds over the simpler
    `me_writer_bind_multiplier` rotation.
    """
    api_data: Optional[Dict[str, Any]] = None
    try:
        api_data = api("/v1/stats/me-writers/by-shard")
    except Exception:
        # Older telemt without the by-shard endpoint, or API down —
        # fall back to /proc/net/tcp inference below.
        api_data = None

    if api_data and api_data.get("middle_proxy_enabled"):
        return _render_shards_from_api(api_data)
    return _render_shards_from_proc()


def _render_shards_from_api(data: Dict[str, Any]) -> str:
    """Render /shards from the authoritative by-shard API — single
    source of truth: actual writer count and bind address per shard,
    not just established TCP sockets visible to the bot."""
    mode = data.get("mode", "unknown")
    shards: List[Dict[str, Any]] = data.get("shards", [])

    if mode == "shard":
        mode_icon = "🧩"
        mode_label = "<b>shard</b> · per-source-IP isolation"
    else:
        mode_icon = "🔁"
        mode_label = "<b>round_robin</b> (single pool)"

    rows = [f"🧩 <b>Шарды (MePoolMux)</b>", HR, f"{mode_icon} mode: {mode_label}"]
    rows.append(f"  <b>{len(shards)}</b> shards · live writer counts from API")

    if not shards:
        rows.append("\n<i>Нет шардов в активном состоянии</i>")
        return "\n".join(rows)

    # Use alive_writers per shard for the balance check — this is what
    # the proxy actually sees as its working pool, more precise than
    # the established-TCP count from /proc.
    counts = {
        sh.get("bind_address") or f"shard-{sh.get('shard_idx', '?')}":
            sh.get("summary", {}).get("alive_writers", 0)
        for sh in shards
    }
    busiest = max(counts.values()) if counts else 1
    total = sum(counts.values())

    cv: Optional[float] = None
    if len(counts) >= 2 and total > 0:
        mean = total / len(counts)
        variance = sum((c - mean) ** 2 for c in counts.values()) / len(counts)
        cv = (variance ** 0.5) / mean if mean > 0 else None

    rows.append("")
    rows.append("<pre>")
    rows.append(f"{'shard / bind':<22} {'writers':>7}  balance")
    for label, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        bar_w = int(n / busiest * 12) if busiest else 0
        bar = "█" * bar_w + "░" * (12 - bar_w)
        rows.append(f"{label:<22} {n:>7}  {bar}")
    rows.append(f"{'TOTAL':<22} {total:>7}")
    rows.append("</pre>")

    # Per-shard required/coverage from the API summary — these surface
    # under/over-provisioning per shard, which /proc/net/tcp can't show.
    rows.append("")
    rows.append("<b>Coverage per shard</b>")
    rows.append("<pre>")
    rows.append(f"{'shard':<6} {'alive':>5} {'req':>5} {'cov%':>6}")
    for sh in shards:
        idx = sh.get("shard_idx", "?")
        s = sh.get("summary", {})
        alive = s.get("alive_writers", 0)
        req = s.get("required_writers", 0)
        cov = s.get("coverage_pct", 0.0)
        rows.append(f"{idx:<6} {alive:>5} {req:>5} {cov:>6.1f}")
    rows.append("</pre>")

    rows.append(_balance_verdict_line(cv))
    return "\n".join(rows)


def _render_shards_from_proc() -> str:
    """Fallback: infer shard view from /proc/net/tcp source-IP
    distribution. Less authoritative (just counts established TCP
    sockets, can't distinguish writer state) but works when the API is
    unreachable or the new endpoint isn't deployed yet."""
    topo = shard_topology()
    mode = topo["config_mode"]
    cfg_n = topo["config_bind_count"]
    cfg_mult = topo["config_multiplier"]
    live_n = topo["live_source_ip_count"]
    total = topo["live_total_conns"]
    cv = topo["balance_cv"]
    counts = topo["live_per_ip"]
    err = topo["config_error"]

    if mode == "shard":
        mode_icon = "🧩"
        mode_label = f"<b>shard</b> · per-source-IP isolation"
    elif mode == "round_robin":
        mode_icon = "🔁"
        if cfg_mult > 1:
            mode_label = f"<b>round_robin</b> ×{cfg_mult} (multiplier mode)"
        else:
            mode_label = "<b>round_robin</b> (single pool)"
    else:
        mode_icon = "❓"
        mode_label = "<b>unknown</b>"

    rows = [
        f"🧩 <b>Шарды (MePoolMux)</b>",
        HR,
        f"{mode_icon} mode: {mode_label}",
        "<i>(API fallback: данные из /proc/net/tcp, не из telemt API)</i>",
    ]
    if err:
        rows.append(f"<i>⚠️ {esc(err)} — config undetected, showing live only</i>")
    rows.append(
        f"  configured: <b>{cfg_n}</b> bind addresses · live: <b>{live_n}</b> active source IPs"
    )
    if mode == "shard" and cfg_n != live_n and cfg_n > 0:
        rows.append(
            f"  <i>⚠️ только {live_n}/{cfg_n} shards активны — проверь journalctl</i>"
        )

    if not counts:
        rows.append(
            "\n<i>Нет активных outbound коннекций к TG — pool ещё прогревается?</i>"
        )
        return "\n".join(rows)

    busiest = max(counts.values()) if counts else 1
    rows.append("")
    rows.append("<pre>")
    rows.append(f"{'source IP':<18} {'conns':>6}  balance")
    for ip, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        bar_w = int(n / busiest * 12) if busiest else 0
        bar = "█" * bar_w + "░" * (12 - bar_w)
        rows.append(f"{ip:<18} {n:>6}  {bar}")
    rows.append(f"{'TOTAL':<18} {total:>6}")
    rows.append("</pre>")

    rows.append(_balance_verdict_line(cv))
    return "\n".join(rows)


def _balance_verdict_line(cv: Optional[float]) -> str:
    """Translate coefficient-of-variation into the operator-facing
    verdict. Shared between API and /proc paths so both renderers
    produce identical messaging."""
    if cv is None:
        return "<i>(нужно ≥2 шарда для оценки баланса)</i>"
    if cv < 0.10:
        return f"<i>✓ баланс отличный (CV={cv:.2%})</i>"
    if cv < 0.25:
        return f"<i>✓ баланс ОК (CV={cv:.2%})</i>"
    if cv < 0.50:
        return (
            f"<i>⚠️ дисбаланс (CV={cv:.2%}) — один shard может квантировать endpoint, "
            f"сиблинги нет</i>"
        )
    return (
        f"<i>🔴 сильный дисбаланс (CV={cv:.2%}) — shard вероятно сломан, "
        f"смотри journalctl на flap warns</i>"
    )


def cmd_refresh(_: str) -> str:
    info = api("/v1/system/info")
    return (
        f"♻️ <b>Snapshot refreshed</b>\n{HR}\n"
        f"<pre>"
        f"version           {info.get('version','')}\n"
        f"uptime            {fmt_secs(info.get('uptime_seconds',0))}\n"
        f"config_reload     #{info.get('config_reload_count',0)}\n"
        f"config_hash       {str(info.get('config_hash',''))[:12]}"
        f"</pre>"
    )


def cmd_menu(_: str) -> str:
    return (
        f"📡 <b>telemt-bot</b>  ·  главное меню\n{HR}\n"
        "Выбери раздел кнопкой ниже или используй текстовую команду:\n\n"
        "  <code>/user &lt;name&gt;</code>  —  детали пользователя\n"
        "  <code>/metric &lt;name&gt;</code>  —  любая метрика\n"
        "  <code>/help</code>  —  справка"
    )


COMMANDS: Dict[str, Callable[[str], str]] = {
    "/start": cmd_menu,
    "/menu": cmd_menu,
    "/help": cmd_help,
    "/status": cmd_status,
    "/dc": cmd_dc,
    "/dcall": cmd_dcall,
    "/me": cmd_me,
    "/shards": cmd_shards,
    "/users": cmd_users,
    "/user": cmd_user,
    "/online": cmd_online,
    "/handshake": cmd_handshake,
    "/ips": cmd_ips,
    "/metric": cmd_metric,
    "/refresh": cmd_refresh,
}

CALLBACK_TO_CMD: Dict[str, str] = {
    "menu": "/menu",
    "help": "/help",
    "status": "/status",
    "dc": "/dc",
    "dcall": "/dcall",
    "me": "/me",
    "shards": "/shards",
    "users": "/users",
    "online": "/online",
    "handshake": "/handshake",
    "ips": "/ips",
    "refresh": "/refresh",
}


# ─── dispatch ───────────────────────────────────────────────────────────

def execute(cmd: str, args: str) -> str:
    handler = COMMANDS.get(cmd)
    if not handler:
        return f"unknown command: <code>{esc(cmd)}</code>\n/help"
    try:
        return handler(args)
    except urllib.error.URLError as e:
        return f"❌ <b>upstream unreachable</b>\n<code>{esc(e)}</code>"
    except Exception as e:
        log.exception("handler %s failed", cmd)
        return f"❌ <b>{esc(type(e).__name__)}</b>\n<code>{esc(e)}</code>"


def keyboard_for(cmd: str) -> Dict[str, Any]:
    """Pick the right inline keyboard for a response. /menu → main menu;
    everything else → back-to-menu button."""
    if cmd in ("/menu", "/start"):
        return main_menu()
    return back_menu()


def handle_message(msg: Dict[str, Any]) -> None:
    chat_id = msg.get("chat", {}).get("id")
    text = (msg.get("text") or "").strip()
    if not chat_id or not text:
        return
    if chat_id not in OWNERS:
        log.info("ignoring chat_id=%s (not in whitelist): %r", chat_id, text[:60])
        return
    first, _, rest = text.partition(" ")
    cmd = first.split("@", 1)[0]
    log.info("chat_id=%s cmd=%s", chat_id, cmd)
    reply = execute(cmd, rest)
    send(chat_id, reply, reply_markup=keyboard_for(cmd))


def handle_callback(cb: Dict[str, Any]) -> None:
    chat_id = cb.get("message", {}).get("chat", {}).get("id")
    message_id = cb.get("message", {}).get("message_id")
    data = cb.get("data", "")
    cb_id = cb.get("id")
    from_id = cb.get("from", {}).get("id")

    if from_id not in OWNERS:
        log.info("ignoring callback from chat_id=%s", from_id)
        try:
            tg("answerCallbackQuery", callback_query_id=cb_id, text="🚫 not authorized", show_alert=False)
        except Exception:
            pass
        return

    # Special "REFRESH" callback: re-execute the inferred command from the
    # current message. Simpler: treat REFRESH as /menu refresh — better UX is
    # to just re-render the last shown panel. We approximate by re-rendering
    # whatever command's button was last pressed. To keep it stateless, we
    # require callbacks to carry the cmd token.
    if data == "REFRESH":
        # Without per-message state we re-show the menu.
        cmd = "/menu"
    else:
        cmd = CALLBACK_TO_CMD.get(data)
        if not cmd:
            try:
                tg("answerCallbackQuery", callback_query_id=cb_id, text="unknown action")
            except Exception:
                pass
            return

    log.info("callback chat_id=%s data=%s -> %s", chat_id, data, cmd)
    reply = execute(cmd, "")
    markup = keyboard_for(cmd)
    try:
        tg("answerCallbackQuery", callback_query_id=cb_id)
    except Exception as e:
        log.info("answerCallbackQuery failed: %s", e)

    # Try inline edit first (cleaner UX). Fall back to sendMessage if edit fails
    # (e.g. response too long, or original message deleted).
    if chat_id and message_id:
        ok = edit(chat_id, message_id, reply, reply_markup=markup)
        if not ok:
            send(chat_id, reply, reply_markup=markup)
    else:
        send(chat_id, reply, reply_markup=markup)


def handle_update(update: Dict[str, Any]) -> None:
    if "message" in update or "edited_message" in update:
        handle_message(update.get("message") or update.get("edited_message") or {})
    elif "callback_query" in update:
        handle_callback(update["callback_query"])


# ─── startup & main loop ────────────────────────────────────────────────

def register_commands() -> None:
    """Populate the / popup in Telegram client with available commands."""
    cmds = [
        {"command": "menu", "description": "📡 Главное меню"},
        {"command": "status", "description": "📊 Статус: версия, uptime, accept"},
        {"command": "online", "description": "🟢 Active connections сейчас"},
        {"command": "dc", "description": "🌐 DC: компактная таблица"},
        {"command": "dcall", "description": "🌐📋 Полный блок по КАЖДОМУ DC"},
        {"command": "me", "description": "🔌 ME pool: writers, coverage"},
        {"command": "shards", "description": "🧩 Шарды: balance check (Phase 2)"},
        {"command": "users", "description": "👥 Все пользователи"},
        {"command": "user", "description": "👤 Детали: /user <name>"},
        {"command": "handshake", "description": "🔐 Bad handshake breakdown"},
        {"command": "ips", "description": "🌍 Outbound source-IP распределение"},
        {"command": "metric", "description": "📈 Любая метрика: /metric <name>"},
        {"command": "refresh", "description": "♻️ Обновить snapshot"},
        {"command": "help", "description": "ℹ️ Помощь"},
    ]
    try:
        tg("setMyCommands", commands=cmds)
        log.info("setMyCommands registered (%d entries)", len(cmds))
    except Exception as e:
        log.warning("setMyCommands failed: %s", e)


def main() -> None:
    if not BOT_TOKEN:
        sys.exit("FATAL: TELEMT_BOT_TOKEN env not set")
    if not OWNERS:
        sys.exit("FATAL: TELEMT_BOT_OWNERS env not set (comma-separated chat IDs)")
    log.info("started; api=%s owners=%s", API_BASE, sorted(OWNERS))
    register_commands()

    offset: Optional[int] = None
    # Drop stale updates left over from previous downtime.
    try:
        resp = tg("getUpdates", timeout=0, limit=1)
        results = resp.get("result", [])
        if results:
            offset = results[-1]["update_id"] + 1
    except Exception as e:
        log.warning("startup getUpdates failed: %s", e)

    backoff = 1
    while True:
        try:
            params: Dict[str, Any] = {
                "timeout": POLL_TIMEOUT,
                "allowed_updates": ["message", "callback_query"],
            }
            if offset is not None:
                params["offset"] = offset
            resp = tg("getUpdates", **params)
            for u in resp.get("result", []):
                handle_update(u)
                offset = u["update_id"] + 1
            backoff = 1
        except urllib.error.HTTPError as e:
            log.warning("Telegram HTTPError %s — sleep %ds", e.code, backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
        except Exception as e:
            log.warning("loop err: %s — sleep %ds", e, backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)


if __name__ == "__main__":
    main()
