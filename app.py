#!/usr/bin/env python3
"""Cyber Cyber Lagebild - personal SSH/auth attack dashboard. Run locally on the machine, open in a browser.

Usage:
    sudo python3 app.py [--port 8080] [--bind 127.0.0.1] [--quiet]

Each HTTP request is logged to the terminal; --quiet turns that off.

Time range is selected in the browser UI (1 day / 1 week / 1 month / 1 year / all).

Optional: set GREYNOISE_API_KEY for more GreyNoise lookups than the keyless daily quota.

No third-party dependencies - stdlib only.
"""

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

AUTH_LOG = "/var/log/auth.log"


def log_error(msg):
    print("ERROR:", msg, file=sys.stderr, flush=True)


class CommandTimeout(Exception):
    pass


def run(cmd, timeout=15):
    """stdout of a shell command. A timeout raises CommandTimeout, so it never looks like "no data"."""
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout).stdout
    except subprocess.TimeoutExpired:
        log_error(f"timed out after {timeout}s: {cmd}")
        raise CommandTimeout(f"{cmd.split()[0]} took longer than {timeout} s")
    except Exception as e:
        log_error(f"{e}: {cmd}")
        return ""


VALID_SINCE = {
    "1d": "1 day ago",
    "1w": "7 days ago",
    "1m": "30 days ago",
    "1y": "365 days ago",
    "all": None,
}


# Each bot attempt writes several SSH lines (connect, PAM, disconnect, ...). The panels only use
# these three kinds, so journalctl filters for them itself (-g) and everything else never
# reaches Python. One read serves all SSH panels and the chart.
SSH_LINES = "Failed password|Invalid user|Accepted "
SSH_TIMEOUT = 60  # seconds; long ranges on a busy server can take a while
IPV4 = r"\d+\.\d+\.\d+\.\d+"
ISO_LINE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")  # "-o short-iso" line start
USER_RE = re.compile(r"(?:Invalid user|Failed password for(?: invalid user)?) (\S+)")
FAILED_IP_RE = re.compile(rf"Failed password.*?from ({IPV4})")
ACCEPTED_RE = re.compile(rf"Accepted (\S+) for (\S+) from ({IPV4})")


def chart_bins_are_days(since, first_ts):
    """True if the page's chart uses day/week/month bins for this range (see timeFrame in the page):
    fixed ranges over 8 days, or "all" when the journal reaches back more than 8 days.
    `first_ts` is the oldest line's ISO time; journalctl prints in time order."""
    if since in (VALID_SINCE["1d"], VALID_SINCE["1w"]):
        return False
    if since is not None:
        return True
    return datetime.now() - datetime.strptime(first_ts, "%Y-%m-%dT%H:%M:%S") > timedelta(days=8)


def journal_ssh(since):
    since_clause = f'--since "{since}"' if since else ""
    # -g is case-sensitive here because the pattern has capitals
    return run(f'journalctl -u ssh {since_clause} -g "{SSH_LINES}" -q --no-pager -o short-iso 2>/dev/null',
               timeout=SSH_TIMEOUT)


def top(counter, n=15):
    return [{"key": k, "count": c} for k, c in counter.most_common(n)]


def top_all(counter):
    """Every entry, most first; equal counts in alphabetical order (case-insensitive)."""
    rows = sorted(counter.items(), key=lambda kc: (-kc[1], kc[0].casefold(), kc[0]))
    return [{"key": k, "count": c} for k, c in rows]


def hour_series(counter):
    return [{"hour": h, "count": counter[h]} for h in sorted(counter)]


def stat_sudo():
    log = run(f'grep "sudo:" {AUTH_LOG} 2>/dev/null')
    commands = re.findall(r"sudo:\s*(\S+)\s*:.*COMMAND=", log)
    failures = len(re.findall(r"sudo:.*authentication failure", log))
    return {"by_user": top(Counter(commands)), "failures": failures}


def stat_su():
    log = run(f'grep "su:" {AUTH_LOG} 2>/dev/null')
    opened = len(re.findall(r"su:.*session opened", log))
    failed = len(re.findall(r"su:.*authentication failure", log))
    return {"opened": opened, "failed": failed}


def stat_new_accounts():
    log = run(f'grep -E "useradd|groupadd|new user|new group" {AUTH_LOG} 2>/dev/null')
    return [l for l in log.splitlines() if l][-20:]


def stat_cron_auth():
    log = run(f'grep "CRON" {AUTH_LOG} 2>/dev/null | grep "session opened"')
    users = re.findall(r"session opened for user (\S+)", log)
    return top(Counter(users))


def stat_fail2ban():
    out = run("fail2ban-client status sshd 2>/dev/null")
    m = re.search(r"Banned IP list:\s*(.*)", out)
    if not m:
        return []
    return [ip for ip in m.group(1).split() if ip]


def stat_ufw_ports():
    log = run('grep "UFW BLOCK" /var/log/ufw.log 2>/dev/null')
    ports = re.findall(r"DPT=(\d+)", log)
    return top(Counter(ports))


def stat_ufw_ips():
    """Blocked packets per source IP, plus which destination ports (= services) each IP tried."""
    log = run('grep "UFW BLOCK" /var/log/ufw.log 2>/dev/null')
    counts, ports = Counter(), {}
    for src, dpt in re.findall(r"SRC=(\d+\.\d+\.\d+\.\d+)\b.*?(?:DPT=(\d+)|$)", log, re.MULTILINE):
        counts[src] += 1
        if dpt:
            ports.setdefault(src, Counter())[dpt] += 1
    return [dict(r, ports=[p for p, _ in ports.get(r["key"], Counter()).most_common(3)])
            for r in top(counts)]


def build_fast_stats():
    """Panels from whole log files (grep) and fail2ban: quick, and the same for every time range."""
    return {
        "sudo": stat_sudo(),
        "su": stat_su(),
        "new_accounts": stat_new_accounts(),
        "cron_auth": stat_cron_auth(),
        "fail2ban_banned": stat_fail2ban(),
        "ufw_by_port": stat_ufw_ports(),
        "ufw_by_ip": stat_ufw_ips(),
    }


def build_ssh_stats(since):
    """Panels from the SSH journal for the selected range, computed in one pass over the filtered lines."""
    total_failed = 0
    by_ip, by_user, per_hour = Counter(), Counter(), Counter()
    ip_hour = Counter()  # (ip, hour) -> failed passwords, for the per-IP timelines
    # (user, time bin) -> failed passwords, so hovering a username can highlight it in the chart.
    # Every username is included, so on ranges whose chart bins are days or longer this
    # counts per day instead of per hour, which keeps the response small.
    user_time = Counter()
    per_day = None  # decided at the first line
    accepted = []
    for line in journal_ssh(since).splitlines():
        m = ISO_LINE.match(line)
        if not m:
            continue
        hour = line[:13]  # "2026-11-22T14"
        if per_day is None:
            per_day = chart_bins_are_days(since, m.group(0))
        failed = "Failed password" in line
        u = None
        if failed or "Invalid user" in line:
            total_failed += 1
            u = USER_RE.search(line)
            if u:
                by_user[u.group(1)] += 1
        if failed:
            per_hour[hour] += 1
            ip = FAILED_IP_RE.search(line)
            if ip:
                by_ip[ip.group(1)] += 1
                ip_hour[ip.group(1), hour] += 1
            if u:
                user_time[u.group(1), line[:10] + "T00" if per_day else hour] += 1
        elif "Accepted " in line:
            a = ACCEPTED_RE.search(line)
            if a:
                ts = datetime.strptime(m.group(0), "%Y-%m-%dT%H:%M:%S").strftime("%b %d %H:%M:%S")
                accepted.append({"timestamp": ts, "method": a.group(1), "user": a.group(2), "ip": a.group(3)})

    top_ips = top(by_ip)
    per_ip = {r["key"]: Counter() for r in top_ips}
    for (ip, hour), c in ip_hour.items():
        if ip in per_ip:
            per_ip[ip][hour] = c
    per_user = {}  # {user: [[time bin, count], ...]} - compact, it covers every username
    for (user, t), c in sorted(user_time.items()):
        per_user.setdefault(user, []).append([t, c])
    return {
        "since": since or "all time",
        "ssh": {
            "total_failed": total_failed,
            "by_ip": top_ips,
            "by_user": top_all(by_user),
            "accepted": accepted,
            "per_hour": hour_series(per_hour),
            "per_ip_hour": {ip: hour_series(c) for ip, c in per_ip.items()},  # top IPs only
            "per_user_time": per_user,
        },
    }


# ---- GreyNoise community API (only called when the user clicks an IP's check button) ----
GREYNOISE_KEY = os.environ.get("GREYNOISE_API_KEY", "").strip()
_gn_cache = {}  # ip -> result; only definite answers are cached, never errors
_gn_lock = threading.Lock()


def greynoise_lookup(raw_ip):
    """Return (http_status, result dict) with a normalized `classification`:
    malicious / benign / unknown / not seen. Errors come back as {"error": ...}."""
    try:
        addr = ipaddress.ip_address(raw_ip)
    except ValueError:
        return 400, {"error": "not an IP address"}
    ip = str(addr)
    if not addr.is_global:
        return 400, {"error": "private/reserved address, not sent to GreyNoise"}
    with _gn_lock:
        if ip in _gn_cache:
            return 200, _gn_cache[ip]

    headers = {"Accept": "application/json", "User-Agent": "cyber-cyber-lagebild"}
    if GREYNOISE_KEY:
        headers["key"] = GREYNOISE_KEY
    req = urllib.request.Request(f"https://api.greynoise.io/v3/community/{ip}", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as res:
            status, body = res.status, res.read()
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read()
    except Exception as e:
        return 502, {"error": f"GreyNoise unreachable: {e}"}

    try:
        data = json.loads(body or b"{}")
    except ValueError:
        data = {}
    if status == 429:
        return 429, {"error": "GreyNoise rate limit reached (without API key ~25 lookups/day)"}
    if status not in (200, 404):
        return 502, {"error": f"GreyNoise HTTP {status}: {data.get('message', '')}".strip()}

    if status == 404:  # never seen scanning the internet
        classification = "not seen"
    else:
        classification = data.get("classification") or ("benign" if data.get("riot") else "unknown")
    result = {
        "ip": ip,
        "classification": classification,
        "name": data.get("name") or "",
        "riot": bool(data.get("riot")),
        "last_seen": data.get("last_seen") or "",
        "link": f"https://viz.greynoise.io/ip/{ip}",
        "message": data.get("message") or "",
    }
    with _gn_lock:
        _gn_cache[ip] = result
    return 200, result


PAGE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Cyber Cyber Lagebild</title>
<style>
  :root { --bg:#0b0e14; --card:#131722; --text:#e6e6e6; --muted:#8a90a0; --accent:#ff5c5c; --accent2:#5c9cff; }
  body { background:var(--bg); color:var(--text); font-family:-apple-system,Segoe UI,Roboto,sans-serif; margin:0; padding:24px; }
  h1 { font-size:20px; margin:0 0 4px; display:flex; align-items:center; gap:10px; }
  .spinner { width:14px; height:14px; box-sizing:border-box; border-radius:50%; border:2px solid #2a3040;
             border-top-color:var(--accent2); visibility:hidden; animation:spin .8s linear infinite; }
  body.is-loading .spinner { visibility:visible; }
  @keyframes spin { to { transform:rotate(360deg); } }
  @media (prefers-reduced-motion: reduce) { .spinner { animation-duration:2.4s; } }
  .grid, .kpis { transition:opacity .2s; }
  body.is-stale .card.ssh { opacity:.6; } /* SSH panels of the old range still shown while the new one loads */
  .kpis { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:16px; margin-bottom:16px; }
  .kpi .big { line-height:1.1; }
  .kpi-cap { font-size:11px; color:var(--muted); margin-top:6px; }
  .sub { color:var(--muted); font-size:13px; margin-bottom:20px; }
  /* dense: if a wide card doesn't fit at the end of a row, a later normal card fills the gap */
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); gap:16px; grid-auto-flow:dense; }
  .card.wide { grid-column:span 2; }
  /* single-column layout: spanning 2 would create an extra column and overflow the page */
  @media (max-width: 720px) { .card.wide { grid-column:auto; } }
  .card { background:var(--card); border-radius:10px; padding:16px; display:flex; flex-direction:column; }
  .src { font-size:11px; color:var(--muted); margin:-8px 0 10px; line-height:1.4; }
  .src code { font-family:ui-monospace,Menlo,monospace; font-size:10.5px; color:#a7adbb; background:#1a1f2b;
              padding:0 4px; border-radius:3px; }
  .svc { font-size:11px; color:var(--muted); }
  .card h2 { font-size:14px; margin:0 0 12px; color:var(--muted); font-weight:600; text-transform:uppercase; letter-spacing:.03em; }
  .scroll { overflow-y:auto; max-height:320px; }
  .scroll.short { max-height:220px; }
  .scroll::-webkit-scrollbar { width:6px; }
  .scroll::-webkit-scrollbar-thumb { background:#2a3040; border-radius:3px; }
  .big { font-size:32px; font-weight:700; }
  .hint { font-size:11px; font-weight:400; text-transform:none; letter-spacing:0; color:#5a6070; margin-left:6px; }
  tr.iprow, tr.userrow { cursor:default; outline:none; }
  tr.iprow:hover td, tr.iprow:focus td, tr.userrow:hover td, tr.userrow:focus td { background:rgba(92,156,255,.08); }
  #ipPopover { position:fixed; display:none; z-index:10; width:340px; max-width:calc(100vw - 24px);
               box-sizing:border-box; pointer-events:none; background:var(--card); border:1px solid #2a3040;
               border-radius:10px; padding:12px 14px; box-shadow:0 8px 24px rgba(0,0,0,.45); }
  .pop-head { display:flex; justify-content:space-between; align-items:baseline; margin-bottom:2px; }
  .pop-ip { font-weight:600; font-size:14px; font-family:ui-monospace,Menlo,monospace; }
  .pop-total { color:var(--accent2); font-weight:600; font-size:13px; }
  .pop-sub { font-size:11px; color:var(--muted); margin-bottom:10px; }
  /* GreyNoise: per-IP check button, replaced by a classification badge */
  /* negative vertical margins: the button must not make its row taller than a badge row */
  .gn-btn { display:inline-flex; align-items:center; justify-content:center; width:18px; height:15px; padding:0;
            margin:-3px 0 -3px 6px; vertical-align:-2px; background:none; border:1px solid #2a3040; border-radius:4px;
            color:var(--muted); cursor:pointer; transition:color .15s, border-color .15s, transform .08s; }
  .gn-btn:hover, .gn-btn:focus-visible { color:var(--accent2); border-color:var(--accent2); outline:none; }
  .gn-btn:active { transform:scale(.9); }
  .gn-btn.err { color:#e5b85c; border-color:#e5b85c; font-size:11px; font-weight:700; }
  .gn-btn.busy { cursor:progress; }
  .gn-btn.busy svg { display:none; }
  .gn-btn.busy::after { content:''; width:8px; height:8px; border-radius:50%; border:2px solid #2a3040;
                        border-top-color:var(--accent2); animation:spin .8s linear infinite; }
  .gn { margin-left:6px; padding:1px 6px; border-radius:8px; font-size:10px; font-weight:600; text-transform:uppercase;
        letter-spacing:.03em; text-decoration:none; vertical-align:1px; white-space:nowrap; }
  .gn:hover { filter:brightness(1.25); text-decoration:underline; }
  .gn-malicious { color:#ff7b7b; background:rgba(255,92,92,.15); }
  .gn-benign    { color:#5fd38d; background:rgba(95,211,141,.14); }
  .gn-unknown   { color:#e5b85c; background:rgba(229,184,92,.14); }
  .gn-notseen   { color:var(--muted); background:#1e2330; }
  .tchart.mini { flex:none; height:130px; min-height:0; }
  .search { display:flex; align-items:center; flex-wrap:wrap; gap:8px; margin-bottom:8px; }
  .search input { flex:1; min-width:140px; background:var(--bg); color:var(--text); border:1px solid #242a38;
                  border-radius:6px; padding:6px 10px; font-size:13px; transition:border-color .15s; }
  .search input:focus { outline:none; border-color:var(--accent2); }
  .searchmeta { font-size:11px; color:var(--muted); white-space:nowrap; }
  mark { background:rgba(92,156,255,.3); color:var(--text); border-radius:2px; }
  /* time chart: fills the card (cards stretch to row height), never scrolls */
  .tchart { flex:1; display:flex; flex-direction:column; min-height:200px; position:relative; }
  .tplot { flex:1; display:flex; align-items:stretch; position:relative; padding-top:16px;
           border-bottom:1px solid #2a3040; }
  .tplot::before { content:''; position:absolute; left:0; right:0; top:16px; border-top:1px dashed #1e2330; }
  .tmax { position:absolute; top:0; left:0; font-size:11px; color:var(--muted); }
  .tcol { flex:1; min-width:0; display:flex; align-items:flex-end; border-radius:4px 4px 0 0; }
  .tcol:hover { background:rgba(255,255,255,.04); }
  .tbar { position:relative; width:100%; background:var(--accent); border-radius:4px 4px 0 0;
          transition:filter .1s, opacity .15s; }
  .tcol:hover .tbar { filter:brightness(1.25); }
  /* hovered username: its share of each bar in blue, bars without it dimmed */
  .tchart.hl-user .tcol:not(.hl) .tbar { opacity:.2; }
  .tseg { position:absolute; left:0; right:0; bottom:0; min-height:2px; background:var(--accent2);
          border-radius:inherit; }
  .thl { position:absolute; top:0; right:0; max-width:75%; overflow:hidden; text-overflow:ellipsis;
         white-space:nowrap; font-size:11px; color:var(--accent2); }
  .taxis { display:flex; justify-content:space-between; font-size:11px; color:var(--muted); margin-top:6px; }
  .ttip { position:absolute; display:none; pointer-events:none; transform:translate(-50%, calc(-100% - 6px));
          background:#1e2330; border:1px solid #2a3040; border-radius:6px; padding:4px 8px;
          font-size:12px; color:var(--text); white-space:nowrap; z-index:2; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  td { padding:4px 0; border-bottom:1px solid #1e2330; }
  td.count { padding-left:10px; text-align:right; color:var(--accent2); font-weight:600; }
  .bar { height:6px; background:#1e2330; border-radius:3px; overflow:hidden; margin-top:2px; }
  .bar div { height:100%; background:var(--accent); }
  .flag { color:var(--accent); font-weight:600; }
  .empty { color:var(--muted); font-size:13px; }
  pre { font-size:12px; color:var(--muted); white-space:pre-wrap; max-height:200px; overflow:auto; }
  .ranges { display:flex; gap:8px; margin-bottom:20px; flex-wrap:wrap; }
  .ranges button {
    background:var(--card); color:var(--text); border:1px solid #242a38; border-radius:6px;
    padding:6px 14px; font-size:13px; cursor:pointer;
  }
  .ranges button { transition:background .15s, border-color .15s, color .15s, transform .08s, opacity .15s; }
  .ranges button:hover { border-color:var(--accent2); }
  .ranges button:active { transform:scale(.94); }
  .ranges button:focus-visible { outline:2px solid var(--accent2); outline-offset:2px; }
  .ranges button.active { background:var(--accent2); color:#0b0e14; border-color:var(--accent2); font-weight:600; }
  .ranges button.loading { opacity:.6; cursor:progress; }
  #autoRefreshToggle { display:inline-flex; align-items:center; gap:8px; background:var(--bg); }
  #autoRefreshToggle .dot { width:8px; height:8px; border-radius:50%; background:var(--muted); transition:background .15s; }
  #autoRefreshToggle.on { background:var(--accent2); border-color:var(--accent2); color:#0b0e14; font-weight:600; }
  #autoRefreshToggle.on .dot { background:#0b0e14; animation:pulse 1.6s ease-out infinite; }
  @keyframes pulse {
    0%   { box-shadow:0 0 0 0 rgba(11,14,20,.6); }
    100% { box-shadow:0 0 0 6px rgba(11,14,20,0); }
  }
</style>
</head>
<body>
<h1>Cyber Cyber Lagebild <span id="loadingIcon" class="spinner" role="status" aria-label="Loading data" title="Loading data…"></span></h1>
<div class="sub" id="sub">loading...</div>
<div class="ranges" id="ranges">
  <button data-range="1d">1 day</button>
  <button data-range="1w">1 week</button>
  <button data-range="1m">1 month</button>
  <button data-range="1y">1 year</button>
  <button data-range="all">All</button>
  <button id="autoRefreshToggle" style="margin-left:auto;" aria-pressed="false" title="Reload stats every 30 seconds">
    <span class="dot"></span><span class="label">Auto-refresh: off</span>
  </button>
</div>
<div class="kpis" id="kpis"></div>
<div class="grid" id="grid"></div>
<div id="ipPopover" role="tooltip"></div>

<script>
const REFRESH_SECONDS = 30;
let currentRange = '1d';
let autoRefreshEnabled = false; // off by default; toggle with the button
let refreshTimer = null;
let lastWindow = '';
let lastUpdated = null;
const RANGE_LABEL = {'1d': '1 day', '1w': '1 week', '1m': '1 month', '1y': '1 year', all: 'all time'};
let displayedRange = null; // range whose data is currently rendered
let loadingRange = null;   // range being fetched right now (null = idle)
let requestSeq = 0;        // only the newest request may render
let inflight = null;       // AbortController of the newest request

function setLoading(range) {
  loadingRange = range;
  document.body.classList.toggle('is-loading', !!range);
  // dim only when the shown data belongs to a different range than the one requested
  document.body.classList.toggle('is-stale', !!range && displayedRange !== null && range !== displayedRange);
  document.querySelectorAll('.ranges button[data-range]').forEach(b =>
    b.classList.toggle('loading', !!range && b.dataset.range === range));
  updateSub();
}

function updateSub() {
  const parts = [];
  if (lastWindow) parts.push('Window: ' + lastWindow);
  if (loadingRange) {
    parts.push(loadingRange !== displayedRange ? `loading ${RANGE_LABEL[loadingRange]}…` : 'updating…');
  }
  parts.push(autoRefreshEnabled ? `auto-refresh on (every ${REFRESH_SECONDS}s)` : 'auto-refresh off');
  if (lastUpdated) parts.push('last updated ' + lastUpdated.toLocaleTimeString());
  document.getElementById('sub').textContent = parts.join(' · ');
}

function renderAutoRefreshButton() {
  const btn = document.getElementById('autoRefreshToggle');
  btn.classList.toggle('on', autoRefreshEnabled);
  btn.setAttribute('aria-pressed', String(autoRefreshEnabled));
  btn.querySelector('.label').textContent = autoRefreshEnabled
    ? `Auto-refresh: on (${REFRESH_SECONDS}s)`
    : 'Auto-refresh: off';
}

function setupAutoRefreshToggle() {
  const btn = document.getElementById('autoRefreshToggle');
  btn.addEventListener('click', () => {
    autoRefreshEnabled = !autoRefreshEnabled;
    if (autoRefreshEnabled) {
      startAutoRefresh();
      refresh(); // immediate update so turning it on visibly does something
    } else {
      stopAutoRefresh();
    }
    renderAutoRefreshButton();
    updateSub();
  });
  renderAutoRefreshButton();
}

function startAutoRefresh() {
  stopAutoRefresh();
  // skip a tick if a load is still running instead of aborting it
  refreshTimer = setInterval(() => { if (!loadingRange) refresh(); }, REFRESH_SECONDS * 1000);
}

function stopAutoRefresh() {
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
}

document.getElementById('ranges').addEventListener('click', (e) => {
  const btn = e.target.closest('button[data-range]');
  if (!btn) return;
  if (btn.dataset.range === currentRange && loadingRange === currentRange) return; // already loading it
  currentRange = btn.dataset.range;
  setActiveButton();
  refresh();
});

function setActiveButton() {
  document.querySelectorAll('.ranges button[data-range]').forEach(b => {
    b.classList.toggle('active', b.dataset.range === currentRange);
  });
}

// source: one line under the title naming the attacked service and the log it comes from
function card(title, bodyHtml, extraClass = '', source = '') {
  const src = source ? `<div class="src">${source}</div>` : '';
  return `<div class="card ${extraClass}"><h2>${title}</h2>${src}${bodyHtml}</div>`;
}

// What usually listens on the destination ports scanners probe most.
const PORT_NAMES = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 81: 'HTTP alt', 110: 'POP3',
  111: 'RPC', 123: 'NTP', 135: 'MS RPC', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 389: 'LDAP',
  443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 502: 'Modbus', 587: 'SMTP sub', 993: 'IMAPS', 995: 'POP3S',
  1080: 'SOCKS', 1433: 'MS SQL', 1521: 'Oracle DB', 1723: 'PPTP VPN', 1883: 'MQTT', 2222: 'SSH alt',
  2323: 'Telnet alt', 2375: 'Docker API', 2376: 'Docker TLS', 3128: 'HTTP proxy', 3306: 'MySQL',
  3389: 'RDP', 5060: 'SIP', 5432: 'PostgreSQL', 5555: 'ADB (Android)', 5900: 'VNC', 5985: 'WinRM',
  6379: 'Redis', 7547: 'TR-069 (router)', 8000: 'HTTP alt', 8080: 'HTTP alt', 8081: 'HTTP alt',
  8291: 'MikroTik', 8443: 'HTTPS alt', 8888: 'HTTP alt', 9000: 'HTTP alt', 9200: 'Elasticsearch',
  10250: 'Kubelet', 11211: 'Memcached', 27017: 'MongoDB', 37215: 'Huawei router (exploit)',
  52869: 'Realtek UPnP (exploit)',
};
function portName(p) { return PORT_NAMES[p] || ''; }

function portKeyHtml(p) {
  const name = portName(p);
  return escapeHtml(p) + (name ? ` <span class="svc">${escapeHtml(name)}</span>` : '');
}

// ufw source IP: address, GreyNoise slot, and the services (ports) it was blocked on
function ufwIpKeyHtml(ip, row) {
  const ports = (row && row.ports) || [];
  // short names, max 2, so a row stays on one line next to a GreyNoise badge
  const svc = ports.slice(0, 2).map(p => (portName(p) || 'port ' + p).replace(/ \\(.*\\)$/, '')).join(', ')
    + (ports.length > 2 ? ' …' : '');
  return ipKeyHtml(ip) + (svc ? ` <span class="svc" title="most-hit ports: ${escapeHtml(ports.join(', '))}">→ ${escapeHtml(svc)}</span>` : '');
}

// single-number tile; alert=true colours the value red
function kpi(title, value, caption, alert = false, extraClass = '') {
  return `<div class="card kpi ${extraClass}"><h2>${title}</h2>
    <div class="big${alert ? ' flag' : ''}">${value}</div>
    <div class="kpi-cap">${caption}</div></div>`;
}
// Log values (usernames, IPs) are attacker-controlled: always escape before inserting as HTML.
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
}

function maxCount(rows) {
  return rows.reduce((m, r) => Math.max(m, r.count), 1);
}

// opts.max: scale bars against this instead of the shown rows' max
// opts.keyHtml: custom (already escaped) rendering of the key column
function tableFrom(rows, opts = {}) {
  if (!rows || rows.length === 0) return '<div class="empty">No data</div>';
  const max = opts.max || maxCount(rows);
  const keyHtml = opts.keyHtml || escapeHtml;
  const rowAttr = opts.rowAttr || (() => '');
  return '<table>' + rows.map(r => `
    <tr${rowAttr(r)}><td>${keyHtml(r.key, r)}<div class="bar"><div style="width:${(r.count/max*100)}%"></div></div></td><td class="count">${r.count}</td></tr>
  `).join('') + '</table>';
}

// ---- GreyNoise lookup per IP (on click only: the free API allows ~25 lookups/day) ----
const gnResults = new Map(); // ip -> {classification, name, ...} or {error}; survives re-renders
const gnBusy = new Set();
const GN_ICON = '<svg width="10" height="10" viewBox="0 0 16 16" aria-hidden="true"><circle cx="6.5" cy="6.5" r="4.5" fill="none" stroke="currentColor" stroke-width="2"/><path d="M10 10l4.5 4.5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>';

function gnInnerHtml(ip) {
  const r = gnResults.get(ip);
  const ipAttr = escapeHtml(ip);
  if (r && !r.error) {
    const cls = 'gn-' + r.classification.replace(/\\s+/g, '');
    const tip = [`GreyNoise: ${r.classification}`, r.name && r.name !== 'unknown' ? r.name : '',
                 r.riot ? 'known business service (RIOT)' : '', r.last_seen ? `last seen ${r.last_seen}` : '',
                 'click to open GreyNoise'].filter(Boolean).join(' · ');
    return `<a class="gn ${escapeHtml(cls)}" href="${escapeHtml(r.link)}" target="_blank" rel="noopener noreferrer"
      title="${escapeHtml(tip)}">${escapeHtml(r.classification)}</a>`;
  }
  const busy = gnBusy.has(ip);
  const title = r ? `GreyNoise lookup failed: ${r.error} (click to retry)` : 'Check this IP on GreyNoise';
  return `<button type="button" class="gn-btn${r ? ' err' : ''}${busy ? ' busy' : ''}" data-gn-ip="${ipAttr}"
    title="${escapeHtml(title)}" aria-label="${escapeHtml(title)}">${r ? '!' : GN_ICON}</button>`;
}

// IP cell: the address plus a slot that holds the button or the badge
function ipKeyHtml(ip) {
  return `${escapeHtml(ip)}<span class="gn-slot" data-ip="${escapeHtml(ip)}">${gnInnerHtml(ip)}</span>`;
}

// the same IP can appear in several panels: update every slot for it
function renderGnSlots(ip) {
  document.querySelectorAll('.gn-slot').forEach(s => { if (s.dataset.ip === ip) s.innerHTML = gnInnerHtml(ip); });
}

async function checkGreyNoise(ip) {
  if (gnBusy.has(ip)) return;
  gnBusy.add(ip);
  gnResults.delete(ip); // clear an earlier error
  renderGnSlots(ip);
  try {
    const res = await fetch('/api/greynoise?ip=' + encodeURIComponent(ip));
    const data = await res.json().catch(() => ({error: 'HTTP ' + res.status}));
    gnResults.set(ip, res.ok ? data : {error: data.error || 'HTTP ' + res.status});
  } catch (err) {
    gnResults.set(ip, {error: err.message});
  }
  gnBusy.delete(ip);
  renderGnSlots(ip);
}

function setupGreyNoise() {
  document.getElementById('grid').addEventListener('click', (e) => {
    const btn = e.target.closest('.gn-btn');
    if (btn) checkGreyNoise(btn.dataset.gnIp);
  });
}

// ---- Username panel with search ----
let userRows = [];   // latest by_user data, sorted by count, then A–Z (from the server)
let userQuery = '';  // survives auto-refresh re-renders

function highlightMatch(text, q) {
  const s = String(text);
  const i = q ? s.toLowerCase().indexOf(q) : -1;
  if (i < 0) return escapeHtml(s);
  return escapeHtml(s.slice(0, i)) + '<mark>' + escapeHtml(s.slice(i, i + q.length)) + '</mark>'
       + escapeHtml(s.slice(i + q.length));
}

function renderUserList() {
  const list = document.getElementById('userList');
  const meta = document.getElementById('userSearchMeta');
  if (!list) return;
  const q = userQuery.trim().toLowerCase();
  let rows = userRows;
  if (q) {
    rows = userRows
      .filter(r => String(r.key).toLowerCase().includes(q))
      .sort((a, b) => String(a.key).localeCompare(String(b.key), undefined, {sensitivity: 'base'}));
  }
  if (userRows.length === 0) {
    list.innerHTML = '<div class="empty">No data</div>';
  } else if (rows.length === 0) {
    list.innerHTML = '<div class="empty">No usernames match "' + escapeHtml(userQuery.trim()) + '"</div>';
  } else {
    // bars keep the overall scale, so search results stay comparable to the full list
    list.innerHTML = tableFrom(rows, {max: maxCount(userRows), keyHtml: k => highlightMatch(k, q),
      rowAttr: r => ` class="userrow" tabindex="0" data-user="${escapeHtml(r.key)}"`});
  }
  meta.textContent = q
    ? `${rows.length} of ${userRows.length} · A–Z`
    : `${userRows.length} · most tried first`;
}

function userCardHtml() {
  return `<div class="card ssh"><h2>Top usernames tried</h2>
    <div class="src">SSH · usernames from failed and invalid-user logins · <code>journalctl -u ssh</code> · hover a row to see it in the chart</div>
    <div class="search">
      <input id="userSearch" type="search" placeholder="Search usernames…" autocomplete="off" spellcheck="false">
      <span class="searchmeta" id="userSearchMeta"></span>
    </div>
    <div class="scroll fill" id="userList"></div></div>`;
}

function setupUserSearch() {
  const grid = document.getElementById('grid');
  grid.addEventListener('input', (e) => {
    if (e.target.id !== 'userSearch') return;
    userQuery = e.target.value;
    renderUserList();
    document.getElementById('userList').scrollTop = 0;
  });
}

// ---- Failed attempts over time: column chart, time runs left -> right ----
// Bucket size adapts to the window so the chart never has hundreds of columns:
// <=2 days -> hour, <=8 days -> 6 hours, <=62 days -> day, <=400 days -> week, else month.
const RANGE_DAYS = {'1d': 1, '1w': 7, '1m': 30, '1y': 365};
const UNIT_NAME = {hour: 'hour', '6h': '6 hours', day: 'day', week: 'week', month: 'month'};

function parseHourKey(k) { // "2026-11-22T14" (server local time)
  const [date, h] = k.split('T');
  const [y, m, d] = date.split('-').map(Number);
  return new Date(y, m - 1, d, Number(h));
}

function floorTo(unit, d) {
  const x = new Date(d);
  x.setMinutes(0, 0, 0);
  if (unit === '6h') x.setHours(Math.floor(x.getHours() / 6) * 6);
  if (unit === 'day' || unit === 'week' || unit === 'month') x.setHours(0);
  if (unit === 'week') x.setDate(x.getDate() - (x.getDay() + 6) % 7); // Monday
  if (unit === 'month') x.setDate(1);
  return x;
}

function stepUnit(unit, d) {
  const x = new Date(d);
  if (unit === 'hour') x.setHours(x.getHours() + 1);
  else if (unit === '6h') x.setHours(x.getHours() + 6);
  else if (unit === 'day') x.setDate(x.getDate() + 1);
  else if (unit === 'week') x.setDate(x.getDate() + 7);
  else x.setMonth(x.getMonth() + 1);
  return x;
}

function bucketLabel(unit, t, short) {
  const f = (o) => t.toLocaleString(undefined, o);
  const time = {hour: '2-digit', minute: '2-digit'};
  const md = {month: 'short', day: 'numeric'};
  if (unit === 'hour') return short ? f(time) : f({...md, ...time});
  if (unit === '6h') {
    if (short) return f(md);
    const end = stepUnit('6h', t);
    return f({...md, ...time}) + '–' + end.toLocaleString(undefined, time);
  }
  if (unit === 'day') return short ? f(md) : f({weekday: 'short', ...md});
  if (unit === 'week') return short ? f(md) : 'Week of ' + f(md);
  return short ? f({month: 'short', year: '2-digit'}) : f({month: 'long', year: 'numeric'});
}

// Time frame (start + bin size) is derived from the overall series and then shared,
// so per-IP timelines line up with the main chart.
function timeFrame(perHour, range) {
  const now = new Date();
  const first = perHour && perHour.length ? parseHourKey(perHour[0].hour) : now;
  const start = RANGE_DAYS[range] ? new Date(now - RANGE_DAYS[range] * 864e5) : first;
  const spanH = (now - start) / 36e5;
  const unit = spanH <= 48 ? 'hour' : spanH <= 8 * 24 ? '6h' : spanH <= 62 * 24 ? 'day'
             : spanH <= 400 * 24 ? 'week' : 'month';
  return {start, now, unit};
}

function bucketize(perHour, frame) {
  const counts = new Map();
  (perHour || []).forEach(p => {
    const k = floorTo(frame.unit, parseHourKey(p.hour)).getTime();
    counts.set(k, (counts.get(k) || 0) + p.count);
  });
  const buckets = [];
  for (let t = floorTo(frame.unit, frame.start); t <= frame.now && buckets.length < 500; t = stepUnit(frame.unit, t)) {
    buckets.push({t, c: counts.get(t.getTime()) || 0}); // empty buckets stay as real zeros
  }
  return buckets;
}

// mini: fixed-height chart without hover tooltips (used inside the IP popover)
function columnsHtml(buckets, unit, mini = false) {
  const max = buckets.reduce((m, b) => Math.max(m, b.c), 1);
  const cols = buckets.map(b => {
    const bar = b.c ? `<div class="tbar" style="height:max(2px, ${b.c / max * 100}%)"></div>` : '';
    const tip = mini ? '' : ` data-tip="${bucketLabel(unit, b.t, false)} — ${b.c} failed"`;
    return `<div class="tcol" data-c="${b.c}"${tip}>${bar}</div>`;
  }).join('');
  const mid = buckets[Math.floor(buckets.length / 2)];
  const axis = [buckets[0], mid, buckets[buckets.length - 1]]
    .map(b => `<span>${bucketLabel(unit, b.t, true)}</span>`).join('');
  return `
    <div class="tchart${mini ? ' mini' : ''}">
      <div class="tplot" style="gap:${buckets.length > 60 ? 1 : 2}px">
        <span class="tmax">${max}</span>${mini ? '' : '<span class="thl"></span>'}${cols}
      </div>
      <div class="taxis">${axis}</div>
      ${mini ? '' : '<div class="ttip"></div>'}
    </div>`;
}

function timeChartCard(perHour, frame) {
  const title = 'Failed SSH attempts per ' + UNIT_NAME[frame.unit];
  const src = 'SSH · "Failed password" lines · <code>journalctl -u ssh</code>';
  const buckets = bucketize(perHour, frame);
  if (!buckets.some(b => b.c)) return card(title, '<div class="empty">No failed attempts in window</div>', 'wide ssh', src);
  return card(title, columnsHtml(buckets, frame.unit), 'wide ssh', src);
}

// ---- Top source IPs: hover a row for that IP's timeline ----
let ipTimelines = {}; // ip -> [{hour, count}]
let chartFrame = null; // frame of the currently displayed data
let hoveredIpRow = null;

function ipPopoverHtml(ip) {
  const buckets = bucketize(ipTimelines[ip], chartFrame);
  const total = buckets.reduce((s, b) => s + b.c, 0);
  const head = `<div class="pop-head"><span class="pop-ip">${escapeHtml(ip)}</span>
    <span class="pop-total">${total} failed</span></div>`;
  if (!total) return head + '<div class="empty">No timeline data in window</div>';
  const peak = buckets.reduce((p, b) => (b.c > p.c ? b : p), buckets[0]);
  const active = buckets.filter(b => b.c).length;
  const unitName = UNIT_NAME[chartFrame.unit];
  return head
    + `<div class="pop-sub">per ${unitName} · peak ${bucketLabel(chartFrame.unit, peak.t, false)} (${peak.c})
       · active in ${active} of ${buckets.length} bins</div>`
    + columnsHtml(buckets, chartFrame.unit, true);
}

function showIpPopover(row) {
  const pop = document.getElementById('ipPopover');
  if (!row) { pop.style.display = 'none'; hoveredIpRow = null; return; }
  if (row === hoveredIpRow && pop.style.display === 'block') return;
  hoveredIpRow = row;
  pop.innerHTML = ipPopoverHtml(row.dataset.ip);
  pop.style.display = 'block';

  // place beside the panel (right, else left, else below the row), clamped to the viewport
  const cardRect = row.closest('.card').getBoundingClientRect();
  const r = row.getBoundingClientRect();
  const pw = pop.offsetWidth, ph = pop.offsetHeight, m = 12;
  let x, y = r.top + r.height / 2 - ph / 2;
  if (cardRect.right + m + pw <= innerWidth) x = cardRect.right + m;
  else if (cardRect.left - m - pw >= 0) x = cardRect.left - m - pw;
  else { x = r.left; y = r.bottom + 6; }
  pop.style.left = Math.max(m, Math.min(innerWidth - pw - m, x)) + 'px';
  pop.style.top = Math.max(m, Math.min(innerHeight - ph - m, y)) + 'px';
}

function setupIpPopover() {
  const grid = document.getElementById('grid');
  grid.addEventListener('mouseover', (e) => showIpPopover(e.target.closest('tr.iprow')));
  grid.addEventListener('mouseleave', () => showIpPopover(null));
  grid.addEventListener('focusin', (e) => showIpPopover(e.target.closest('tr.iprow')));
  grid.addEventListener('focusout', () => showIpPopover(null));
  window.addEventListener('scroll', () => showIpPopover(null), {passive: true});
}

// ---- Top usernames: hover a row to highlight that username in the time chart ----
let userTimes = new Map(); // user -> [[time bin, count], ...] of "Failed password" lines, like the chart
let hoveredUser = null;

// Bars without attempts for `user` are dimmed; the others get a blue segment for its share.
function highlightUser(user) {
  if (user === hoveredUser) return;
  hoveredUser = user;
  const chart = document.querySelector('#grid .tchart:not(.mini)');
  if (!chart) return;
  const cols = chart.querySelectorAll('.tcol');
  chart.querySelectorAll('.tseg').forEach(el => el.remove());
  cols.forEach(c => c.classList.remove('hl'));
  chart.classList.toggle('hl-user', user !== null);
  const label = chart.querySelector('.thl');
  if (user === null) { label.textContent = ''; return; }

  // same frame as the chart, so bucket i belongs to column i
  const series = (userTimes.get(user) || []).map(([hour, count]) => ({hour, count}));
  const buckets = bucketize(series, chartFrame);
  let total = 0, active = 0;
  buckets.forEach((b, i) => {
    const col = cols[i], bar = col && col.querySelector('.tbar');
    if (!b.c || !bar) return;
    total += b.c;
    active++;
    col.classList.add('hl');
    const seg = document.createElement('div');
    seg.className = 'tseg';
    seg.style.height = Math.min(100, b.c / Number(col.dataset.c) * 100) + '%';
    bar.appendChild(seg);
  });
  // textContent: usernames come from attackers
  label.textContent = total
    ? `${user} · ${total} failed password${total === 1 ? '' : 's'} · in ${active} of ${buckets.length} bars`
    : `${user} · no failed passwords in this window`;
}

function setupUserHighlight() {
  const grid = document.getElementById('grid');
  const rowUser = (e) => { const r = e.target.closest('tr.userrow'); return r ? r.dataset.user : null; };
  grid.addEventListener('mouseover', (e) => highlightUser(rowUser(e)));
  grid.addEventListener('mouseleave', () => highlightUser(null));
  grid.addEventListener('focusin', (e) => highlightUser(rowUser(e)));
  grid.addEventListener('focusout', () => highlightUser(null));
}

function setupChartTooltips() {
  const grid = document.getElementById('grid');
  const hideAll = () => grid.querySelectorAll('.ttip').forEach(t => { t.style.display = 'none'; });
  grid.addEventListener('mousemove', (e) => {
    const col = e.target.closest('.tcol');
    if (!col) return hideAll();
    const chart = col.closest('.tchart');
    const tip = chart.querySelector('.ttip');
    tip.textContent = col.dataset.tip;
    tip.style.display = 'block';
    const cr = chart.getBoundingClientRect();
    const r = col.getBoundingClientRect();
    const half = tip.offsetWidth / 2;
    const x = Math.max(half, Math.min(cr.width - half, r.left + r.width / 2 - cr.left));
    tip.style.left = x + 'px';
    tip.style.top = (r.top - cr.top) + 'px';
  });
  grid.addEventListener('mouseleave', hideAll);
}

// Two requests in parallel: the fast part (auth.log, ufw, fail2ban) and the slow SSH journal.
// Each part is drawn as soon as it arrives; until then its panels show "Loading…".
let fastData = null; // last /api/stats/fast response
let sshData = null;  // last /api/stats/ssh response (for displayedRange)
let fastError = null, sshError = null; // message shown in a part's panels when its request failed

async function refresh() {
  // The old data stays on screen until the new response arrives.
  const seq = ++requestSeq;
  const range = currentRange;
  if (inflight) inflight.abort(); // a newer click wins; drop the older requests
  const ctrl = new AbortController();
  inflight = ctrl;
  setLoading(range);

  const errors = [];
  const load = async (url, onData, onError) => {
    try {
      const res = await fetch(url, {signal: ctrl.signal});
      if (!res.ok) {
        let msg = 'HTTP ' + res.status;
        try { msg = (await res.json()).error || msg; } catch (e) { /* not JSON */ }
        throw new Error(msg);
      }
      const d = await res.json();
      if (seq !== requestSeq) return; // a different range was requested meanwhile
      onData(d);
    } catch (err) {
      if (seq !== requestSeq) return; // superseded by a newer request
      errors.push(err.message);
      onError(err.message);
    }
    render();
  };

  await Promise.all([
    load('/api/stats/fast',
      d => { fastData = d; fastError = null; },
      msg => { fastData = null; fastError = msg; }),
    load('/api/stats/ssh?range=' + encodeURIComponent(range),
      d => { sshData = d; sshError = null; displayedRange = range; lastWindow = d.since;
             document.body.classList.remove('is-stale'); },
      // drop the old range's SSH data, so it is never shown under the new range's button
      msg => { sshData = null; sshError = msg; displayedRange = range; lastWindow = '';
               document.body.classList.remove('is-stale'); }),
  ]);
  if (seq !== requestSeq) return;
  inflight = null;
  setLoading(null);
  if (errors.length) {
    document.getElementById('sub').textContent = 'Failed to load stats: ' + errors.join(', ');
    return;
  }
  lastUpdated = new Date();
  updateSub();
}

const LOADING_HTML = '<div class="empty">Loading…</div>';
const placeholderHtml = err => (err ? `<div class="empty flag">${escapeHtml(err)}</div>` : LOADING_HTML);

function render() {
  const f = fastData, s = sshData && sshData.ssh;
  const fastPh = placeholderHtml(fastError), sshPh = placeholderHtml(sshError);
  const range = displayedRange || currentRange;
  const g = document.getElementById('grid');
  // remember search-box focus/caret so an auto-refresh doesn't interrupt typing
  const active = document.activeElement;
  const searchFocus = active && active.id === 'userSearch'
    ? {start: active.selectionStart, end: active.selectionEnd} : null;
  // 1. Single-number tiles get their own row, so they never sit next to long lists.
  document.getElementById('kpis').innerHTML =
      kpi('Total failed SSH attempts', s ? s.total_failed : (sshError ? '–' : '…'), 'SSH logins from the network · journalctl -u ssh · selected window', false, 'ssh')
    + kpi('sudo failures', f ? f.sudo.failures : (fastError ? '–' : '…'), 'local, wrong sudo password · /var/log/auth.log · whole file', !!f && f.sudo.failures > 0)
    + kpi('su failures', f ? f.su.failed : (fastError ? '–' : '…'), `local · ${f ? f.su.opened : '…'} su sessions opened · /var/log/auth.log · whole file`, !!f && f.su.failed > 0);

  // 2. List panels, roughly longest first, so neighbours in a row have similar heights.
  ipTimelines = s ? s.per_ip_hour || {} : {};
  chartFrame = timeFrame(s ? s.per_hour : [], range);
  showIpPopover(null); // rows are about to be replaced
  highlightUser(null); // so is the chart
  userRows = s ? s.by_user || [] : [];
  userTimes = new Map(Object.entries(s ? s.per_user_time || {} : {}));

  let accHtml;
  if (!s) {
    accHtml = sshPh;
  } else if (s.accepted.length === 0) {
    accHtml = '<div class="empty">No successful logins in window</div>';
  } else {
    accHtml = '<div class="scroll short"><table>' + s.accepted.map(a =>
      `<tr><td>${escapeHtml(a.timestamp)}</td><td>${escapeHtml(a.user)} via ${escapeHtml(a.method)}</td><td class="flag">${escapeHtml(a.ip)}</td></tr>`
    ).join('') + '</table></div>';
  }
  const naHtml = !f ? fastPh : f.new_accounts.length
    ? '<pre>' + f.new_accounts.map(escapeHtml).join('\\n') + '</pre>'
    : '<div class="empty">None detected in log</div>';
  const fbHtml = !f ? fastPh : f.fail2ban_banned.length
    ? '<table>' + f.fail2ban_banned.map(ip => `<tr><td>${ipKeyHtml(ip)}</td></tr>`).join('') + '</table>'
    : '<div class="empty">fail2ban not running / no bans</div>';
  const fastTable = (rows, opts) => (f ? tableFrom(rows(f), opts) : fastPh);

  g.innerHTML = [
    // long: up to 15 rows, a full-height chart, or a scrollable list
    card('Top source IPs (failed SSH)',
      s ? tableFrom(s.by_ip, {keyHtml: ipKeyHtml,
        rowAttr: r => ` class="iprow" tabindex="0" data-ip="${escapeHtml(r.key)}"`}) : sshPh,
      'ssh', `SSH · password guessing · <code>journalctl -u ssh</code> · hover a row for its timeline, ${GN_ICON} = GreyNoise lookup`),
    userCardHtml(),
    s ? timeChartCard(s.per_hour, chartFrame)
      : card('Failed SSH attempts over time', sshPh, 'wide ssh', 'SSH · "Failed password" lines · <code>journalctl -u ssh</code>'),
    card('ufw blocked - by source IP', fastTable(f => f.ufw_by_ip, {keyHtml: ufwIpKeyHtml}),
      '', 'Any port · firewall drops before a service sees them · → services tried · <code>/var/log/ufw.log</code>'),
    // medium
    card('ufw blocked - by port', fastTable(f => f.ufw_by_port, {keyHtml: portKeyHtml}),
      '', 'Destination port = service being probed · <code>/var/log/ufw.log</code>'),
    card('fail2ban: currently banned IPs', fbHtml,
      '', 'SSH · banned after repeated failed logins · <code>fail2ban-client status sshd</code>'),
    card('Successful SSH logins', accHtml,
      'ssh', 'SSH · accepted logins · <code>journalctl -u ssh</code>'),
    // short
    card('cron auth sessions by user', fastTable(f => f.cron_auth),
      '', 'Local · cron jobs opening sessions · <code>/var/log/auth.log</code>'),
    card('sudo usage by user', fastTable(f => f.sudo.by_user),
      '', 'Local · sudo commands run · <code>/var/log/auth.log</code>'),
    card('New user/group creation', naHtml,
      '', 'Local · useradd / groupadd · <code>/var/log/auth.log</code>'),
  ].join('');

  const search = document.getElementById('userSearch');
  search.value = userQuery;
  if (s) renderUserList();
  else document.getElementById('userList').innerHTML = sshPh;
  if (searchFocus) {
    search.focus();
    search.setSelectionRange(searchFocus.start, searchFocus.end);
  }

  fitScrollPanels();
}

// Every `.scroll.fill` panel (usernames list, per-hour chart) grows to the height
// of the tallest card in its grid row instead of stopping at the 320px CSS cap.
function fitScrollPanels() {
  requestAnimationFrame(() => {
    const grid = document.getElementById('grid');
    const fills = Array.from(grid.querySelectorAll('.scroll.fill'));
    if (fills.length === 0) return;

    // 1. Back to the CSS cap, and stop grid stretching, so the natural
    //    height of every card can be measured.
    fills.forEach(s => { s.style.maxHeight = ''; });
    grid.style.alignItems = 'start';

    const rowHeights = new Map(); // row top (px) -> tallest card in that row
    grid.querySelectorAll('.card').forEach(c => {
      const r = c.getBoundingClientRect();
      const key = Math.round(r.top);
      rowHeights.set(key, Math.max(rowHeights.get(key) || 0, r.height));
    });

    // 2. Let each fill panel use whatever its row offers. "chrome" is the card's
    //    title + padding, i.e. everything that is not the scroll area.
    fills.forEach(s => {
      const cardEl = s.closest('.card');
      const cr = cardEl.getBoundingClientRect();
      const chrome = cr.height - s.getBoundingClientRect().height;
      const rowH = rowHeights.get(Math.round(cr.top)) || cr.height;
      s.style.maxHeight = Math.max(120, rowH - chrome) + 'px';
    });

    grid.style.alignItems = '';
  });
}

window.addEventListener('resize', () => {
  clearTimeout(window._resizeTimer);
  window._resizeTimer = setTimeout(fitScrollPanels, 150);
});

setupAutoRefreshToggle();
setupChartTooltips();
setupUserSearch();
setupIpPopover();
setupUserHighlight();
setupGreyNoise();
setActiveButton();
refresh();
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    quiet = False  # set by --quiet

    def log_message(self, fmt, *args):
        # Default access log to stderr: client IP, time, request line, status.
        if not self.quiet:
            super().log_message(fmt, *args)

    def do_GET(self):
        # The page loads the two parts in parallel, so the fast panels don't wait for the SSH journal.
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/stats/fast":
            self._send_stats(build_fast_stats)
        elif parsed.path == "/api/stats/ssh":
            qs = urllib.parse.parse_qs(parsed.query)
            range_key = qs.get("range", ["1d"])[0]
            since = VALID_SINCE.get(range_key, VALID_SINCE["1d"])
            self._send_stats(lambda: build_ssh_stats(since))
        elif self.path.startswith("/api/greynoise"):
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            status, result = greynoise_lookup(qs.get("ip", [""])[0])
            self._send(json.dumps(result).encode(), "application/json", status)
        else:
            self._send(PAGE.encode(), "text/html")

    def _send_stats(self, build):
        try:
            body, status = build(), 200
        except CommandTimeout as e:
            body, status = {"error": str(e)}, 504  # the page shows this instead of empty panels
        self._send(json.dumps(body).encode(), "application/json", status)

    def _send(self, data, content_type, status=200):
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass  # browser aborted the request (e.g. switched time range mid-load)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--quiet", action="store_true", help="don't log each HTTP request")
    args = p.parse_args()
    Handler.quiet = args.quiet

    server = ThreadingHTTPServer((args.bind, args.port), Handler)
    print(f"Dashboard running at http://{args.bind}:{args.port}", flush=True)
    print("Press Ctrl+C to stop.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
