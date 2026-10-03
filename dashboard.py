#!/usr/bin/env python3
"""Live terminal dashboard for Heimdall.

A lightweight curses dashboard inspired by btop: it shows Heimdall daemon state,
system load, memory/disk summary, recent Heimdall events, and top processes.
"""

import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

VERSION_LABEL = "dashboard-v1"


class Theme:
    """Curses color-pair names for the Heimdall dashboard."""

    normal = 0
    dim = 0
    title = 0
    border = 0
    accent = 0
    ok = 0
    warn = 0
    danger = 0
    bar_hot = 0
    bar_cool = 0
    selected = 0


def _init_theme(curses):
    theme = Theme()
    try:
        curses.start_color()
        curses.use_default_colors()
        pairs = [
            (1, curses.COLOR_CYAN, -1),
            (2, curses.COLOR_YELLOW, -1),
            (3, curses.COLOR_GREEN, -1),
            (4, curses.COLOR_RED, -1),
            (5, curses.COLOR_MAGENTA, -1),
            (6, curses.COLOR_BLUE, -1),
            (7, curses.COLOR_BLACK, curses.COLOR_CYAN),
            (8, curses.COLOR_WHITE, -1),
        ]
        for number, fg, bg in pairs:
            curses.init_pair(number, fg, bg)
        theme.border = curses.color_pair(1)
        theme.title = curses.color_pair(2) | curses.A_BOLD
        theme.ok = curses.color_pair(3) | curses.A_BOLD
        theme.warn = curses.color_pair(2) | curses.A_BOLD
        theme.danger = curses.color_pair(4) | curses.A_BOLD
        theme.accent = curses.color_pair(5) | curses.A_BOLD
        theme.bar_hot = curses.color_pair(2) | curses.A_BOLD
        theme.bar_cool = curses.color_pair(6) | curses.A_BOLD
        theme.selected = curses.color_pair(7) | curses.A_BOLD
        theme.normal = curses.color_pair(8)
        theme.dim = curses.A_DIM
    except Exception:
        theme.title = getattr(curses, 'A_BOLD', 0)
        theme.selected = getattr(curses, 'A_REVERSE', 0)
        theme.ok = getattr(curses, 'A_BOLD', 0)
        theme.warn = getattr(curses, 'A_BOLD', 0)
        theme.danger = getattr(curses, 'A_BOLD', 0)
        theme.accent = getattr(curses, 'A_BOLD', 0)
    return theme


def _read_first(path, default=""):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except Exception:
        return default


def _loadavg():
    text = _read_first("/proc/loadavg")
    parts = text.split()
    return " ".join(parts[:3]) if len(parts) >= 3 else "?"


def _uptime():
    text = _read_first("/proc/uptime")
    try:
        seconds = int(float(text.split()[0]))
    except Exception:
        return "?"
    hours, rem = divmod(seconds, 3600)
    mins, _ = divmod(rem, 60)
    days, hours = divmod(hours, 24)
    if days:
        return f"{days}d {hours:02d}h {mins:02d}m"
    return f"{hours:02d}h {mins:02d}m"


def _meminfo():
    values = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, raw = line.split(":", 1)
            values[key] = int(raw.strip().split()[0]) * 1024
    except Exception:
        return {"total": 0, "used": 0, "available": 0, "pct": 0}
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", 0)
    used = max(0, total - available)
    pct = int((used / total) * 100) if total else 0
    return {"total": total, "used": used, "available": available, "pct": pct}


def _fmt_bytes(num):
    try:
        num = float(num)
    except Exception:
        return "?"
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    for unit in units:
        if abs(num) < 1024 or unit == units[-1]:
            return f"{num:.1f}{unit}" if unit != "B" else f"{int(num)}B"
        num /= 1024


def _disk(path="/"):
    try:
        usage = shutil.disk_usage(path)
        pct = int((usage.used / usage.total) * 100) if usage.total else 0
        return {"total": usage.total, "used": usage.used, "free": usage.free, "pct": pct}
    except Exception:
        return {"total": 0, "used": 0, "free": 0, "pct": 0}


def _bar(pct, width, glyph="█", empty="░"):
    width = max(0, int(width or 0))
    pct = max(0, min(100, int(pct or 0)))
    filled = int(width * pct / 100)
    return glyph * filled + empty * (width - filled)


def _risk_attr(theme, pct):
    if pct >= 90:
        return theme.danger
    if pct >= 70:
        return theme.warn
    return theme.ok


def _top_processes(limit=10):
    try:
        result = subprocess.run(
            ["ps", "-eo", "pid,user,comm,%cpu,%mem", "--sort=-%cpu"],
            capture_output=True, text=True, timeout=2, check=False)
        lines = result.stdout.splitlines()[1:limit + 1]
        return [line.strip() for line in lines if line.strip()]
    except Exception:
        return []


def _session_events(limit=8):
    paths = []
    home = Path.home() / ".heimdall"
    if home.exists():
        paths.extend(sorted(home.glob("session-*.jsonl"), reverse=True)[:2])
        for project_file in sorted((home / "projects").glob("*/memory.jsonl"), reverse=True)[:3]:
            paths.append(project_file)
    events = []
    for path in paths:
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]:
                row = json.loads(line)
                kind = row.get("kind") or row.get("status") or "event"
                command = row.get("command") or row.get("goal") or row.get("summary") or ""
                events.append(f"{path.parent.name}: {kind} {command}"[:160])
        except Exception:
            continue
    return events[-limit:]


def _daemon_snapshot(daemon):
    snap = {"daemon": "unknown", "version": "?", "mode": "?", "error": None}
    try:
        ping = daemon.ping()
        snap["daemon"] = "alive"
        snap["version"] = str(ping.get("version", "?"))
    except Exception as exc:
        snap["daemon"] = "down"
        snap["error"] = str(exc)
    try:
        snap["mode"] = daemon.mode_show().get("mode", "?")
    except Exception:
        pass
    return snap


def _box(stdscr, y, x, h, w, title, theme=None):
    if h < 2 or w < 4:
        return
    border = getattr(theme, 'border', 0) if theme else 0
    title_attr = getattr(theme, 'title', border) if theme else border
    try:
        stdscr.addstr(y, x, "╭" + "─" * (w - 2) + "╮", border)
        label = f" {title} "
        if len(label) < w - 4:
            stdscr.addstr(y, x + 2, label, title_attr)
        for row in range(1, h - 1):
            stdscr.addstr(y + row, x, "│", border)
            stdscr.addstr(y + row, x + w - 1, "│", border)
        stdscr.addstr(y + h - 1, x, "╰" + "─" * (w - 2) + "╯", border)
    except Exception:
        pass


def _write(stdscr, y, x, text, width=None, attr=0):
    try:
        if width is not None:
            text = str(text)[:max(0, width)]
        stdscr.addstr(y, x, str(text), attr)
    except Exception:
        pass


def _draw(stdscr, daemon, refresh, theme=None):
    import curses
    theme = theme or Theme()
    try:
        stdscr.bkgd(" ", theme.normal)
    except Exception:
        pass
    stdscr.erase()
    height, width = stdscr.getmaxyx()
    now = datetime.now().strftime("%H:%M:%S")
    snap = _daemon_snapshot(daemon)
    mem = _meminfo()
    disk = _disk("/")

    header = f" ⛨ HEIMDALL WATCHTOWER  {now}  q:quit  r:refresh  interval:{refresh:.1f}s "
    _write(stdscr, 0, 0, header[:width], width, theme.selected or curses.A_REVERSE)

    left_w = max(38, width // 2)
    right_w = max(30, width - left_w - 1)
    top_h = 8
    mid_h = 9
    bottom_h = max(7, height - top_h - mid_h - 2)

    _box(stdscr, 1, 0, top_h, left_w, "daemon", theme)
    status_attr = theme.ok if snap['daemon'] == 'alive' else theme.danger
    _write(stdscr, 2, 2, "status : ", attr=theme.dim)
    _write(stdscr, 2, 11, snap['daemon'], left_w - 13, status_attr)
    _write(stdscr, 3, 2, "version: ", attr=theme.dim)
    _write(stdscr, 3, 11, snap['version'], left_w - 13, theme.accent)
    _write(stdscr, 4, 2, "mode   : ", attr=theme.dim)
    _write(stdscr, 4, 11, snap['mode'], left_w - 13, theme.warn if snap['mode'] == 'sandbox' else theme.ok)
    _write(stdscr, 5, 2, "socket : ", attr=theme.dim)
    _write(stdscr, 5, 11, "/run/heimdall/bifrost.sock", left_w - 13, theme.normal)
    if snap.get("error"):
        _write(stdscr, 6, 2, f"error  : {snap['error']}"[:left_w - 4], attr=theme.danger)

    _box(stdscr, 1, left_w + 1, top_h, right_w, "system", theme)
    _write(stdscr, 2, left_w + 3, "load   : ", attr=theme.dim)
    _write(stdscr, 2, left_w + 12, _loadavg(), right_w - 14, theme.accent)
    _write(stdscr, 3, left_w + 3, "uptime : ", attr=theme.dim)
    _write(stdscr, 3, left_w + 12, _uptime(), right_w - 14, theme.ok)
    _write(stdscr, 4, left_w + 3, f"mem    : {_fmt_bytes(mem['used'])}/{_fmt_bytes(mem['total'])} {mem['pct']}%", attr=_risk_attr(theme, mem['pct']))
    _write(stdscr, 5, left_w + 3, _bar(mem['pct'], max(8, right_w - 14))[:right_w - 6], attr=_risk_attr(theme, mem['pct']))
    _write(stdscr, 6, left_w + 3, f"disk / : {_fmt_bytes(disk['used'])}/{_fmt_bytes(disk['total'])} {disk['pct']}%", attr=_risk_attr(theme, disk['pct']))

    _box(stdscr, top_h + 1, 0, mid_h, left_w, "recent heimdall activity", theme)
    events = _session_events(mid_h - 2)
    if not events:
        events = ["no recent client/project events"]
    for idx, event in enumerate(events[:mid_h - 2]):
        attr = theme.selected if idx == len(events[:mid_h - 2]) - 1 else theme.normal
        _write(stdscr, top_h + 2 + idx, 2, event, left_w - 4, attr)

    _box(stdscr, top_h + 1, left_w + 1, mid_h, right_w, "top processes", theme)
    for idx, proc in enumerate(_top_processes(mid_h - 2)):
        attr = theme.selected if idx == 0 else (theme.ok if idx < 3 else theme.normal)
        _write(stdscr, top_h + 2 + idx, left_w + 3, proc, right_w - 4, attr)

    _box(stdscr, top_h + mid_h + 1, 0, bottom_h, width, "notes", theme)
    notes = [
        "Every command still goes through heimdald policy before execution.",
        "Use --project NAME for scoped memory, --temp for no client history.",
        "Use --auto-approve only when policy explicitly enables it.",
        "This dashboard is read-only; it does not execute commands.",
    ]
    for idx, note in enumerate(notes[:bottom_h - 2]):
        _write(stdscr, top_h + mid_h + 2 + idx, 2, note, width - 4, theme.warn if idx == 0 else theme.normal)
    stdscr.refresh()


def run_dashboard(daemon, refresh=1.0):
    try:
        import curses
    except Exception as exc:
        print(f"dashboard requires curses: {exc}")
        return 2

    def _main(stdscr):
        theme = _init_theme(curses)
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.timeout(int(refresh * 1000))
        while True:
            _draw(stdscr, daemon, refresh, theme)
            key = stdscr.getch()
            if key in (ord("q"), ord("Q"), 27):
                return 0
            if key in (ord("r"), ord("R")):
                continue
            time.sleep(refresh)

    return curses.wrapper(_main)
