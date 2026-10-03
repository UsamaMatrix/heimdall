#!/usr/bin/env python3
"""Attach canonical safety labels via a live heimdald."""

import argparse
import json
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NORM = ROOT / "data" / "normalized"
OUT = ROOT / "data" / "labeled"
DEFAULT_SOCKET = "/run/heimdall/bifrost.sock"
DEV_SOCKET = str(ROOT / "dev-run" / "run" / "bifrost.sock")


def parse_tcp_endpoint(value):
    host, sep, port = value.rpartition(":")
    if not sep or not host:
        raise argparse.ArgumentTypeError("expected HOST:PORT")
    try:
        return host, int(port)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("PORT must be an integer") from exc


def connect_daemon(socket_path=DEFAULT_SOCKET, tcp_endpoint=None, timeout=10):
    if tcp_endpoint:
        return socket.create_connection(tcp_endpoint, timeout=timeout)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect(socket_path)
    return sock


def ask_daemon(cmd, socket_path=DEFAULT_SOCKET, tcp_endpoint=None, timeout=10):
    sock = connect_daemon(socket_path=socket_path, tcp_endpoint=tcp_endpoint, timeout=timeout)
    try:
        sock.sendall((json.dumps({"op": "verdict", "cmd": cmd}) + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf.split(b"\n", 1)[0])
    finally:
        sock.close()


def label_row(row, socket_path=DEFAULT_SOCKET, tcp_endpoint=None):
    verdict = ask_daemon(row["command"], socket_path=socket_path, tcp_endpoint=tcp_endpoint)
    row["flag_path"] = verdict.get("flag_path")
    row["safety_label"] = {
        "ALLOW": "allow",
        "ASK": "ask",
        "DENY": "deny",
        "DEFER": "deny",
    }.get(verdict.get("verdict"), "deny")
    row["safety_message_key"] = verdict.get("message_key")
    row["mode"] = verdict.get("mode")
    row["reason"] = verdict.get("reason")
    return row


def label_file(socket_path=DEFAULT_SOCKET, tcp_endpoint=None):
    OUT.mkdir(parents=True, exist_ok=True)
    src = NORM / "data.jsonl"
    if not src.exists():
        sys.exit(f"missing {src}")
    dst = OUT / "data.jsonl"
    total = kept = 0
    with open(src, encoding="utf-8") as inp, open(dst, "w", encoding="utf-8") as out:
        for line in inp:
            total += 1
            try:
                row = label_row(json.loads(line), socket_path=socket_path, tcp_endpoint=tcp_endpoint)
                out.write(json.dumps(row, ensure_ascii=False) + "\n")
                kept += 1
            except Exception as exc:
                print(f"[label] row {total} skipped: {exc}")
            if total % 500 == 0:
                print(f"[label] {total} processed, {kept} kept")
    print(f"[label] done: {kept}/{total} rows labeled")
    return kept


def main(argv=None):
    parser = argparse.ArgumentParser()
    endpoint = parser.add_mutually_exclusive_group()
    endpoint.add_argument("--socket", default=DEFAULT_SOCKET, help=f"heimdald Unix socket (default: {DEFAULT_SOCKET})")
    endpoint.add_argument("--dev", action="store_true", help=f"use repo-local dev socket ({DEV_SOCKET})")
    endpoint.add_argument("--tcp", type=parse_tcp_endpoint, metavar="HOST:PORT", help="connect to a TCP daemon endpoint")
    args = parser.parse_args(argv)
    socket_path = DEV_SOCKET if args.dev else args.socket
    label_file(socket_path=socket_path, tcp_endpoint=args.tcp)


if __name__ == "__main__":
    main()

