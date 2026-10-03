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


def ask_daemon(cmd, endpoint=("127.0.0.1", 47651), timeout=10):
    sock = socket.create_connection(endpoint, timeout=timeout)
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


def label_row(row, endpoint):
    verdict = ask_daemon(row["command"], endpoint)
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


def label_file(endpoint=("127.0.0.1", 47651)):
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
                row = label_row(json.loads(line), endpoint)
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
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=47651)
    args = parser.parse_args(argv)
    label_file((args.host, args.port))


if __name__ == "__main__":
    main()

