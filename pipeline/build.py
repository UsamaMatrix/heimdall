#!/usr/bin/env python3
"""Run the M5 dataset pipeline."""

import argparse
import json
from pathlib import Path

from . import bootstrap, dedupe, fetch, label, normalize, split
from .schema import SYSTEM_PROMPT, make_execute_row

ROOT = Path(__file__).resolve().parent.parent


def dry_run():
    sample = {
        "id": "dry-run-1",
        "source": "dry-run",
        "goal": "list files",
        "command": "ls -la",
        "license": "test",
        "provenance": "generated",
        "flag_path": "linux_administration.file_read",
        "safety_label": "allow",
        "safety_message_key": None,
    }
    row = make_execute_row(sample).to_jsonl()
    print("[build] dry-run ok")
    print(f"[build] system prompt bytes={len(SYSTEM_PROMPT.encode())}")
    print(json.dumps({"id": row["id"], "messages": len(row["messages"]), "action": row["action"]}))


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--sources", nargs="*", default=None)
    parser.add_argument("--allow-unknown-license", action="store_true")
    parser.add_argument("--skip-fetch", action="store_true")
    parser.add_argument("--skip-label", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    endpoint = parser.add_mutually_exclusive_group()
    endpoint.add_argument("--daemon-socket", default=label.DEFAULT_SOCKET, help=f"heimdald Unix socket (default: {label.DEFAULT_SOCKET})")
    endpoint.add_argument("--daemon-dev", action="store_true", help=f"use repo-local dev socket ({label.DEV_SOCKET})")
    endpoint.add_argument("--daemon-tcp", type=label.parse_tcp_endpoint, metavar="HOST:PORT", help="connect to a TCP daemon endpoint")
    args = parser.parse_args(argv)
    if args.dry_run:
        dry_run()
        return
    if not args.skip_fetch:
        names = args.sources or list(fetch.SOURCES)
        for name in names:
            if name == "bootstrap":
                bootstrap.write_bootstrap()
            elif name in fetch.SOURCES:
                fetch.fetch_one(name, fetch.SOURCES[name], args.allow_unknown_license)
            else:
                print(f"[fetch] unknown source: {name}")
    normalize.normalize_sources(args.sources)
    if not args.skip_label:
        socket_path = label.DEV_SOCKET if args.daemon_dev else args.daemon_socket
        label.label_file(socket_path=socket_path, tcp_endpoint=args.daemon_tcp)
    else:
        labeled = ROOT / "data" / "labeled"
        labeled.mkdir(parents=True, exist_ok=True)
        (labeled / "data.jsonl").write_text((ROOT / "data" / "normalized" / "data.jsonl").read_text(encoding="utf-8"), encoding="utf-8")
    dedupe.dedupe()
    split.split()


if __name__ == "__main__":
    main()

