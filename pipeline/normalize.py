#!/usr/bin/env python3
"""Normalize raw datasets into a common command row shape."""

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"
OUT = ROOT / "data" / "normalized"


def _first_text(row, keys):
    for key in keys:
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _adapter(source, row):
    goal = _first_text(row, ("goal", "question", "instruction", "prompt", "nl", "description", "input"))
    command = _first_text(row, ("command", "bash", "cmd", "output", "answer", "response", "completion"))
    if not goal or not command:
        text = _first_text(row, ("text", "content"))
        if "```" in text:
            parts = text.split("```")
            goal = goal or parts[0].strip()
            command = command or parts[1].strip().splitlines()[-1]
    if not goal or not command:
        return None
    ident = hashlib.sha256(f"{source}\0{goal}\0{command}".encode()).hexdigest()[:20]
    license_name = row.get("license") or {
        "nl2bash": "MIT",
        "darkknight": "MIT",
        "trendyol": "Apache-2.0",
    }.get(source, "unknown")
    return {
        "id": ident,
        "source": source,
        "goal": goal,
        "command": command.splitlines()[0].strip(),
        "language": "bash",
        "raw_output": row,
        "license": license_name,
        "provenance": source,
    }


def normalize_sources(sources=None):
    OUT.mkdir(parents=True, exist_ok=True)
    sources = sources or [path.name for path in RAW.iterdir() if path.is_dir()] if RAW.exists() else []
    dst = OUT / "data.jsonl"
    total = kept = 0
    with open(dst, "w", encoding="utf-8") as out:
        for source in sources:
            path = RAW / source / "data.jsonl"
            if not path.exists():
                print(f"[normalize] missing {path}; skipping")
                continue
            with open(path, encoding="utf-8") as stream:
                for line in stream:
                    total += 1
                    try:
                        row = _adapter(source, json.loads(line))
                    except Exception:
                        row = None
                    if row:
                        out.write(json.dumps(row, ensure_ascii=False) + "\n")
                        kept += 1
    print(f"[normalize] {kept}/{total} rows -> {dst}")
    return kept


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--sources", nargs="*", default=None)
    args = parser.parse_args(argv)
    normalize_sources(args.sources)


if __name__ == "__main__":
    main()

