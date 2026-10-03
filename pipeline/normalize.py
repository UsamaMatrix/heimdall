#!/usr/bin/env python3
"""Normalize raw datasets into a common command row shape."""

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"
OUT = ROOT / "data" / "normalized"


COMMAND_HEADS = {
    "apt", "awk", "cat", "cd", "chmod", "chown", "cp", "curl", "dig", "docker",
    "echo", "find", "git", "grep", "head", "ip", "journalctl", "ls", "mkdir",
    "mv", "netstat", "nmap", "ping", "pip", "python", "python3", "rm", "rsync",
    "sed", "ss", "sudo", "systemctl", "tail", "tar", "tcpdump", "tr", "ufw",
    "uname", "whois", "wget", "which", "zip",
}


def _first_text(row, keys):
    for key in keys:
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _strip_prompt(line):
    line = line.strip()
    for prompt in ("$ ", "# ", "> "):
        if line.startswith(prompt):
            return line[len(prompt):].strip()
    return line


def _looks_like_command(line):
    line = _strip_prompt(line)
    if not line or line.startswith(("//", "#", "<!--")):
        return False
    first = line.split()[0]
    return first in COMMAND_HEADS or first.startswith(("./", "/"))


def _command_from_text(text):
    if not text:
        return ""
    if "```" in text:
        chunks = text.split("```")
        for chunk in chunks[1::2]:
            lines = chunk.splitlines()
            if lines and lines[0].strip().lower() in {"bash", "sh", "shell", "console", "terminal"}:
                lines = lines[1:]
            for line in lines:
                candidate = _strip_prompt(line)
                if _looks_like_command(candidate):
                    return candidate
    for line in text.splitlines():
        candidate = _strip_prompt(line)
        if _looks_like_command(candidate):
            return candidate
    return ""


def _adapter(source, row):
    goal = _first_text(row, ("goal", "question", "instruction", "prompt", "nl", "description", "input", "user"))
    command = _first_text(row, ("command", "bash", "cmd"))
    if not command:
        command = _command_from_text(_first_text(row, ("assistant", "output", "answer", "response", "completion", "text", "content")))
    if not goal or not command:
        text = _first_text(row, ("text", "content"))
        if "```" in text:
            parts = text.split("```")
            goal = goal or parts[0].strip()
            command = command or _command_from_text(text)
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

