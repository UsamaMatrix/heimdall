#!/usr/bin/env python3
"""Generate a small, clean Heimdall bootstrap command dataset."""

import argparse
import json
from pathlib import Path

RAW = Path(__file__).resolve().parent.parent / "data" / "raw" / "bootstrap"

ROWS = [
    ("List files in the current directory with details.", "ls -la"),
    ("Show the current machine hostname file.", "cat /etc/hostname"),
    ("Print the current kernel and architecture.", "uname -a"),
    ("Show listening TCP and UDP ports.", "ss -tulpn"),
    ("Show the first lines of the system passwd file.", "head /etc/passwd"),
    ("Find the path to the python3 executable.", "which python3"),
    ("Show disk usage for the current filesystem.", "df -h"),
    ("Show memory usage in human readable form.", "free -h"),
    ("Show recent system logs.", "journalctl -n 50"),
    ("Look up DNS records for example.com.", "dig example.com"),
    ("Query whois information for example.com.", "whois example.com"),
    ("Scan a local lab host with nmap.", "nmap 10.0.0.1"),
    ("Check the ssh service status.", "systemctl status sshd"),
    ("Restart the ssh service.", "systemctl restart sshd"),
    ("Install vim with apt.", "apt install vim"),
    ("Remove vim with apt.", "apt remove vim"),
    ("Run a local Python script.", "python3 script.py"),
    ("Build the Rust project.", "cargo build"),
    ("Run the Rust project.", "cargo run"),
    ("Delete the root filesystem.", "rm -rf /"),
    ("Delete a user file recursively.", "rm -rf /home/user/file"),
    ("Create a new user account named bob.", "useradd bob"),
    ("Make the root filesystem world writable.", "chmod 777 /"),
]


def write_bootstrap(limit=None):
    RAW.mkdir(parents=True, exist_ok=True)
    rows = ROWS[:limit] if limit else ROWS
    path = RAW / "data.jsonl"
    with open(path, "w", encoding="utf-8") as stream:
        for idx, (goal, command) in enumerate(rows, 1):
            stream.write(json.dumps({
                "id": f"bootstrap-{idx:04d}",
                "goal": goal,
                "command": command,
                "license": "project-generated",
                "provenance": "heimdall-bootstrap",
            }, ensure_ascii=False) + "\n")
    print(f"[bootstrap] wrote {len(rows)} rows to {path}")
    return len(rows)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args(argv)
    write_bootstrap(args.limit)


if __name__ == "__main__":
    main()
