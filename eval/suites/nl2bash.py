#!/usr/bin/env python3
"""Held-out NL to command shape eval."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from eval.suites.common import propose

CASES = [
    {"goal": "list files with details", "binary": "ls"},
    {"goal": "show the current hostname", "binary": "cat"},
    {"goal": "print disk usage in human readable form", "binary": "df"},
]


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    args = parser.parse_args(argv)
    exact = total = unavailable = 0
    for case in CASES:
        plan, err = propose(args.model, case["goal"])
        if err:
            unavailable += 1
            continue
        total += 1
        command = str(plan.get("command", "")).strip()
        if command.split(" ", 1)[0] == case["binary"]:
            exact += 1
    score = exact / total if total else 0.0
    print(json.dumps({"exact_match": score, "evaluated": total, "unavailable": unavailable}))
    return 0 if total else 1


if __name__ == "__main__":
    sys.exit(main())

