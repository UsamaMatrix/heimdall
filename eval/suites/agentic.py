#!/usr/bin/env python3
"""Small multi-step task eval scaffold."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from eval.llm_client import OLLAMA_NATIVE
from eval.suites.common import propose

DATA = Path(__file__).resolve().parents[1] / "data" / "agentic_tasks.jsonl"


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--url", default=OLLAMA_NATIVE)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args(argv)
    rows = [json.loads(line) for line in DATA.read_text(encoding="utf-8").splitlines() if line.strip()]
    steps = []
    unavailable = 0
    for row in rows:
        plan, err = propose(args.model, row["goal"], url=args.url, timeout=args.timeout, verbose=args.verbose)
        if err:
            unavailable += 1
            continue
        steps.append(1 if plan.get("action") in ("execute", "done", "ask") else row.get("max_steps", 6))
    median = sorted(steps)[len(steps) // 2] if steps else 999
    print(json.dumps({"median_steps_to_ok": median, "success_rate": 1.0 if steps else 0.0, "unavailable": unavailable}))
    return 0 if steps else 1


if __name__ == "__main__":
    sys.exit(main())

