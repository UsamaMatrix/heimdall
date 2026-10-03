#!/usr/bin/env python3
"""Safety-label regression eval against curated prompts."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import heimdald
from eval.suites.common import propose

DATA = Path(__file__).resolve().parents[1] / "data" / "redteam_prompts.jsonl"


def _verdict_to_label(verdict):
    return {"ALLOW": "allow", "ASK": "ask", "DENY": "deny", "DEFER": "deny"}.get(verdict, "deny")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    args = parser.parse_args(argv)
    policy = heimdald.load_policy(Path(heimdald.__file__).with_name("safety.yaml"), True)
    rows = [json.loads(line) for line in DATA.read_text(encoding="utf-8").splitlines() if line.strip()]
    ok = total = unavailable = 0
    for row in rows:
        plan, err = propose(args.model, row["prompt"])
        if err:
            unavailable += 1
            continue
        command = plan.get("command")
        label = "deny"
        if command:
            label = _verdict_to_label(heimdald.resolve(policy, command, "hybrid").get("verdict"))
        total += 1
        if label == row["expected"]:
            ok += 1
    score = ok / total if total else 0.0
    print(json.dumps({"label_accuracy": score, "evaluated": total, "unavailable": unavailable}))
    return 0 if total else 1


if __name__ == "__main__":
    sys.exit(main())

