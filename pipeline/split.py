#!/usr/bin/env python3
"""Stratified train/val/test split and final TrainingRow conversion."""

import argparse
from collections import defaultdict
import json
import random
from pathlib import Path

from .schema import make_execute_row

ROOT = Path(__file__).resolve().parent.parent
INP = ROOT / "data" / "deduped"
OUT = ROOT / "data" / "final"


def _bucket(row):
    flag = row.get("flag_path") or "unknown"
    domain = flag.split(".")[0]
    return domain, row.get("safety_label", "deny")


def split(seed=1337):
    OUT.mkdir(parents=True, exist_ok=True)
    src = INP / "data.jsonl"
    buckets = defaultdict(list)
    with open(src, encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            buckets[_bucket(row)].append(row)
    rng = random.Random(seed)
    splits = {"train": [], "val": [], "test": []}
    for rows in buckets.values():
        rng.shuffle(rows)
        n = len(rows)
        val_n = max(1, int(n * 0.05)) if n >= 20 else 0
        test_n = max(1, int(n * 0.05)) if n >= 20 else 0
        splits["val"].extend(rows[:val_n])
        splits["test"].extend(rows[val_n:val_n + test_n])
        splits["train"].extend(rows[val_n + test_n:])
    for name, rows in splits.items():
        path = OUT / f"{name}.jsonl"
        with open(path, "w", encoding="utf-8") as out:
            for row in rows:
                out.write(json.dumps(make_execute_row(row).to_jsonl(), ensure_ascii=False) + "\n")
        print(f"[split] {name}={len(rows)} -> {path}")
    return {name: len(rows) for name, rows in splits.items()}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=1337)
    args = parser.parse_args(argv)
    split(args.seed)


if __name__ == "__main__":
    main()

