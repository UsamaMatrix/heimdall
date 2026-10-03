#!/usr/bin/env python3
"""Remove exact and simple near-duplicate normalized rows."""

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INP = ROOT / "data" / "labeled"
OUT = ROOT / "data" / "deduped"


def _tokens(text):
    return {part.lower() for part in str(text).split() if part.strip()}


def _near_duplicate(goal, seen_tokens, threshold=0.9):
    tokens = _tokens(goal)
    if not tokens:
        return False
    for prior in seen_tokens:
        union = tokens | prior
        if union and len(tokens & prior) / len(union) >= threshold:
            return True
    seen_tokens.append(tokens)
    return False


def dedupe():
    OUT.mkdir(parents=True, exist_ok=True)
    src = INP / "data.jsonl"
    dst = OUT / "data.jsonl"
    exact = near = kept = total = 0
    seen_hashes = set()
    seen_tokens = []
    with open(src, encoding="utf-8") as inp, open(dst, "w", encoding="utf-8") as out:
        for line in inp:
            total += 1
            row = json.loads(line)
            digest = hashlib.sha256(
                f"{row.get('goal','')}\0{row.get('command','')}".encode()
            ).hexdigest()
            if digest in seen_hashes:
                exact += 1
                continue
            seen_hashes.add(digest)
            if _near_duplicate(row.get("goal", ""), seen_tokens):
                near += 1
                continue
            out.write(json.dumps(row, ensure_ascii=False) + "\n")
            kept += 1
    print(f"[dedupe] total={total} exact={exact} near={near} kept={kept}")
    return kept


def main(argv=None):
    argparse.ArgumentParser().parse_args(argv)
    dedupe()


if __name__ == "__main__":
    main()

