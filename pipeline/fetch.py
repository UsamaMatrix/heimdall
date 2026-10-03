#!/usr/bin/env python3
"""Download source datasets into data/raw/<source>/."""

import argparse
import json
import sys
from pathlib import Path

RAW = Path(__file__).resolve().parent.parent / "data" / "raw"

SOURCES = {
    "nl2bash": {"hf": ("michaelin/nl2bash", None, "train"), "license": "MIT"},
    "darkknight": {"hf": ("darkknight25/Linux_Terminal_Commands_Dataset", None, "train"), "license": "MIT"},
    "blackhat": {"hf": ("TahaGorji/BlackHat-KaliLinux-CyberSecurity-dataset-Instruct", None, "train"), "license": "unknown"},
    "trendyol": {"hf": ("Trendyol/Trendyol-Cybersecurity-Instruction-Tuning-Dataset", None, "train"), "license": "Apache-2.0"},
    "fenrir": {"hf": ("AlicanKiraz0/Cybersecurity-Dataset-Fenrir-v2.1", None, "train"), "license": "unknown"},
}


def fetch_one(name, spec, allow_unknown=False):
    if spec.get("license") == "unknown" and not allow_unknown:
        print(f"[fetch] {name}: skipped unknown license; pass --allow-unknown-license")
        return 0
    try:
        from datasets import load_dataset
    except ImportError:
        sys.exit("pip install datasets")
    repo, config, split = spec["hf"]
    out = RAW / name
    out.mkdir(parents=True, exist_ok=True)
    print(f"[fetch] {name}: {repo}")
    try:
        ds = load_dataset(repo, config, split=split)
    except Exception as exc:
        print(f"[fetch] {name} failed: {exc}")
        return 0
    path = out / "data.jsonl"
    with open(path, "w", encoding="utf-8") as stream:
        for row in ds:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"[fetch] {name}: wrote {len(ds)} rows to {path}")
    return len(ds)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", nargs="*", default=None)
    parser.add_argument("--allow-unknown-license", action="store_true")
    args = parser.parse_args(argv)
    names = args.only or list(SOURCES)
    total = 0
    for name in names:
        if name not in SOURCES:
            print(f"[fetch] unknown source: {name}")
            continue
        total += fetch_one(name, SOURCES[name], args.allow_unknown_license)
    print(f"[fetch] total rows: {total}")


if __name__ == "__main__":
    main()

