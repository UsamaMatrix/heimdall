#!/usr/bin/env python3
"""objectives.py ? success detection for CTF and bug-bounty playbooks."""

import re
from dataclasses import dataclass

@dataclass
class ObjectiveHit:
    id: str
    value: str
    match_type: str
    evidence: str

def check_output(objectives: list, cmd: str, stdout: str, stderr: str = "") -> list:
    hits = []
    text = (stdout or "") + "\n" + (stderr or "")
    for obj in objectives or []:
        pattern = obj.get("pattern")
        if not pattern:
            continue
        try:
            rx = re.compile(pattern)
        except re.error:
            continue
        match = obj.get("match", "any")
        if match == "first":
            found = rx.search(text)
            if found:
                hits.append(ObjectiveHit(obj["id"], found.group(0), "first", cmd))
        elif match == "any":
            for found in rx.finditer(text):
                hits.append(ObjectiveHit(obj["id"], found.group(0), "any", cmd))
        elif match == "count":
            count = len(rx.findall(text))
            if count > 0:
                hits.append(ObjectiveHit(obj["id"], str(count), "count", cmd))
    return hits

def dedupe_hits(hits: list) -> list:
    seen, out = set(), []
    for hit in hits:
        key = (hit.id, hit.value)
        if key not in seen:
            seen.add(key)
            out.append(hit)
    return out
