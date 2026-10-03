#!/usr/bin/env python3
"""Shared eval helpers."""

import importlib.util
import json
from pathlib import Path

from eval.llm_client import OLLAMA_NATIVE, call

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("heimdall_client", ROOT / "heimdall.py")
_hc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_hc)
SYSTEM_PROMPT = _hc.SYSTEM_PROMPT
_parse_llm_json = _hc._parse_llm_json


def propose(model, goal, url=OLLAMA_NATIVE, timeout=120, verbose=False):
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"GOAL: {goal}"},
    ]
    result = call(url, model, messages, timeout=timeout)
    if result.error:
        return None, result.error
    if verbose:
        print(f"[eval] raw model content: {result.content!r}")
    try:
        return _parse_llm_json(result.content), None
    except Exception as exc:
        return None, f"parse: {exc}"
