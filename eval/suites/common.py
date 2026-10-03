#!/usr/bin/env python3
"""Shared eval helpers."""

import json
import urllib.error
import urllib.request


def propose(model, goal, url="http://127.0.0.1:11434/v1/chat/completions", timeout=30):
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": f"GOAL: {goal}"}],
        "temperature": 0.2,
        "stream": False,
    }
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode())
        content = body["choices"][0]["message"]["content"]
        return json.loads(_strip_fence(content)), None
    except (urllib.error.URLError, TimeoutError) as exc:
        return None, f"model unavailable: {exc}"
    except Exception as exc:
        return None, f"bad model response: {exc}"


def _strip_fence(text):
    text = str(text).strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return text

