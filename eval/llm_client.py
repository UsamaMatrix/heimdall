#!/usr/bin/env python3
"""Thin Ollama / OpenAI-compatible client used by eval suites."""

import json
import time
import urllib.error
import urllib.request

OLLAMA_NATIVE = "http://127.0.0.1:11434/api/chat"
OLLAMA_OPENAI = "http://127.0.0.1:11434/v1/chat/completions"


class LLMResult:
    __slots__ = ("content", "error", "latency_ms", "raw")

    def __init__(self, content=None, error=None, latency_ms=0, raw=None):
        self.content = content
        self.error = error
        self.latency_ms = latency_ms
        self.raw = raw


def call(url, model, messages, temperature=0.2, num_ctx=8192,
         timeout=120, tries=3, base_delay=0.5):
    if "/v1/" in url:
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "stream": False,
        }
    else:
        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature, "num_ctx": num_ctx},
        }

    last_err = None
    for attempt in range(tries):
        t0 = time.monotonic()
        try:
            request = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = json.loads(response.read().decode("utf-8"))
            latency = int((time.monotonic() - t0) * 1000)

            if "/v1/" in url:
                content = raw["choices"][0]["message"]["content"]
            else:
                content = raw["message"]["content"]
            return LLMResult(content=content, latency_ms=latency, raw=raw)
        except urllib.error.HTTPError as exc:
            last_err = f"HTTP {exc.code}: {exc.read().decode('utf-8', errors='replace')[:200]}"
        except urllib.error.URLError as exc:
            last_err = f"URLError: {exc.reason}"
        except (KeyError, IndexError, TypeError) as exc:
            last_err = f"unexpected response shape: {exc}"
        except Exception as exc:
            last_err = f"{type(exc).__name__}: {exc}"

        if attempt < tries - 1:
            time.sleep(base_delay * (2 ** attempt))

    return LLMResult(error=last_err or "unknown failure")
