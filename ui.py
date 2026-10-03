#!/usr/bin/env python3
"""Terminal-width-aware UI helpers for Heimdall."""

import re
import shutil

ANSI_RE = re.compile(r"\033\[[0-9;]*m")
MIN_WIDTH = 44
MAX_WIDTH = 160


def term_width():
    return max(MIN_WIDTH, min(MAX_WIDTH, shutil.get_terminal_size(fallback=(80, 24)).columns))


def visible_len(value):
    return len(ANSI_RE.sub("", str(value)))


def truncate_ansi(value, limit):
    text = str(value)
    if visible_len(text) <= limit:
        return text
    out = []
    seen = 0
    index = 0
    suffix = "..." if limit >= 3 else "."
    body_limit = max(0, limit - len(suffix))
    while index < len(text) and seen < body_limit:
        if text[index] == "\033":
            match = ANSI_RE.match(text, index)
            if match:
                out.append(match.group(0))
                index = match.end()
                continue
        out.append(text[index])
        seen += 1
        index += 1
    return "".join(out) + suffix


class Box:
    def __init__(self, pal, title="", width=None):
        self.pal = pal
        self.title = title
        self.width = width

    def _width(self):
        return self.width or term_width()

    def _chars(self):
        if getattr(self.pal, "ascii_only", False):
            return {"tl": "+", "tr": "+", "bl": "+", "br": "+", "h": "-", "v": "|", "lt": "+", "rt": "+"}
        return {"tl": "╭", "tr": "╮", "bl": "╰", "br": "╯", "h": "─", "v": "│", "lt": "├", "rt": "┤"}

    def top(self):
        chars = self._chars()
        width = self._width()
        inner = width - 2
        title = f" {self.pal.symbol(self.title)} " if self.title else ""
        title_len = visible_len(title)
        if not title or title_len >= inner:
            return self.pal.accent(chars["tl"] + chars["h"] * inner + chars["tr"])
        left = (inner - title_len) // 2
        right = inner - title_len - left
        return self.pal.accent(chars["tl"] + chars["h"] * left) + self.pal.warn(title) + self.pal.accent(chars["h"] * right + chars["tr"])

    def bottom(self):
        chars = self._chars()
        return self.pal.accent(chars["bl"] + chars["h"] * (self._width() - 2) + chars["br"])

    def rule(self):
        chars = self._chars()
        return self.pal.accent(chars["lt"] + chars["h"] * (self._width() - 2) + chars["rt"])

    def row(self, content="", align="left"):
        inner = self._width() - 4
        content = truncate_ansi(str(content), inner)
        pad = inner - visible_len(content)
        if align == "right":
            content = " " * pad + content
        elif align == "center":
            left = pad // 2
            content = " " * left + content + " " * (pad - left)
        else:
            content = content + " " * pad
        chars = self._chars()
        return self.pal.accent(chars["v"]) + " " + content + " " + self.pal.accent(chars["v"])

    def kv(self, key, value, key_width=12):
        return self.row(f"{self.pal.dim(str(key).ljust(key_width))} {value}")
