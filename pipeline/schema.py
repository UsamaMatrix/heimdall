#!/usr/bin/env python3
"""Unified training schema aligned to Heimdall's runtime LLM contract."""

from dataclasses import asdict, dataclass
import importlib.util
from pathlib import Path
from typing import Optional


def _load_system_prompt() -> str:
    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("heimdall_client", root / "heimdall.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load heimdall.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.SYSTEM_PROMPT


SYSTEM_PROMPT = _load_system_prompt()


@dataclass
class Message:
    role: str
    content: str

    def validate(self) -> None:
        if self.role not in ("system", "user", "assistant"):
            raise ValueError(f"invalid role: {self.role}")
        if not isinstance(self.content, str) or not self.content.strip():
            raise ValueError("message content must be nonempty text")


@dataclass
class TrainingRow:
    id: str
    source: str
    domain: str
    subdomain: Optional[str]
    flag_path: Optional[str]
    safety_label: str
    safety_message_key: Optional[str]
    messages: list
    action: str
    license: str
    provenance: str
    quality_score: float = 0.0

    def validate(self) -> None:
        for field in ("id", "source", "domain", "safety_label", "action", "license", "provenance"):
            value = getattr(self, field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field} must be nonempty text")
        if self.safety_label not in ("allow", "ask", "deny"):
            raise ValueError(f"invalid safety_label: {self.safety_label}")
        if self.action not in ("execute", "ask", "done"):
            raise ValueError(f"invalid action: {self.action}")
        if not self.messages:
            raise ValueError("messages must not be empty")
        for message in self.messages:
            if isinstance(message, dict):
                message = Message(**message)
            message.validate()
        first = self.messages[0]
        if isinstance(first, dict):
            first = Message(**first)
        if first.role != "system" or first.content != SYSTEM_PROMPT:
            raise ValueError("first message must be byte-identical to heimdall.SYSTEM_PROMPT")

    def to_jsonl(self) -> dict:
        self.validate()
        data = asdict(self)
        data["messages"] = [
            asdict(message) if isinstance(message, Message) else asdict(Message(**message))
            for message in self.messages
        ]
        return data


def make_execute_row(row: dict) -> TrainingRow:
    goal = str(row.get("goal", "")).strip()
    command = str(row.get("command", "")).strip()
    if not goal or not command:
        raise ValueError("normalized row requires goal and command")
    safety_label = row.get("safety_label") or "allow"
    flag_path = row.get("flag_path")
    domain = (flag_path or row.get("domain") or "unknown").split(".")[0]
    parts = (flag_path or "").split(".")
    subdomain = parts[1] if len(parts) > 2 else None
    return TrainingRow(
        id=str(row.get("id") or ""),
        source=str(row.get("source") or "unknown"),
        domain=domain,
        subdomain=subdomain,
        flag_path=flag_path,
        safety_label=safety_label,
        safety_message_key=row.get("safety_message_key"),
        messages=[
            Message("system", SYSTEM_PROMPT),
            Message("user", f"GOAL: {goal}"),
            Message(
                "assistant",
                f'{{"action":"execute","reasoning":"{_json_escape(row.get("reasoning") or "Use the requested command.")}","command":"{_json_escape(command)}"}}',
            ),
        ],
        action="execute",
        license=str(row.get("license") or "unknown"),
        provenance=str(row.get("provenance") or row.get("source") or "unknown"),
        quality_score=float(row.get("quality_score") or 0.0),
    )


def _json_escape(value) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')

