#!/usr/bin/env python3
"""
scanners.py - static pre-execution scanning for Heimdall.

scan(cmd, scan_config) -> ScanReport
"""

import json
import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field


@dataclass
class ScanReport:
    language: str
    ran: list = field(default_factory=list)
    missing: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    blocked: bool = False
    block_reason: str = ""


def _extract_targets(cmd, language):
    """Return file paths the command will likely read or run."""
    try:
        argv = shlex.split(cmd)
    except ValueError:
        return []
    if not argv:
        return []

    base = os.path.basename(argv[0])
    targets = []

    if language == "python" and base in ("python", "python3"):
        for arg in argv[1:]:
            if arg in ("-m", "-c"):
                return []
            if arg.startswith("-"):
                continue
            if arg.endswith(".py"):
                targets.append(arg)
            break

    if language == "shell":
        for arg in argv[1:]:
            if arg.startswith("-"):
                continue
            targets.append(arg)
            break

    if language == "rust":
        targets.append(".")

    if not targets and (argv[0].endswith(".py") or argv[0].endswith(".sh")):
        targets.append(argv[0])

    return [target for target in targets if os.path.exists(target)]


def _run_shellcheck(path, timeout=30):
    if not shutil.which("shellcheck"):
        return "missing", None
    try:
        process = subprocess.run(
            ["shellcheck", "-f", "json", "-S", "warning", path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return "ran", json.loads(process.stdout or "[]")
    except Exception as exc:
        return "error", str(exc)


def _run_bandit(path, timeout=30):
    if not shutil.which("bandit"):
        return "missing", None
    try:
        process = subprocess.run(
            ["bandit", "-f", "json", "-q", path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        data = json.loads(process.stdout or "{}")
        return "ran", data.get("results", [])
    except Exception as exc:
        return "error", str(exc)


def _run_ruff(path, timeout=30):
    if not shutil.which("ruff"):
        return "missing", None
    try:
        process = subprocess.run(
            ["ruff", "check", "--output-format", "json", path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return "ran", json.loads(process.stdout or "[]")
    except Exception as exc:
        return "error", str(exc)


def _run_clippy(crate_dir, timeout=120):
    if not shutil.which("cargo"):
        return "missing", None
    try:
        process = subprocess.run(
            ["cargo", "clippy", "--message-format", "json", "--quiet"],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=crate_dir,
        )
        findings = []
        for line in process.stdout.splitlines():
            try:
                obj = json.loads(line)
                if obj.get("reason") == "compiler-message":
                    msg = obj.get("message", {})
                    if msg.get("level") in ("warning", "error"):
                        findings.append({
                            "level": msg["level"],
                            "message": msg.get("message", ""),
                        })
            except Exception:
                continue
        return "ran", findings
    except Exception as exc:
        return "error", str(exc)


def _run_scanner(name, targets, language):
    if name == "shellcheck":
        results = []
        for target in targets:
            status, data = _run_shellcheck(target)
            if status != "ran":
                return status, []
            for finding in data or []:
                results.append({
                    "scanner": "shellcheck",
                    "target": target,
                    "severity": (finding.get("level") or "").lower(),
                    "code": finding.get("code"),
                    "message": finding.get("message", ""),
                })
        return "ran", results

    if name == "bandit":
        results = []
        for target in targets:
            status, data = _run_bandit(target)
            if status != "ran":
                return status, []
            for finding in data or []:
                results.append({
                    "scanner": "bandit",
                    "target": target,
                    "severity": (finding.get("issue_severity") or "").lower(),
                    "code": finding.get("test_id"),
                    "message": finding.get("issue_text", ""),
                })
        return "ran", results

    if name == "ruff":
        results = []
        for target in targets:
            status, data = _run_ruff(target)
            if status != "ran":
                return status, []
            for finding in data or []:
                results.append({
                    "scanner": "ruff",
                    "target": target,
                    "severity": "warning",
                    "code": finding.get("code"),
                    "message": finding.get("message", ""),
                })
        return "ran", results

    if name == "clippy":
        for target in targets:
            status, data = _run_clippy(target)
            if status != "ran":
                return status, []
            return "ran", [{
                "scanner": "clippy",
                "target": target,
                "severity": finding.get("level", "warning"),
                "code": None,
                "message": finding.get("message", ""),
            } for finding in data]
    return "missing", []


HIGH_SEVERITIES = {"high", "error"}


def scan(cmd, scan_config, timeout=60):
    cfg = scan_config or {}
    language = cfg.get("language", "python")
    scanners = cfg.get("scanners", [])
    block = bool(cfg.get("block_on_fail", False))

    report = ScanReport(language=language)
    targets = _extract_targets(cmd, language)
    if not targets:
        report.block_reason = "no scannable targets found"
        return report

    for name in scanners:
        status, findings = _run_scanner(name, targets, language)
        if status == "ran":
            report.ran.append(name)
            report.findings.extend(findings)
        elif status == "missing":
            report.missing.append(name)
        else:
            report.missing.append(f"{name}(error)")

    if block:
        highs = [
            finding for finding in report.findings
            if (finding.get("severity") or "").lower() in HIGH_SEVERITIES
        ]
        if highs:
            report.blocked = True
            first = highs[0]
            report.block_reason = (
                f"{first['scanner']} flagged {first['severity']}: "
                f"{first['message'][:120]}"
            )
    return report
