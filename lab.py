#!/usr/bin/env python3
"""Lab mode support for Heimdall."""

import hashlib
import json
import os
import platform
import shlex
import subprocess
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

TIMER_TICK_SECONDS = 2.0


def _run(argv, timeout=5):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError:
        return 127, "", f"{argv[0]} not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except Exception as exc:
        return 1, "", str(exc)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path, max_bytes=64 * 1024 * 1024):
    h = hashlib.sha256()
    total = 0
    try:
        with open(path, "rb") as stream:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    return f"partial:{h.hexdigest()}"
                h.update(chunk)
        return h.hexdigest()
    except Exception as exc:
        return f"error:{exc}"


def _extract_sample_paths(cmd):
    try:
        argv = shlex.split(cmd)
    except Exception:
        return []
    out = []
    for arg in argv[1:]:
        if arg.startswith("-"):
            continue
        if "/" in arg or "." in arg:
            try:
                path = Path(arg)
                if path.exists() and path.is_file():
                    out.append(str(path))
            except Exception:
                continue
    return out[:8]


def _check_no_default_route():
    rc, out, _err = _run(["ip", "route", "show", "default"])
    if rc != 0:
        try:
            lines = Path("/proc/net/route").read_text().splitlines()[1:]
            has_default = any(line.split()[1] == "00000000" for line in lines if line.strip())
            return (False, "default route present (via /proc/net/route)") if has_default else (True, None)
        except Exception:
            return True, None
    if out.strip():
        return False, "default route present"
    return True, None


def _check_no_non_lo_addr():
    rc, out, _err = _run(["ip", "-br", "addr"])
    if rc != 0:
        return True, None
    up = []
    for line in out.splitlines():
        parts = line.split()
        if not parts or parts[0] == "lo":
            continue
        if len(parts) >= 2 and parts[1].upper() == "UP":
            up.append(parts[0])
    if up:
        return False, "non-loopback interfaces up: " + ", ".join(up)
    return True, None


def _check_no_host_mounts(extra_paths=None):
    suspects = ["/media", "/mnt", "/run/media"]
    if extra_paths:
        suspects.extend(extra_paths)
    rc, out, _err = _run(["mount"])
    if rc != 0:
        return True, None
    hits = set()
    for line in out.splitlines():
        for suspect in suspects:
            if f" on {suspect}" in line or f" on {suspect}/" in line:
                hits.add(suspect)
    if hits:
        return False, "host mounts detected under: " + ", ".join(sorted(hits))
    return True, None


def _check_evidence_writable(evidence_dir):
    directory = Path(evidence_dir)
    try:
        directory.mkdir(parents=True, exist_ok=True)
        probe = directory / ".write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True, None
    except Exception as exc:
        return False, f"evidence dir not writable: {exc}"


def env_check(policy, dev=False):
    lab_mode = policy.get("lab_mode", {}) or {}
    evidence_dir = lab_mode.get("evidence_dir", "/var/lib/heimdall/evidence")
    checks = {}
    overall = True
    if lab_mode.get("require_offline", True):
        ok, detail = _check_no_default_route()
        checks["no_default_route"] = {"ok": ok, "detail": detail}
        overall = overall and ok
        ok, detail = _check_no_non_lo_addr()
        checks["no_non_lo_addr"] = {"ok": ok, "detail": detail}
        overall = overall and ok
    if lab_mode.get("forbid_host_mounts", True):
        ok, detail = _check_no_host_mounts()
        checks["no_host_mounts"] = {"ok": ok, "detail": detail}
        overall = overall and ok
    ok, detail = _check_evidence_writable(evidence_dir)
    checks["evidence_writable"] = {"ok": ok, "detail": detail}
    overall = overall and ok
    return {
        "ok": bool(overall),
        "checks": checks,
        "ts": datetime.now(timezone.utc).isoformat(),
        "host": platform.node(),
        "uid": os.getuid() if hasattr(os, "getuid") else -1,
        "dev_mode": bool(dev),
    }


class EvidenceWriter:
    def __init__(self, evidence_dir, dev=False):
        self.dir = Path(evidence_dir)
        self.dev = dev
        self.dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, evidence_id):
        return self.dir / f"{evidence_id}.json"

    def new_id(self):
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
        return f"{ts}-{os.urandom(4).hex()}"

    def _write(self, evidence_id, record):
        record["evidence_id"] = evidence_id
        record["ts_written"] = datetime.now(timezone.utc).isoformat()
        path = self._path_for(evidence_id)
        tmp = path.with_suffix(".json.tmp")
        with open(tmp, "w", encoding="utf-8") as stream:
            json.dump(record, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o640)
        except Exception:
            pass

    def start_record(self, evidence_id, cmd, flag_path, env_snapshot, uid, sample_paths=None):
        samples = []
        for path_text in (sample_paths if sample_paths is not None else _extract_sample_paths(cmd)):
            try:
                st = os.stat(path_text)
                samples.append({
                    "path": path_text,
                    "sha256": _sha256_file(path_text),
                    "size": st.st_size,
                    "mtime": st.st_mtime,
                })
            except Exception as exc:
                samples.append({"path": path_text, "error": str(exc)})
        self._write(evidence_id, {
            "kind": "start",
            "status": "running",
            "command": cmd,
            "command_sha256": _sha256_bytes(cmd.encode("utf-8")),
            "flag_path": flag_path,
            "uid": uid,
            "env_snapshot": env_snapshot,
            "samples": samples,
            "started_at": datetime.now(timezone.utc).isoformat(),
        })

    def end_record(self, evidence_id, rc, stdout_sha256=None, stderr_sha256=None,
                   duration_ms=None, sandboxed=False, stdout="", stderr=""):
        path = self._path_for(evidence_id)
        existing = {}
        if path.exists():
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                existing = {}
        existing.update({
            "kind": "end",
            "status": "complete",
            "rc": rc,
            "duration_ms": duration_ms,
            "sandboxed": bool(sandboxed),
            "stdout_sha256": stdout_sha256 or _sha256_bytes(str(stdout).encode("utf-8")),
            "stderr_sha256": stderr_sha256 or _sha256_bytes(str(stderr).encode("utf-8")),
            "stdout_bytes": len(str(stdout).encode("utf-8")) if stdout else None,
            "stderr_bytes": len(str(stderr).encode("utf-8")) if stderr else None,
            "ended_at": datetime.now(timezone.utc).isoformat(),
        })
        self._write(evidence_id, existing)


@dataclass
class LabState:
    enabled: bool = False
    enabled_at: float = 0.0
    enabled_by_uid: int = -1
    auto_off_at: float = 0.0
    env_snapshot: dict = field(default_factory=dict)
    reason: str = ""


class LabTimer(threading.Thread):
    def __init__(self, manager):
        super().__init__(name="lab-timer", daemon=True)
        self.mgr = manager
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def run(self):
        while not self._stop_event.is_set():
            time.sleep(TIMER_TICK_SECONDS)
            try:
                state = self.mgr._state
                if state.enabled and state.auto_off_at > 0 and time.time() >= state.auto_off_at:
                    self.mgr._auto_disable("auto-off timer expired")
            except Exception:
                pass


class LabManager:
    def __init__(self, policy, history, dev=False):
        self.policy = policy
        self.history = history
        self.dev = dev
        lab_mode = policy.get("lab_mode", {}) or {}
        self._configured = bool(lab_mode.get("enabled", False))
        self._auto_off_minutes = int(lab_mode.get("auto_flip_off_after_minutes", 120))
        self._evidence_dir = Path(lab_mode.get("evidence_dir", "/var/lib/heimdall/evidence"))
        self._require_sample_hash = bool(lab_mode.get("require_sample_hash_log", True))
        self._state = LabState(enabled=False)
        self._lock = threading.RLock()
        self._evidence = EvidenceWriter(self._evidence_dir, dev=dev)
        self._timer = LabTimer(self)
        self._timer.start()

    def is_enabled(self):
        with self._lock:
            if not self._state.enabled:
                return False
            if self._state.auto_off_at and time.time() >= self._state.auto_off_at:
                return False
            return True

    def status(self):
        with self._lock:
            state = asdict(self._state)
            if state["enabled"] and state["auto_off_at"]:
                state["seconds_until_auto_off"] = max(0, int(state["auto_off_at"] - time.time()))
            else:
                state["seconds_until_auto_off"] = None
            state["configured"] = self._configured
            state["auto_off_minutes"] = self._auto_off_minutes
            state["evidence_dir"] = str(self._evidence_dir)
            return state

    def enable(self, uid):
        if not self._configured:
            return False, "lab_mode disabled", None
        snapshot = env_check(self.policy, dev=self.dev)
        if not snapshot["ok"]:
            failed = [key for key, value in snapshot["checks"].items() if not value["ok"]]
            msg = "lab env check failed: " + ", ".join(failed)
            self._log("lab_enable_failed", {"uid": uid, "reason": msg, "snapshot": snapshot})
            return False, msg, snapshot
        now = time.time()
        with self._lock:
            self._state = LabState(
                enabled=True,
                enabled_at=now,
                enabled_by_uid=-1 if uid is None else int(uid),
                auto_off_at=now + self._auto_off_minutes * 60,
                env_snapshot=snapshot,
            )
        self._log("lab_enable", {"uid": uid, "auto_off_after_minutes": self._auto_off_minutes, "snapshot": snapshot})
        return True, None, snapshot

    def disable(self, uid):
        with self._lock:
            was_enabled = self._state.enabled
            previous = asdict(self._state)
            self._state = LabState(enabled=False)
        self._log("lab_disable", {"uid": uid, "was_enabled": was_enabled, "previous": previous if was_enabled else None})
        return True, None

    def _auto_disable(self, reason):
        with self._lock:
            if not self._state.enabled:
                return
            previous = asdict(self._state)
            self._state = LabState(enabled=False, reason=reason)
        self._log("lab_auto_disable", {"reason": reason, "previous": previous})

    def verify(self, uid):
        snapshot = env_check(self.policy, dev=self.dev)
        self._log("lab_verify", {"uid": uid, "ok": snapshot["ok"], "snapshot": snapshot})
        return snapshot["ok"], snapshot

    def guard(self, flag_path):
        if not flag_path or not flag_path.startswith("destructive_study."):
            return True, None, None
        if not self._configured:
            return False, "lab_mode disabled", None
        if not self.is_enabled():
            with self._lock:
                reason = self._state.reason or "lab_mode not enabled"
            return False, f"lab mode not active ({reason})", None
        snapshot = env_check(self.policy, dev=self.dev)
        if not snapshot["ok"]:
            failed = [key for key, value in snapshot["checks"].items() if not value["ok"]]
            self._auto_disable("env invalidated: " + ", ".join(failed))
            return False, "lab env check failed: " + ", ".join(failed), snapshot
        return True, None, snapshot

    def record_start(self, cmd, flag_path, env_snapshot, uid):
        evidence_id = self._evidence.new_id()
        sample_paths = _extract_sample_paths(cmd) if self._require_sample_hash else None
        self._evidence.start_record(evidence_id, cmd, flag_path, env_snapshot, uid, sample_paths=sample_paths)
        self._log("evidence_start", {"evidence_id": evidence_id, "command": cmd, "flag_path": flag_path, "uid": uid})
        return evidence_id

    def record_end(self, evidence_id, rc, stdout_sha256=None, stderr_sha256=None, duration_ms=None, sandboxed=False):
        self._evidence.end_record(evidence_id, rc, stdout_sha256=stdout_sha256,
                                  stderr_sha256=stderr_sha256, duration_ms=duration_ms,
                                  sandboxed=sandboxed)
        self._log("evidence_end", {"evidence_id": evidence_id, "rc": rc, "duration_ms": duration_ms, "sandboxed": sandboxed})

    def shutdown(self):
        self._timer.stop()

    def _log(self, op, fields):
        try:
            rec = {"ts": datetime.now(timezone.utc).isoformat(), "op": op, "policy_id": self.policy.get("policy_id")}
            rec.update(fields)
            self.history.write(rec)
        except Exception:
            pass
