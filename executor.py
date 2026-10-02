#!/usr/bin/env python3
"""
executor.py - command execution for Heimdall.

run_command(cmd, mode, sandbox_config, timeout) -> ExecResult

Modes:
  direct   subprocess.run in the user's environment
  sandbox  bwrap with read-only root binds and configured writable paths
"""

import os
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass


@dataclass
class ExecResult:
    rc: int
    stdout: str
    stderr: str
    sandboxed: bool
    duration_ms: int


class SandboxUnavailable(Exception):
    pass


def _expand(path: str) -> str:
    return os.path.expanduser(os.path.expandvars(path))


def _build_bwrap_argv(cmd_argv, cfg, cwd=None):
    """Build a bwrap invocation from policy-supplied sandbox config."""
    if not shutil.which("bwrap"):
        raise SandboxUnavailable(
            "bwrap not installed. On Kali: sudo apt install bubblewrap")

    argv = ["bwrap"]

    ro_dirs = [
        "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64",
        "/libx32", "/etc/alternatives", "/opt",
    ]
    for path in ro_dirs:
        if os.path.exists(path):
            argv += ["--ro-bind", path, path]

    if os.path.exists("/etc"):
        argv += ["--ro-bind", "/etc", "/etc"]

    argv += ["--tmpfs", "/run"]
    argv += ["--tmpfs", "/tmp"]
    argv += ["--proc", "/proc"]
    argv += ["--dev", "/dev"]

    for path in cfg.get("rw_paths", []):
        expanded = _expand(path)
        if os.path.exists(expanded):
            argv += ["--bind", expanded, expanded]

    if cwd and os.path.isdir(cwd):
        argv += ["--chdir", cwd]

    argv += ["--die-with-parent", "--new-session"]

    for ns in cfg.get("unshare", []):
        if ns == "ipc":
            argv.append("--unshare-ipc")
        elif ns == "uts":
            argv.append("--unshare-uts")
        elif ns == "pid":
            argv.append("--unshare-pid")
        elif ns == "cgroup":
            argv.append("--unshare-cgroup-try")
        else:
            argv.append(f"--unshare-{ns}")

    if cfg.get("net", "none") == "none":
        argv.append("--unshare-net")

    caps = cfg.get("cap_drop", [])
    if caps:
        argv += ["--cap-drop", ",".join(cap.upper() for cap in caps)]

    argv += ["--"]
    argv += cmd_argv
    return argv


def run_command(cmd, mode, sandbox_config=None, timeout=180, cwd=None):
    try:
        cmd_argv = shlex.split(cmd)
    except ValueError as exc:
        return ExecResult(2, "", f"parse error: {exc}", False, 0)
    if not cmd_argv:
        return ExecResult(2, "", "empty command", False, 0)

    t0 = time.monotonic()
    sandboxed = False

    if mode == "sandbox":
        try:
            argv = _build_bwrap_argv(cmd_argv, sandbox_config or {}, cwd=cwd)
            sandboxed = True
        except SandboxUnavailable as exc:
            return ExecResult(3, "", str(exc), False, 0)
    else:
        argv = cmd_argv

    try:
        process = subprocess.run(
            argv,
            capture_output=True,
            timeout=timeout,
            text=True,
            errors="replace",
            stdin=subprocess.DEVNULL,
            cwd=cwd,
        )
        return ExecResult(
            process.returncode,
            process.stdout or "",
            process.stderr or "",
            sandboxed,
            int((time.monotonic() - t0) * 1000),
        )
    except subprocess.TimeoutExpired:
        return ExecResult(
            124, "", f"[timeout after {timeout}s]", sandboxed,
            int((time.monotonic() - t0) * 1000),
        )
    except FileNotFoundError as exc:
        return ExecResult(
            127, "", f"command not found: {exc.filename or exc}", sandboxed,
            int((time.monotonic() - t0) * 1000),
        )
    except PermissionError:
        return ExecResult(
            126, "", "permission denied", sandboxed,
            int((time.monotonic() - t0) * 1000),
        )
    except Exception as exc:
        return ExecResult(
            1, "", f"execution error: {exc}", sandboxed,
            int((time.monotonic() - t0) * 1000),
        )
