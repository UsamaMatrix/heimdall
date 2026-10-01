#!/usr/bin/env python3
"""
heimdald — Heimdall policy daemon
=================================

Reads /opt/heimdall/safety.yaml (or --policy PATH) and exposes a Unix
socket /run/heimdall/bifrost.sock that returns verdicts for proposed
commands. It NEVER executes anything.

Modes:
  prod  (default)  requires root; uses /opt, /run, /var/lib
  dev   (--dev)    allows non-root; uses ./dev-run/ tree; verbose

Usage:
  sudo heimdald                          # prod, foreground
  sudo heimdald --install                # installer flow (M4 stub)
  heimdald --dev                         # dev, no root needed
  heimdald --test "ls -la"               # one-shot verdict print, no socket
  heimdald --selftest                    # run built-in unit tests

Protocol (JSON lines over SOCK_STREAM):
  → {"op":"verdict","cmd":"<shell string>","request_mode":null}
  ← {"verdict":"ALLOW|DENY|ASK|DEFER","mode":"...","flag_path":"...",
     "message_key":null,"reason":null,"token":null,"latency_ms":N}
  → {"op":"mode_show"}
  ← {"mode":"direct","overrides":{...}}
  → {"op":"mode_set","mode":"sandbox","phrase":"I UNDERSTAND THE RISK"}
  ← {"ok":true,"previous":"direct","current":"sandbox"}
  → {"op":"ping"}
  ← {"pong":true,"version":"2.0.0"}
"""

import argparse
import hashlib
import hmac
import json
import os
import platform
import re
import shlex
import signal
import socket
import stat
import struct
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

VERSION = "2.0.0-m1"

BANNER = r"""
  H   H  EEEEE  III  M   M  DDDD    AAA   L      L
  H   H  E       I   MM MM  D   D  A   A  L      L
  HHHHH  EEEE    I   M M M  D   D  AAAAA  L      L
  H   H  E       I   M   M  D   D  A   A  L      L
  H   H  EEEEE  III  M   M  DDDD   A   A  LLLLL  LLLLL

                  T H E   W A T C H T O W E R
  -----------------------------------------------------
              Policy first. Every command.
""".strip("\n")


def print_banner():
    print(BANNER, flush=True)
    print(f"  Policy daemon / {VERSION}\n", flush=True)

# --------------------------------------------------------------------------
# Platform-aware path resolution
# --------------------------------------------------------------------------

def default_paths(dev: bool) -> dict:
    if dev:
        base = Path.cwd() / "dev-run"
        return {
            "policy":   Path(__file__).resolve().parent / "safety.yaml",
            "run":      base / "run",
            "var":      base / "var",
            "history":  base / "var" / "history",
            "evidence": base / "var" / "evidence",
            "mode_file": base / "etc" / "mode",
            "secret":   base / "var" / "secret",
        }
    return {
        "policy":   Path("/opt/heimdall/safety.yaml"),
        "run":      Path("/run/heimdall"),
        "var":      Path("/var/lib/heimdall"),
        "history":  Path("/var/lib/heimdall/history"),
        "evidence": Path("/var/lib/heimdall/evidence"),
        "mode_file": Path("/etc/heimdall/mode"),
        "secret":   Path("/var/lib/heimdall/secret"),
    }

# --------------------------------------------------------------------------
# Policy loading with strict validation
# --------------------------------------------------------------------------

class PolicyError(Exception):
    pass

def _check_owned_and_mode(path: Path, dev: bool):
    """In prod, safety.yaml must be root:root 0600 and not a symlink."""
    if dev:
        return
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise PolicyError(f"policy not found: {path}")
    if stat.S_ISLNK(st.st_mode):
        raise PolicyError(f"policy is a symlink: {path}")
    if not stat.S_ISREG(st.st_mode):
        raise PolicyError(f"policy is not a regular file: {path}")
    if st.st_uid != 0:
        raise PolicyError(f"policy not owned by root (uid={st.st_uid})")
    if st.st_mode & 0o077:
        raise PolicyError(f"policy mode must be 0600 (got {oct(st.st_mode & 0o777)})")
    parent = path.parent
    pst = os.stat(parent)
    if pst.st_mode & 0o002:
        raise PolicyError(f"policy directory is world-writable: {parent}")

def load_policy(path: Path, dev: bool) -> dict:
    _check_owned_and_mode(path, dev)
    try:
        import yaml
    except ImportError:
        raise PolicyError("PyYAML required: pip install pyyaml")
    with open(path, "r", encoding="utf-8") as f:
        policy = yaml.safe_load(f)
    if not isinstance(policy, dict):
        raise PolicyError("policy root must be a mapping")
    for req in ("version", "policy_id", "runtime_mode", "domains",
                "command_map", "global_deny"):
        if req not in policy:
            raise PolicyError(f"policy missing required section: {req}")
    try:
        for section in ("runtime_mode", "domains", "command_map"):
            if not isinstance(policy[section], dict):
                raise ValueError(f"{section} must be a mapping")
        if policy["runtime_mode"].get("default") not in ("direct", "sandbox", "hybrid"):
            raise ValueError("invalid default runtime mode")
        for rule in policy["global_deny"]:
            re.compile(rule["match"])
        paths = list(policy["command_map"].values())
        for submap in policy.get("command_map_subcommand", {}).values():
            paths.extend(submap.values())
        for flag in paths:
            if not isinstance(flag, str) or "." not in flag:
                raise ValueError(f"invalid flag path: {flag}")
            node = policy["domains"]
            for index, part in enumerate(flag.split(".")):
                node = node[part] if index == 0 else node["flags"][part]
            if type(node) is not bool and not (
                isinstance(node, dict) and node.get("action") in ("allow", "deny", "warn")
            ):
                raise ValueError(f"invalid flag value: {flag}")
    except (ValueError, TypeError, KeyError, AttributeError, re.error) as exc:
        raise PolicyError(f"invalid policy: {exc}") from exc
    return policy

# --------------------------------------------------------------------------
# Rule engine
# --------------------------------------------------------------------------

VERDICT_ALLOW = "ALLOW"
VERDICT_DENY  = "DENY"
VERDICT_ASK   = "ASK"
VERDICT_DEFER = "DEFER"

def _walk_flag(policy: dict, flag_path: str):
    """
    Walk a flag path like 'red_teaming.recon.passive_whois' through the
    nested domain tree. Returns (value, error_reason) where value is
    True/False/dict({'action':...}) or None on error.
    """
    parts = flag_path.split(".")
    domains = policy.get("domains", {})
    if parts[0] not in domains:
        return None, f"unknown domain '{parts[0]}'"
    node = domains[parts[0]]
    if not node.get("enabled", False):
        return None, f"domain '{parts[0]}' disabled"

    i = 1
    while i < len(parts):
        flags = node.get("flags", {})
        key = parts[i]
        if i == len(parts) - 1:
            if key not in flags:
                return None, f"unknown flag '{'.'.join(parts)}'"
            return flags[key], None
        # intermediate: must be a sub-domain
        sub = flags.get(key)
        if not isinstance(sub, dict) or "enabled" not in sub:
            return None, f"'{key}' is not a sub-domain"
        if not sub.get("enabled", False):
            return None, f"sub-domain '{key}' disabled"
        node = sub
        i += 1
    return None, "empty flag path"

def _resolve_flag_path(policy: dict, command: str):
    """Return (flag_path, error_reason)."""
    try:
        argv = shlex.split(command)
    except ValueError as e:
        return None, f"parse error: {e}"
    if not argv:
        return None, "empty command"
    cmd = os.path.basename(argv[0])
    sub = argv[1] if len(argv) > 1 else None

    submap = policy.get("command_map_subcommand", {}).get(cmd, {})
    if sub and sub in submap:
        return submap[sub], None
    if cmd in ("apt", "dnf", "cargo", "pip", "pip3") and submap:
        return None, f"unsupported subcommand for '{cmd}'"
    # Subcommands must match exactly; e.g. 'remove-all' is not 'remove'.

    flag_path = policy.get("command_map", {}).get(cmd)
    if flag_path is None:
        return None, f"no mapping for '{cmd}'"
    return flag_path, None

def _resolve_runtime_mode(policy: dict, flag_path: str, default_mode: str) -> str:
    rt = policy.get("runtime_mode", {})
    mode = default_mode or rt.get("default", "hybrid")

    domain = flag_path.split(".")[0]
    dom_enforce = rt.get("domain_enforce", {})
    if domain in dom_enforce:
        mode = dom_enforce[domain]

    flag_enforce = rt.get("flag_enforce", {})
    if flag_path in flag_enforce:
        mode = flag_enforce[flag_path]

    if mode == "hybrid":
        mode = _apply_hybrid(policy, flag_path)
    return mode

def _apply_hybrid(policy: dict, flag_path: str) -> str:
    hy = policy.get("runtime_mode", {}).get("hybrid", {})
    if not hy:
        return "direct"
    for rule in hy.get("auto_sandbox_when", []):
        if "flag_suffix_in" in rule:
            for suf in rule["flag_suffix_in"]:
                if flag_path.endswith(suf):
                    return "sandbox"
        if "flag_prefix_in" in rule:
            for pre in rule["flag_prefix_in"]:
                if flag_path.startswith(pre):
                    return "sandbox"
    return hy.get("default", "direct")

def resolve(policy: dict, command: str, default_mode: str) -> dict:
    """Return a verdict dict. Never raises."""
    t0 = time.perf_counter()
    result = {
        "verdict": VERDICT_DENY,
        "mode": None,
        "flag_path": None,
        "message_key": None,
        "message": None,
        "reason": None,
        "token": None,
    }

    if not isinstance(command, str):
        result.update(reason="command must be a string", latency_ms=0)
        return result

    # 1. global_deny — absolute
    for rule in policy.get("global_deny", []):
        try:
            if re.search(rule["match"], command):
                result["reason"] = f"global_deny: {rule.get('reason','matched')}"
                result["latency_ms"] = round((time.perf_counter()-t0)*1000, 2)
                return result
        except (re.error, KeyError, TypeError):
            result.update(reason="invalid global deny rule", latency_ms=0)
            return result

    # M1 handles a single simple command, never shell programs or wrappers.
    # Conservatively reject even quoted operators until a shell AST is supported.
    if any(char in command for char in ";&|<>`$\n\r()"):
        result.update(reason="shell syntax is unsupported", latency_ms=0)
        return result

    # 2. flag path resolution
    flag_path, err = _resolve_flag_path(policy, command)
    if flag_path is None:
        default_flag = policy.get("defaults", {}).get("unknown_command", False)
        result["reason"] = err
        result["verdict"] = VERDICT_ALLOW if default_flag is True else VERDICT_DENY
        result["latency_ms"] = round((time.perf_counter()-t0)*1000, 2)
        return result

    # 3. lab_mode gate
    if flag_path.startswith("destructive_study."):
        if not policy.get("lab_mode", {}).get("enabled", False):
            result["flag_path"] = flag_path
            result["reason"] = "lab_mode disabled"
            result["latency_ms"] = round((time.perf_counter()-t0)*1000, 2)
            return result

    # 4. flag value
    value, err = _walk_flag(policy, flag_path)
    if value is None and err:
        result["flag_path"] = flag_path
        result["reason"] = err
        result["latency_ms"] = round((time.perf_counter()-t0)*1000, 2)
        return result

    # 5. verdict from value
    if value is True:
        result["verdict"] = VERDICT_ALLOW
    elif value is False:
        result["verdict"] = VERDICT_DENY
        result["reason"] = "flag is false"
    elif isinstance(value, dict):
        action = value.get("action", "deny")
        if action == "allow":
            result["verdict"] = VERDICT_ALLOW
        elif action == "deny":
            result["verdict"] = VERDICT_DENY
        elif action == "warn":
            result["verdict"] = VERDICT_ASK
            result["message_key"] = value.get("message_key")
            result["message"] = value.get("message")
        else:
            result["verdict"] = VERDICT_DENY
            result["reason"] = f"unknown action '{action}'"
    else:
        result["verdict"] = VERDICT_DENY
        result["reason"] = "unrecognized flag value"

    # 6. runtime mode
    result["flag_path"] = flag_path
    result["mode"] = _resolve_runtime_mode(policy, flag_path, default_mode)
    if result.get("message_key"):
        result["message"] = policy.get("messages", {}).get(result["message_key"])
    result["latency_ms"] = round((time.perf_counter()-t0)*1000, 2)
    return result

# --------------------------------------------------------------------------
# HMAC token
# --------------------------------------------------------------------------

def _load_or_create_secret(path: Path) -> bytes:
    if path.exists():
        return path.read_bytes()
    path.parent.mkdir(parents=True, exist_ok=True)
    secret = os.urandom(32)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, secret)
    finally:
        os.close(fd)
    return secret

def mint_token(secret: bytes, command: str, mode: str) -> str:
    ch = hashlib.sha256(command.encode("utf-8")).hexdigest()
    payload = f"{ch}|{mode}"
    sig = hmac.new(secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}|{sig}"

def verify_token(secret: bytes, token: str, command: str, mode: str) -> bool:
    try:
        ch_part, mode_part, sig = token.split("|")
    except ValueError:
        return False
    ch = hashlib.sha256(command.encode("utf-8")).hexdigest()
    if ch_part != ch or mode_part != mode:
        return False
    expected = hmac.new(secret, f"{ch}|{mode}".encode("utf-8"),
                        hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)

# --------------------------------------------------------------------------
# Write-ahead history logger (hash-chained JSONL)
# --------------------------------------------------------------------------

class History:
    def __init__(self, directory: Path):
        self.dir = directory
        self.dir.mkdir(parents=True, exist_ok=True)
        self._last_hash_cache = {}
        self._last_hash_date = None

    def _today_path(self) -> Path:
        return self.dir / (datetime.now(timezone.utc).strftime("%Y-%m-%d") + ".jsonl")

    def _last_hash(self, path: Path) -> str:
        key = str(path)
        if key in self._last_hash_cache and self._last_hash_date == key:
            return self._last_hash_cache[key]
        if not path.exists():
            self._last_hash_cache[key] = "genesis"
            self._last_hash_date = key
            return "genesis"
        last_line = None
        with open(path, "rb") as f:
            for line in f:
                if line.strip():
                    last_line = line
        if last_line is None:
            return "genesis"
        try:
            record = json.loads(last_line)
            h = hashlib.sha256(last_line.rstrip(b"\n")).hexdigest()
            self._last_hash_cache[key] = h
            self._last_hash_date = key
            return h
        except Exception as exc:
            raise ValueError("invalid history tail") from exc

    def write(self, record: dict):
        """Write-ahead: called BEFORE execution in prod."""
        path = self._today_path()
        record["prev_hash"] = self._last_hash(path)
        line = (json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n").encode()
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0), 0o640)
        try:
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(line)
                stream.flush()
            os.fsync(fd)
        finally:
            os.close(fd)
        self._last_hash_cache[str(path)] = hashlib.sha256(line.rstrip(b"\n")).hexdigest()
        self._last_hash_date = str(path)

# --------------------------------------------------------------------------
# Socket server
# --------------------------------------------------------------------------

def peer_uid(conn: socket.socket):
    """Return peer uid, or None if not available (Windows/dev)."""
    try:
        SO_PEERCRED = getattr(socket, "SO_PEERCRED", None)
        if SO_PEERCRED is None:
            return None
        creds = conn.getsockopt(socket.SOL_SOCKET, SO_PEERCRED,
                                struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", creds)
        return uid
    except Exception:
        return None

class Daemon:
    def __init__(self, policy: dict, secret: bytes, paths: dict, dev: bool):
        self.policy = policy
        self.secret = secret
        self.paths = paths
        self.dev = dev
        self.history = History(paths["history"])
        self.default_mode = self._read_mode_file()
        self.running = True

    def _read_mode_file(self) -> str:
        mf = self.paths["mode_file"]
        if mf.exists():
            try:
                mode = mf.read_text().strip()
                if mode not in ("direct", "sandbox", "hybrid"):
                    raise PolicyError("invalid persisted mode")
                return mode
            except PolicyError:
                raise
            except Exception:
                pass
        return self.policy.get("runtime_mode", {}).get("default", "hybrid")

    def _write_mode_file(self, mode: str):
        mf = self.paths["mode_file"]
        mf.parent.mkdir(parents=True, exist_ok=True)
        mf.write_text(mode + "\n")

    def handle(self, conn: socket.socket, addr):
        uid = peer_uid(conn)
        conn.settimeout(10.0)
        buf = b""
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                buf += data
                if len(buf) > 65536:
                    conn.sendall(b'{"error":"request too large"}\n')
                    break
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        req = json.loads(line)
                    except Exception:
                        conn.sendall(b'{"error":"bad json"}\n')
                        continue
                    resp = self.dispatch(req, uid)
                    conn.sendall((json.dumps(resp) + "\n").encode())
        except socket.timeout:
            pass
        except Exception as e:
            try:
                conn.sendall((json.dumps({"error": str(e)}) + "\n").encode())
            except Exception:
                pass
        finally:
            conn.close()

    def dispatch(self, req: dict, uid) -> dict:
        if not isinstance(req, dict):
            return {"error": "request must be an object"}
        op = req.get("op")
        if op == "ping":
            return {"pong": True, "version": VERSION}
        if op == "verdict":
            return self._op_verdict(req, uid)
        if op == "mode_show":
            return self._op_mode_show()
        if op == "mode_set":
            return self._op_mode_set(req, uid)
        return {"error": f"unknown op '{op}'"}

    def _op_verdict(self, req: dict, uid) -> dict:
        if req.get("request_mode") is not None:
            return {"verdict": VERDICT_DENY, "reason": "request_mode overrides are not supported in M1"}
        cmd = req.get("cmd", "")
        result = resolve(self.policy, cmd, self.default_mode)
        # ASK is pending confirmation, not an authorization token.
        if result["verdict"] == VERDICT_ALLOW and result["mode"]:
            result["token"] = mint_token(self.secret, cmd, result["mode"])
        # enrich with message body if message_key present
        if result.get("message_key"):
            body = self.policy.get("messages", {}).get(result["message_key"])
            if body:
                result["message"] = body.strip()
        # write-ahead log
        try:
            self.history.write({
                "ts": datetime.now(timezone.utc).isoformat(),
                "peer_uid": uid,
                "op": "verdict",
                "command_sha256": hashlib.sha256(cmd.encode()).hexdigest() if isinstance(cmd, str) else None,
                "verdict": result["verdict"],
                "mode": result["mode"],
                "flag_path": result["flag_path"],
                "message_key": result.get("message_key"),
                "reason": result.get("reason"),
                "policy_id": self.policy.get("policy_id"),
            })
        except Exception as e:
            # fail-closed in prod
            if not self.dev:
                return {"verdict": VERDICT_DENY,
                        "reason": f"history write failed: {e}"}
        return result

    def _op_mode_show(self) -> dict:
        return {
            "mode": self.default_mode,
            "domain_enforce": self.policy.get("runtime_mode", {}).get("domain_enforce", {}),
            "flag_enforce": self.policy.get("runtime_mode", {}).get("flag_enforce", {}),
        }

    def _op_mode_set(self, req: dict, uid) -> dict:
        if not self.dev and uid != 0:
            return {"ok": False, "error": "peer not root"}
        new_mode = req.get("mode")
        if new_mode not in ("sandbox", "direct", "hybrid"):
            return {"ok": False, "error": "invalid mode"}
        phrase = req.get("phrase", "")
        expected = self.policy.get("defaults", {}).get(
            "mode_switch_confirmation_phrase", "I UNDERSTAND THE RISK")
        if not isinstance(phrase, str) or phrase.strip() != expected:
            return {"ok": False, "error": "phrase mismatch"}
        prev = self.default_mode
        try:
            self.history.write({
                "ts": datetime.now(timezone.utc).isoformat(),
                "peer_uid": uid,
                "op": "mode_set",
                "previous": prev,
                "current": new_mode,
            })
            self._write_mode_file(new_mode)
        except Exception as exc:
            return {"ok": False, "error": f"mode change failed: {exc}"}
        self.default_mode = new_mode
        return {"ok": True, "previous": prev, "current": new_mode}

    def serve(self, socket_path: Path):
        socket_path.parent.mkdir(parents=True, exist_ok=True)
        windows_dev = self.dev and os.name == "nt"
        if windows_dev:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.bind(("127.0.0.1", 47651))
            endpoint = "127.0.0.1:47651 (development only)"
        else:
            if socket_path.exists():
                if not stat.S_ISSOCK(socket_path.lstat().st_mode):
                    raise OSError(f"refusing to remove non-socket: {socket_path}")
                probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    probe.connect(str(socket_path))
                except ConnectionRefusedError:
                    socket_path.unlink()
                else:
                    raise OSError("another daemon is already listening")
                finally:
                    probe.close()
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(str(socket_path))
            os.chmod(str(socket_path), 0o660)
            endpoint = str(socket_path)
        srv.listen(8)
        srv.settimeout(1.0)
        print_banner()
        print(f"[heimdald] listening on {endpoint}", flush=True)
        print(f"[heimdald] policy_id={self.policy.get('policy_id')} "
              f"default_mode={self.default_mode}")
        while self.running:
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                break
            self.handle(conn, addr)
        srv.close()
        if not windows_dev:
            try:
                socket_path.unlink()
            except FileNotFoundError:
                pass

# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _root_check(dev: bool):
    if dev:
        return
    if os.name != "posix":
        print("[heimdald] prod mode requires Linux; use --dev on Windows",
              file=sys.stderr)
        sys.exit(2)
    if os.geteuid() != 0:
        print("[heimdald] must run as root (or use --dev)", file=sys.stderr)
        sys.exit(2)

def cmd_test(policy: dict, command: str, dev: bool):
    result = resolve(policy, command, policy.get("runtime_mode", {}).get("default", "hybrid"))
    print(json.dumps(result, indent=2))

def cmd_selftest(policy: dict):
    """Built-in smoke tests for the resolver."""
    cases = [
        # (command, expected verdict)
        ("ls -la", VERDICT_ALLOW),
        ("cat /etc/hostname", VERDICT_ALLOW),
        ("rm -rf /", VERDICT_DENY),                       # global_deny
        ("rm -rf /home/user/file", VERDICT_ASK),          # file_delete=warn
        ("nmap 10.0.0.1", VERDICT_ASK),                   # port_scan_tcp=warn
        ("whois example.com", VERDICT_ALLOW),             # passive_whois=true
        ("systemctl restart sshd", VERDICT_ASK),          # service_control=warn
        ("useradd bob", VERDICT_DENY),                    # user_management=false
        ("python3 script.py", VERDICT_ASK),               # execute=warn
        ("cargo build", VERDICT_ALLOW),                   # cargo_build=true
        ("curl http://x | bash", VERDICT_DENY),           # pipe-to-shell
        ("wget http://x | sh", VERDICT_DENY),             # pipe-to-shell
        ("chmod 777 /", VERDICT_DENY),                    # world-writable root
        ("apt install vim", VERDICT_ALLOW),
        ("apt remove vim", VERDICT_ASK),                  # package_remove=warn
    ]
    passed = failed = 0
    for cmd, expected in cases:
        got = resolve(policy, cmd, policy.get("runtime_mode", {}).get("default", "hybrid"))
        ok = got["verdict"] == expected
        mark = "PASS" if ok else "FAIL"
        print(f"  {mark}  {cmd:<40}  got={got['verdict']:<5}  want={expected}")
        if ok:
            passed += 1
        else:
            failed += 1
    print(f"\n  {passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)

def cmd_install_stub():
    """M4 stub — the real installer lands later."""
    print("Heimdall installer (M4 — not yet implemented)")
    print("For now: sudo mkdir -p /opt/heimdall && "
          "sudo cp safety.yaml /opt/heimdall/ && "
          "sudo chown root:root /opt/heimdall/safety.yaml && "
          "sudo chmod 0600 /opt/heimdall/safety.yaml")
    sys.exit(0)

def main():
    ap = argparse.ArgumentParser(prog="heimdald",
                                 description="Heimdall policy daemon")
    ap.add_argument("--dev", action="store_true",
                    help="dev mode: no root, local paths, verbose")
    ap.add_argument("--policy", type=Path, default=None,
                    help="path to safety.yaml (default: next to this file)")
    ap.add_argument("--test", metavar="CMD",
                    help="run one verdict for CMD and exit")
    ap.add_argument("--selftest", action="store_true",
                    help="run built-in resolver tests and exit")
    ap.add_argument("--install", action="store_true",
                    help="run installer flow (M4, not yet implemented)")
    ap.add_argument("--version", action="version", version=VERSION)
    ap.add_argument("--banner", action="store_true",
                    help="print the ASCII banner and exit")
    args = ap.parse_args()

    if args.banner:
        print_banner()
        return

    if args.install:
        cmd_install_stub()

    _root_check(args.dev)

    paths = default_paths(args.dev)
    policy_path = args.policy or paths["policy"]
    if not policy_path.exists():
        print(f"[heimdald] policy not found: {policy_path}", file=sys.stderr)
        sys.exit(2)
    try:
        policy = load_policy(policy_path, args.dev)
    except PolicyError as e:
        print(f"[heimdald] policy error: {e}", file=sys.stderr)
        sys.exit(2)

    if args.selftest:
        cmd_selftest(policy)
    if args.test:
        cmd_test(policy, args.test, args.dev)
        return

    # ensure runtime dirs
    paths["run"].mkdir(parents=True, exist_ok=True)
    paths["history"].mkdir(parents=True, exist_ok=True)
    paths["evidence"].mkdir(parents=True, exist_ok=True)
    if args.dev:
        try:
            os.chmod(str(paths["run"]), 0o755)
        except Exception:
            pass

    secret = _load_or_create_secret(paths["secret"])
    daemon = Daemon(policy, secret, paths, args.dev)

    def _stop(signum, frame):
        daemon.running = False
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    sock_path = paths["run"] / "bifrost.sock"
    try:
        daemon.serve(sock_path)
    except KeyboardInterrupt:
        pass
    print("[heimdald] stopped")

if __name__ == "__main__":
    main()
