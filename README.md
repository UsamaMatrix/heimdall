# Heimdall M2

Heimdall proposes one command at a time, checks it with a policy daemon, and
runs approved commands in direct mode. The daemon never executes commands;
the client uses the privileges of the user who started it. The client never
reads `safety.yaml` or the daemon's HMAC secret.

M2 includes the client, confirmation flow, direct execution, and an LLM loop.
Sandbox execution, scanners, rate limiting, session files, and the installer
remain later milestones. Commands requiring a sandbox stop before execution.

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
python heimdall.py --cmd "rm -rf /" --dry-run
```

The nmap preview requests the typed phrase; root deletion is denied. Dry-run
exercises confirmation and daemon approval but never launches a command. A goal
dry-run stops after its first proposal without reporting simulated success.

Windows defaults to dry-run. `--execute-on-windows` opts into direct execution
of available native tools; Linux tools typically are not installed on Windows.
Batch files are unsupported. Commands use POSIX quoting on both platforms;
use forward slashes in quoted Windows executable paths.

This workspace has a local runtime: replace `python` with
`.\.tooling\python\python.exe` if needed. Tooling and runtime state are excluded
from Git. State lives in `dev-run/` under the working directory. Windows listens
on `127.0.0.1:47651`; TCP is unauthenticated and for local development only.

## Kali production setup or update

Stop the old daemon with Ctrl+C. From your existing Desktop checkout:

```bash
cd ~/Desktop/heimdall
git pull --ff-only
sudo apt install python3-yaml
python3 -m unittest discover -s tests

sudo install -d -o root -g root -m 0755 /opt/heimdall
sudo install -o root -g root -m 0755 heimdald.py heimdall.py /opt/heimdall/
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
heimdall --cmd "cat /etc/hostname"
heimdall --cmd "systemctl status sshd" --dry-run
heimdall --cmd "nmap -sn 127.0.0.1" --dry-run
heimdall --cmd "python3 script.py"
```

Expected: ping succeeds, hostname prints, service and scan previews ask for
`I UNDERSTAND THE RISK`, and Python execution stops because it requires a
sandbox. The client does not elevate privileges. `sudo` wrappers are not mapped.
`newgrp` starts a subshell; `exit` leaves it.

Production requires root for the daemon and a private root-owned policy. Its
socket is `/run/heimdall/bifrost.sock`, mode 0660. `--socket-group heimdall` sets
the socket group on every startup. Without it, access uses the daemon's group.
A systemd service is not supplied yet.

For Linux development, start `python3 heimdald.py --dev` and use
`python3 heimdall.py --dev ping`. Linux production does not fall back to a
development endpoint when its socket is missing. Restart the daemon after
updating to M2 so the confirmation contract is available.

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
`HEIMDALL_LLM_MODEL`, for another compatible server. M2 does not add API-key
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
resolved mode `direct` before execution. It checks public hash and mode fields;
it cannot independently verify the HMAC signature and trusts the configured
daemon. Tokens have no expiry or replay protection and are not standalone
security capabilities. Confirmation records the client's assertion of approval,
not proof that a human was present.

`ping`, `mode_show`, and root-only production `mode_set` remain supported.
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

Lab environment checks, scanners, policy rate limits, and confirmation timeouts
are not enforced yet. M2 refuses to execute sandbox-required commands; M3 will
implement the sandbox. History is hash-chained JSONL, but it cannot protect
against an attacker rewriting the complete log. It records decisions and
confirmation, not command completion or persistent client sessions.

M1 was validated on Windows and Kali, including root production mode and a live
Unix-socket ping. M2 automated tests cover daemon confirmation, execution gates,
timeouts, bounded output, socket protocol, CLI previews, and an HTTP mock LLM
loop. A real Ollama model and Kali M2 execution still need validation.
