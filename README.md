# Heimdall M1

Policy daemon for Windows development and Kali Linux. Returns decisions for
proposed commands; it never executes them. Client, LLM integration, scanners,
sandbox execution, and installer are later milestones.

The ASCII Watchtower banner appears when the daemon starts. Preview it with
`python heimdald.py --banner`. Verdict JSON and selftest output remain separate.

## Windows

With Python installed:

```powershell
python -m pip install -r requirements.txt
python heimdald.py --dev --selftest
python -m unittest discover -s tests
python heimdald.py --dev --test "nmap 10.0.0.1"
python heimdald.py --dev
```

This workspace also has a local runtime: replace `python` with
`.\.tooling\python\python.exe` if needed. Runtime state is stored in `dev-run/`
under the working directory. Windows uses TCP `127.0.0.1:47651`; Linux uses
`dev-run/run/bifrost.sock`. The Windows endpoint has no peer authentication
and is for local development only.

## Kali

After transferring the repository to `/opt/heimdall`:

```bash
sudo apt install python3-yaml
sudo chown root:root /opt/heimdall/safety.yaml
sudo chmod 0600 /opt/heimdall/safety.yaml
sudo python3 /opt/heimdall/heimdald.py --selftest
sudo python3 /opt/heimdall/heimdald.py
```

Production requires root and listens on `/run/heimdall/bifrost.sock` (0600
policy, 0660 socket). Socket access depends on its owning group; M1 does not
create a group, shell entry point, or systemd service.

## Protocol and limits

Send newline-delimited JSON objects: `{"op":"ping"}`,
`{"op":"verdict","cmd":"ls -la"}`, `{"op":"mode_show"}`, or
`{"op":"mode_set","mode":"direct","phrase":"I UNDERSTAND THE RISK"}`.
Production mode changes require a root peer. Request mode overrides are rejected.

`ALLOW` receives an HMAC token bound to command and mode. `ASK` requires later
client confirmation and receives no token. Tokens have no expiry or replay
protection yet and are not execution capabilities. History is hash-chained JSONL,
with consistent hashes across restarts; this does not protect against an attacker
rewriting the entire log.

The resolver supports simple commands and exact first-argument subcommands.
Compound shell syntax is denied, including quoted shell metacharacters. Unknown
package-manager subcommands and options before subcommands fail closed.
This is command classification, not shell analysis or an execution security
boundary. Argument-specific distinctions outside the subcommand map are not
enforced. The supplied policy includes settings for future milestones: isolation
checks, rate limits, scanners, confirmation timeouts, and sandbox restrictions
are not implemented in M1. A `sandbox` verdict describes the required mode;
it does not launch a sandbox.

The supplied policy's `netdiscover`, `arp-scan`, and `nmap -sn` mappings point to
`recon.host_discovery`; `nmap -sV` points to `recon.service_fingerprint`.
Those flags live in recon, not scanning.
