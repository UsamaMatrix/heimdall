# Heimdall Safety Guide

Heimdall is a policy-first terminal assistant. It helps run Linux commands through a local policy daemon before anything executes. This guide explains how the safety system works, how to edit rules safely, how to test changes, and what responsibilities remain with the operator.

This document is practical guidance, not legal advice. You are responsible for making sure every target, lab, website, network, account, dataset, and machine you test is owned by you or covered by clear written authorization.

## Safety model

Heimdall has several layers that work together.

1. `safety.yaml` is the machine-wide policy. It maps command names to policy flags and decides whether those flags are allowed, require confirmation, run in sandbox, or are denied.
2. `heimdald.py` is the daemon. It loads the root-owned policy and makes final command decisions.
3. `heimdall.py` is the client. It proposes commands, asks the daemon for a verdict, handles confirmations, applies playbook scope checks, and executes only after authorization.
4. Playbook scope files are session-specific guardrails for bug bounty or program work. They add stricter target boundaries on top of `safety.yaml`.
5. Lab mode gates destructive study, malware analysis, and similar work that should only happen in isolated environments.

Policy answers: “is this command type allowed on this machine?” Scope answers: “is this target allowed for this engagement?” Both must pass.

## Key files

| File | Purpose |
|---|---|
| `safety.yaml` | Main policy source in the repo. Installed to `/opt/heimdall/safety.yaml`. |
| `/opt/heimdall/safety.yaml` | Production policy used by the daemon after install. Root-owned and mode `0600`. |
| `heimdald.py` | Policy daemon and verdict engine. |
| `heimdall.py` | Client, model loop, playbook runner, scope gate, and command execution. |
| `scope.py` | Bug bounty in-scope and out-of-scope matching. |
| `objectives.py` | Objective, flag, and finding detection for playbooks. |
| `playbooks/*.yaml` | CTF, bug bounty, and self-hacking playbooks. |
| `templates/reports/*.j2` | Report layouts. |

## Verdicts

| Verdict | Meaning |
|---|---|
| `ALLOW` | Command may run without extra confirmation. Runtime mode still applies. |
| `ASK` | Command may run only after confirmation. The daemon may require an exact phrase. |
| `DENY` | Command is refused. Do not try to bypass this with another spelling. Fix policy only if you truly intended to allow it. |
| `DEFER` | Command cannot be decided safely in the current context. |

## Runtime modes

The active runtime mode is configured under `runtime_mode` in `safety.yaml` and stored at `/etc/heimdall/mode` after install.

| Mode | Use case |
|---|---|
| `direct` | Commands run on the host. Use only on machines you own and understand. |
| `sandbox` | Commands run under the sandbox backend when possible. Good for generated code and untrusted execution. |
| `hybrid` | Direct for low-risk work, sandbox for configured risky flags. Recommended default. |

Check mode:

```bash
heimdall mode show
```

Change mode:

```bash
sudo heimdall mode set hybrid
sudo heimdall mode set sandbox
```

## Editing policy safely

Use the repo file when developing changes:

```bash
cd ~/Desktop/heimdall
nano safety.yaml
python3 -m unittest discover -s tests
sudo ./heimdall-install.sh --mode hybrid
heimdall doctor
```

Use the installed file only for emergency local edits:

```bash
sudo nano /opt/heimdall/safety.yaml
sudo chmod 0600 /opt/heimdall/safety.yaml
sudo chown root:root /opt/heimdall/safety.yaml
sudo systemctl restart heimdald
heimdall doctor
```

Prefer repo edits because they are versioned, testable, and can be pushed to GitHub. Direct edits in `/opt/heimdall` are easy to lose during reinstall.

## Policy structure

A normal flag path looks like this:

```yaml
domains:
  red_teaming:
    flags:
      scanning:
        enabled: true
        flags:
          port_scan_tcp: { action: warn, message_key: offensive_active }

command_map:
  nmap: red_teaming.scanning.port_scan_tcp
```

The shape matters. Every category under `flags` that contains more flags must have its own `flags:` map.

Correct:

```yaml
bug_bounty:
  enabled: true
  flags:
    recon:
      enabled: true
      flags:
        subfinder: { action: warn, message_key: offensive_passive }
```

Incorrect:

```yaml
bug_bounty:
  enabled: true
  flags:
    recon:
      subfinder: { action: warn, message_key: offensive_passive }
      assetfinder: { action: warn, message_key: offensive_passive }
```

The incorrect version will fail policy loading because the daemon expects nested categories to expose `flags`.

## Flag values

A flag can be one of these shapes:

```yaml
safe_read: true
blocked_tool: false
warn_tool: { action: warn, message_key: offensive_active }
warn_custom: { action: warn, message: "Explain the specific risk here." }
```

Use `true` for read-only or low-risk operations. Use `false` for commands that should not run. Use `warn` when the command may be valid but needs human confirmation.

## Adding a new command mapping

1. Decide the domain and flag path.
2. Add the flag under `domains`.
3. Add the command basename under `command_map`.
4. Add or update tests if it changes expected behavior.
5. Run unit tests and daemon selftest.
6. Reinstall and restart daemon.

Example:

```yaml
domains:
  bug_bounty:
    flags:
      recon:
        enabled: true
        flags:
          example_passive_tool: { action: warn, message_key: offensive_passive }

command_map:
  example-passive-tool: bug_bounty.recon.example_passive_tool
```

Validate:

```bash
python3 -m unittest discover -s tests
python3 heimdald.py --dev --selftest
sudo ./heimdall-install.sh --mode hybrid
heimdall --cmd "example-passive-tool --help" --dry-run
```

## Confirmation messages

Reusable messages live under `messages:` in `safety.yaml`.

```yaml
messages:
  offensive_active: >-
    Active reconnaissance sends traffic to the target. Using it against
    systems you do not own or have written authorization to test is illegal
    in most jurisdictions. Proceed at your own responsibility?
```

Reference a reusable message like this:

```yaml
nmap_scan: { action: warn, message_key: offensive_active }
```

Use a specific message when the risk is special:

```yaml
custom_risky_step:
  action: warn
  message: "This action can alter service state. Confirm you have approval."
```

## Global deny rules

`global_deny` is the last-resort hard stop for patterns that should never run, regardless of command mapping.

```yaml
- match: '^rm\s+-rf\s+/(\s|$)'
  reason: "Root filesystem deletion"
- match: '(curl|wget)\s+[^|]*\|\s*(ba|z|k)?sh'
  reason: "Pipe-to-shell"
```

Only edit `global_deny` with great care. If a command is blocked here, assume the block is correct until you can prove otherwise.

## Scope files for bug bounty

Bug bounty playbooks require `--scope-file`. A scope file defines allowed and forbidden targets for that engagement.

```yaml
program: acme
platform: hackerone
in_scope:
  - host: "*.acme-test.com"
  - host: "acme-test.com"
out_of_scope:
  - host: "admin.acme-test.com"
rules:
  - no_dos
  - no_bruteforce
  - no_social_engineering
```

Run an in-scope dry-run:

```bash
heimdall --playbook bug_bounty --target acme-test.com \
  --scope-file /tmp/scope.yaml "recon this program" --dry-run
```

Run an out-of-scope dry-run:

```bash
heimdall --playbook bug_bounty --target admin.acme-test.com \
  --scope-file /tmp/scope.yaml "check admin panel" --dry-run
```

Expected behavior: Heimdall blocks before daemon verdict.

## CTF playbooks

CTF playbooks are objective-based. They finish when flags or declared objectives are detected, not merely when all phases have run.

```bash
heimdall --playbook ctf_linux --target 10.10.10.5 "solve this box" --dry-run
```

CTF authorization still matters. Only run CTF techniques against challenge machines that explicitly allow them.

## Lab mode

Lab mode protects destructive study workflows. It should be used for malware analysis, destructive samples, or isolated experiments.

```bash
heimdall lab status
heimdall lab verify
sudo heimdall lab on
sudo heimdall lab off
```

Do not enable lab mode on a normal internet-connected daily-use system just to force risky commands through. Fix the workflow or build an isolated lab.

## Auto-approve

Auto-approve never overrides `DENY` or `global_deny`.

Policy must opt in:

```yaml
defaults:
  allow_auto_approve: true
  auto_approve_requires_phrase: true
  auto_approve_phrase: "I ACCEPT AUTO-APPROVE FOR THIS SESSION"
```

Client usage:

```bash
heimdall --auto-approve --cmd "systemctl status sshd" --dry-run
```

Use auto-approve only when you understand the policy class and target scope.

## Common policy edit tasks

### Allow a read-only command

```yaml
domains:
  linux_administration:
    flags:
      system_info: true

command_map:
  hostnamectl: linux_administration.system_info
```

### Convert an allowed command to confirmation-required

```yaml
some_flag: { action: warn, message_key: privileged }
```

### Deny a command completely

```yaml
some_flag: false
```

### Add a tool that should run in sandbox

```yaml
runtime_mode:
  flag_enforce:
    "code_generation.python.execute": sandbox
```

## Testing checklist after policy edits

Run these before installing:

```bash
python3 -m unittest discover -s tests
python3 heimdald.py --dev --selftest
```

Install and verify:

```bash
sudo ./heimdall-install.sh --mode hybrid
heimdall doctor
heimdall ping
heimdall mode show
```

Try representative dry-runs:

```bash
heimdall --cmd "cat /etc/hostname" --dry-run
heimdall --cmd "rm -rf /" --dry-run
heimdall --cmd "nmap 10.0.0.1" --dry-run
```

Expected broad behavior:

- harmless read-only commands should be `ALLOW`
- destructive commands should be `DENY`
- active recon or privileged actions should usually be `ASK`

## Terminal encoding note

If box-drawing characters appear as `â•­â”€`, use ASCII mode:

```bash
heimdall --ascii ping
heimdall --ascii --playbook ctf_linux --target 10.10.10.5 "solve this box" --dry-run
```

## Operator responsibility

Heimdall can reduce mistakes, but it cannot grant authorization. Before running offensive, active, or destructive workflows, make sure you have:

- written authorization
- clearly defined scope
- time windows if required
- rate limits if required
- a rollback or recovery plan for systems you own
- permission to store evidence and logs

If any of these are missing, stop and clarify scope before running commands.

## Recovery commands

If policy breaks daemon startup, inspect logs:

```bash
sudo journalctl -u heimdald -n 80 --no-pager
```

Reinstall known-good repo policy:

```bash
cd ~/Desktop/heimdall
sudo ./heimdall-install.sh --mode hybrid
heimdall doctor
```

If a direct edit broke installed policy, compare it with repo policy:

```bash
sudo diff -u safety.yaml /opt/heimdall/safety.yaml
```

Restore from repo:

```bash
sudo install -o root -g root -m 0600 safety.yaml /opt/heimdall/safety.yaml
sudo systemctl restart heimdald
heimdall doctor
```

## Default recommendation

Keep the default posture conservative:

- Use `hybrid` mode.
- Keep `global_deny` strict.
- Use `ASK` for active recon and exploitation-adjacent tools.
- Use scope files for bug bounty work.
- Use lab mode for destructive study.
- Prefer dry-runs before real execution.
