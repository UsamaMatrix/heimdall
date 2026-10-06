#!/usr/bin/env python3
"""
scope.py ? bug bounty scope enforcement.

Scope file format (YAML):
  program: "acme-corp"
  platform: hackerone | bugcrowd | intigriti | private
  in_scope:
    - host: "*.acme.com"
    - host: "api.acme.com"
    - cidr: "10.20.0.0/16"
    - url:  "https://acme.com/*"
  out_of_scope:
    - host: "*.internal.acme.com"
    - url:  "https://acme.com/admin/dangerous-delete"
  rules:
    - no_dos
    - no_bruteforce
    - no_social_engineering
    - max_requests_per_second: 5
"""

import fnmatch
import ipaddress
import re
from dataclasses import dataclass
from typing import Optional

try:
    import yaml
except ImportError:  # pragma: no cover - exercised on minimal systems
    yaml = None

HOST_RE = re.compile(r"\b([a-z0-9][a-z0-9\-\.]*[a-z0-9]\.[a-z]{2,})\b", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)

@dataclass
class ScopeDecision:
    ok: bool
    reason: str = ""
    matched_rule: Optional[str] = None
    target: Optional[str] = None
    rule_name: Optional[str] = None
    rule_text: Optional[str] = None

class Scope:
    def __init__(self, spec: dict):
        spec = spec or {}
        self.program = spec.get("program", "unknown")
        self.platform = spec.get("platform", "private")
        self.in_scope = spec.get("in_scope") or []
        self.out_of_scope = spec.get("out_of_scope") or []
        self.rules = spec.get("rules") or []
        self._parse_rules()

    def _parse_rules(self):
        self.rule_flags = {
            "no_dos": True,
            "no_bruteforce": True,
            "no_social_engineering": True,
            "no_physical": True,
            "max_requests_per_second": None,
        }
        for rule in self.rules:
            if isinstance(rule, str):
                self.rule_flags[rule] = True
            elif isinstance(rule, dict):
                self.rule_flags.update(rule)

    @classmethod
    def load(cls, path):
        if yaml is None:
            raise RuntimeError("PyYAML required")
        with open(path, encoding="utf-8") as handle:
            return cls(yaml.safe_load(handle))

    def _extract_targets(self, cmd: str) -> list:
        targets = []
        targets.extend(URL_RE.findall(cmd))
        targets.extend(IP_RE.findall(cmd))
        for host in HOST_RE.findall(cmd):
            if host not in targets:
                targets.append(host)
        seen, out = set(), []
        for target in targets:
            cleaned = target.rstrip(".,;:)]}")
            if cleaned not in seen:
                seen.add(cleaned)
                out.append(cleaned)
        return out

    def _url_host(self, url: str) -> str:
        match = re.match(r"https?://([^/:]+)", url, re.I)
        return match.group(1) if match else url

    def _host_in(self, host: str, rules: list) -> Optional[dict]:
        host = self._url_host(host).lower()
        for rule in rules:
            pattern = rule.get("host") if isinstance(rule, dict) else None
            if pattern and fnmatch.fnmatch(host, pattern.lower()):
                return rule
        return None

    def _ip_in(self, ip_str: str, rules: list) -> Optional[dict]:
        try:
            ip = ipaddress.ip_network(ip_str, strict=False)
        except ValueError:
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                return None
        for rule in rules:
            cidr = rule.get("cidr") if isinstance(rule, dict) else None
            if not cidr:
                continue
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if isinstance(ip, ipaddress._BaseAddress):
                    if ip in net:
                        return rule
                elif ip.subnet_of(net) or net.subnet_of(ip):
                    return rule
            except ValueError:
                continue
        return None

    def _url_in(self, url: str, rules: list) -> Optional[dict]:
        for rule in rules:
            pattern = rule.get("url") if isinstance(rule, dict) else None
            if pattern and fnmatch.fnmatch(url, pattern):
                return rule
        return None

    def check_target(self, target: str) -> ScopeDecision:
        for match_fn in (self._url_in, self._host_in):
            rule = match_fn(target, self.out_of_scope)
            if rule:
                return ScopeDecision(False, f"target '{target}' matches out-of-scope rule", rule_name="out_of_scope", rule_text=str(rule))
        if IP_RE.fullmatch(target):
            rule = self._ip_in(target, self.out_of_scope)
            if rule:
                return ScopeDecision(False, f"target '{target}' matches out-of-scope CIDR", rule_name="out_of_scope", rule_text=str(rule))
        for match_fn in (self._url_in, self._host_in):
            rule = match_fn(target, self.in_scope)
            if rule:
                return ScopeDecision(True, target=target, matched_rule=str(rule))
        if IP_RE.fullmatch(target):
            rule = self._ip_in(target, self.in_scope)
            if rule:
                return ScopeDecision(True, target=target, matched_rule=str(rule))
        return ScopeDecision(False, f"target '{target}' is not in scope", rule_name="not_in_scope")

    def check_command(self, cmd: str) -> ScopeDecision:
        rule_decision = self.check_rules(cmd)
        if not rule_decision.ok:
            return rule_decision
        targets = self._extract_targets(cmd)
        if not targets:
            return ScopeDecision(True, "no target in command")
        checked = 0
        for target in targets:
            low = target.lower()
            if low in ("localhost", "127.0.0.1", "example.com"):
                continue
            decision = self.check_target(target)
            checked += 1
            if not decision.ok:
                return decision
        return ScopeDecision(True, f"all {checked} target(s) in scope")

    def check_rules(self, cmd: str) -> ScopeDecision:
        low = cmd.lower()
        if self.rule_flags.get("no_dos"):
            for bad in ("hping3", "slowloris", "goldeneye", "loic", "hoic"):
                if bad in low:
                    return ScopeDecision(False, f"DoS tool '{bad}' forbidden by scope", rule_name="no_dos")
        if self.rule_flags.get("no_bruteforce"):
            for bad in ("hydra", "medusa", "patator", "ncrack"):
                if bad in low:
                    return ScopeDecision(False, f"bruteforce tool '{bad}' forbidden", rule_name="no_bruteforce")
        if self.rule_flags.get("no_social_engineering"):
            for bad in ("setoolkit", "gophish", "evilginx"):
                if bad in low:
                    return ScopeDecision(False, f"SE tool '{bad}' forbidden", rule_name="no_social_engineering")
        return ScopeDecision(True)

    def summary(self) -> str:
        lines = [
            f"program: {self.program}",
            f"platform: {self.platform}",
            f"in-scope: {len(self.in_scope)} rule(s)",
            f"out-of-scope: {len(self.out_of_scope)} rule(s)",
            f"rules: {', '.join(k for k, v in self.rule_flags.items() if v is True) or '(none)'}",
        ]
        return "\n".join(lines)
