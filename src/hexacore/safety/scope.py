"""Scope Validator — the deny-by-default technical boundary (Brain/05 §2, Epic A4).

Resolves an intended target (URL / host / IP) and returns allow/deny against the engagement
Scope. Rules, in order:

1. Deny list ALWAYS wins.
2. Link-local / loopback / cloud-metadata IPs are denied unless the *exact* IP is explicitly
   allowed (guards SSRF-to-metadata, e.g. 169.254.169.254).
3. Allow only if the target matches an ``allow_domains`` suffix/wildcard entry or an
   ``allow_cidrs`` range. Everything else is denied.

An optional resolver enables a DNS-rebind guard: a hostname that is in-scope by domain but
resolves to a denied / metadata / out-of-scope IP is blocked at execution time.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional
from urllib.parse import urlsplit

from .actions import ActionClass

# IP ranges that must never be touched unless the exact address is explicitly allowed.
_METADATA_IPS = frozenset({
    ipaddress.ip_address("169.254.169.254"),   # AWS/GCP/Azure IMDS
    ipaddress.ip_address("100.100.100.200"),   # Alibaba metadata
    ipaddress.ip_address("fd00:ec2::254"),      # AWS IMDS IPv6
})


def _is_special_ip(ip: ipaddress._BaseAddress) -> bool:
    """Link-local, loopback, or a known metadata endpoint — off-limits by default."""
    return (
        ip in _METADATA_IPS
        or ip.is_link_local
        or ip.is_loopback
    )


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    matched_rule: Optional[str] = None
    target: Optional[str] = None

    def __bool__(self) -> bool:  # so callers can do `if decision:`
        return self.allowed


def _normalize_host(host: str) -> str:
    """Lowercase, strip trailing dot, and IDN-encode to punycode (ascii)."""
    host = host.strip().rstrip(".").lower()
    if not host:
        return host
    try:
        # Encodes unicode labels to xn--... so an allowlist of ascii domains stays exact.
        host = host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        # Un-encodable host (e.g. contains '_' or homoglyph mix) — leave as-is; it simply
        # won't match an ascii allowlist entry, which is the safe (deny) outcome.
        pass
    return host


def _extract_host(target: str) -> str:
    """Pull the host out of a URL, ``host:port``, or bare host/IP string."""
    t = target.strip()
    if "://" in t:
        t = urlsplit(t).hostname or ""
    else:
        # Bare "host:port" or "[ipv6]:port"
        if t.startswith("["):
            end = t.find("]")
            if end != -1:
                return t[1:end]
        elif t.count(":") == 1:
            t = t.split(":", 1)[0]
    return t


def _as_ip(host: str) -> Optional[ipaddress._BaseAddress]:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _domain_matches(host: str, entry: str) -> bool:
    """Suffix / wildcard match. ``example.com`` matches the apex and any subdomain;
    ``*.example.com`` matches subdomains only (not the apex)."""
    entry = entry.strip().rstrip(".").lower()
    if not entry or not host:
        return False
    if entry.startswith("*."):
        base = entry[2:]
        return host.endswith("." + base)
    return host == entry or host.endswith("." + entry)


@dataclass
class Scope:
    """The technical boundary for one engagement (Brain/05 §2)."""
    allow_domains: list[str] = field(default_factory=list)
    allow_cidrs: list[str] = field(default_factory=list)
    deny_list: list[str] = field(default_factory=list)  # domains and/or IPs/CIDRs; always wins
    max_action_class: ActionClass = ActionClass.ACTIVE_SCAN

    def __post_init__(self) -> None:
        self.max_action_class = ActionClass.parse(self.max_action_class)

    # -- deny-list helpers -------------------------------------------------
    def _deny_hit(self, host: str, ip: Optional[ipaddress._BaseAddress]) -> Optional[str]:
        for entry in self.deny_list:
            e = entry.strip().lower()
            if not e:
                continue
            net = _parse_network(e)
            if net is not None and ip is not None and ip in net:
                return entry
            if net is None and _domain_matches(host, e):
                return entry
            if net is None and host == e:
                return entry
        return None

    def _cidr_hit(self, ip: ipaddress._BaseAddress) -> Optional[str]:
        for entry in self.allow_cidrs:
            net = _parse_network(entry)
            if net is not None and ip in net:
                return entry
        return None

    def _domain_hit(self, host: str) -> Optional[str]:
        for entry in self.allow_domains:
            if _domain_matches(host, entry):
                return entry
        return None

    def _explicitly_allowed_ip(self, ip: ipaddress._BaseAddress) -> bool:
        """An exact /32 or /128 (or single-address) allow entry for this IP."""
        for entry in self.allow_cidrs:
            net = _parse_network(entry)
            if net is not None and net.num_addresses == 1 and ip in net:
                return True
        return False


def _parse_network(entry: str):
    entry = entry.strip()
    try:
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        # A bare IP address is a single-host network.
        ip = _as_ip(entry)
        if ip is not None:
            return ipaddress.ip_network(entry + ("/32" if ip.version == 4 else "/128"))
        return None


# A resolver maps a hostname to a list of IP strings (for the DNS-rebind guard).
Resolver = Callable[[str], Iterable[str]]


class ScopeValidator:
    """Wraps a Scope and answers allow/deny for targets. Instantiate per engagement."""

    def __init__(self, scope: Scope, resolver: Optional[Resolver] = None):
        self.scope = scope
        self.resolver = resolver

    def check(
        self,
        target: str,
        action_class: Optional[ActionClass] = None,
    ) -> Decision:
        raw = target
        host = _normalize_host(_extract_host(target))
        if not host:
            return Decision(False, "empty or unparseable target", target=raw)

        ip = _as_ip(host)

        # 1. Deny list always wins.
        deny = self.scope._deny_hit(host, ip)
        if deny is not None:
            return Decision(False, f"target is on the deny list ({deny})", deny, raw)

        # 2. Action-class ceiling.
        if action_class is not None and action_class > self.scope.max_action_class:
            return Decision(
                False,
                f"action class {action_class.value} exceeds engagement ceiling "
                f"{self.scope.max_action_class.value}",
                target=raw,
            )

        # 3/4. Allow decision for a literal IP target.
        if ip is not None:
            if _is_special_ip(ip) and not self.scope._explicitly_allowed_ip(ip):
                return Decision(False, "link-local / loopback / metadata IP is off-limits", target=raw)
            hit = self.scope._cidr_hit(ip)
            if hit is not None:
                return Decision(True, f"IP in allowed CIDR ({hit})", hit, raw)
            return Decision(False, "IP not in any allowed CIDR (deny-by-default)", target=raw)

        # 5. Allow decision for a hostname.
        hit = self.scope._domain_hit(host)
        if hit is None:
            return Decision(False, "host not in any allowed domain (deny-by-default)", target=raw)

        # 6. DNS-rebind guard: an in-scope hostname must not resolve to a denied,
        #    metadata, or out-of-scope address.
        if self.resolver is not None:
            resolved = [r for r in (_as_ip(a) for a in self.resolver(host)) if r is not None]
            for rip in resolved:
                if self.scope._deny_hit(host, rip) is not None:
                    return Decision(False, f"host resolves to a denied IP ({rip})", target=raw)
                if _is_special_ip(rip) and not self.scope._explicitly_allowed_ip(rip):
                    return Decision(
                        False,
                        f"host resolves to a link-local/metadata IP ({rip}) — possible DNS rebind",
                        target=raw,
                    )
        return Decision(True, f"host in allowed domain ({hit})", hit, raw)
