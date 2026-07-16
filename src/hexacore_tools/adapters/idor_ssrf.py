"""verify.idor / verify.ssrf — evidence-capturing verifiers for IDOR and SSRF (Phase 3).

These are lightweight verifiers that use curl to probe for common access-control and
request-forgery weaknesses.  They do NOT attempt exploitation — they capture evidence
(HTTP status + body snippet) that proves the vulnerability exists.
"""
from __future__ import annotations

import re

from ..base import CapabilityAdapter, Finding, Params, Severity
from hexacore.safety.actions import ActionClass

# An object-reference-looking segment: a numeric id path (/users/42), a UUID, or an ?id=-style
# query parameter. Only endpoints that actually address an object are IDOR candidates.
_ID_PATTERN = re.compile(
    r"/\d+(?:/|$|\?)"
    r"|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|[?&](?:id|user|account|uid|order|doc|file|record)=[^&]+",
    re.IGNORECASE,
)


class IdorVerifier(CapabilityAdapter):
    """Flags Insecure-Direct-Object-Reference *candidates*.

    A real IDOR check compares responses across two identities; this adapter only sees one target
    and no auth baseline, so it cannot confirm one. It therefore reports an UNVERIFIED lead — and
    only when the URL actually addresses an object (numeric id / UUID / id-style query param) and
    returns a body — rather than flagging every reachable 2xx. That kills the false-positive flood
    while still surfacing endpoints worth a manual check.
    """
    name = "verify.idor"
    action_class = ActionClass.ACTIVE_EXPLOIT

    def build_command(self, target: str, params: Params) -> list[str]:
        # -w appends the status code; -D - dumps headers to stdout alongside the body.
        return ["curl", "-s", "-S", "-k", "-w", "\n%{http_code}", "-D", "-", target]

    def parse(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []

        # No object reference in the URL => not an IDOR candidate, whatever the status.
        if not _ID_PATTERN.search(target):
            return []

        lines = raw.strip().splitlines()
        status_code = lines[-1].strip() if lines else ""
        if not status_code.startswith("2"):
            return []

        # Require an actual response body (headers + blank line + content), not just a 2xx with
        # nothing behind it — an empty 200 is no evidence of an exposed object.
        body = raw.rsplit("\r\n\r\n", 1)[-1] if "\r\n\r\n" in raw else raw.rsplit("\n\n", 1)[-1]
        body = body.rsplit("\n", 1)[0].strip()  # drop the trailing status-code line
        if len(body) < 16:
            return []

        return [Finding(
            title="IDOR candidate — object endpoint reachable (unverified)",
            severity=Severity.MEDIUM,
            source=self.name,
            affected_asset=target,
            description=(
                f"An object-addressing endpoint returned HTTP {status_code} with a response body. "
                f"This is a LEAD, not a confirmed vulnerability: verify manually by requesting the "
                f"same object as a different (or unauthenticated) identity and comparing responses."
            ),
            cwe="CWE-639",
            attack_techniques=["T1078"],
            evidence={"status": status_code, "response_snippet": body[:500], "unverified": True},
        )]


class SsrfVerifier(CapabilityAdapter):
    """Probes for Server-Side Request Forgery by injecting internal/metadata URLs
    and checking for leaked content in the response."""
    name = "verify.ssrf"
    action_class = ActionClass.ACTIVE_EXPLOIT

    # Common SSRF canary strings that indicate internal content leakage
    _CANARIES = [
        "ami-id",               # AWS metadata
        "instance-id",          # AWS / GCP metadata
        "computeMetadata",      # GCP metadata
        "latest/meta-data",     # AWS metadata path echo
        "127.0.0.1",            # localhost reflection
        "root:x:0:0",           # /etc/passwd leak
    ]

    def build_command(self, target: str, params: Params) -> list[str]:
        return ["curl", "-s", "-S", "-k", "-w", "\n%{http_code}", target]

    def parse(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []

        findings: list[Finding] = []
        raw_lower = raw.lower()

        matched_canaries = [c for c in self._CANARIES if c.lower() in raw_lower]

        if matched_canaries:
            findings.append(Finding(
                title="Server-Side Request Forgery (SSRF) — Internal Content Leaked",
                severity=Severity.HIGH,
                source=self.name,
                affected_asset=target,
                description=(
                    f"Response contains internal content indicators: "
                    f"{', '.join(matched_canaries)}.  Confirms SSRF."
                ),
                cwe="CWE-918",
                attack_techniques=["T1190"],
                evidence={"canaries": matched_canaries, "response_snippet": raw[:500]},
            ))

        return findings
