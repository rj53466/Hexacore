"""Action Classifier — maps (capability, params) -> ActionClass (Brain/05 §4, Epic A5).

Table-driven and conservative: a capability we don't recognise is classified DESTRUCTIVE so it
always hits the approval gate (deny-by-default extends to classification). Some capabilities
escalate based on parameters — e.g. sqlmap in detection-only mode is a scan-safe check, but
enabling data extraction / OS shell makes it exploit- or destructive-class.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping, Optional

from .actions import ActionClass

Params = Mapping[str, object]
Escalator = Callable[[Params], Optional[ActionClass]]


@dataclass(frozen=True)
class CapabilitySpec:
    default_class: ActionClass
    escalate: Optional[Escalator] = None


def _sqlmap_escalate(params: Params) -> Optional[ActionClass]:
    # Verify-don't-detonate: detection-only is a safe check; extraction/shell is real exploitation.
    mode = str(params.get("mode", "detection")).lower()
    if params.get("os_shell") or params.get("dump_all"):
        return ActionClass.DESTRUCTIVE
    if mode in {"detection", "detect", "check"}:
        return ActionClass.ACTIVE_SCAN
    return ActionClass.ACTIVE_EXPLOIT


def _msf_escalate(params: Params) -> Optional[ActionClass]:
    action = str(params.get("action", "check")).lower()
    if action == "check":
        return ActionClass.ACTIVE_SCAN      # Metasploit `check` module is a safe verification
    if action == "exploit":
        return ActionClass.DESTRUCTIVE      # memory-corruption exploits carry crash risk
    return ActionClass.ACTIVE_EXPLOIT


# Default registry seeded from Brain/06 and Brain/08. Extend as capabilities are added.
DEFAULT_REGISTRY: dict[str, CapabilitySpec] = {
    # --- recon (passive) ---
    "recon.subdomains": CapabilitySpec(ActionClass.PASSIVE),
    "recon.dns": CapabilitySpec(ActionClass.PASSIVE),
    "recon.http_probe": CapabilitySpec(ActionClass.PASSIVE),
    "recon.tech": CapabilitySpec(ActionClass.PASSIVE),
    "recon.tls": CapabilitySpec(ActionClass.PASSIVE),
    "recon.ct_logs": CapabilitySpec(ActionClass.PASSIVE),
    "recon.osint": CapabilitySpec(ActionClass.PASSIVE),
    # --- active scan ---
    "scan.ports": CapabilitySpec(ActionClass.ACTIVE_SCAN),
    "scan.tls": CapabilitySpec(ActionClass.ACTIVE_SCAN),
    "scan.web_nuclei": CapabilitySpec(ActionClass.ACTIVE_SCAN),
    "scan.web_nikto": CapabilitySpec(ActionClass.ACTIVE_SCAN),
    "scan.web_dir": CapabilitySpec(ActionClass.ACTIVE_SCAN),
    "scan.web_dast_zap": CapabilitySpec(ActionClass.ACTIVE_SCAN),
    "scan.web_dast_burp": CapabilitySpec(ActionClass.ACTIVE_SCAN),
    "scan.smb_enum": CapabilitySpec(ActionClass.ACTIVE_SCAN),
    # --- verify / exploit (gated) ---
    "verify.web_sqli": CapabilitySpec(ActionClass.ACTIVE_EXPLOIT, _sqlmap_escalate),
    "verify.msf_check": CapabilitySpec(ActionClass.ACTIVE_EXPLOIT, _msf_escalate),
    "verify.idor": CapabilitySpec(ActionClass.ACTIVE_EXPLOIT),
    "verify.ssrf": CapabilitySpec(ActionClass.ACTIVE_EXPLOIT),
    "verify.adcs_find": CapabilitySpec(ActionClass.ACTIVE_SCAN),   # `find`, not `abuse`
    # --- AD / identity ---
    "enum.bloodhound": CapabilitySpec(ActionClass.ACTIVE_SCAN),
    "enum.netexec": CapabilitySpec(ActionClass.ACTIVE_EXPLOIT),
    # --- cloud ---
    "cloud.scout": CapabilitySpec(ActionClass.ACTIVE_SCAN),
    "cloud.enum": CapabilitySpec(ActionClass.ACTIVE_SCAN),
    "cloud.exploit": CapabilitySpec(ActionClass.ACTIVE_EXPLOIT),
}


class UnknownCapability(Exception):
    pass


class ActionClassifier:
    def __init__(
        self,
        registry: Optional[Mapping[str, CapabilitySpec]] = None,
        *,
        strict: bool = False,
    ):
        """``strict=True`` raises on an unknown capability; otherwise it is classified
        DESTRUCTIVE (max caution) so it can never slip through un-gated."""
        self.registry = dict(registry) if registry is not None else dict(DEFAULT_REGISTRY)
        self.strict = strict

    def classify(self, capability: str, params: Optional[Params] = None) -> ActionClass:
        params = params or {}
        spec = self.registry.get(capability)
        if spec is None:
            if self.strict:
                raise UnknownCapability(capability)
            return ActionClass.DESTRUCTIVE
        if spec.escalate is not None:
            escalated = spec.escalate(params)
            if escalated is not None:
                return escalated
        return spec.default_class
