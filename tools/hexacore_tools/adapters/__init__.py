"""Concrete capability adapters. `default_registry()` wires all Phase 1–3 adapters."""
from ..base import CapabilityRegistry
from .httpx import HttpxAdapter
from .nmap import NmapPortsAdapter
from .nuclei import NucleiAdapter
from .recon_extra import CrtShAdapter, DnsxAdapter, WhatwebAdapter
from .scan_extra import FfufAdapter, NiktoAdapter, TestsslAdapter
from .subfinder import SubfinderAdapter
from .sqlmap import SqlmapAdapter
from .metasploit import MetasploitCheckAdapter
from .idor_ssrf import IdorVerifier, SsrfVerifier
from .netexec import NetexecAdapter
from .certipy import CertipyFindAdapter
from .bloodhound import BloodhoundCollectorAdapter
from .cloud import ScoutSuiteAdapter, CloudFoxAdapter
from .api_sec import KiterunnerAdapter
from .linux_persistence import LinpeasAdapter

_ALL = [
    SubfinderAdapter, HttpxAdapter, DnsxAdapter, WhatwebAdapter, CrtShAdapter,  # recon
    NmapPortsAdapter, NucleiAdapter, TestsslAdapter, FfufAdapter, NiktoAdapter,  # scan
    SqlmapAdapter, MetasploitCheckAdapter,  # verify (Phase 2)
    IdorVerifier, SsrfVerifier, CertipyFindAdapter,  # verify (Phase 3)
    NetexecAdapter, BloodhoundCollectorAdapter, LinpeasAdapter,  # enum (Phase 3)
    ScoutSuiteAdapter, CloudFoxAdapter, KiterunnerAdapter,  # cloud & api_sec (Phase 3)
]


def default_registry() -> CapabilityRegistry:
    reg = CapabilityRegistry()
    for adapter in _ALL:
        reg.register(adapter())
    return reg


__all__ = [
    "SubfinderAdapter", "HttpxAdapter", "DnsxAdapter", "WhatwebAdapter", "CrtShAdapter",
    "NmapPortsAdapter", "NucleiAdapter", "TestsslAdapter", "FfufAdapter", "NiktoAdapter",
    "SqlmapAdapter", "MetasploitCheckAdapter",
    "IdorVerifier", "SsrfVerifier", "CertipyFindAdapter",
    "NetexecAdapter", "BloodhoundCollectorAdapter",
    "ScoutSuiteAdapter", "CloudFoxAdapter", "KiterunnerAdapter",
    "default_registry",
]
