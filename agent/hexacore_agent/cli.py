"""`make engage SCOPE=engagements/<name>.yaml` — load, authorize, start, and run an engagement.

Wires the whole stack together: scope-file loader -> EngagementService (audited) -> SafetyLayer
built from the engagement's scope -> CapabilityExecutor on the configured backend (dryrun/docker/
vm) -> SimpleEngagementRunner. Prints the live feed and the severity rollup. With the default
`dryrun` backend nothing executes (0 findings) but the full flow + safety gating is exercised;
point HEXACORE_RUNNER_BACKEND at docker/vm to run for real.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
for _p in ("api", "tools"):
    _pp = str(_ROOT / _p)
    if _pp not in sys.path:
        sys.path.insert(0, _pp)

from hexacore.engagements import EngagementError, EngagementService  # noqa: E402
from hexacore.loader import load_engagement  # noqa: E402
from hexacore.safety import (  # noqa: E402
    ActionClassifier, ApprovalGate, AuditLog, KillSwitch, SafetyLayer, ScopeValidator,
)
from hexacore_tools import CapabilityExecutor, RunnerSettings, build_backend  # noqa: E402
from hexacore_tools.adapters import default_registry  # noqa: E402

from .runner import RunEvent, SimpleEngagementRunner  # noqa: E402


def _print_event(ev: RunEvent) -> None:
    # ASCII markers so the live feed prints on any terminal/codepage (Windows cp1252 included).
    icon = {"phase.changed": "==", "command.started": "->", "command.finished": "ok",
            "scope.denied": "XX", "gate.requested": "||", "finding.created": " *"}.get(ev.type, "  ")
    print(f"  [{icon}] [{ev.phase:<7}] {ev.detail}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a HexaCore engagement from a scope file.")
    parser.add_argument("--scope", required=True, help="path to engagements/<name>.yaml")
    parser.add_argument("--quiet", action="store_true", help="suppress the live event feed")
    parser.add_argument("--report-dir", default="reports",
                        help="write html/pdf/docx report here (default: reports/)")
    parser.add_argument("--engine", choices=["deterministic", "langgraph"], default="deterministic",
                        help="orchestration engine (langgraph = the stateful graph agent)")
    args = parser.parse_args(argv)

    audit = AuditLog()
    kill = KillSwitch()
    service = EngagementService(audit=audit, kill_switch=kill)

    loaded = load_engagement(args.scope, service)
    eng = loaded.engagement
    print(f"Engagement: {eng.name} ({eng.client})  status={eng.status.value}  "
          f"autonomy={eng.autonomy_profile}")
    print(f"Scope ceiling: {eng.scope.max_action_class.value}  "
          f"domains={eng.scope.allow_domains}  cidrs={eng.scope.allow_cidrs}")

    settings = RunnerSettings.from_env()
    backend = build_backend(settings)
    check = backend.check()
    print(f"Backend: {settings.backend}  ({'ready' if check.ok else 'NOT READY'}: {check.detail})")

    try:
        service.start(eng.id, actor="operator")
    except EngagementError as exc:
        print(f"\n[X] cannot start: {exc}")
        print("    (add a valid authorization block to the scope file — Brain/05 §3)")
        return 1

    safety = SafetyLayer(
        scope_validator=ScopeValidator(eng.scope), classifier=ActionClassifier(),
        gate=ApprovalGate(), kill_switch=kill, audit=audit,
    )
    executor = CapabilityExecutor(safety=safety, registry=default_registry(), sandbox=backend)
    on_event = None if args.quiet else _print_event
    if args.engine == "langgraph":
        from .graph import LangGraphEngagementRunner
        runner = LangGraphEngagementRunner(executor, on_event=on_event)
    else:
        runner = SimpleEngagementRunner(executor, on_event=on_event)

    print(f"\nRunning golden path (recon -> scan -> analyze) [engine={args.engine}]...\n")
    report = runner.run(eng, seed_domains=loaded.seed_domains, seed_hosts=loaded.seed_hosts)

    c = report.counts
    print("\n--- Severity summary ---")
    print(f"  Critical {c.critical} | High {c.high} | Medium {c.medium} | Low {c.low} | "
          f"Info {c.info}   (total {c.total})")
    if report.denied_targets:
        print(f"  Scope-denied targets: {sorted(set(report.denied_targets))}")
    if report.gated:
        print(f"  Actions awaiting approval: {len(report.gated)}")
    print(f"\n{len(report.findings)} findings. Audit events: {len(audit.events)}.")

    # Branded report (html always; pdf/docx best-effort so a missing lib never fails the run).
    from pathlib import Path
    from hexacore_reporting import build_html
    outdir = Path(args.report_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / f"{eng.name}-report.html").write_text(build_html(eng, report), encoding="utf-8")
    written = ["html"]
    for fmt, builder in (("pdf", "build_pdf"), ("docx", "build_docx")):
        try:
            import hexacore_reporting as R
            (outdir / f"{eng.name}-report.{fmt}").write_bytes(getattr(R, builder)(eng, report))
            written.append(fmt)
        except Exception as exc:  # ponytail: report is a deliverable, not a run-blocker
            print(f"  [!] {fmt} skipped: {exc}")
    print(f"Report written to {outdir}/ ({', '.join(written)}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
