"""Skill ingester + frontmatter validator (Brain/06 §3, Epic B1-B2).

Walks ``Heart/skills/**/SKILL.md``, parses YAML frontmatter + a couple of body sections, and
produces:

  * ``skills-index.json``           — a compact index of the valid skills (name, description, tags,
                                       domain, subdomain, frameworks, folder, body-section flags).
  * ``skills-validation-report.md`` — the punch list of malformed entries to curate.

Detected problems (the ones Brain/00 §1.2 and Brain/06 §3 call out):
  * missing/empty required fields (name, description, tags)
  * leaked YAML block scalar as description (a literal ``>-`` / ``|`` etc.)
  * truncated descriptions (end mid-sentence / mid-word)
  * folder/name mismatch
  * duplicate skill names
  * unparseable frontmatter or a missing frontmatter block
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

REQUIRED_FIELDS = ("name", "description", "tags")
# Body headings a well-formed skill should carry; their presence is a validation signal.
BODY_SECTIONS = ("When to Use", "Prerequisites", "Workflow", "Steps", "Instructions", "Verification")
# The corpus names the procedure one of these; a skill needs at least one.
PROCEDURE_SECTIONS = ("Workflow", "Steps", "Instructions")

_FRONTMATTER_RE = re.compile(r"^\s*---\s*\n(.*?)\n---\s*(?:\n|$)", re.DOTALL)
# A description that is just a leaked YAML block indicator (the ">-" bug from Brain/00).
_BLOCK_SCALAR_LEAK_RE = re.compile(r"^[>|][+\-]?\d*\s*$")
_ENDS_CLEANLY_RE = re.compile(r"[.!?)\"']$")


@dataclass
class SkillIssue:
    slug: str
    field: str
    problem: str
    detail: str = ""


@dataclass
class SkillRecord:
    slug: str                 # folder name
    path: str
    name: Optional[str] = None
    description: Optional[str] = None
    domain: Optional[str] = None
    subdomain: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    mitre_attack: list[str] = field(default_factory=list)
    nist_csf: list[str] = field(default_factory=list)
    sections_present: list[str] = field(default_factory=list)
    valid: bool = True

    def to_index(self) -> dict:
        return {
            "slug": self.slug,
            "name": self.name,
            "description": self.description,
            "domain": self.domain,
            "subdomain": self.subdomain,
            "tags": self.tags,
            "mitre_attack": self.mitre_attack,
            "nist_csf": self.nist_csf,
            "sections_present": self.sections_present,
            "path": self.path,
        }


@dataclass
class IngestResult:
    records: list[SkillRecord]
    issues: list[SkillIssue]

    @property
    def valid_records(self) -> list[SkillRecord]:
        return [r for r in self.records if r.valid]


def _split_frontmatter(text: str) -> tuple[Optional[str], str]:
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return None, text
    return m.group(1), text[m.end():]


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return [str(value).strip()]


def _sections_in_body(body: str) -> list[str]:
    present = []
    for heading in BODY_SECTIONS:
        if re.search(rf"^#+\s*{re.escape(heading)}\b", body, re.MULTILINE | re.IGNORECASE):
            present.append(heading)
    return present


def _validate(rec: SkillRecord, meta: dict, issues: list[SkillIssue]) -> None:
    before = len(issues)

    for f in REQUIRED_FIELDS:
        val = meta.get(f)
        if val is None or (isinstance(val, (str, list)) and len(val) == 0):
            issues.append(SkillIssue(rec.slug, f, "missing or empty required field"))

    desc = meta.get("description")
    if isinstance(desc, str):
        stripped = desc.strip()
        if _BLOCK_SCALAR_LEAK_RE.match(stripped):
            issues.append(SkillIssue(
                rec.slug, "description", "leaked YAML block scalar as description",
                detail=repr(stripped)))
        elif stripped and not _ENDS_CLEANLY_RE.search(stripped):
            issues.append(SkillIssue(
                rec.slug, "description", "possibly truncated (no terminal punctuation)",
                detail=repr(stripped[-60:])))

    name = meta.get("name")
    if isinstance(name, str) and name.strip() and name.strip() != rec.slug:
        issues.append(SkillIssue(
            rec.slug, "name", "frontmatter name does not match folder",
            detail=f"name={name.strip()!r} folder={rec.slug!r}"))

    if not any(s in rec.sections_present for s in PROCEDURE_SECTIONS):
        issues.append(SkillIssue(
            rec.slug, "body", "missing a procedure section",
            detail="expected a 'Workflow', 'Steps', or 'Instructions' heading"))

    if len(issues) > before:
        rec.valid = False


def ingest(heart_dir: Path) -> IngestResult:
    skills_root = heart_dir / "skills"
    if not skills_root.is_dir():
        raise FileNotFoundError(f"no skills directory at {skills_root}")

    records: list[SkillRecord] = []
    issues: list[SkillIssue] = []

    for skill_dir in sorted(p for p in skills_root.iterdir() if p.is_dir()):
        slug = skill_dir.name
        skill_md = skill_dir / "SKILL.md"
        rec = SkillRecord(slug=slug, path=str(skill_md.relative_to(heart_dir.parent))
                          if heart_dir.parent in skill_md.parents else str(skill_md))
        if not skill_md.is_file():
            rec.valid = False
            issues.append(SkillIssue(slug, "file", "no SKILL.md in skill folder"))
            records.append(rec)
            continue

        text = skill_md.read_text(encoding="utf-8", errors="replace")
        fm_text, body = _split_frontmatter(text)
        if fm_text is None:
            rec.valid = False
            issues.append(SkillIssue(slug, "frontmatter", "no frontmatter block found"))
            records.append(rec)
            continue

        try:
            meta = yaml.safe_load(fm_text) or {}
            if not isinstance(meta, dict):
                raise ValueError("frontmatter is not a mapping")
        except (yaml.YAMLError, ValueError) as exc:
            rec.valid = False
            issues.append(SkillIssue(slug, "frontmatter", "unparseable YAML", detail=str(exc)[:120]))
            records.append(rec)
            continue

        rec.name = str(meta.get("name")).strip() if meta.get("name") is not None else None
        rec.description = (str(meta.get("description")).strip()
                           if meta.get("description") is not None else None)
        rec.domain = meta.get("domain")
        rec.subdomain = meta.get("subdomain")
        rec.tags = _as_list(meta.get("tags"))
        rec.mitre_attack = _as_list(meta.get("mitre_attack"))
        rec.nist_csf = _as_list(meta.get("nist_csf"))
        rec.sections_present = _sections_in_body(body)

        _validate(rec, meta, issues)
        records.append(rec)

    # Duplicate-name detection across the corpus.
    name_counts = Counter(r.name for r in records if r.name)
    for name, n in name_counts.items():
        if n > 1:
            for r in records:
                if r.name == name:
                    r.valid = False
                    issues.append(SkillIssue(r.slug, "name", "duplicate skill name", detail=name))

    return IngestResult(records=records, issues=issues)


def write_index(result: IngestResult, out_path: Path) -> None:
    payload = {
        "count": len(result.records),
        "valid": len(result.valid_records),
        "skills": [r.to_index() for r in result.records if r.valid],
    }
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def write_report(result: IngestResult, out_path: Path) -> None:
    total = len(result.records)
    valid = len(result.valid_records)
    flagged = total - valid
    by_problem = Counter(i.problem for i in result.issues)

    lines: list[str] = []
    lines.append("# Skills Validation Report")
    lines.append("")
    lines.append(f"Generated by `skillsvc.ingest` over `Heart/skills/`. "
                 f"See Brain/06 §3 for the curation pipeline.")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Total skills:** {total}")
    lines.append(f"- **Valid (indexed):** {valid}")
    lines.append(f"- **Flagged:** {flagged}")
    lines.append(f"- **Total issues:** {len(result.issues)}")
    lines.append("")
    lines.append("### Issues by type")
    lines.append("")
    lines.append("| Problem | Count |")
    lines.append("|---|---|")
    for problem, n in by_problem.most_common():
        lines.append(f"| {problem} | {n} |")
    lines.append("")

    if result.issues:
        lines.append("## Flagged skills")
        lines.append("")
        lines.append("| Skill | Field | Problem | Detail |")
        lines.append("|---|---|---|---|")
        for i in sorted(result.issues, key=lambda x: (x.slug, x.field)):
            detail = i.detail.replace("|", "\\|")[:100]
            lines.append(f"| `{i.slug}` | {i.field} | {i.problem} | {detail} |")
        lines.append("")
    else:
        lines.append("No issues found. 🎉")
        lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Ingest + validate the HexaCore skills corpus.")
    parser.add_argument("--heart", default="Heart", help="path to the Heart/ corpus (default: Heart)")
    parser.add_argument("--report", default="skills-validation-report.md")
    parser.add_argument("--index", default="skills-index.json")
    args = parser.parse_args(argv)

    heart = Path(args.heart).resolve()
    result = ingest(heart)
    write_index(result, Path(args.index))
    write_report(result, Path(args.report))

    total = len(result.records)
    valid = len(result.valid_records)
    print(f"Ingested {total} skills: {valid} valid, {total - valid} flagged, "
          f"{len(result.issues)} issues.")
    print(f"Wrote {args.index} and {args.report}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
