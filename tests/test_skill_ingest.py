from pathlib import Path

from skillsvc.ingest import ingest, write_index, write_report


def _skill(root: Path, slug: str, frontmatter: str, body: str = "\n## Workflow\nsteps\n") -> None:
    d = root / "skills" / slug
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(f"---\n{frontmatter}\n---\n{body}", encoding="utf-8")


def test_valid_skill_indexed(tmp_path):
    _skill(tmp_path, "good-skill",
           "name: good-skill\ndescription: Does a clean thing.\ntags:\n- recon\n")
    result = ingest(tmp_path)
    assert len(result.valid_records) == 1
    assert result.valid_records[0].name == "good-skill"
    assert result.valid_records[0].tags == ["recon"]


def test_block_scalar_leak_flagged(tmp_path):
    # The ">-" leaked-description bug from Brain/00 §1.2.
    _skill(tmp_path, "leaky", 'name: leaky\ndescription: ">-"\ntags:\n- x\n')
    result = ingest(tmp_path)
    assert any(i.problem.startswith("leaked YAML block scalar") for i in result.issues)
    assert len(result.valid_records) == 0


def test_truncated_description_flagged(tmp_path):
    _skill(tmp_path, "cut",
           "name: cut\ndescription: This sentence just stops mid\ntags:\n- x\n")
    result = ingest(tmp_path)
    assert any("truncated" in i.problem for i in result.issues)


def test_missing_fields_flagged(tmp_path):
    _skill(tmp_path, "bare", "name: bare\n")
    result = ingest(tmp_path)
    problems = {i.field for i in result.issues}
    assert "description" in problems and "tags" in problems


def test_folder_name_mismatch_flagged(tmp_path):
    _skill(tmp_path, "folder-slug",
           "name: different-name\ndescription: Fine.\ntags:\n- x\n")
    result = ingest(tmp_path)
    assert any(i.field == "name" and "match" in i.problem for i in result.issues)


def test_missing_frontmatter_flagged(tmp_path):
    d = tmp_path / "skills" / "no-fm"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text("# Just a body\n", encoding="utf-8")
    result = ingest(tmp_path)
    assert any(i.problem == "no frontmatter block found" for i in result.issues)


def test_missing_procedure_section_flagged(tmp_path):
    _skill(tmp_path, "no-proc",
           "name: no-proc\ndescription: Fine.\ntags:\n- x\n", body="\n## When to Use\nx\n")
    result = ingest(tmp_path)
    assert any("procedure" in i.problem for i in result.issues)


def test_steps_heading_counts_as_procedure(tmp_path):
    _skill(tmp_path, "uses-steps",
           "name: uses-steps\ndescription: Fine.\ntags:\n- x\n", body="\n## Steps\ndo things\n")
    result = ingest(tmp_path)
    assert not any("procedure" in i.problem for i in result.issues)
    assert result.valid_records and result.valid_records[0].slug == "uses-steps"


def test_report_and_index_written(tmp_path):
    _skill(tmp_path, "good",
           "name: good\ndescription: Fine.\ntags:\n- x\n")
    _skill(tmp_path, "bad", 'name: good\ndescription: ">-"\ntags:\n- x\n')  # dup name + leak
    result = ingest(tmp_path)
    write_index(result, tmp_path / "idx.json")
    write_report(result, tmp_path / "report.md")
    assert (tmp_path / "idx.json").exists()
    report = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "# Skills Validation Report" in report
    assert "Flagged" in report
