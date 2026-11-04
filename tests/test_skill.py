"""Validate the bundled agent skill (skills/secure-kb-audit)."""
import os, re, subprocess, sys
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILL = os.path.join(ROOT, "skills", "secure-kb-audit")


def _fm():
    txt = open(os.path.join(SKILL, "SKILL.md"), encoding="utf-8").read()
    assert txt.startswith("---"), "SKILL.md must start with YAML frontmatter"
    return yaml.safe_load(txt.split("---", 2)[1])


def test_frontmatter_spec():
    fm = _fm()
    assert re.match(r"^[a-z0-9]+(?:-[a-z0-9]+)*$", fm["name"]) and len(fm["name"]) <= 64
    assert fm["name"] == os.path.basename(SKILL), "name must match the directory"
    assert 0 < len(fm["description"]) <= 1024
    assert "anthropic" not in fm["name"] and "claude" not in fm["name"]


def test_referenced_files_exist():
    body = open(os.path.join(SKILL, "SKILL.md"), encoding="utf-8").read()
    for rel in re.findall(r"`((?:references|assets|scripts)/[\w./-]+)`", body):
        assert os.path.exists(os.path.join(SKILL, rel)), f"SKILL.md references missing {rel}"


def test_find_kb_locates_this_repo():
    env = dict(os.environ, SECURE_KB_HOME=ROOT)
    r = subprocess.run([sys.executable, os.path.join(SKILL, "scripts", "find_kb.py")],
                       capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode == 0 and r.stdout.strip() == ROOT


# ---------- Phase 5: the skill must teach defensible dismissal ----------
def test_template_requires_a_threat_model():
    t = open(os.path.join(SKILL, "assets", "report-template.md"), encoding="utf-8").read()
    assert "## Threat model" in t, "the report must open with a threat model block"
    for field in ("Assets", "Trust boundaries", "Assumptions", "Out of scope"):
        assert field in t, f"threat model block lacks {field!r}"
    # the block must come before the findings, not after them
    assert t.index("## Threat model") < t.index("## Findings")


def test_template_forces_reasons_on_dismissals():
    t = open(os.path.join(SKILL, "assets", "report-template.md"), encoding="utf-8").read()
    assert "## Not applicable" in t and "What would make it apply" in t, (
        "an n/a row must state the condition that would make the check apply")
    assert "## Accepted risks" in t and "Not** acceptable for" in t, (
        "an accepted risk must say who it is NOT acceptable for")


def test_reporting_explains_how_to_dismiss():
    t = open(os.path.join(SKILL, "references", "reporting.md"), encoding="utf-8").read()
    assert "## Dismissing a finding" in t
    assert "assumption" in t.lower(), "a dismissal must name the assumption it rests on"
    assert "acceptable for" in t.lower(), "a dismissal must scope who it is acceptable for"


def test_skill_body_sends_the_agent_to_the_threat_model_first():
    body = open(os.path.join(SKILL, "SKILL.md"), encoding="utf-8").read()
    assert "threat model block" in body.lower()
    assert "dismissal needs a reason" in body.lower()
