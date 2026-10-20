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
