"""The release verifier must pass, and must actually detect drift.

scripts/verify_release.py answers "is this repo consistent with itself?". These tests assert it
passes on the real repo, and — more importantly — that it fails when something is wrong, so it
cannot become a check that always says ok.
"""
import importlib.util
import os
import shutil
import textwrap

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _mod():
    spec = importlib.util.spec_from_file_location(
        "verify_release", os.path.join(ROOT, "scripts", "verify_release.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


vr = _mod()


@pytest.mark.parametrize("name,fn", vr.CHECKS, ids=[c[0] for c in vr.CHECKS])
def test_check_passes_on_this_repo(name, fn):
    assert fn() == [], f"{name} failed on the current tree"


def test_every_check_is_registered():
    assert len(vr.CHECKS) >= 9, "the verifier should cover version, counts, hash, shards, docs, skill"


def test_detects_a_phantom_card_in_the_shards(tmp_path, monkeypatch):
    """The bug that actually shipped: shards containing cards that no longer exist."""
    root = tmp_path
    (root / "checks" / "web").mkdir(parents=True)
    (root / "checks" / "web" / "SKB-A.yaml").write_text(
        "id: SKB-A\ntitle: t\n", encoding="utf-8")
    (root / "index" / "checks").mkdir(parents=True)
    (root / "index" / "checks" / "part-001.jsonl").write_text(
        '{"id": "SKB-A"}\n{"id": "SKB-GONE"}\n', encoding="utf-8")
    monkeypatch.setattr(vr, "ROOT", str(root))
    problems = vr.check_shards_match_cards()
    assert any("phantom" in p and "SKB-GONE" in p for p in problems), problems


def test_detects_a_version_mismatch(tmp_path, monkeypatch):
    root = tmp_path
    (root / "VERSION").write_text("1.2.3\n", encoding="utf-8")
    (root / "pyproject.toml").write_text('version = "9.9.9"\n', encoding="utf-8")
    (root / "manifest.json").write_text('{"version": "1.2.3", "cards": 0, "content_hash": "x"}',
                                        encoding="utf-8")
    (root / "manifest.committed.json").write_text(
        '{"version": "1.2.3", "cards": 0, "content_hash": "x"}', encoding="utf-8")
    monkeypatch.setattr(vr, "ROOT", str(root))
    problems = vr.check_version_consistency()
    assert any("pyproject.toml" in p for p in problems), problems


def test_detects_a_hash_mismatch(tmp_path, monkeypatch):
    root = tmp_path
    (root / "manifest.json").write_text('{"version":"1","cards":0,"content_hash":"aaa"}', encoding="utf-8")
    (root / "manifest.committed.json").write_text('{"version":"1","cards":0,"content_hash":"bbb"}',
                                                  encoding="utf-8")
    monkeypatch.setattr(vr, "ROOT", str(root))
    assert vr.check_content_hash(), "a differing content_hash must be reported"
