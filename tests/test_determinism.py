"""The corpus must be reproducible: same inputs -> same content_hash, on any day.

The build used to stamp `datetime.date.today()` into every card as `last_verified`, so the same
sources produced a different corpus each day and the determinism CI job only passed when it happened
to run on the day the corpus was built. These tests pin that behaviour down.
"""
import os
import re
import subprocess
import sys

import pytest
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILDERS = ["scripts/build_cards_v2.py", "scripts/build_authored.py"]


def test_corpus_date_is_committed_and_shaped():
    p = os.path.join(ROOT, "CORPUS_DATE")
    assert os.path.isfile(p), "CORPUS_DATE must exist at the repo root"
    value = open(p, encoding="utf-8").read().strip()
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", value), f"CORPUS_DATE must be YYYY-MM-DD, got {value!r}"


@pytest.mark.parametrize("script", BUILDERS)
def test_builder_does_not_use_wall_clock(script):
    """A card's last_verified must come from CORPUS_DATE, never from today()."""
    body = open(os.path.join(ROOT, script), encoding="utf-8").read()
    assert "date.today()" not in body, f"{script} stamps the build date into card content"
    assert "datetime.now()" not in body, f"{script} uses the wall clock"
    assert "CORPUS_DATE" in body, f"{script} does not read CORPUS_DATE"


@pytest.mark.parametrize("script", BUILDERS)
def test_builder_fails_closed_without_corpus_date(script):
    """Missing CORPUS_DATE must abort, not silently fall back to today."""
    body = open(os.path.join(ROOT, script), encoding="utf-8").read()
    assert "CORPUS_DATE not found" in body, f"{script} should raise SystemExit when CORPUS_DATE is absent"


def test_every_card_uses_the_corpus_date():
    """Cards on disk must agree with CORPUS_DATE — catches a stale or hand-edited corpus."""
    corpus_date = open(os.path.join(ROOT, "CORPUS_DATE"), encoding="utf-8").read().strip()
    import glob
    stale = []
    for path in glob.glob(os.path.join(ROOT, "checks", "**", "*.yaml"), recursive=True)[:200]:
        card = yaml.safe_load(open(path, encoding="utf-8"))
        if card.get("last_verified") != corpus_date:
            stale.append(os.path.basename(path))
    assert not stale, f"cards not on CORPUS_DATE {corpus_date}: {stale[:5]}"


def test_index_build_is_idempotent():
    """Re-indexing the same cards twice must produce the same content_hash."""
    def build():
        subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "build_index.py")],
                       capture_output=True, cwd=ROOT, check=True)
        return yaml.safe_load(open(os.path.join(ROOT, "manifest.json"), encoding="utf-8"))["content_hash"]
    assert build() == build()
