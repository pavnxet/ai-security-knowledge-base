"""KNOWN_LIMITATIONS.md must not drift from the measured numbers.

A limitations page that quietly stops being true is worse than none — it is a false reassurance.
These tests parse the tables in the document and compare them to bench/results.json, so publishing a
better (or worse) benchmark forces the page to be updated in the same change.
"""
import json
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, "KNOWN_LIMITATIONS.md")
RESULTS = os.path.join(ROOT, "bench", "results.json")

# how the document names each set -> the key in results.json
SETS = {
    "Held-out (all)": "all",
    "Curated v1": "curated_v1",
    "Curated v2": "curated_v2",
    "v2_dev (developer vocabulary)": "v2_dev",
    "Templated": "templated",
}


def _doc() -> str:
    assert os.path.isfile(DOC), "KNOWN_LIMITATIONS.md is missing"
    return open(DOC, encoding="utf-8").read()


def _results() -> dict:
    assert os.path.isfile(RESULTS), (
        "bench/results.json is missing — run `python bench/run_bench.py` first")
    return json.load(open(RESULTS, encoding="utf-8"))


def _row(text: str, label: str) -> list:
    """Return the table cells of the row whose first cell starts with `label`."""
    for line in text.splitlines():
        if line.strip().startswith("|") and label in line:
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if cells and cells[0].startswith(label):
                return cells
    raise AssertionError(f"no table row for {label!r} in KNOWN_LIMITATIONS.md")


@pytest.mark.parametrize("label,key", SETS.items())
def test_retrieval_numbers_match_the_benchmark(label, key):
    cells = _row(_doc(), label)
    measured = _results()["heldout"][key]
    assert int(cells[1]) == measured["n"], f"{label}: n {cells[1]} != measured {measured['n']}"
    assert abs(float(cells[2]) - measured["recall@5"]) < 1e-9, (
        f"{label}: recall@5 {cells[2]} != measured {measured['recall@5']} — update the page")


def test_lab_coverage_numbers_match_the_benchmark():
    lab = _results()["lab_coverage"]
    text = _doc()
    assert f"{lab['covered']} ({lab['coverage_pct']}%)" in text, (
        f"lab coverage {lab['covered']}/{lab['classes']} ({lab['coverage_pct']}%) not reflected")
    assert f"{lab['in_fast_gate']} (**{lab['gate_recall_pct']}%**)" in text, (
        f"fast-gate recall {lab['gate_recall_pct']}% not reflected")


def test_corpus_defect_counts_match_the_cards():
    """The defect counts must be real: re-count them from checks/ and compare."""
    import glob
    import yaml

    cards = [yaml.safe_load(open(p, encoding="utf-8"))
             for p in glob.glob(os.path.join(ROOT, "checks", "**", "*.yaml"), recursive=True)]
    pointer = [c for c in cards
               if re.match(r"^see\s+\S+/\S+.*for remediation", (c.get("fix") or "").strip(), re.I)]
    front_matter = [c for c in cards if "masvs_v1_id" in (c.get("check") or "")]
    no_cwe = [c for c in cards if not c.get("cwe")]

    text = _doc()
    assert f"{len(pointer):,}" in text, f"pointer-fix count {len(pointer):,} not stated"
    assert f"{len(front_matter)}" in text, f"front-matter count {len(front_matter)} not stated"
    assert f"{len(no_cwe):,}" in text, f"no-CWE count {len(no_cwe):,} not stated"


def test_page_is_linked_from_the_front_door():
    for doc in ("README.md", "SECURITY.md", "docs/THREAT_MODEL.md"):
        body = open(os.path.join(ROOT, doc), encoding="utf-8").read()
        assert "KNOWN_LIMITATIONS.md" in body, f"{doc} does not link KNOWN_LIMITATIONS.md"
