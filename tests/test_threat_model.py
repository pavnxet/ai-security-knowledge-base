"""Validate docs/THREAT_MODEL.md.

The threat model is only useful if it stays internally consistent: every risk in the STRIDE
analysis must appear in the summary matrix, IDs must be unique, and every claim about the code
must still be true. These tests fail when the document drifts from the repo.
"""
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, "docs", "THREAT_MODEL.md")

STATUSES = ("Mitigated", "Partially mitigated", "Accepted", "Deferred", "Open")


def _text():
    return open(DOC, encoding="utf-8").read()


def _section(text, start, end):
    a = text.index(start)
    b = text.index(end, a)
    return text[a:b]


def _ids(block):
    return re.findall(r"^\|\s*(R-\d{3})\s*\|", block, re.M)


def test_doc_exists():
    assert os.path.isfile(DOC), "docs/THREAT_MODEL.md is missing"


def test_stride_and_matrix_agree():
    """Every risk in the STRIDE tables must be in the summary matrix, and vice versa."""
    t = _text()
    stride = _section(t, "## 5. STRIDE analysis", "## 6. Risk summary matrix")
    matrix = _section(t, "## 6. Risk summary matrix", "## 7. Security assumptions")
    s_ids, m_ids = _ids(stride), _ids(matrix)
    assert s_ids, "no risks found in the STRIDE section"
    assert set(s_ids) == set(m_ids), (
        f"STRIDE-only: {sorted(set(s_ids) - set(m_ids))}; "
        f"matrix-only: {sorted(set(m_ids) - set(s_ids))}")
    assert len(s_ids) == len(set(s_ids)), "duplicate risk id in STRIDE tables"
    assert len(m_ids) == len(set(m_ids)), "duplicate risk id in the matrix"


def test_every_risk_has_a_status():
    matrix = _section(_text(), "## 6. Risk summary matrix", "## 7. Security assumptions")
    rows = [l for l in matrix.splitlines() if re.match(r"^\|\s*R-\d{3}\s*\|", l)]
    assert rows, "matrix has no risk rows"
    for row in rows:
        cells = [c.strip() for c in row.strip("|").split("|")]
        assert len(cells) == 7, f"expected 7 columns, got {len(cells)}: {row[:60]}"
        status = cells[6].replace("*", "").replace("`", "").strip()
        assert any(status.startswith(s) for s in STATUSES), f"bad status {status!r} in {cells[0]}"


def test_relative_links_resolve():
    t = _text()
    links = re.findall(r"\]\((\.\.?/[^)]+)\)", t)
    assert links, "expected at least one relative link"
    for link in links:
        target = os.path.normpath(os.path.join(os.path.dirname(DOC), link.split("#")[0]))
        assert os.path.exists(target), f"broken link {link} -> {target}"


def test_has_trust_boundary_diagram():
    t = _text()
    assert "```mermaid" in t, "trust boundaries should be a mermaid diagram"
    assert "Untrusted" in t, "the audited codebase must be marked untrusted"


def test_claims_about_the_code_still_hold():
    """Spot-check the code facts the document asserts."""
    cli = open(os.path.join(ROOT, "cli", "secure_kb.py"), encoding="utf-8").read()
    assert "def iter_files(path, cap=8000)" in cli, "R-014: detect walk cap changed"
    assert "os.path.getsize(fp) > 200_000" in cli, "R-010: per-file read cap changed"

    fp = cli[cli.index("def fingerprint_target"):]
    fp = fp[: fp.index("\ndef ")]
    assert ".read()" in fp, "R-013: fingerprint_target no longer reads whole files"
    assert "getsize" not in fp, (
        "R-013 appears FIXED: fingerprint_target now has a size guard — update the threat model")

    mcp = open(os.path.join(ROOT, "mcp", "server.py"), encoding="utf-8").read()
    assert "fullmatch" in mcp, "R-015: profile-name guard removed from the MCP server"
