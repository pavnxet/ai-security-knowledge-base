"""Tests for audit/report-schema.json + scripts/validate_findings.py.

One test per rejection rule. The validator is the thing that makes an audit's output machine-checkable,
so it has to fail for the right reasons — not just pass on a good file.
"""
import copy
import importlib.util
import json
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA = os.path.join(ROOT, "audit", "report-schema.json")
EXAMPLE = os.path.join(ROOT, "audit", "findings.example.json")


def _mod():
    spec = importlib.util.spec_from_file_location(
        "validate_findings", os.path.join(ROOT, "scripts", "validate_findings.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


vf = _mod()


def _golden():
    return json.load(open(EXAMPLE, encoding="utf-8"))


def _validate(tmp_path, records):
    p = tmp_path / "findings.json"
    p.write_text(json.dumps(records), encoding="utf-8")
    return vf.validate(str(p), SCHEMA)


def test_example_is_valid():
    assert vf.validate(EXAMPLE, SCHEMA) == []


def test_confirmed_without_sink_is_rejected(tmp_path):
    recs = _golden()
    recs[0]["trace"] = [s for s in recs[0]["trace"] if s["kind"] != "sink"]
    errs = _validate(tmp_path, recs)
    assert any("no 'sink' trace step" in e for e in errs), errs


def test_confirmed_without_entrypoint_is_rejected(tmp_path):
    recs = _golden()
    recs[0]["trace"] = [s for s in recs[0]["trace"] if s["kind"] != "entrypoint"]
    errs = _validate(tmp_path, recs)
    assert any("no 'entrypoint' trace step" in e for e in errs), errs


def test_needs_validation_may_not_carry_severity(tmp_path):
    """Rating an unproven issue is the anti-pattern this schema exists to stop."""
    recs = _golden()
    recs[1]["severity"] = "high"
    errs = _validate(tmp_path, recs)
    assert any("severity" in e for e in errs), errs


def test_rejected_may_not_carry_severity(tmp_path):
    recs = _golden()
    recs[2]["severity"] = "low"
    errs = _validate(tmp_path, recs)
    assert any("severity" in e for e in errs), errs


def test_rejected_without_reason_is_rejected(tmp_path):
    recs = _golden()
    del recs[2]["reason"]
    errs = _validate(tmp_path, recs)
    assert any("reason" in e for e in errs), errs


def test_duplicate_fingerprint_is_rejected(tmp_path):
    recs = _golden()
    recs[1]["fingerprint"] = recs[0]["fingerprint"]
    errs = _validate(tmp_path, recs)
    assert any("duplicate fingerprint" in e for e in errs), errs


def test_unknown_verdict_is_rejected(tmp_path):
    recs = _golden()
    recs[0]["verdict"] = "probably-bad"
    assert _validate(tmp_path, recs), "an unknown verdict must not validate"


def test_bad_fingerprint_pattern_is_rejected(tmp_path):
    recs = _golden()
    recs[0]["fingerprint"] = "has spaces and !"
    assert _validate(tmp_path, recs)


def test_bad_card_id_is_rejected(tmp_path):
    recs = _golden()
    recs[0]["card_id"] = "not-a-card-id"
    errs = _validate(tmp_path, recs)
    assert any("card_id" in e for e in errs), errs


def test_bad_kb_hash_is_rejected(tmp_path):
    recs = _golden()
    recs[0]["kb"] = {"version": "0.9.16", "content_hash": "NOTAHASH"}
    errs = _validate(tmp_path, recs)
    assert any("content_hash" in e for e in errs), errs


def test_trace_line_must_be_positive(tmp_path):
    recs = _golden()
    recs[0]["trace"][0]["line"] = 0
    errs = _validate(tmp_path, recs)
    assert any("line" in e for e in errs), errs


def test_missing_required_field_is_rejected(tmp_path):
    recs = _golden()
    del recs[0]["root_cause"]
    errs = _validate(tmp_path, recs)
    assert any("root_cause" in e for e in errs), errs


def test_blockers_must_be_non_empty(tmp_path):
    recs = _golden()
    recs[1]["blockers"] = []
    errs = _validate(tmp_path, recs)
    assert any("blockers" in e for e in errs), errs
