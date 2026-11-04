"""Tests for scripts/check_risks.py — one per failure mode.

A validator that is not itself tested is a validator you cannot trust. Each test builds a small
register with exactly one defect and asserts the checker names it.
"""
import datetime as dt
import importlib.util
import os

import pytest
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _mod():
    spec = importlib.util.spec_from_file_location(
        "check_risks", os.path.join(ROOT, "scripts", "check_risks.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


cr = _mod()
TODAY = dt.date(2026, 11, 4)


def _write(tmp_path, risks):
    p = tmp_path / "risk-register.yaml"
    p.write_text(yaml.safe_dump({"version": 1, "risks": risks}), encoding="utf-8")
    return str(p)


def _risk(**over):
    base = {
        "id": "R-001",
        "title": "t",
        "stride": "Spoofing",
        "asset": "corpus",
        "likelihood": "low",
        "impact": "low",
        "status": "mitigated",
        "justification": "x" * 50,
        "verification": {"kind": "test", "ref": "tests/test_cli.py::test_cards_load"},
        "review_by": None,
        "issue": None,
    }
    base.update(over)
    return base


def test_real_register_is_clean():
    assert cr.check(os.path.join(ROOT, "risk-register.yaml"), today=TODAY) == []


def test_duplicate_id(tmp_path):
    p = _write(tmp_path, [_risk(), _risk()])
    assert any("duplicate id" in x for x in cr.check(p, today=TODAY))


def test_bad_status(tmp_path):
    p = _write(tmp_path, [_risk(status="sort-of-fine")])
    assert any("status" in x and "not one of" in x for x in cr.check(p, today=TODAY))


def test_accepted_needs_justification(tmp_path):
    p = _write(tmp_path, [_risk(status="accepted", justification="too short",
                               verification={"kind": "none", "ref": None},
                               review_by="2027-01-01")])
    assert any("needs a justification" in x for x in cr.check(p, today=TODAY))


def test_accepted_needs_review_date(tmp_path):
    p = _write(tmp_path, [_risk(status="accepted", verification={"kind": "none", "ref": None},
                               review_by=None)])
    assert any("needs a review_by date" in x for x in cr.check(p, today=TODAY))


def test_past_review_date_fails(tmp_path):
    p = _write(tmp_path, [_risk(status="accepted", verification={"kind": "none", "ref": None},
                               review_by="2020-01-01")])
    assert any("has passed" in x for x in cr.check(p, today=TODAY))


def test_mitigated_needs_verification(tmp_path):
    p = _write(tmp_path, [_risk(verification={"kind": "none", "ref": None})])
    assert any("needs a verification" in x for x in cr.check(p, today=TODAY))


def test_verification_test_must_exist(tmp_path):
    p = _write(tmp_path, [_risk(verification={
        "kind": "test", "ref": "tests/test_cli.py::test_does_not_exist"})])
    assert any("not defined in" in x for x in cr.check(p, today=TODAY))


def test_verification_file_must_exist(tmp_path):
    p = _write(tmp_path, [_risk(verification={
        "kind": "test", "ref": "tests/nope.py::test_x"})])
    assert any("does not exist" in x for x in cr.check(p, today=TODAY))


def test_verification_ci_job_must_exist(tmp_path):
    p = _write(tmp_path, [_risk(verification={"kind": "ci", "ref": "no-such-job"})])
    assert any("not found in ci.yml" in x for x in cr.check(p, today=TODAY))


def test_verification_doc_must_exist(tmp_path):
    p = _write(tmp_path, [_risk(verification={"kind": "doc", "ref": "docs/NOPE.md"})])
    assert any("does not exist" in x for x in cr.check(p, today=TODAY))


def test_register_and_threat_model_must_agree(tmp_path):
    p = _write(tmp_path, [_risk(id="R-999")])
    problems = cr.check(p, today=TODAY)
    assert any("R-999" in x and "not in docs/THREAT_MODEL.md" in x for x in problems)
