#!/usr/bin/env python3
"""Validate risk-register.yaml.

The register is the single source of truth for risk decisions. This script enforces the rules that
stop it from becoming prose:

  * ids are unique and shaped R-NNN
  * status is from a fixed set
  * accepted / deferred / open carry a real justification and a review date
  * mitigated / partially_mitigated carry a verification that RESOLVES
      - kind: test  -> a pytest nodeid whose file exists and defines that function
      - kind: ci    -> a job name that exists in .github/workflows/ci.yml
      - kind: doc   -> a file that exists
  * a review_by date in the past fails the build (re-decide, don't let it rot)
  * the register and docs/THREAT_MODEL.md describe the same set of risks

Usage:
    python scripts/check_risks.py [--warn-only] [--register PATH]

Exit 0 when clean (or when --warn-only), 1 otherwise.
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTER = os.path.join(ROOT, "risk-register.yaml")
THREAT_MODEL = os.path.join(ROOT, "docs", "THREAT_MODEL.md")
CI = os.path.join(ROOT, ".github", "workflows", "ci.yml")

STATUSES = {"mitigated", "partially_mitigated", "accepted", "deferred", "open"}
NEEDS_JUSTIFICATION = {"accepted", "deferred", "open"}
NEEDS_VERIFICATION = {"mitigated", "partially_mitigated"}
VERIFY_KINDS = {"test", "ci", "doc", "none"}
MIN_JUSTIFICATION = 40
ID_RE = re.compile(r"^R-\d{3}$")


def _jobs() -> set[str]:
    """Top-level job names under `jobs:` in ci.yml."""
    if not os.path.exists(CI):
        return set()
    out, in_jobs = set(), False
    for line in open(CI, encoding="utf-8"):
        if re.match(r"^jobs:\s*$", line):
            in_jobs = True
            continue
        if in_jobs:
            if line.strip() and not line.startswith(" "):
                break                      # left the jobs block
            m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
            if m:
                out.add(m.group(1))
    return out


def _model_ids() -> set[str]:
    """Risk ids listed in the threat model's summary matrix."""
    if not os.path.exists(THREAT_MODEL):
        return set()
    text = open(THREAT_MODEL, encoding="utf-8").read()
    try:
        block = text[text.index("## 6. Risk summary matrix"):]
    except ValueError:
        return set()
    return set(re.findall(r"^\|\s*(R-\d{3})\s*\|", block, re.M))


def _check_verification(v: dict, jobs: set[str]) -> str | None:
    kind, ref = v.get("kind"), v.get("ref")
    if kind not in VERIFY_KINDS:
        return f"verification.kind {kind!r} not one of {sorted(VERIFY_KINDS)}"
    if kind == "none":
        return None
    if not ref:
        return "verification.ref is required when kind is not 'none'"
    if kind == "doc":
        return None if os.path.exists(os.path.join(ROOT, ref)) else f"doc {ref!r} does not exist"
    if kind == "ci":
        return None if ref in jobs else f"ci job {ref!r} not found in ci.yml (have {sorted(jobs)})"
    # kind == "test"
    if "::" not in ref:
        return f"test ref {ref!r} must be a pytest nodeid (path::function)"
    path, func = ref.split("::", 1)
    full = os.path.join(ROOT, path)
    if not os.path.exists(full):
        return f"test file {path!r} does not exist"
    body = open(full, encoding="utf-8").read()
    if not re.search(rf"^def {re.escape(func)}\(", body, re.M):
        return f"test function {func!r} not defined in {path}"
    return None


def check(register_path: str = REGISTER, today: dt.date | None = None) -> list[str]:
    """Return a list of human-readable problems. Empty means the register is valid."""
    today = today or dt.date.today()
    problems: list[str] = []

    try:
        data = yaml.safe_load(open(register_path, encoding="utf-8"))
    except Exception as e:                                    # noqa: BLE001
        return [f"cannot parse {register_path}: {e}"]
    if not isinstance(data, dict) or not isinstance(data.get("risks"), list):
        return ["register must be a mapping with a 'risks' list"]

    jobs = _jobs()
    seen: set[str] = set()

    for i, r in enumerate(data["risks"]):
        rid = str(r.get("id", f"<row {i}>"))
        if not ID_RE.match(rid):
            problems.append(f"{rid}: id must match R-NNN")
        if rid in seen:
            problems.append(f"{rid}: duplicate id")
        seen.add(rid)

        status = r.get("status")
        if status not in STATUSES:
            problems.append(f"{rid}: status {status!r} not one of {sorted(STATUSES)}")
            continue

        just = (r.get("justification") or "").strip()
        if status in NEEDS_JUSTIFICATION and len(just) < MIN_JUSTIFICATION:
            problems.append(
                f"{rid}: status {status!r} needs a justification of >= {MIN_JUSTIFICATION} chars "
                f"(has {len(just)})")

        review = r.get("review_by")
        if status in NEEDS_JUSTIFICATION and not review:
            problems.append(f"{rid}: status {status!r} needs a review_by date")
        if review:
            try:
                when = review if isinstance(review, dt.date) else dt.date.fromisoformat(str(review))
            except ValueError:
                problems.append(f"{rid}: review_by {review!r} is not an ISO date (YYYY-MM-DD)")
            else:
                if when < today:
                    problems.append(
                        f"{rid}: review_by {when} has passed — re-decide this risk or extend the date")

        v = r.get("verification") or {}
        if status in NEEDS_VERIFICATION:
            if v.get("kind") in (None, "none"):
                problems.append(
                    f"{rid}: status {status!r} needs a verification of kind test|ci|doc")
            else:
                err = _check_verification(v, jobs)
                if err:
                    problems.append(f"{rid}: {err}")
        elif v.get("kind") not in (None, "none"):
            err = _check_verification(v, jobs)      # still must resolve if present
            if err:
                problems.append(f"{rid}: {err}")

    model = _model_ids()
    if model:
        only_reg = sorted(seen - model)
        only_model = sorted(model - seen)
        if only_reg:
            problems.append(f"in the register but not in docs/THREAT_MODEL.md: {only_reg}")
        if only_model:
            problems.append(f"in docs/THREAT_MODEL.md but not in the register: {only_model}")

    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--register", default=REGISTER)
    ap.add_argument("--warn-only", action="store_true", help="report but exit 0")
    a = ap.parse_args()

    problems = check(a.register)
    if not problems:
        n = len(yaml.safe_load(open(a.register, encoding="utf-8"))["risks"])
        print(f"risk register OK — {n} risks, every verification resolves")
        return 0
    print(f"risk register has {len(problems)} problem(s):")
    for p in problems:
        print(f"  - {p}")
    return 0 if a.warn_only else 1


if __name__ == "__main__":
    sys.exit(main())
