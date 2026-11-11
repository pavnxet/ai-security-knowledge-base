#!/usr/bin/env python3
"""Validate findings.json against audit/report-schema.json.

This is the machine-checked output contract for a secure-kb audit. It exists because a prose report
cannot be deduplicated, re-verified, or compared across runs — and because three specific mistakes are
easy to make and hard to see:

  * a "confirmed" record whose trace never reaches a sink (the claim is not actually traced)
  * a "needs_validation" record carrying a severity (rating an unproven issue — it has no impact yet)
  * a "rejected" record with no reason (a dismissal indistinguishable from an oversight)

The validator interprets the schema directly, so the schema is the single source of truth. Only the
standard library is used, so it runs anywhere the CLI runs.

Usage:
    python scripts/validate_findings.py [findings.json]
    python scripts/validate_findings.py --schema path --findings path

Exit 0 when valid, 1 otherwise.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SCHEMA = os.path.join(ROOT, "audit", "report-schema.json")
VERDICTS = ("confirmed", "needs_validation", "rejected")


def _resolve(node: dict, root: dict) -> dict:
    """Follow a local $ref."""
    seen = 0
    while isinstance(node, dict) and "$ref" in node:
        ref = node["$ref"]
        if not ref.startswith("#/definitions/"):
            raise ValueError(f"unsupported $ref {ref!r}")
        node = root["definitions"][ref.split("/", 2)[-1]]
        seen += 1
        if seen > 10:
            raise ValueError(f"$ref cycle at {ref!r}")
    return node


def _check(value, node: dict, root: dict, path: str, errs: list[str]) -> None:
    """Validate `value` against a small, well-defined subset of JSON Schema."""
    node = _resolve(node, root)

    if "oneOf" in node:
        best = None
        for variant in node["oneOf"]:
            sub: list[str] = []
            _check(value, variant, root, path, sub)
            if not sub:
                return                      # one variant matched cleanly
            if best is None or len(sub) < len(best):
                best = sub
        errs.extend(best or [f"{path}: matches none of the allowed shapes"])
        return

    expected = node.get("type")
    if expected == "object":
        if not isinstance(value, dict):
            errs.append(f"{path}: expected an object, got {type(value).__name__}")
            return
        for field in node.get("required", []):
            if field not in value:
                errs.append(f"{path}: missing required field {field!r}")
        for field, sub in (node.get("properties") or {}).items():
            if field in value:
                _check(value[field], sub, root, f"{path}.{field}", errs)
        if "not" in node:                                   # "must NOT contain"
            for field in node["not"].get("required", []):
                if field in value:
                    errs.append(f"{path}: must not contain {field!r} for this verdict")

    elif expected == "array":
        if not isinstance(value, list):
            errs.append(f"{path}: expected an array, got {type(value).__name__}")
            return
        if len(value) < node.get("minItems", 0):
            errs.append(f"{path}: needs at least {node['minItems']} item(s), has {len(value)}")
        if "items" in node:
            for i, item in enumerate(value):
                _check(item, node["items"], root, f"{path}[{i}]", errs)

    elif expected == "string":
        if not isinstance(value, str):
            errs.append(f"{path}: expected a string, got {type(value).__name__}")
            return
        if len(value) < node.get("minLength", 0):
            errs.append(f"{path}: must be at least {node['minLength']} character(s)")
        if "const" in node and value != node["const"]:
            errs.append(f"{path}: must be {node['const']!r}, got {value!r}")
        if "enum" in node and value not in node["enum"]:
            errs.append(f"{path}: must be one of {node['enum']}, got {value!r}")
        if "pattern" in node and not re.search(node["pattern"], value):
            errs.append(f"{path}: {value!r} does not match {node['pattern']}")

    elif expected == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            errs.append(f"{path}: expected an integer, got {type(value).__name__}")
            return
        if "minimum" in node and value < node["minimum"]:
            errs.append(f"{path}: must be >= {node['minimum']}, got {value}")


def _semantic(records: list, errs: list[str]) -> None:
    """Rules the schema shape cannot express."""
    seen: dict[str, int] = {}
    for i, rec in enumerate(records):
        if not isinstance(rec, dict):
            continue
        fp = rec.get("fingerprint")
        if isinstance(fp, str):
            if fp in seen:
                errs.append(
                    f"[{i}]: duplicate fingerprint {fp!r} (also at record {seen[fp]}) — "
                    f"records must be deduplicated")
            else:
                seen[fp] = i

        if rec.get("verdict") == "confirmed":
            kinds = {s.get("kind") for s in rec.get("trace", []) if isinstance(s, dict)}
            if "entrypoint" not in kinds:
                errs.append(f"[{i}] {fp}: confirmed record has no 'entrypoint' trace step")
            if "sink" not in kinds:
                errs.append(
                    f"[{i}] {fp}: confirmed record has no 'sink' trace step — the claim is not "
                    f"actually traced to where it takes effect")


def validate(findings_path: str, schema_path: str = DEFAULT_SCHEMA) -> list[str]:
    try:
        schema = json.load(open(schema_path, encoding="utf-8"))
    except Exception as e:                                        # noqa: BLE001
        return [f"cannot read schema {schema_path}: {e}"]
    try:
        data = json.load(open(findings_path, encoding="utf-8"))
    except Exception as e:                                        # noqa: BLE001
        return [f"cannot read findings {findings_path}: {e}"]

    errs: list[str] = []
    _check(data, schema, schema, "$", errs)
    if not errs and isinstance(data, list):
        _semantic(data, errs)
    return errs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("findings", nargs="?", default=os.path.join("audit", "findings.json"))
    ap.add_argument("--schema", default=DEFAULT_SCHEMA)
    a = ap.parse_args()

    errs = validate(a.findings, a.schema)
    if not errs:
        n = len(json.load(open(a.findings, encoding="utf-8")))
        by = {}
        for r in json.load(open(a.findings, encoding="utf-8")):
            by[r["verdict"]] = by.get(r["verdict"], 0) + 1
        print(f"findings OK — {n} record(s): " + ", ".join(f"{k}={v}" for k, v in sorted(by.items())))
        return 0
    print(f"findings.json has {len(errs)} problem(s):")
    for e in errs:
        print(f"  - {e}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
