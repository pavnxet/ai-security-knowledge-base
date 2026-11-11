#!/usr/bin/env python3
"""Verify that a release is internally coherent.

One command to answer "is this repo consistent with itself?" — the version, the card count, the
content hash, the shipped index, the posture docs, and the agent skill must all agree. Every check
here corresponds to a drift that actually happened at some point in this project's history:

  * README advertised v0.9.0 and 2,057 cards long after both changed
  * the shipped `index/checks/part-*.jsonl` carried 2,057 records for 2,052 cards (5 phantom cards)
  * `AGENTS.md` and `llms.txt` advertised 7 MCP tools when the server exposed 9
  * `manifest.committed.json` and `manifest.json` diverged, breaking the determinism job

Usage:
    python scripts/verify_release.py [--quiet]

Exit 0 when every check passes, 1 otherwise.
"""
from __future__ import annotations

import glob
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(path):
    return open(os.path.join(ROOT, path), encoding="utf-8").read()


def _json(path):
    return json.loads(_read(path))


def check_version_consistency() -> list[str]:
    v = _read("VERSION").strip()
    man = _json("manifest.json")
    com = _json("manifest.committed.json")
    pyproject = re.search(r'^version\s*=\s*"([^"]+)"', _read("pyproject.toml"), re.M)
    problems = []
    for label, got in (("pyproject.toml", pyproject.group(1) if pyproject else None),
                       ("manifest.json", man.get("version")),
                       ("manifest.committed.json", com.get("version"))):
        if got != v:
            problems.append(f"VERSION is {v!r} but {label} says {got!r}")
    return problems


def check_readme_quotes_the_version() -> list[str]:
    v = _read("VERSION").strip()
    if f"v{v}" not in _read("README.md"):
        return [f"README.md does not mention the current version v{v} (doc drift)"]
    return []


def check_card_counts() -> list[str]:
    man, com = _json("manifest.json"), _json("manifest.committed.json")
    on_disk = len(glob.glob(os.path.join(ROOT, "checks", "**", "*.yaml"), recursive=True))
    problems = []
    if man.get("cards") != on_disk:
        problems.append(f"manifest says {man.get('cards')} cards, checks/ has {on_disk}")
    if com.get("cards") != on_disk:
        problems.append(f"manifest.committed says {com.get('cards')} cards, checks/ has {on_disk}")
    return problems


def check_content_hash() -> list[str]:
    man, com = _json("manifest.json"), _json("manifest.committed.json")
    if man.get("content_hash") != com.get("content_hash"):
        return [f"content_hash differs: manifest {man.get('content_hash')} "
                f"vs committed {com.get('content_hash')} — the build is not reproducible"]
    return []


def check_shipped_index_matches_hash() -> list[str]:
    """The hash in the manifest must describe the index/checks.jsonl that actually ships.

    check_content_hash() only compares manifest.json with manifest.committed.json, so both could
    agree while the shipped file was stale — which is exactly what happened: index/checks.jsonl was
    1,709 lines behind the build while the manifests matched.
    """
    man = _json("manifest.json")
    path = os.path.join(ROOT, "index", "checks.jsonl")
    if not os.path.exists(path):
        return ["index/checks.jsonl is missing (run scripts/build_index.py)"]
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    actual = digest.hexdigest()[:16]
    if actual != man.get("content_hash"):
        return [f"index/checks.jsonl hashes to {actual} but manifest.json says "
                f"{man.get('content_hash')} — the shipped index is stale (run scripts/build_index.py)"]
    return []


def check_shards_match_cards() -> list[str]:
    """The zero-install jq/grep fallback must not contain cards that no longer exist."""
    shard_ids, lines = set(), 0
    for p in glob.glob(os.path.join(ROOT, "index", "checks", "part-*.jsonl")):
        for line in open(p, encoding="utf-8"):
            if line.strip():
                shard_ids.add(json.loads(line)["id"])
                lines += 1
    card_ids = {yaml.safe_load(open(p, encoding="utf-8"))["id"]
                for p in glob.glob(os.path.join(ROOT, "checks", "**", "*.yaml"), recursive=True)}
    problems = []
    phantom = sorted(shard_ids - card_ids)
    missing = sorted(card_ids - shard_ids)
    if phantom:
        problems.append(f"{len(phantom)} phantom card(s) in index/checks/: {phantom[:5]}")
    if missing:
        problems.append(f"{len(missing)} card(s) missing from index/checks/: {missing[:5]}")
    if lines != len(shard_ids):
        problems.append(f"index/checks/ has {lines} lines but {len(shard_ids)} unique ids (duplicates)")
    return problems


def check_kb_sqlite_not_committed() -> list[str]:
    try:
        out = subprocess.run(["git", "ls-files", "index/kb.sqlite"], cwd=ROOT,
                             capture_output=True, text=True, timeout=30)
    except Exception:
        return []                                  # not a git checkout; nothing to assert
    if out.stdout.strip():
        return ["index/kb.sqlite is a generated cache and must not be committed"]
    return []


def check_posture_docs() -> list[str]:
    docs = ["docs/THREAT_MODEL.md", "risk-register.yaml", "KNOWN_LIMITATIONS.md", "SECURITY.md"]
    problems = [f"{d} is missing" for d in docs if not os.path.exists(os.path.join(ROOT, d))]
    for door in ("README.md", "AGENTS.md", "llms.txt"):
        body = _read(door)
        problems += [f"{door} does not link {d}" for d in docs if d not in body]
    return problems


def check_skill() -> list[str]:
    path = os.path.join(ROOT, "skills", "secure-kb-audit", "SKILL.md")
    if not os.path.exists(path):
        return ["skills/secure-kb-audit/SKILL.md is missing"]
    body = open(path, encoding="utf-8").read()
    if not body.startswith("---"):
        return ["SKILL.md has no YAML frontmatter"]
    fm = yaml.safe_load(body.split("---", 2)[1])
    problems = []
    if not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", fm.get("name", "")):
        problems.append(f"skill name {fm.get('name')!r} is not kebab-case")
    if not 0 < len(fm.get("description", "")) <= 1024:
        problems.append("skill description must be 1..1024 chars")
    return problems


def check_mcp_tool_lists() -> list[str]:
    server = _read(os.path.join("mcp", "server.py"))
    tools = re.findall(r'\{"name": "([a-z_]+)"', server)
    problems = []
    for doc in ("AGENTS.md", "llms.txt"):
        body = _read(doc)
        missing = [t for t in tools if t not in body]
        if missing:
            problems.append(f"{doc} is missing MCP tools: {missing}")
    return problems


def check_findings_schema() -> list[str]:
    """The audit output contract must exist and its golden example must validate."""
    schema = os.path.join(ROOT, "audit", "report-schema.json")
    example = os.path.join(ROOT, "audit", "findings.example.json")
    problems = []
    for path in (schema, example):
        if not os.path.exists(path):
            problems.append(f"{os.path.relpath(path, ROOT)} is missing")
    if problems:
        return problems
    spec = importlib.util.spec_from_file_location(
        "vf", os.path.join(ROOT, "scripts", "validate_findings.py"))
    vf = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vf)
    problems = vf.validate(example, schema)
    return [f"findings example does not validate: {p}" for p in problems[:3]]

CHECKS = [
    ("version consistency", check_version_consistency),
    ("README quotes the version", check_readme_quotes_the_version),
    ("card counts", check_card_counts),
    ("content hash", check_content_hash),
    ("shipped index matches the hash", check_shipped_index_matches_hash),
    ("shards match cards", check_shards_match_cards),
    ("kb.sqlite not committed", check_kb_sqlite_not_committed),
    ("posture docs linked", check_posture_docs),
    ("agent skill valid", check_skill),
    ("MCP tool lists", check_mcp_tool_lists),
    ("findings schema", check_findings_schema),
]


def main() -> int:
    quiet = "--quiet" in sys.argv
    failures = 0
    for name, fn in CHECKS:
        problems = fn()
        if problems:
            failures += 1
            print(f"FAIL  {name}")
            for p in problems:
                print(f"        - {p}")
        elif not quiet:
            print(f"ok    {name}")
    if failures:
        print(f"\n{failures} check(s) failed — the release is not internally consistent")
        return 1
    if not quiet:
        print(f"\nall {len(CHECKS)} checks passed — release is internally consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
