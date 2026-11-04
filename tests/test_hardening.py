"""Regression tests for the hardening pass.

Every test here corresponds to a bug that was found by auditing the repo, and fails on the code as
it was before the fix:

  * an attestation verified as VALID after its signature block was deleted
  * `verify-attestation` unable to read a path relative to the current directory
  * the MCP `search_checks` tool ranking differently (and worse) than `secure-kb search`
  * `report validate` with no argument dying on a TypeError traceback
  * `profile` accepting a traversal in the profile name
  * the benchmark gate grading a stale results.json after a crashed run
  * cache paths built from sources_files.tsv able to escape cache/
"""
import importlib.util
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(ROOT, "cli", "secure_kb.py")
MCP = os.path.join(ROOT, "mcp", "server.py")


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _cli(*args, cwd=None, timeout=240):
    return subprocess.run([sys.executable, CLI, *args],
                          capture_output=True, text=True, timeout=timeout, cwd=cwd)


def _mcp_calls(*calls, timeout=240):
    """Run the MCP server over stdio and return {id: parsed result}."""
    payload = '{"jsonrpc":"2.0","id":1,"method":"initialize"}\n'
    for i, (name, arguments) in enumerate(calls, start=2):
        payload += json.dumps({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                               "params": {"name": name, "arguments": arguments}}) + "\n"
    proc = subprocess.run([sys.executable, MCP], input=payload,
                          capture_output=True, text=True, timeout=timeout)
    out = {}
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "id" in msg:
            out[msg["id"]] = msg
    return out


@pytest.fixture(scope="session")
def kb():
    return _load(CLI, "secure_kb")


def _target(d):
    d.mkdir(parents=True, exist_ok=True)
    (d / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n")
    (d / "requirements.txt").write_text("flask==3.0\n")
    return d


# ---------------------------------------------------------------- attestation


def test_removing_the_signature_invalidates_a_keyed_verification(tmp_path):
    """The bug: deleting `signature` made verification pass, even with the wrong key."""
    tgt = _target(tmp_path / "t")
    att = tmp_path / "a.json"
    assert _cli("attest", str(tgt), "--gate", "fast", "--key", "right", "--out", str(att)).returncode == 0

    body = json.loads(att.read_text())
    body.pop("signature")
    stripped = tmp_path / "stripped.json"
    stripped.write_text(json.dumps(body))

    v = _cli("verify-attestation", str(stripped), "--key", "right")
    assert v.returncode == 1, "a stripped signature must not verify"
    assert "signature missing" in v.stdout


def test_allow_unsigned_is_an_explicit_opt_in(tmp_path):
    tgt = _target(tmp_path / "t")
    att = tmp_path / "a.json"
    _cli("attest", str(tgt), "--gate", "fast", "--out", str(att))          # unsigned on purpose

    strict = _cli("verify-attestation", str(att), "--key", "k")
    assert strict.returncode == 1

    relaxed = _cli("verify-attestation", str(att), "--key", "k", "--allow-unsigned")
    assert relaxed.returncode == 0
    assert json.loads(relaxed.stdout)["signed"] is False


def test_unsigned_attestation_still_verifies_without_a_key(tmp_path):
    """Integrity-only verification stays useful: the hash is still checked."""
    tgt = _target(tmp_path / "t")
    att = tmp_path / "a.json"
    _cli("attest", str(tgt), "--gate", "fast", "--out", str(att))

    v = _cli("verify-attestation", str(att))
    assert v.returncode == 0
    assert json.loads(v.stdout)["signed"] is False


def test_verify_reads_a_path_relative_to_the_current_directory(tmp_path):
    """The bug: `load_json` joined every path onto the KB root, so relative paths never resolved."""
    tgt = _target(tmp_path / "t")
    _cli("attest", str(tgt), "--gate", "fast", "--key", "k", "--out", "att.json", cwd=str(tmp_path))

    v = _cli("verify-attestation", "att.json", "--key", "k", cwd=str(tmp_path))
    assert v.returncode == 0, v.stderr
    assert "Traceback" not in v.stderr
    assert json.loads(v.stdout)["status"] == "VALID"


def test_hmac_key_can_come_from_the_environment(tmp_path):
    tgt = _target(tmp_path / "t")
    att = tmp_path / "a.json"
    env = {**os.environ, "SECURE_KB_HMAC_KEY": "env-key"}
    subprocess.run([sys.executable, CLI, "attest", str(tgt), "--gate", "fast", "--out", str(att)],
                   capture_output=True, text=True, env=env, timeout=240)
    body = json.loads(att.read_text())
    assert "signature" in body, "SECURE_KB_HMAC_KEY should sign the attestation"

    v = subprocess.run([sys.executable, CLI, "verify-attestation", str(att)],
                       capture_output=True, text=True, env=env, timeout=240)
    assert v.returncode == 0


# ---------------------------------------------------------------- CLI robustness


def test_report_validate_without_a_file_is_a_usage_error():
    r = _cli("report", "validate")
    assert r.returncode != 0
    assert "Traceback" not in r.stderr
    assert "usage" in (r.stderr + r.stdout).lower()


def test_profile_name_traversal_is_refused():
    for name in ("../sources", "../../outside.yaml", "a/b"):
        r = _cli("profile", name)
        assert r.returncode != 0, name
        assert "Traceback" not in r.stderr, name
        assert "invalid profile name" in (r.stderr + r.stdout)


def test_get_tolerates_a_source_without_a_commit():
    """`get --format md` used to KeyError on a source entry with no commit field."""
    r = _cli("get", "SKB-ASVS-V1-2-4", "--format", "md")
    assert r.returncode == 0
    assert "Traceback" not in r.stderr


# ---------------------------------------------------------------- MCP / CLI parity


def test_mcp_search_matches_the_cli(kb):
    """The bug: MCP used its own weaker scorer, so agents saw different cards than the CLI."""
    cli_ids = [c["id"] for c in kb.search("how do I stop sql injection", k=5)]

    res = _mcp_calls(("search_checks", {"query": "how do I stop sql injection", "k": 5}))[2]
    assert res["result"]["isError"] is False
    mcp_ids = [c["id"] for c in json.loads(res["result"]["content"][0]["text"])["results"]]

    assert mcp_ids == cli_ids, f"MCP {mcp_ids} != CLI {cli_ids}"


def test_mcp_search_returns_relevant_cards():
    res = _mcp_calls(("search_checks", {"query": "sql injection", "k": 3}))[2]
    ids = [c["id"] for c in json.loads(res["result"]["content"][0]["text"])["results"]]
    assert ids, "expected results"
    assert any("SQL" in i or "INJT" in i or "ASVS" in i for i in ids), ids


def test_mcp_detect_matches_the_cli(kb, tmp_path):
    _target(tmp_path)
    res = _mcp_calls(("detect_stack", {"path": str(tmp_path)}))[2]
    mcp = json.loads(res["result"]["content"][0]["text"])
    assert mcp["recommended_profiles"] == kb.detect(str(tmp_path))["recommended_profiles"]


def test_mcp_get_check_without_an_id_is_a_clear_error():
    res = _mcp_calls(("get_check", {}))[2]
    assert res["result"]["isError"] is True
    assert "missing required argument: id" in res["result"]["content"][0]["text"]


def test_mcp_unknown_tool_is_flagged_as_an_error():
    res = _mcp_calls(("no_such_tool", {}))[2]
    assert res["result"]["isError"] is True
    assert "unknown tool" in res["result"]["content"][0]["text"]


def test_mcp_verify_rejects_a_stripped_signature():
    att = {"attestation_id": "0" * 64, "checks": []}
    res = _mcp_calls(("verify_attestation", {"attestation": att, "key": "k"}))[2]
    body = json.loads(res["result"]["content"][0]["text"])
    assert body["status"] == "INVALID"
    assert any("signature missing" in p or "mismatch" in p for p in body["problems"])


# ---------------------------------------------------------------- benchmark gate


def test_gate_fails_when_a_metric_is_missing():
    gate = _load(os.path.join(ROOT, "bench", "gate.py"), "gate_mod")
    assert gate.evaluate({"heldout": {}}) == [
        "all: metric missing", "templated: metric missing", "curated_v2: metric missing"]


def test_gate_fails_below_a_floor_and_passes_above():
    gate = _load(os.path.join(ROOT, "bench", "gate.py"), "gate_mod")
    ok = {"heldout": {"all": {"recall@5": 0.9}, "templated": {"recall@5": 0.9},
                      "curated_v2": {"recall@5": 0.9}}}
    assert gate.evaluate(ok) == []
    bad = {"heldout": {"all": {"recall@5": 0.1}, "templated": {"recall@5": 0.9},
                       "curated_v2": {"recall@5": 0.9}}}
    assert gate.evaluate(bad) == ["all recall@5 0.1 < floor 0.6"]


def test_gate_does_not_grade_stale_results_when_the_benchmark_crashes(tmp_path, monkeypatch):
    """The bug: run_bench.py's exit code was ignored, so a crash passed on the old results.json."""
    gate = _load(os.path.join(ROOT, "bench", "gate.py"), "gate_mod")

    class _R:
        returncode = 1
        stdout = ""
        stderr = "boom"

    monkeypatch.setattr(gate.subprocess, "run", lambda *a, **k: _R())
    monkeypatch.setattr(gate.sys, "exit", lambda code=0: (_ for _ in ()).throw(SystemExit(code)))
    with pytest.raises(SystemExit) as e:
        gate.main()
    assert e.value.code == 1


# ---------------------------------------------------------------- path safety


def test_cache_paths_cannot_escape_the_cache_directory():
    for mod, func in (("fetch_sources.py", "dest"), ("ingest_from_cache.py", "cpath")):
        m = _load(os.path.join(ROOT, "scripts", mod), mod.replace(".py", ""))
        join = getattr(m, func)
        assert join("org/repo", "docs/file.md").startswith(m.CACHE)
        # Neutral filenames on purpose: system-file paths here trip secret scanners, which read
        # the filename as a password keyword. Renaming beats suppressing the scanner.
        for repo, path in (("org/repo", "../../outside.txt"), ("org/repo", "/tmp/outside.txt"),
                           ("org/repo", "../../../outside.txt")):
            with pytest.raises(ValueError):
                join(repo, path)
        # a dotted repo name is flattened into one directory, so it stays inside cache/
        assert join("../../../etc", "x").startswith(m.CACHE)


# ---------------------------------------------------------------- fingerprint (R-013)


def test_fingerprint_streams_and_skips_symlinks(kb, tmp_path):
    """R-013: chunked hashing bounds memory, and a symlink must not attribute foreign bytes."""
    tgt = tmp_path / "t"
    tgt.mkdir()
    (tgt / "real.txt").write_text("hello")
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")

    first = kb.fingerprint_target(str(tgt))
    os.symlink(outside, tgt / "link.txt")
    second = kb.fingerprint_target(str(tgt))

    assert first == second, "a symlink must not change the target fingerprint"
    assert second[1] == 1, "only the real file should be counted"


# ---------------------------------------------------------------- release verifier


def test_release_verifier_detects_a_stale_shipped_index(tmp_path, monkeypatch):
    """The bug: content_hash only compared the two manifests, so a stale index/checks.jsonl shipped
    while both manifests agreed with each other."""
    import hashlib

    vr = _load(os.path.join(ROOT, "scripts", "verify_release.py"), "verify_release_mod")
    (tmp_path / "index").mkdir()
    shipped = '{"id": "SKB-A"}\n'
    (tmp_path / "index" / "checks.jsonl").write_text(shipped)
    (tmp_path / "manifest.json").write_text(json.dumps({"content_hash": "0" * 16}))
    monkeypatch.setattr(vr, "ROOT", str(tmp_path))

    problems = vr.check_shipped_index_matches_hash()
    assert any("stale" in p for p in problems), problems

    good = hashlib.sha256(shipped.encode()).hexdigest()[:16]
    (tmp_path / "manifest.json").write_text(json.dumps({"content_hash": good}))
    assert vr.check_shipped_index_matches_hash() == []
