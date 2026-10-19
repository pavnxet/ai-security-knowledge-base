"""Unit tests for the CLI and MCP server. Run: python -m pytest tests/ -q"""
import os, sys, json, subprocess, importlib.util
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m

@pytest.fixture(scope="session")
def kb():
    return _load(os.path.join(ROOT, "cli", "secure_kb.py"), "secure_kb")

def test_cards_load(kb):
    cards = kb.load_cards()
    assert len(cards) > 2000

def test_ids_unique_and_shaped(kb):
    import re
    cards = kb.load_cards()
    ids = list(cards)
    assert len(ids) == len(set(ids))
    assert all(re.fullmatch(r"SKB-[A-Z0-9]+-[A-Z0-9-]+", i) for i in ids)

def test_get_by_id():
    r = _cli("get", "SKB-ASVS-V1-2-4", "--format", "md")
    assert r.returncode == 0
    assert "SKB-ASVS-V1-2-4" in r.stdout

def _cli(*args, timeout=180):
    return subprocess.run([sys.executable, os.path.join(ROOT, "cli", "secure_kb.py"), *args],
                          capture_output=True, text=True, timeout=timeout)

def test_detect_web(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==3.0\n")
    (tmp_path / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n")
    r = _cli("detect", str(tmp_path))
    assert r.returncode == 0
    assert "web" in r.stdout

def test_search_returns_hits():
    r = _cli("search", "how do I stop sql injection", "--k", "5")
    assert r.returncode == 0
    assert "SKB-" in r.stdout

def test_profile_rejects_traversal():
    """MCP get_profile must reject path traversal in the profile name."""
    proc = subprocess.run([sys.executable, os.path.join(ROOT, "mcp", "server.py")],
        input='{"jsonrpc":"2.0","id":1,"method":"initialize"}\n'
              '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_profile","arguments":{"name":"../sources"}}}\n',
        capture_output=True, text=True, timeout=180)
    lines = [json.loads(l) for l in proc.stdout.splitlines() if l.strip().startswith("{")]
    call = next((x for x in lines if x.get("id") == 2), None)
    assert call is not None
    body = json.dumps(call)
    assert "invalid profile name" in body

def test_mcp_lists_tools():
    proc = subprocess.run([sys.executable, os.path.join(ROOT, "mcp", "server.py")],
        input='{"jsonrpc":"2.0","id":1,"method":"initialize"}\n'
              '{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n',
        capture_output=True, text=True, timeout=180)
    lines = [json.loads(l) for l in proc.stdout.splitlines() if l.strip().startswith("{")]
    tools = next((x["result"]["tools"] for x in lines if x.get("id") == 2), [])
    names = {t["name"] for t in tools}
    assert {"search_checks", "get_check", "detect_stack", "get_profile"} <= names


# ---------- Verifiable Security Attestation (VSA) ----------
def _mk_target(d):
    (d / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n")
    (d / "requirements.txt").write_text("flask==3.0\n")

def test_attest_roundtrip(tmp_path):
    tgt = tmp_path / "t"; tgt.mkdir(); _mk_target(tgt)
    att = tmp_path / "a.json"
    r = _cli("attest", str(tgt), "--gate", "fast", "--key", "k", "--out", str(att))
    assert r.returncode == 0 and att.exists()
    v = _cli("verify-attestation", str(att), "--key", "k", "--path", str(tgt))
    assert v.returncode == 0
    assert '"status": "VALID"' in v.stdout or '"VALID"' in v.stdout

def test_attest_tamper_detected(tmp_path):
    tgt = tmp_path / "t"; tgt.mkdir(); _mk_target(tgt)
    att = tmp_path / "a.json"
    _cli("attest", str(tgt), "--gate", "fast", "--out", str(att))
    a = json.loads(att.read_text()); a["checks"][0]["status"] = "pass"; att.write_text(json.dumps(a))
    v = _cli("verify-attestation", str(att))
    assert v.returncode == 1

def test_attest_target_change_detected(tmp_path):
    tgt = tmp_path / "t"; tgt.mkdir(); _mk_target(tgt)
    att = tmp_path / "a.json"
    _cli("attest", str(tgt), "--gate", "fast", "--out", str(att))
    (tgt / "app.py").write_text("x = 1\n")          # mutate the tree
    v = _cli("verify-attestation", str(att), "--path", str(tgt))
    assert v.returncode == 1

def test_attest_wrong_key(tmp_path):
    tgt = tmp_path / "t"; tgt.mkdir(); _mk_target(tgt)
    att = tmp_path / "a.json"
    _cli("attest", str(tgt), "--gate", "fast", "--key", "right", "--out", str(att))
    v = _cli("verify-attestation", str(att), "--key", "wrong")
    assert v.returncode == 1

def test_attest_fingerprint_is_deterministic(tmp_path):
    tgt = tmp_path / "t"; tgt.mkdir(); _mk_target(tgt)
    a1 = tmp_path / "a1.json"; a2 = tmp_path / "a2.json"
    _cli("attest", str(tgt), "--gate", "fast", "--out", str(a1))
    _cli("attest", str(tgt), "--gate", "fast", "--out", str(a2))
    j1 = json.loads(a1.read_text()); j2 = json.loads(a2.read_text())
    assert j1["attestation_id"] == j2["attestation_id"]
    assert j1["target"]["fingerprint"] == j2["target"]["fingerprint"]
