#!/usr/bin/env python3
"""secure-kb MCP server (stdio, newline-delimited JSON-RPC 2.0).

Read-only by default. Exposes: detect_stack, get_profile, search_checks, get_check,
list_tools, start_report, submit_result. Run: python3 mcp/server.py
"""
import os, sys, json, importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
spec = importlib.util.spec_from_file_location("secure_kb", os.path.join(ROOT, "cli", "secure_kb.py"))
kb = importlib.util.module_from_spec(spec); spec.loader.exec_module(kb)


def _manifest_version():
    import json as _j
    try:
        return _j.load(open(os.path.join(ROOT, "manifest.json")))["version"]
    except Exception:
        return "0.9.0"

TOOLS = [
 {"name": "detect_stack", "description": "Fingerprint a codebase path and return ranked platforms + recommended profiles.",
  "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
 {"name": "get_profile", "description": "Return the ordered launch-gate checks for a platform profile.",
  "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}, "gate": {"enum": ["fast", "full"]}}, "required": ["name"]}},
 {"name": "search_checks", "description": "Free-text search over check cards with structured filters.",
  "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}, "platform": {"type": "string"}, "severity": {"type": "string"}, "domain": {"type": "string"}, "k": {"type": "integer"}}, "required": ["query"]}},
 {"name": "get_check", "description": "Fetch one full check card by id.",
  "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}},
 {"name": "list_tools", "description": "List scanner tool adapters, optionally for a platform.",
  "inputSchema": {"type": "object", "properties": {"platform": {"type": "string"}}}},
 {"name": "start_report", "description": "Create a security report skeleton for a target.",
  "inputSchema": {"type": "object", "properties": {"target": {"type": "string"}}}},
 {"name": "attest", "description": "Produce a Verifiable Security Attestation: a deterministic, tamper-evident record of which checks were run against a target's exact content fingerprint and which KB version. Verifiable offline.",
  "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "profile": {"type": "string"}, "gate": {"enum": ["fast","full"]}, "results": {"type": "array"}, "key": {"type": "string"}}, "required": ["path"]}},
 {"name": "verify_attestation", "description": "Verify a Verifiable Security Attestation offline: recompute its id, check the KB content hash, and (optionally) its HMAC signature and target fingerprint.",
  "inputSchema": {"type": "object", "properties": {"attestation": {"type": "object"}, "key": {"type": "string"}, "path": {"type": "string"}}, "required": ["attestation"]}},
 {"name": "submit_result", "description": "Record one check result (pass/fail/n/a/unknown) with evidence.",
  "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}, "status": {"enum": ["pass","fail","n/a","unknown"]}, "evidence": {"type": "string"}}, "required": ["id","status"]}},
]

_STATE = {"report": None}

def call(name, a):
    if name == "detect_stack":
        return _detect(a.get("path", "."))
    if name == "get_profile":
        import yaml, re as _re
        _name = str(a.get("name", ""))
        if not _re.fullmatch(r"[a-z0-9][a-z0-9_-]*", _name):
            return {"error": "invalid profile name"}
        with open(os.path.join(ROOT, "profiles", _name + ".yaml")) as f:
            prof = yaml.safe_load(f)
        ids = prof["gate"][a.get("gate", "fast")]
        cards = kb.load_cards()
        return {"profile": a["name"], "gate": a.get("gate", "fast"),
                "checks": [kb.brief(cards[i]) for i in ids if i in cards]}
    if name == "attest":
        import hashlib as _h, json as _j, fnmatch as _fn
        path = a.get("path", ".")
        profile = a.get("profile")
        if not profile:
            router = kb.load_map("router.json"); votes = {}
            for fp in kb.iter_files(path):
                base = os.path.basename(fp); rel = os.path.relpath(fp, path)
                for pat, profs in router.get("files", {}).items():
                    if _fn.fnmatch(base, pat) or _fn.fnmatch(rel, pat):
                        for pr in profs: votes[pr] = votes.get(pr, 0) + 1
            profile = max(votes, key=votes.get) if votes else "web"
        gate = a.get("gate", "fast")
        ids = kb._gate_ids(profile, gate)
        st = {r.get("id"): r for r in (a.get("results") or [])}
        checks = [{"id": cid, "status": st.get(cid, {}).get("status", "unknown"),
                   "evidence_sha256": _h.sha256(str(st.get(cid, {}).get("evidence", "")).encode()).hexdigest() if st.get(cid, {}).get("evidence") else None}
                  for cid in ids]
        payload = kb._attest_payload(path, profile, gate, checks)
        aid = _h.sha256(kb._canon(payload)).hexdigest()
        out = dict(payload); out["attestation_id"] = aid
        if a.get("key"):
            import hmac as _hm
            out["signature"] = {"alg": "HMAC-SHA256", "value": _hm.new(a["key"].encode(), aid.encode(), _h.sha256).hexdigest()}
        return out
    if name == "verify_attestation":
        import hashlib as _h, hmac as _hm, json as _j
        att = dict(a.get("attestation", {}))
        aid = att.pop("attestation_id", None); sig = att.pop("signature", None)
        if not aid: return {"status": "INVALID", "problems": ["no attestation_id"]}
        problems = []
        if _h.sha256(kb._canon(att)).hexdigest() != aid: problems.append("attestation_id mismatch")
        key = a.get("key") or os.environ.get("SECURE_KB_HMAC_KEY")
        if sig:
            if not key: problems.append("signature present but no key supplied")
            elif not _hm.compare_digest(_hm.new(key.encode(), aid.encode(), _h.sha256).hexdigest(),
                                        str(sig.get("value") or "")):
                problems.append("HMAC signature does not verify")
        elif key and not a.get("allow_unsigned"):
            problems.append("signature missing: this attestation is unsigned and cannot be "
                            "verified against a key (pass allow_unsigned to accept an "
                            "integrity-only check)")
        local = kb.load_json("manifest.json").get("content_hash")
        kb_ok = att.get("kb", {}).get("content_hash") == local
        if not kb_ok: problems.append("kb content_hash mismatch")
        if a.get("path") and att.get("target", {}).get("fingerprint"):
            if kb.fingerprint_target(a["path"])[0] != att["target"]["fingerprint"]: problems.append("target fingerprint mismatch")
        return {"status": "VALID" if not problems else "INVALID", "attestation_id": aid,
                "signed": sig is not None, "kb_match": kb_ok, "problems": problems}
    if name == "search_checks":
        return _search(a)
    if name == "get_check":
        if not a.get("id"):
            raise ValueError("missing required argument: id (e.g. SKB-ASVS-V1-2-4)")
        card = kb.load_cards().get(a["id"])
        if card is None:
            raise ValueError(f"unknown check id: {a['id']} (try search_checks first)")
        return card
    if name == "list_tools":
        import glob, yaml
        out = []
        for p in sorted(glob.glob(os.path.join(ROOT, "tools", "*.yaml"))):
            t = yaml.safe_load(open(p, encoding="utf-8"))
            if not a.get("platform") or a["platform"] in t.get("platforms", []):
                out.append({"name": t["name"], "detects": t.get("detects"), "run": t.get("run")})
        return out
    if name == "start_report":
        _STATE["report"] = {"schema": "secure-kb/report@1", "target": a.get("target", ""),
                            "summary": {}, "results": [], "launch_gate": {"passed": False}}
        return _STATE["report"]
    if name == "submit_result":
        if _STATE["report"] is None:
            _STATE["report"] = {"schema": "secure-kb/report@1", "results": []}
        for req in ("id", "status"):
            if not a.get(req):
                raise ValueError(f"missing required argument: {req}")
        if a["status"] == "pass" and not a.get("evidence"):
            return {"error": "pass requires evidence"}
        _STATE["report"]["results"].append({"id": a["id"], "status": a["status"], "evidence": a.get("evidence", "")})
        return {"ok": True, "results": len(_STATE["report"]["results"])}
    raise ValueError("unknown tool " + str(name))

def _detect(path):
    """Delegates to kb.detect so MCP and CLI fingerprint a tree identically."""
    return kb.detect(path)

def _search(a):
    """Same ranking as `secure-kb search`. This used to be a second, weaker scorer, which meant an
    agent got different (and worse) cards than the CLI for the same query."""
    if not a.get("query"):
        raise ValueError("missing required argument: query")
    cards = kb.search(a["query"], a.get("platform"), a.get("stack"), a.get("severity"),
                      a.get("phase"), a.get("domain"), a.get("k", 8),
                      bool(a.get("synonyms")))
    return {"results": [kb.brief(c) for c in cards], "gap": not cards}

def send(msg):
    sys.stdout.write(json.dumps(msg) + "\n"); sys.stdout.flush()

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line: continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        rid = req.get("id"); method = req.get("method")
        if method == "initialize":
            send({"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2024-11-05",
                 "capabilities": {"tools": {}}, "serverInfo": {"name": "secure-kb", "version": _manifest_version()}}})
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
        elif method == "tools/call":
            p = req.get("params", {})
            try:
                out = call(p.get("name"), p.get("arguments", {}))
                send({"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": json.dumps(out, indent=1, ensure_ascii=False)}], "isError": False}})
            except Exception as e:
                send({"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": str(e)}], "isError": True}})
        elif method == "ping":
            send({"jsonrpc": "2.0", "id": rid, "result": {}})
        else:
            if rid is not None:
                send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method not found"}})

if __name__ == "__main__":
    main()
