#!/usr/bin/env python3
"""secure-kb CLI. Zero required dependencies (stdlib only; sqlite3 optional accelerator).

Usage:
  secure-kb detect [PATH]
  secure-kb profile <name> [--gate fast|full] [--budget-tokens N] [--format brief|json|md]
  secure-kb search "<query>" [--platform P] [--stack S] [--severity SEV] [--phase PH] [--domain D] [--k N]
  secure-kb get <id> [--format json|md]
  secure-kb cwe <n>            # e.g. secure-kb cwe 79
  secure-kb ref <ASVS:3.4.1>   # direct lookup by ASVS/MASVS/API/Top10 id
  secure-kb tools <platform>
  secure-kb report init [--out FILE]
  secure-kb report validate <FILE>
"""
import os, sys, json, re, math, hmac, hashlib, fnmatch, argparse, sqlite3

def find_root():
    if os.environ.get("SECURE_KB_DIR"):
        return os.environ["SECURE_KB_DIR"]
    here = os.path.dirname(os.path.abspath(__file__))
    for _ in range(5):
        if os.path.exists(os.path.join(here, "manifest.json")):
            return here
        here = os.path.dirname(here)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ROOT = find_root()
IDX = os.path.join(ROOT, "index")

def ensure_index():
    """Regenerate index/ from checks/ on first use (index/ is gitignored, auto-built)."""
    src = os.path.join(ROOT, "index", "checks.jsonl")
    if os.path.exists(src): return
    import subprocess, sys as _sys
    subprocess.run([_sys.executable, os.path.join(ROOT, "scripts", "build_index.py")],
                   cwd=ROOT, capture_output=True)

def ensure_db():
    """Build index/kb.sqlite from index/checks.jsonl on first use (cached, <2s). Never committed."""
    db = os.path.join(ROOT, "index", "kb.sqlite")
    src = os.path.join(ROOT, "index", "checks.jsonl")
    if os.path.exists(db) and os.path.exists(src) and os.path.getmtime(db) >= os.path.getmtime(src):
        # Never trust a cached DB on mtime alone: a build that died mid-way leaves a valid-looking
        # but empty file. Verify the row count matches the source, else rebuild.
        try:
            con = sqlite3.connect(db)
            rows = con.execute("SELECT count(*) FROM checks_fts").fetchone()[0]
            con.close()
            if rows == sum(1 for _ in open(src, encoding="utf-8")):
                return db
        except Exception:
            pass
        # fall through and rebuild
    import sqlite3
    if not os.path.exists(src): return db
    con = sqlite3.connect(db)
    con.execute("DROP TABLE IF EXISTS checks_fts")
    con.execute("CREATE VIRTUAL TABLE checks_fts USING fts5(id, title, summary, tags, aliases, check, cwe, tokenize='porter unicode61')")
    for line in open(src, encoding="utf-8"):
        if not line.strip(): continue
        c = json.loads(line)
        con.execute("INSERT INTO checks_fts VALUES (?,?,?,?,?,?,?)",
                    (c["id"], c["title"], c["summary"], " ".join(c.get("tags", [])),
                     " ".join(c.get("aliases", [])), c["check"], " ".join(cwe_tokens(c))))
    con.commit(); con.close()
    return db

def load_cards():
    ensure_index()
    cards = {}
    with open(os.path.join(IDX, "checks.jsonl"), encoding="utf-8") as f:
        for line in f:
            c = json.loads(line)
            cards[c["id"]] = c
    return cards

def load_map(name):
    p = os.path.join(IDX, name)
    return json.load(open(p, encoding="utf-8")) if os.path.exists(p) else {}

def load_json(p):
    return json.load(open(os.path.join(ROOT, p), encoding="utf-8"))

def load_synonyms():
    """Merge schema/vocab.json synonyms with synonyms.yaml (if present)."""
    syn = dict(load_json("schema/vocab.json").get("synonyms", {}))
    hubs = {}
    p = os.path.join(ROOT, "synonyms.yaml")
    if os.path.exists(p):
        import yaml
        d = yaml.safe_load(open(p, encoding="utf-8")) or {}
        for k, v in (d.get("synonyms") or {}).items():
            syn.setdefault(k, [])
            for t in v:
                if t not in syn[k]: syn[k].append(t)
        hubs = d.get("topic_hubs") or {}
    return syn, hubs

SEV_W = {"critical": 1.6, "high": 1.3, "medium": 1.0, "low": 0.8, "info": 0.6}

def est_tokens(obj):
    return len(json.dumps(obj, ensure_ascii=False)) // 4

def brief(card):
    return {"id": card["id"], "title": card["title"], "severity": card["severity"],
            "check": card["check"], "platforms": card["platforms"], "domain": card["domain"]}

def fmt_cards(cards, fmt, budget=None):
    if fmt == "json":
        return json.dumps(cards, indent=1, ensure_ascii=False)
    if fmt == "md":
        out = []
        for c in cards:
            out.append(f"- **{c['id']}** ({c['severity']}) - {c['title']}\n  - check: {c['check']}")
        return "\n".join(out)
    # brief
    out, used = [], 0
    for c in cards:
        line = f"{c['id']} [{c['severity']}] {c['title']} :: {c['check'][:120]}"
        t = len(line) // 4
        if budget and used + t > budget:
            break
        used += t
        out.append(line)
    return "\n".join(out)

# ---------- detect ----------
def iter_files(path, cap=8000):
    n = 0
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", "venv", ".venv", "dist", "build", "__pycache__")]
        for fn in filenames:
            yield os.path.join(dirpath, fn)
            n += 1
            if n >= cap:
                return

def cmd_detect(args):
    path = args.path
    router = load_map("router.json")
    votes, evidence = {}, {}
    # 1) filename fingerprint
    for fp in iter_files(path):
        base = os.path.basename(fp)
        rel = os.path.relpath(fp, path)
        for glob_pat, profs in router.get("files", {}).items():
            if fnmatch.fnmatch(base, glob_pat) or fnmatch.fnmatch(rel, glob_pat):
                for p in profs:
                    votes[p] = votes.get(p, 0) + 1
                    evidence.setdefault(p, set()).add(base)
    # 2) content signals
    for fp in iter_files(path):
        try:
            if os.path.getsize(fp) > 200_000:
                continue
            with open(fp, "r", errors="ignore", encoding="utf-8") as f:
                head = f.read(200_000)
        except Exception:
            continue
        for sig, profs in router.get("signals", {}).items():
            if sig in head:
                for p in profs:
                    votes[p] = votes.get(p, 0) + 2
                    evidence.setdefault(p, set()).add(sig)
    ranked = sorted(votes.items(), key=lambda kv: -kv[1])
    total = sum(votes.values()) or 1
    result = {"path": os.path.abspath(path),
              "platforms": [{"platform": p, "score": s, "confidence": round(s/total, 2),
                             "evidence": sorted(list(evidence.get(p, [])))[:6]} for p, s in ranked if p != "generic"],
              "recommended_profiles": [p for p, _ in ranked if p != "generic"][:3]}
    print(json.dumps(result, indent=2))

# ---------- profile ----------
def cmd_profile(args):
    prof = load_json(os.path.join("profiles", args.name + ".yaml")) if False else None
    import yaml
    with open(os.path.join(ROOT, "profiles", args.name + ".yaml"), encoding="utf-8") as f:
        prof = yaml.safe_load(f)
    ids = prof["gate"]["fast"] if args.gate == "fast" else prof["gate"]["full"]
    cards = load_cards()
    sel = [cards[i] for i in ids if i in cards]
    if args.format == "json":
        print(json.dumps({"profile": args.name, "gate": args.gate, "checks": [brief(c) for c in sel]}, indent=1))
    else:
        print(f"# {args.name} / {args.gate} gate ({len(sel)} checks)\n")
        print(fmt_cards(sel, args.format, args.budget_tokens))

# ---------- search ----------
# Official-CWE query expansion: maps a query phrase to the CWE token it implies, so cards that
# legitimately carry that mapped CWE rank higher. This changes only the QUERY, never a card's refs.
CWE_EXPAND = [
 (r"integer overflow|integer underflow", "cwe190"), (r"reentran", "cwe841"),
 (r"missing authentication|no authentication|unauthenticated", "cwe306"),
 (r"hard-?coded|secrets? in|api key", "cwe798"), (r"path traversal|directory traversal", "cwe22"),
 (r"sql injection|sqli", "cwe89"), (r"cross-?site scripting|xss", "cwe79"),
 (r"cross-?site request forgery|csrf", "cwe352"), (r"server-?side request forgery|ssrf", "cwe918"),
 (r"deserializ|pickle|unserialize", "cwe502"), (r"xml external entit|xxe", "cwe611"),
 (r"idor|object level authoriz|bola", "cwe639"), (r"file upload", "cwe434"),
 (r"unmaintained|outdated (component|dependency)|vulnerable (dependency|dependencies)", "cwe1104"),
 (r"as root|non-?root|runasuser|privileged", "cwe250"), (r"cleartext|no tls", "cwe319"),
 (r"open redirect|unvalidated redirect", "cwe601"), (r"clickjack", "cwe1021"),
 (r"brute force|credential stuffing", "cwe307"), (r"command injection", "cwe78"),
 (r"prototype pollution", "cwe1321"), (r"race condition|toctou", "cwe362"),
 (r"rate limit|resource consumption|denial of service", "cwe770"), (r"mass assignment", "cwe915"),
 (r"sensitive.*log|logging sensitive", "cwe532"), (r"privilege escalation", "cwe269"),
 (r"weak (crypt|hash|random)", "cwe330"), (r"supply chain|dependency confusion", "cwe1357"),
]

def expand_cwe(q):
    low = (q or "").lower(); out = []
    for pat, tok in CWE_EXPAND:
        if re.search(pat, low): out.append(tok)
    return list(dict.fromkeys(out))

def cwe_tokens(c):
    return ["cwe" + str(x).split("-")[-1] for x in c.get("cwe", []) if str(x).startswith("CWE")]

# Query normalisation: strip conversational intent, expand abbreviations.
# Query-side only — it changes what we SEARCH FOR, never what a card contains.
_ABBR = {"sqli":"sql injection","xss":"cross site scripting","idor":"insecure direct object reference",
         "authz":"authorization","authn":"authentication","rce":"remote code execution",
         "ssrf":"server side request forgery","csrf":"cross site request forgery","lfi":"local file inclusion",
         "xxe":"xml external entity","jwt":"json web token","mfa":"multi factor authentication",
         "rls":"row level security","sca":"software composition analysis","sast":"static analysis"}
_STOP = [r"\bhow do i\b", r"\bhow to\b", r"\bhow can i\b", r"\bwhat is\b", r"\bkaise\b",
         r"\bcan you\b", r"\bdo i\b", r"\bmy\b", r"\bi have\b", r"\bkaise roke\b", r"\bkaise bache\b"]

def normalize_query(q):
    low = (q or "").lower()
    for p in _STOP: low = re.sub(p, " ", low)
    return " ".join(_ABBR.get(t, t) for t in re.findall(r"[a-z0-9]+", low))

def expand_query(q, synonyms, hubs=None):
    terms = re.findall(r"[a-zA-Z0-9_]+", q.lower())
    extra = []
    for t in terms:
        for canon, syns in synonyms.items():
            if t == canon or t in syns:
                extra.append(canon)
    hubs = hubs or {}
    for t in list(terms):
        if t in hubs:
            extra += [w for h in hubs[t] for w in re.findall(r"[a-zA-Z0-9_]+", h.lower())]
    return list(dict.fromkeys(terms + extra))


# ---------- retrieval (field-weighted BM25 with query expansion) ----------
def _tok(t):
    return [w for w in re.findall(r"[a-z0-9]+", (t or "").lower()) if len(w) > 1]

_FIELDS = (("title", 3.0), ("tags", 2.2), ("summary", 1.6), ("check", 1.0))

def build_corpus_stats(cards):
    """Per-card tokenised fields + document frequency. Cached on the cards dict."""
    if getattr(build_corpus_stats, "_cache", None) is not None:
        return build_corpus_stats._cache
    docs, df, total = {}, {}, 0
    for cid, c in cards.items():
        f = {"title": _tok(c["title"]),
             "tags": _tok(" ".join(c.get("tags", [])) + " " + " ".join(c.get("aliases", []))),
             "summary": _tok(c["summary"]), "check": _tok(c["check"])}
        docs[cid] = f
        dl = sum(len(v) for v in f.values()); total += dl
        for w in set().union(*f.values()): df[w] = df.get(w, 0) + 1
    build_corpus_stats._cache = (docs, df, len(cards) or 1, total / (len(cards) or 1))
    return build_corpus_stats._cache

def rank(query, cards, synonyms=None, hubs=None, k=10):
    """Field-weighted BM25. Query terms weigh 1.0; expanded (synonym/hub) terms 0.55."""
    docs, df, N, avgdl = build_corpus_stats(cards)
    base = _tok(query)
    exp = [t for t in expand_query(query, synonyms or {}, hubs or {}) if t not in base]
    qterms = [(t, 1.0) for t in dict.fromkeys(base)] + [(t, 0.55) for t in dict.fromkeys(exp)]
    k1, b = 1.2, 0.75
    scores = {}
    for cid, f in docs.items():
        dl = sum(len(v) for v in f.values())
        s = 0.0
        for t, w in qterms:
            idf = math.log(1 + (N - df.get(t, 0) + 0.5) / (df.get(t, 0) + 0.5))
            for fname, fw in _FIELDS:
                tf = f[fname].count(t)
                if tf:
                    s += w * fw * idf * (tf * (k1 + 1)) / (tf + k1 * (1 - b + b * dl / avgdl))
        if s > 0: scores[cid] = s
    return sorted(scores, key=lambda c: -scores[c])[:k]

def cmd_search(args):
    cards = load_cards()
    synonyms, hubs = load_synonyms() if getattr(args, 'synonyms', False) else ({}, {})
    nq = normalize_query(args.query)
    terms = expand_query(nq, synonyms, hubs) + expand_cwe(nq)
    scored = {}
    db = os.path.join(IDX, "kb.sqlite")
    if os.path.exists(db):
        con = sqlite3.connect(db)
        match = " OR ".join(f'"{t}"' for t in terms if len(t) > 1) or args.query
        try:
            for cid, r in con.execute(
                "SELECT id, bm25(checks_fts,0,10,6,5,4,1,6) AS r FROM checks_fts WHERE checks_fts MATCH ? ORDER BY r LIMIT 200",
                (match,)).fetchall():
                scored[cid] = -r
        except sqlite3.OperationalError:
            pass
        con.close()
    for cid, c in cards.items():
        hay = " ".join([c["title"], c["summary"], " ".join(c.get("tags", [])),
                        " ".join(c.get("aliases", [])), c["check"]]).lower()
        hits = sum(1 for t in terms if t in hay)
        if hits:
            scored[cid] = max(scored.get(cid, 0), hits * 0.5)

    # filters + boosts
    def keep(c):
        if args.platform and args.platform not in c["platforms"]: return False
        if args.severity and c["severity"] != args.severity: return False
        if args.domain and c["domain"] != args.domain: return False
        if args.phase and args.phase not in c.get("phase", []): return False
        if args.stack and args.stack not in c.get("stacks", []): return False
        return True

    ranked = []
    for cid, base in scored.items():
        c = cards[cid]
        if not keep(c): continue
        score = base * SEV_W.get(c["severity"], 1.0) * (1 + c["priority"] / 200.0)
        if args.platform and args.platform in c["platforms"]:
            score *= 1.25
        ranked.append((score, c))
    ranked.sort(key=lambda x: -x[0])
    top = [c for _, c in ranked[:args.k]]
    if not top:
        print(json.dumps({"query": args.query, "results": [], "gap": True,
                          "hint": "No card matched. See references/ for candidate sources."}))
        return
    if args.format == "json":
        print(json.dumps({"query": args.query, "results": [brief(c) for c in top], "gap": False}, indent=1))
    else:
        print(fmt_cards(top, args.format, args.budget_tokens))

# ---------- get / cwe / ref / tools ----------
def cmd_get(args):
    cards = load_cards()
    c = cards.get(args.id)
    if not c:
        print(f"not found: {args.id}", file=sys.stderr); sys.exit(1)
    if args.format == "md":
        print(f"# {c['id']} - {c['title']}\n\n**Severity:** {c['severity']}  **Domain:** {c['domain']}  "
              f"**Platforms:** {', '.join(c['platforms'])}\n\n**Check:** {c['check']}\n\n**Fix:** {c['fix']}\n\n"
              f"**Evidence required:** {c['verify_evidence']}\n\n**Refs:** {', '.join(c.get('refs', []))}\n\n"
              f"**Sources:** " + "; ".join(f"{s['repo']}@{ (s['commit'] or 'doc')[:12]}" for s in c["sources"]))
    else:
        print(json.dumps(c, indent=2, ensure_ascii=False))

def cmd_cwe(args):
    m = load_map("by_cwe.json")
    ids = m.get(f"CWE-{args.number}") or m.get(args.number) or []
    print(json.dumps(ids))

def cmd_ref(args):
    m = load_map("by_ref.json")
    print(json.dumps(m.get(args.ref, [])))

def cmd_tools(args):
    import glob, yaml
    out = []
    for p in sorted(glob.glob(os.path.join(ROOT, "tools", "*.yaml"))):
        with open(p, encoding="utf-8") as f:
            t = yaml.safe_load(f)
        if not args.platform or args.platform in t.get("platforms", []):
            out.append({"tool": t["name"], "detects": t.get("detects", ""),
                        "install": t.get("install", ""), "run": t.get("run", "")})
    print(json.dumps(out, indent=1))

# ---------- report ----------
REPORT_SKELETON = {
    "schema": "secure-kb/report@1", "target": "", "date": "",
    "summary": {"pass": 0, "fail": 0, "n/a": 0, "unknown": 0, "coverage_pct": 0.0},
    "counts_by_severity": {"critical": {"fail": 0}, "high": {"fail": 0}},
    "results": [{"id": "SKB-...", "status": "unknown", "evidence": "", "note": ""}],
    "launch_gate": {"passed": False, "rule": "zero critical/high fails"},
}
def cmd_report(args):
    if args.action == "init":
        out = args.out or "security-report.json"
        json.dump(REPORT_SKELETON, open(out, "w", encoding="utf-8"), indent=2)
        print(f"wrote {out}")
    elif args.action == "validate":
        r = json.load(open(args.file, encoding="utf-8"))
        errs = []
        if r.get("schema") != "secure-kb/report@1": errs.append("bad schema tag")
        for res in r.get("results", []):
            if res.get("status") not in ("pass", "fail", "n/a", "unknown"): errs.append(f"bad status {res.get('id')}")
            if res.get("status") == "pass" and not res.get("evidence"): errs.append(f"pass without evidence: {res.get('id')}")
        print(json.dumps({"valid": not errs, "errors": errs}, indent=2))
        sys.exit(0 if not errs else 1)

# ---------- Verifiable Security Attestation (VSA) ----------
def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def _sha256_hex(b):
    return hashlib.sha256(b).hexdigest()

_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".mypy_cache", ".pytest_cache"}

def fingerprint_target(path):
    """Deterministic content fingerprint of a target tree: sha256 over sorted (relpath, file-sha256)."""
    files = []
    for dp, dns, fns in os.walk(path):
        dns[:] = [d for d in dns if d not in _SKIP_DIRS]
        for fn in fns:
            fp = os.path.join(dp, fn)
            try:
                data = open(fp, "rb").read()
            except Exception:
                continue
            files.append((os.path.relpath(fp, path), hashlib.sha256(data).hexdigest()))
    files.sort()
    h = hashlib.sha256()
    for rel, dg in files:
        h.update(rel.encode("utf-8", "ignore")); h.update(b"\0"); h.update(dg.encode()); h.update(b"\n")
    return h.hexdigest(), len(files)

def _gate_ids(platform, gate):
    import yaml
    p = os.path.join(ROOT, "profiles", platform + ".yaml")
    if not os.path.exists(p):
        return []
    prof = yaml.safe_load(open(p, encoding="utf-8"))
    return list((prof.get("gate") or {}).get(gate, []))

def _attest_payload(target_path, profile, gate, checks):
    man = load_json("manifest.json")
    fp, n = fingerprint_target(target_path)
    return {
        "attestation_version": 1,
        "kb": {"name": man.get("name", "secure-kb"), "version": man.get("version"), "content_hash": man.get("content_hash")},
        "target": {"path": target_path, "fingerprint": fp, "file_count": n},
        "gate": {"profile": profile, "name": gate, "check_count": len(checks)},
        "checks": checks,
    }

def cmd_attest(args):
    import hashlib as _h
    # pick profile: explicit, else detect
    profile = args.profile
    if not profile:
        router = load_map("router.json")
        votes = {}
        for fp in iter_files(args.path):
            base = os.path.basename(fp); rel = os.path.relpath(fp, args.path)
            for pat, profs in router.get("files", {}).items():
                if fnmatch.fnmatch(base, pat) or fnmatch.fnmatch(rel, pat):
                    for pr in profs: votes[pr] = votes.get(pr, 0) + 1
        profile = max(votes, key=votes.get) if votes else "web"
    ids = _gate_ids(profile, args.gate)
    statuses = {}
    if getattr(args, "results", None):
        for r in load_json(args.results).get("results", []):
            statuses[r["id"]] = (r.get("status", "unknown"), r.get("evidence"))
    checks = []
    for cid in ids:
        st, ev = statuses.get(cid, ("unknown", None))
        checks.append({"id": cid, "status": st,
                       "evidence_sha256": _sha256_hex(ev.encode()) if ev else None})
    payload = _attest_payload(args.path, profile, args.gate, checks)
    aid = _sha256_hex(_canon(payload))
    att = dict(payload); att["attestation_id"] = aid
    if getattr(args, "key", None):
        att["signature"] = {"alg": "HMAC-SHA256",
                            "value": hmac.new(args.key.encode(), aid.encode(), hashlib.sha256).hexdigest()}
    out = json.dumps(att, indent=1, sort_keys=True)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(out + "\n"); print(f"attestation written: {args.out}  id={aid}")
    else:
        print(out)

def cmd_verify_attestation(args):
    att = load_json(args.file)
    aid = att.pop("attestation_id", None)
    sig = att.pop("signature", None)
    if not aid:
        print("INVALID: no attestation_id"); sys.exit(1)
    recomputed = _sha256_hex(_canon(att))
    problems = []
    if recomputed != aid:
        problems.append(f"attestation_id mismatch (stored {aid[:12]}…, recomputed {recomputed[:12]}…)")
    if sig:
        if not args.key:
            problems.append("signature present but no --key supplied")
        else:
            exp = hmac.new(args.key.encode(), aid.encode(), hashlib.sha256).hexdigest()
            if exp != sig.get("value"):
                problems.append("HMAC signature does not verify")
    local = load_json("manifest.json").get("content_hash")
    kb_ok = att.get("kb", {}).get("content_hash") == local
    if not kb_ok:
        problems.append(f"kb content_hash mismatch (attested {att.get('kb',{}).get('content_hash')}, local {local})")
    if getattr(args, "path", None) and att.get("target", {}).get("fingerprint"):
        fp, n = fingerprint_target(args.path)
        if fp != att["target"]["fingerprint"]:
            problems.append("target fingerprint mismatch (tree changed since attestation)")
        else:
            pass
    status = "VALID" if not problems else "INVALID"
    print(json.dumps({"status": status, "attestation_id": aid, "kb_match": kb_ok,
                      "checks": len(att.get("checks", [])), "problems": problems}, indent=1))
    sys.exit(0 if not problems else 1)

def main():
    ap = argparse.ArgumentParser(prog="secure-kb")
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("detect"); d.add_argument("path", nargs="?", default="."); d.set_defaults(fn=cmd_detect)

    p = sub.add_parser("profile"); p.add_argument("name"); p.add_argument("--gate", choices=["fast","full"], default="fast")
    p.add_argument("--budget-tokens", type=int, default=4000); p.add_argument("--format", choices=["brief","json","md"], default="brief"); p.set_defaults(fn=cmd_profile)

    s = sub.add_parser("search"); s.add_argument("query"); s.add_argument("--platform"); s.add_argument("--stack")
    s.add_argument("--severity"); s.add_argument("--phase"); s.add_argument("--domain"); s.add_argument("--k", type=int, default=8)
    s.add_argument("--budget-tokens", type=int, default=2000); s.add_argument("--format", choices=["brief","json","md"], default="brief")
    s.add_argument("--synonyms", action="store_true", help="enable synonyms.yaml / topic-hub expansion (off by default: it measured worse)"); s.set_defaults(fn=cmd_search)

    g = sub.add_parser("get"); g.add_argument("id"); g.add_argument("--format", choices=["json","md"], default="json"); g.set_defaults(fn=cmd_get)

    c = sub.add_parser("cwe"); c.add_argument("number"); c.set_defaults(fn=cmd_cwe)
    r = sub.add_parser("ref"); r.add_argument("ref"); r.set_defaults(fn=cmd_ref)
    t = sub.add_parser("tools"); t.add_argument("platform", nargs="?"); t.set_defaults(fn=cmd_tools)

    rp = sub.add_parser("report"); rp.add_argument("action", choices=["init","validate"]); rp.add_argument("file", nargs="?"); rp.add_argument("--out"); rp.set_defaults(fn=cmd_report)

    a = sub.add_parser("attest", help="produce a verifiable security attestation")
    a.add_argument("path", nargs="?", default="."); a.add_argument("--profile"); a.add_argument("--gate", choices=["fast","full"], default="fast")
    a.add_argument("--results", help="JSON file of {results:[{id,status,evidence}]}"); a.add_argument("--key", help="HMAC key (optional)"); a.add_argument("--out")
    a.set_defaults(fn=cmd_attest)

    va = sub.add_parser("verify-attestation", help="verify an attestation offline")
    va.add_argument("file"); va.add_argument("--key"); va.add_argument("--path", help="re-verify the target fingerprint"); va.set_defaults(fn=cmd_verify_attestation)

    args = ap.parse_args()
    args.fn(args)

if __name__ == "__main__":
    main()
