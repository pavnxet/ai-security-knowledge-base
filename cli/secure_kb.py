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
import os, sys, json, re, fnmatch, argparse, sqlite3

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
        return db
    import sqlite3
    if not os.path.exists(src): return db
    con = sqlite3.connect(db)
    con.execute("DROP TABLE IF EXISTS checks_fts")
    con.execute("CREATE VIRTUAL TABLE checks_fts USING fts5(id, title, summary, tags, aliases, check)")
    for line in open(src):
        if not line.strip(): continue
        c = json.loads(line)
        con.execute("INSERT INTO checks_fts VALUES (?,?,?,?,?,?)",
                    (c["id"], c["title"], c["summary"], " ".join(c.get("tags", [])),
                     " ".join(c.get("aliases", [])), c["check"]))
    con.commit(); con.close()
    return db

def load_cards():
    ensure_index()
    cards = {}
    with open(os.path.join(IDX, "checks.jsonl")) as f:
        for line in f:
            c = json.loads(line)
            cards[c["id"]] = c
    return cards

def load_map(name):
    p = os.path.join(IDX, name)
    return json.load(open(p)) if os.path.exists(p) else {}

def load_json(p):
    return json.load(open(os.path.join(ROOT, p)))

def load_synonyms():
    """Merge schema/vocab.json synonyms with synonyms.yaml (if present)."""
    syn = dict(load_json("schema/vocab.json").get("synonyms", {}))
    hubs = {}
    p = os.path.join(ROOT, "synonyms.yaml")
    if os.path.exists(p):
        import yaml
        d = yaml.safe_load(open(p)) or {}
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
            with open(fp, "r", errors="ignore") as f:
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
    with open(os.path.join(ROOT, "profiles", args.name + ".yaml")) as f:
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

def cmd_search(args):
    cards = load_cards()
    synonyms, hubs = load_synonyms() if getattr(args, "synonyms", False) else ({}, {})
    terms = expand_query(args.query, synonyms, hubs)
    scored = {}
    db = os.path.join(IDX, "kb.sqlite")
    if os.path.exists(db):
        con = sqlite3.connect(db)
        # OR the terms
        match = " OR ".join(f'"{t}"' for t in terms if len(t) > 1) or args.query
        try:
            rows = con.execute(
                "SELECT id, bm25(checks_fts,0,10,6,5,4,1) AS r FROM checks_fts WHERE checks_fts MATCH ? ORDER BY r LIMIT 200",
                (match,)).fetchall()
            for cid, r in rows:
                scored[cid] = -r  # bm25 negative; flip so higher=better
        except sqlite3.OperationalError:
            pass
        con.close()
    # fallback / augment: substring scan
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
        with open(p) as f:
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
        json.dump(REPORT_SKELETON, open(out, "w"), indent=2)
        print(f"wrote {out}")
    elif args.action == "validate":
        r = json.load(open(args.file))
        errs = []
        if r.get("schema") != "secure-kb/report@1": errs.append("bad schema tag")
        for res in r.get("results", []):
            if res.get("status") not in ("pass", "fail", "n/a", "unknown"): errs.append(f"bad status {res.get('id')}")
            if res.get("status") == "pass" and not res.get("evidence"): errs.append(f"pass without evidence: {res.get('id')}")
        print(json.dumps({"valid": not errs, "errors": errs}, indent=2))
        sys.exit(0 if not errs else 1)

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

    args = ap.parse_args()
    args.fn(args)

if __name__ == "__main__":
    main()
