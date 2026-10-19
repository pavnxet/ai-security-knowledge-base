#!/usr/bin/env python3
"""Phase E runner: held-out retrieval, lab coverage, end-to-end gate recall. Honest, with worst cases."""
import os, sys, json, time, yaml, sqlite3, importlib.util, glob
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("secure_kb", os.path.join(ROOT, "cli", "secure_kb.py"))
kb = importlib.util.module_from_spec(spec); spec.loader.exec_module(kb)
CARDS = kb.load_cards()
import os as _os
SYN, HUBS = kb.load_synonyms() if _os.environ.get('SECURE_KB_SYNONYMS') else ({}, {})

def refs_of(c, strict=False):
    r = set(map(str, c.get("owasp", []))) | set(map(str, c.get("refs", [])))
    if strict:
        if c.get("cwe_source") != "heuristic":
            r |= set(map(str, c.get("cwe", [])))
    else:
        r |= set(map(str, c.get("cwe", [])))
    return r

def search_ids(q, k=10):
    terms = kb.expand_query(q, SYN, HUBS)
    scored = {}
    db = os.path.join(ROOT, "index", "kb.sqlite")
    if os.path.exists(db):
        con = sqlite3.connect(db)
        match = " OR ".join(f'"{t}"' for t in terms if len(t) > 1) or q
        try:
            for cid, r in con.execute("SELECT id, bm25(checks_fts,0,10,6,5,4,1) AS r FROM checks_fts WHERE checks_fts MATCH ? ORDER BY r LIMIT 300", (match,)):
                scored[cid] = -r
        except sqlite3.OperationalError: pass
        con.close()
    for cid, c in CARDS.items():
        hay = " ".join([c["title"], c["summary"], " ".join(c.get("tags", [])), " ".join(c.get("aliases", [])), c["check"]]).lower()
        hits = sum(1 for t in terms if t in hay)
        if hits: scored[cid] = max(scored.get(cid, 0), hits * 0.5)
    ranked = sorted(scored.items(), key=lambda kv: -(kv[1] * kb.SEV_W.get(CARDS[kv[0]]["severity"],1.0) * (1 + CARDS[kv[0]]["priority"]/200.0)))
    return [cid for cid, _ in ranked[:k]]

def eval_set(queries, label):
    r5 = r10 = 0; rr = 0.0; lat = []; toks = []; worst = []
    for item in queries:
        exp = set(item["expect_refs"]); q = item["q"]
        t0 = time.perf_counter(); ids = search_ids(q, 10); lat.append((time.perf_counter()-t0)*1000)
        toks.append(len(" ".join(ids))//4)
        hit_rank = None
        for i, cid in enumerate(ids, 1):
            if refs_of(CARDS[cid]) & exp:
                hit_rank = i; break
        if hit_rank:
            rr += 1.0/hit_rank
            if hit_rank <= 5: r5 += 1
            r10 += 1
        else:
            worst.append((q, sorted(exp), ids[:5]))
    n = len(queries) or 1
    lat.sort()
    return {"set": label, "n": n, "recall@5": round(r5/n,3), "recall@10": round(r10/n,3),
            "mrr": round(rr/n,3), "p50_ms": round(lat[n//2],2), "p95_ms": round(lat[int(n*0.95)],2),
            "avg_tokens": round(sum(toks)/n,1)}, worst

def lab_coverage():
    labs = yaml.safe_load(open(os.path.join(ROOT,"bench","labs.yaml")))["labs"]
    rows = []; cov = 0; gate_cov = 0; total = 0
    prof_cache = {}
    for name, d in labs.items():
        plat = d["platform"]
        if plat not in prof_cache:
            prof_cache[plat] = set(yaml.safe_load(open(os.path.join(ROOT,"profiles",plat+".yaml")))["gate"]["fast"])
        gate = prof_cache[plat]
        for ref in d["classes"]:
            total += 1
            ids = [cid for cid,c in CARDS.items() if ref in refs_of(c, strict=True)]
            idsh = [cid for cid,c in CARDS.items() if ref in refs_of(c, strict=False)]
            if idsh: cov += 1
            if any(i in gate for i in ids): gate_cov += 1
            rows.append({"lab": name, "ref": ref, "cards": len(ids), "in_fast_gate": any(i in gate for i in ids)})
    return {"classes": total, "covered": cov, "coverage_pct": round(100*cov/total,1),
            "in_fast_gate": gate_cov, "gate_recall_pct": round(100*gate_cov/total,1)}, rows

def main():
    held = yaml.safe_load(open(os.path.join(ROOT,"bench","heldout_queries.yaml")))["queries"]
    v2path = os.path.join(ROOT,"bench","heldout_queries_v2.yaml")
    held_v2 = yaml.safe_load(open(v2path))["queries"] if os.path.exists(v2path) else []
    allr, worst_all = eval_set(held, "all")
    cur = [q for q in held if q.get("set")=="curated"]
    tmpl = [q for q in held if q.get("set")=="templated"]
    cur_r, cur_worst = eval_set(cur, "curated")
    tmpl_r, _ = eval_set(tmpl, "templated")
    # user set
    v2d_path = os.path.join(ROOT,"bench","v2_dev","queries.yaml")
    v2d = yaml.safe_load(open(v2d_path))["queries"] if os.path.exists(v2d_path) else []
    v2d_r, _ = eval_set(v2d, "v2_dev") if v2d else ({"set":"v2_dev","n":0}, [])
    _uq = os.path.join(ROOT, "bench", "user_queries.yaml")
    user = (yaml.safe_load(open(_uq)).get("queries") or []) if os.path.exists(_uq) else []
    user_r = eval_set(user, "user")[0] if user else {"set":"user","n":0,"note":"empty - add real queries"}

    cur_v2 = [q for q in held_v2 if q.get("set")=="curated"]
    cur_v2_r, cur_v2_worst = eval_set(cur_v2, "curated_v2") if cur_v2 else ({"set":"curated_v2","n":0}, [])
    lab, lab_rows = lab_coverage()
    report = {"cards": len(CARDS), "heldout": {"all": allr, "curated_v1": cur_r, "curated_v2": cur_v2_r, "v2_dev": v2d_r, "templated": tmpl_r, "user": user_r},
              "lab_coverage": lab}
    print(json.dumps(report, indent=2))
    print("\n== 15 WORST (all) ==")
    for q, exp, got in worst_all[:15]:
        print(f"  q={q!r}\n     expect_refs={exp}\n     got_refs={[sorted(refs_of(CARDS[i]))[:2] for i in got]}")
    print("\n== lab classes NOT in fast gate ==")
    for r in lab_rows:
        if not r["in_fast_gate"]:
            print(f"  {r['lab']}: {r['ref']} (cards={r['cards']})")
    json.dump(report, open(os.path.join(ROOT,"bench","results.json"),"w"), indent=2)

if __name__ == "__main__":
    main()
