#!/usr/bin/env python3
"""R0 diagnostics — no behaviour changes. Failure taxonomy, source composition, latency profile."""
import os, sys, json, time, yaml, sqlite3, importlib.util, subprocess
from collections import Counter
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("secure_kb", os.path.join(ROOT, "cli", "secure_kb.py"))
kb = importlib.util.module_from_spec(spec); spec.loader.exec_module(kb)
CARDS = kb.load_cards()
DB = os.path.join(ROOT, "index", "kb.sqlite")

def refs_of(c): return set(map(str, c.get("owasp", []))) | set(map(str, c.get("refs", []))) | set(map(str, c.get("cwe", [])))
def src_of(c):
    s = c.get("sources") or []
    if c.get("origin") == "authored": return "authored"
    r = s[0]["repo"] if s else "?"
    return {"OWASP/ASVS":"ASVS","OWASP/CheatSheetSeries":"cheat-sheet","OWASP/wstg":"WSTG","OWASP/masvg":"MASVS",
            "OWASP/masvs":"MASVS","OWASP/mastg":"MASTG","OWASP/Top10":"Top10","OWASP/API-Security":"API",
            "OWASP/www-project-top-10-for-large-language-model-applications":"LLM",
            "OWASP/owasp-istg":"ISTG"}.get(r, r.split("/")[-1])

def search_ids(q, k=10):
    terms = kb.expand_query(q, {}, {})
    scored = {}
    con = sqlite3.connect(DB)
    match = " OR ".join(f'"{t}"' for t in terms if len(t) > 1) or q
    try:
        for cid, r in con.execute("SELECT id, bm25(checks_fts,0,10,6,5,4,1) AS r FROM checks_fts WHERE checks_fts MATCH ? ORDER BY r LIMIT 300", (match,)):
            scored[cid] = -r
    except sqlite3.OperationalError: pass
    con.close()
    for cid, c in CARDS.items():
        hay = " ".join([c["title"], c["summary"], " ".join(c.get("tags", [])), " ".join(c.get("aliases", [])), c["check"]]).lower()
        h = sum(1 for t in terms if t in hay)
        if h: scored[cid] = max(scored.get(cid, 0), h * 0.5)
    ranked = sorted(scored.items(), key=lambda kv: -(kv[1] * kb.SEV_W.get(CARDS[kv[0]]["severity"],1.0) * (1 + CARDS[kv[0]]["priority"]/200.0)))
    return [cid for cid, _ in ranked[:k]]

def taxonomy(queries, label):
    ranks = []; top5_src = Counter(); miss_src = Counter(); n=0
    for item in queries:
        exp = set(item["expect_refs"]); ids = search_ids(item["q"], 10); n += 1
        rank = next((i for i, cid in enumerate(ids, 1) if refs_of(CARDS[cid]) & exp), None)
        for cid in ids[:5]: top5_src[src_of(CARDS[cid])] += 1
        if rank: ranks.append(rank)
        else:
            for cid in ids[:5]: miss_src[src_of(CARDS[cid])] += 1
    ranks.sort()
    print(f"\n[{label}] n={n} hit={len(ranks)} miss={n-len(ranks)}")
    if ranks:
        print(f"   rank of first correct: median={ranks[len(ranks)//2]} p90={ranks[int(len(ranks)*0.9)-1]} max={max(ranks)}")
    print("   top-5 composition (all):", dict(top5_src.most_common(8)))
    print("   top-5 composition (missed queries only):", dict(miss_src.most_common(8)))

def latency():
    q = "how do I stop sql injection"
    t0=time.perf_counter(); importlib.util.spec_from_file_location("k2", os.path.join(ROOT,"cli","secure_kb.py"))
    # in-process warm query (repeat)
    times=[]
    for _ in range(20):
        t=time.perf_counter(); search_ids(q, 10); times.append((time.perf_counter()-t)*1000)
    times.sort()
    print(f"\n[latency] in-process search p50={times[len(times)//2]:.1f}ms p95={times[int(len(times)*0.95)]:.1f}ms")
    # stage breakdown
    t=time.perf_counter(); json.load(open(os.path.join(ROOT,"index","checks.jsonl"))) if False else None
    t=time.perf_counter(); cards=[json.loads(l) for l in open(os.path.join(ROOT,"index","checks.jsonl"))]; t_json=(time.perf_counter()-t)*1000
    t=time.perf_counter(); con=sqlite3.connect(DB); con.execute("SELECT count(*) FROM checks_fts"); con.close(); t_open=(time.perf_counter()-t)*1000
    t=time.perf_counter(); kb.expand_query(q, {}, {}); t_exp=(time.perf_counter()-t)*1000
    print(f"   checks.jsonl load={t_json:.1f}ms | sqlite open+count={t_open:.1f}ms | expansion={t_exp:.2f}ms")
    # cold CLI
    ct=[]
    for _ in range(3):
        t=time.perf_counter()
        subprocess.run([sys.executable, os.path.join(ROOT,"cli","secure_kb.py"),"search",q,"--k","5"], capture_output=True)
        ct.append((time.perf_counter()-t)*1000)
    ct.sort(); print(f"   cold CLI (process start incl.) p50={ct[len(ct)//2]:.0f}ms")

def cwe_audit(n=100):
    heur=[(cid,c) for cid,c in CARDS.items() if c.get("cwe_source")=="heuristic" and c.get("cwe")]
    import random; random.seed(0); sample=random.sample(heur, min(n,len(heur)))
    per=Counter(); ok=Counter()
    KW={"CWE-89":["sql","parameterized","prepared statement","query"],
        "CWE-79":["cross site scripting","xss","output encoding","escaping","escape","html encod","sanitiz"],
        "CWE-352":["csrf","cross-site request forgery","anti-forgery","xsrf","same-site","same site"],
        "CWE-434":["file upload","upload","content type","attachment"],
        "CWE-918":["ssrf","server side request","url fetch","outbound request","remote url"],
        "CWE-639":["object level","direct object","idor","authoriz","ownership","access control"],
        "CWE-601":["redirect","forward"],
        "CWE-502":["deserial","serializ"],
        "CWE-22":["traversal","path","file include","directory"],
        "CWE-611":["xml","xxe","entity","external"],
        "CWE-1021":["clickjack","frame","iframe"],
        "CWE-798":["hardcod","secret","credential","api key"],
        "CWE-915":["mass assignment","over-post","binding"],
        "CWE-384":["session fixation","session"],
        "CWE-307":["brute force","rate limit","attempt","lockout","throttl"],
        "CWE-770":["rate limit","throttl","resource","denial","dos","pagination"],
        "CWE-78":["command injection","os command","shell","exec"],
        "CWE-943":["nosql","mongo"]}
    for cid,c in sample:
        txt=(c["title"]+" "+c["check"]).lower()
        for cwe in c["cwe"]:
            per[cwe]+=1
            if any(k in txt for k in KW.get(cwe,[])): ok[cwe]+=1
    print(f"\n[CWE audit] sampled {len(sample)} heuristic cards")
    print("   precision per rule (support>=3):")
    for cwe,cnt in per.most_common():
        if cnt>=3: print(f"     {cwe}: {ok[cwe]}/{cnt} = {100*ok[cwe]/cnt:.0f}%")

if __name__ == "__main__":
    v1=yaml.safe_load(open(os.path.join(ROOT,"bench","heldout_queries.yaml")))["queries"]
    v2=yaml.safe_load(open(os.path.join(ROOT,"bench","heldout_queries_v2.yaml")))["queries"]
    taxonomy([q for q in v1 if q.get("set")=="curated"], "curated v1")
    taxonomy([q for q in v2 if q.get("set")=="curated"], "curated v2")
    taxonomy([q for q in v1 if q.get("set")=="templated"], "templated")
    latency()
    cwe_audit(100)
