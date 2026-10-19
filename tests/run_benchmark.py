#!/usr/bin/env python3
"""Benchmark retrieval: recall@5, MRR, latency, tokens per query."""
import os, sys, json, time, yaml, importlib.util

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("secure_kb", os.path.join(ROOT, "cli", "secure_kb.py"))
kb = importlib.util.module_from_spec(spec); spec.loader.exec_module(kb)

cards = kb.load_cards()
vocab = kb.load_json("schema/vocab.json")
syn = vocab.get("synonyms", {})
bench = yaml.safe_load(open(os.path.join(ROOT, "tests", "benchmark.yaml")))
targets = bench.get("targets", {})

def search(query, k=5):
    terms = kb.expand_query(query, syn)
    scored = {}
    for cid, c in cards.items():
        hay = " ".join([c["title"], c["summary"], " ".join(c.get("tags", [])),
                        " ".join(c.get("aliases", [])), c["check"]]).lower()
        hits = sum(1 for t in terms if t in hay)
        if hits:
            scored[cid] = hits * kb.SEV_W.get(c["severity"], 1.0) * (1 + c["priority"] / 200.0)
    return [cid for cid, _ in sorted(scored.items(), key=lambda kv: -kv[1])[:k]]

def run(subset, label):
    hits5 = 0; rr = 0.0; lat = []; toks = []; misses = []
    for item in subset:
        q = item["query"]; exp = set(item["expect"])
        t0 = time.perf_counter()
        res = search(q, 5)
        lat.append((time.perf_counter() - t0) * 1000)
        toks.append(len(" ".join(res)) // 4)
        rank = next((i + 1 for i, cid in enumerate(res) if cid in exp), None)
        if rank:
            hits5 += 1; rr += 1.0 / rank
        else:
            misses.append((q, sorted(exp), res))
    n = len(subset) or 1
    lat.sort()
    return {"queries": len(subset), "recall@5": round(hits5 / n, 3), "mrr": round(rr / n, 3),
            "latency_ms": {"p50": round(lat[n // 2], 2), "p95": round(lat[int(n * 0.95)], 2)},
            "avg_tokens_per_query": round(sum(toks) / n, 1)}, misses

def main():
    allq = bench["queries"]
    manual = [q for q in allq if q.get("platform") is None]
    auto = [q for q in allq if q.get("platform") is not None]
    report, misses = run(allq, "all")
    man_rep, _ = run(manual, "manual")
    report["manual_subset"] = man_rep
    report["note"] = "auto queries derive from card aliases (easy); manual_subset is the harder signal"
    recall = report["recall@5"]
    print(json.dumps(report, indent=2))
    if misses:
        print(f"\n{len(misses)} misses (first 8):")
        for q, exp, got in misses[:8]:
            print(f"  q={q!r} expect={exp} got={got}")
    tgt = targets.get("recall_at_5", 0.85)
    ok = recall >= tgt
    print(f"\nrecall@5 target {tgt}: {'PASS' if ok else 'FAIL'}")
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
