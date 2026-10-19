#!/usr/bin/env python3
"""Rebuild the curated expected refs from the STANDARDS text (staging), not from cards.

The v1 curated refs were hand-written from memory (ASVS v4 ids, pre-2023 WSTG codes) and 27/59
were invalid against the corpus. Here each question's expectation is the official id of the
standard requirement whose text best matches the question - an expectation grounded in the source,
independent of how cards were authored. Originals kept in `expected_refs_v1`.
"""
import os, re, json, glob, yaml, math
from collections import Counter
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STOP = set("the a an and or of to in for is are be with that this it as on by at from any all not must should can may do does my i how what".split())

def toks(s): return [w for w in re.findall(r"[a-z0-9]+", (s or "").lower()) if w not in STOP and len(w) > 2]

# load standards staging (only derive-licensed standards)
STD = []
for p in glob.glob(os.path.join(ROOT, "staging", "*.jsonl")):
    for line in open(p):
        if not line.strip(): continue
        it = json.loads(line)
        STD.append((it["official_id"], toks(it["raw_text"])))

def best_refs(q, k=2, thresh=0.28):
    qt = set(toks(q))
    scored = []
    for oid, tt in STD:
        if not tt: continue
        ov = len(qt & set(tt)) / math.sqrt(len(tt) + 1)
        scored.append((ov, oid))
    scored.sort(reverse=True)
    top = [oid for ov, oid in scored[:k] if ov >= thresh]
    return top

def main():
    b = yaml.safe_load(open(os.path.join(ROOT, "bench", "heldout_queries.yaml")))
    out = []
    for item in b["queries"]:
        if item.get("set") != "curated":
            out.append(item); continue
        refs = best_refs(item["q"])
        out.append({"q": item["q"], "expect_refs": refs or item["expect_refs"],
                    "expected_refs_v1": item["expect_refs"], "set": "curated"})
    doc = {"version": 2, "frozen": True,
           "note": "expected refs derived from standards text (staging), independent of cards",
           "queries": out}
    yaml.safe_dump(doc, open(os.path.join(ROOT, "bench", "heldout_queries_v2.yaml"), "w"),
                   sort_keys=False, allow_unicode=True, width=100)
    cur = [q for q in out if q.get("set") == "curated"]
    print(f"v2 queries: {len(out)} (curated {len(cur)})")
    print("sample:", json.dumps(cur[:3], ensure_ascii=False))

if __name__ == "__main__":
    main()
