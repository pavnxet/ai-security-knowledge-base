#!/usr/bin/env python3
"""Phase C: cluster + merge near-duplicate cards. Writes merged cards, dedupe_report.md, aliases.json."""
import os, re, json, glob, yaml, difflib
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = {x["repo"]: x for x in yaml.safe_load(open(os.path.join(ROOT, "sources.yaml")))["sources"]}

def trust(c):
    return min((int(SRC[r]["trust_tier"]) for r in {s["repo"] for s in c["sources"]} if r in SRC), default=9)

def first_path(c):
    return sorted(str(s.get("path", "")) for s in c["sources"])[0]
STOP = set("the a an and or of to in for is are be with that this it as on by at from any all not must should can may".split())
TIER1 = ("ASVS:","MASVS-","MASTG-","WSTG-","Top10:","API","LLM")

def toks(s):
    return set(w for w in re.findall(r"[a-z0-9]+", (s or "").lower()) if w not in STOP and len(w) > 2)

def jac(a, b):
    if not a or not b: return 0.0
    return len(a & b) / len(a | b)

def tier1(c):
    return any(str(o).startswith(TIER1) for o in c.get("owasp", []))

def main():
    cards = {}
    for p in sorted(glob.glob(os.path.join(ROOT, "checks", "**", "*.yaml"), recursive=True)):
        c = yaml.safe_load(open(p)); c["_path"] = p
        cards[c["id"]] = c

    # block by primary platform+domain to keep comparisons bounded
    blocks = defaultdict(list)
    for c in cards.values():
        blocks[(c["platforms"][0], c["domain"])].append(c)

    merged = {}       # id -> canonical id
    canonical = {}    # id -> card
    merges = []       # (a,b,score)
    borderline = []

    for key, group in blocks.items():
        group = sorted(group, key=lambda c: (trust(c), first_path(c), c["id"]))
        keep = []
        for c in group:
            ct = toks(c["check"] + " " + c["title"])
            hit = None
            c_ref = set(map(str, c.get("owasp", [])))
            c_cwe = set(c.get("cwe", [])) if c.get("cwe_source") != "heuristic" else set()
            for k in keep:
                shared_ref = c_ref & k["_ref"]
                shared_cwe = c_cwe & k["_cwe"]
                sc = jac(ct, k["_tok"])
                if sc >= 0.55 or (shared_cwe and sc >= 0.40) or (shared_ref and sc >= 0.42):
                    hit = k; break
                if sc >= 0.40:
                    borderline.append((c["id"], k["id"], round(sc, 3)))
            if hit:
                # merge c into hit
                have = {s["repo"] + "|" + str(s.get("path")) for s in hit["sources"]}
                for s in c["sources"]:
                    if s["repo"] + "|" + str(s.get("path")) not in have:
                        hit["sources"].append(s)
                hit.setdefault("merged_from", []).append(c["id"])
                hit.setdefault("aliases", []).append(c["id"])
                hit["corroboration"] = len({s["repo"] for s in hit["sources"]})
                merged[c["id"]] = hit["id"]
                merges.append((c["id"], hit["id"], round(jac(ct, hit["_tok"]), 3)))
            else:
                c["_tok"] = ct; c["_ref"] = c_ref
                c["_cwe"] = set(c.get("cwe", [])) if c.get("cwe_source") != "heuristic" else set()
                keep.append(c); canonical[c["id"]] = c

    # rewrite checks/: keep canonical, drop merged files
    for cid, c in canonical.items():
        for k in ("_tok","_ref","_cwe"): c.pop(k, None)
        p = c.pop("_path")
        yaml.safe_dump(c, open(p, "w"), sort_keys=False, allow_unicode=True, width=100)
    removed = 0
    for p in sorted(glob.glob(os.path.join(ROOT, "checks", "**", "*.yaml"), recursive=True)):
        cid = os.path.basename(p)[:-5]
        if cid in merged:
            os.remove(p); removed += 1

    # aliases.json: v0.1 ids -> canonical (fuzzy by title) ; and merged ids -> canonical
    legacy = {}
    v01dir = os.path.join(ROOT, "legacy", "v0.1_checks")
    for p in glob.glob(os.path.join(v01dir, "**", "*.yaml"), recursive=True):
        c = yaml.safe_load(open(p)); legacy[c["id"]] = c
    canon_titles = [(cid, (c["title"] + " " + c["summary"]).lower()) for cid, c in canonical.items()]
    aliases = {}
    for cid in list(merged.keys()):
        aliases[cid] = merged[cid]
    unmatched_v01 = []
    for vid, vc in legacy.items():
        vt = (vc["title"] + " " + vc["summary"]).lower()
        best, score = None, 0.0
        vtoks = toks(vt)
        for cid, ct in canon_titles:
            r = jac(vtoks, toks(ct))
            if r > score: best, score = cid, r
        if score >= 0.30:
            aliases[vid] = best
        else:
            aliases[vid] = None; unmatched_v01.append(vid)
    json.dump(aliases, open(os.path.join(ROOT, "index", "aliases.json"), "w"), indent=0, sort_keys=True)

    # report
    lines = ["# dedupe_report.md", "",
             f"- cards before merge: {len(cards)}",
             f"- merges performed: {len(merges)}",
             f"- cards after merge: {len(canonical)}",
             f"- borderline pairs (NOT merged, for review): {len(borderline)}",
             f"- v0.1 ids mapped to a v0.2 card: {sum(1 for v in aliases.values() if v)} / {len(legacy)}",
             f"- v0.1 ids with no confident match (kept resolvable as legacy): {len(unmatched_v01)}", "",
             "## Merges (merged_id -> canonical_id, similarity)", ""]
    for a, b, s in sorted(merges, key=lambda x: -x[2])[:200]:
        lines.append(f"- {a} -> {b} ({s})")
    lines += ["", "## Borderline (human review)", ""]
    for a, b, s in sorted(borderline, key=lambda x: -x[2])[:120]:
        lines.append(f"- {a} ~ {b} ({s})")
    open(os.path.join(ROOT, "dedupe_report.md"), "w").write("\n".join(lines) + "\n")
    print(f"before={len(cards)} merges={len(merges)} after={len(canonical)} borderline={len(borderline)}")
    print(f"aliases: {len(aliases)} (v0.1 mapped {sum(1 for k,v in aliases.items() if k.startswith('SKB') and v)}; unmatched {len(unmatched_v01)})")

if __name__ == "__main__":
    main()
