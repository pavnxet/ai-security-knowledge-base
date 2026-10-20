#!/usr/bin/env python3
"""Per-rule CWE audit.

For every CWE mapping rule, report:
  n         = cards the rule fires on
  title_hit = fraction where the matched phrase appears in the card TITLE or SUMMARY
              (a conservative precision proxy: a rule that fires only in the body may be off-topic)
  eligible  = n >= 30 and title_hit >= 0.90  (the project's bar for keeping a rule)

Rules are the official CWE-title matches used by build_cards_v2.CWE_TITLE_RULES.
"""
import os, re, sys, glob, yaml, json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import importlib.util
spec = importlib.util.spec_from_file_location("bc", os.path.join(ROOT, "scripts", "build_cards_v2.py"))
bc = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(bc)
except SystemExit:
    pass
RULES = getattr(bc, "CWE_TITLE_RULES", None) or getattr(bc, "CWE_RULES", [])

def main():
    cards = [yaml.safe_load(open(p)) for p in sorted(glob.glob(os.path.join(ROOT, "checks", "**", "*.yaml"), recursive=True))]
    rows = []
    for pat, cwe in RULES:
        rx = re.compile(pat)
        n = 0; title_hit = 0
        for c in cards:
            if rx.search((c["title"] + " " + c.get("check", "")[:300]).lower()):
                n += 1
                if rx.search((c["title"] + " " + c.get("summary", "")).lower()):
                    title_hit += 1
        prec = round(title_hit / n, 3) if n else 0.0
        rows.append({"cwe": f"CWE-{cwe}", "rule": pat, "n": n, "title_hit": prec,
                     "eligible": bool(n >= 30 and prec >= 0.90)})
    rows.sort(key=lambda r: (-r["n"], -r["title_hit"]))
    print(f"{'CWE':9s} {'n':>5s} {'title_hit':>9s}  eligible  rule")
    for r in rows:
        print(f"{r['cwe']:9s} {r['n']:5d} {r['title_hit']:9.3f}  {'yes' if r['eligible'] else 'no ':8s}  {r['rule'][:46]}")
    elig = [r for r in rows if r["eligible"]]
    print(f"\nrules: {len(rows)}  eligible (n>=30 & title_hit>=0.90): {len(elig)}")
    json.dump(rows, open(os.path.join(ROOT, "bench", "cwe_audit.json"), "w"), indent=2)

if __name__ == "__main__":
    main()
