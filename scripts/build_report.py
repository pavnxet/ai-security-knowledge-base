#!/usr/bin/env python3
"""Generate BUILD_REPORT.md + stats.json from the built artifacts."""
import os, json, glob, yaml
from collections import Counter, defaultdict
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = {s["repo"]: s for s in yaml.safe_load(open(os.path.join(ROOT,"sources.yaml")))["sources"]}
cards = [yaml.safe_load(open(p)) for p in glob.glob(os.path.join(ROOT,"checks","**","*.yaml"), recursive=True)]
bench = json.load(open(os.path.join(ROOT,"bench","results.json"))) if os.path.exists(os.path.join(ROOT,"bench","results.json")) else {}
man = json.load(open(os.path.join(ROOT,"manifest.json")))

per_plat = Counter(p for c in cards for p in c["platforms"])
src_cards = Counter(s["repo"] for c in cards for s in c["sources"] if s["type"]=="github")
lic_out = defaultdict(Counter)
for s in SRC.values():
    mode = "tool-adapter" if s["ingest_mode"]=="tool" else "fixture" if s["ingest_mode"]=="fixture" else \
           "reference-only" if s["ingest_mode"] in ("reference","reference-only") or s["license"]=="NONE" else "derive"
    lic_out[mode][s["license"]] += 1
dom_plat = defaultdict(Counter)
for c in cards:
    for p in c["platforms"]:
        dom_plat[p][c["domain"]] += 1

L=[]
L.append(f"# BUILD_REPORT — secure-kb v{man['version']}\n")
L.append(f"Cards: **{len(cards)}** · Sources: **{len(SRC)}** · content_hash `{man['content_hash']}`\n")
L.append("## Cards by extraction / origin")
L.append("| extraction | cards |"); L.append("|---|---|")
for k,v in Counter(c["extraction"] for c in cards).most_common(): L.append(f"| {k} | {v} |")
L.append(f"\nOrigin: " + ", ".join(f"{k}={v}" for k,v in Counter(c["origin"] for c in cards).most_common()))
L.append(f"\nVerified: " + ", ".join(f"{k}={v}" for k,v in Counter(str(c["verified"]) for c in cards).most_common()))
L.append("\n## Cards by platform")
L.append("| platform | cards |"); L.append("|---|---|")
for p,n in per_plat.most_common(): L.append(f"| {p} | {n} |")
L.append("\n## Cards by severity / domain")
L.append("| severity | cards |"); L.append("|---|---|")
for k,v in Counter(c["severity"] for c in cards).most_common(): L.append(f"| {k} | {v} |")
L.append("\nDomains: " + ", ".join(f"{k}={v}" for k,v in Counter(c["domain"] for c in cards).most_common(12)))
L.append("\n## Coverage matrix (platform x domain, non-empty)")
L.append("| platform | domains |"); L.append("|---|---|")
for p in sorted(dom_plat): L.append(f"| {p} | " + ", ".join(f"{d}({n})" for d,n in dom_plat[p].most_common()) + " |")
L.append("\n## Source -> card counts (top 20)")
L.append("| source | cards |"); L.append("|---|---|")
for r,n in src_cards.most_common(20): L.append(f"| {r} | {n} |")
L.append(f"\nSources contributing 0 cards: " + ", ".join(sorted(set(SRC)-set(src_cards))[:40]))
L.append("\n## License outcomes")
L.append("| ingest outcome | licenses |"); L.append("|---|---|")
for mode, c in lic_out.items(): L.append(f"| {mode} | " + ", ".join(f"{k}={v}" for k,v in c.most_common()) + " |")
L.append("\n## Benchmark (frozen; expected = official refs)")
if bench:
    h=bench.get("heldout",{})
    L.append("| set | n | recall@5 | recall@10 | MRR | p50 ms |"); L.append("|---|---|---|---|---|---|")
    for key in ("all","curated","templated","user"):
        d=h.get(key,{})
        L.append(f"| {key} | {d.get('n','-')} | {d.get('recall@5','-')} | {d.get('recall@10','-')} | {d.get('mrr','-')} | {d.get('p50_ms','-')} |")
    lc=bench.get("lab_coverage",{})
    L.append(f"\nLab coverage: {lc.get('covered')}/{lc.get('classes')} classes ({lc.get('coverage_pct')}%); in fast gate {lc.get('in_fast_gate')} ({lc.get('gate_recall_pct')}%).")
L.append("\n## Known weaknesses")
L.append("- fix/detect fields on standards-derived cards are source pointers / heuristics, not extracted remediation.")
L.append("- domain inference is keyword-based; 'config' is over-assigned.")
L.append("- curated benchmark expected refs include pre-2023 WSTG codes and ASVS v4 numbering -> understated recall (benchmark defect).")
L.append("- authored platforms (telegram/desktop) have a single authoritative source -> confidence low.")
open(os.path.join(ROOT,"BUILD_REPORT.md"),"w").write("\n".join(L)+"\n")
json.dump({"cards":len(cards),"per_platform":dict(per_plat),"src_cards":dict(src_cards),
           "extraction":dict(Counter(c["extraction"] for c in cards)),"bench":bench},
          open(os.path.join(ROOT,"stats.json"),"w"), indent=1)
print("BUILD_REPORT.md written;", len(cards), "cards;", len(src_cards), "sources contribute")
print("by extraction:", dict(Counter(c["extraction"] for c in cards)))
