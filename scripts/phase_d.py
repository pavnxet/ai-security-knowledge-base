#!/usr/bin/env python3
"""Phase D: rule-based priority, regenerated gates (fast/standard/full), shards + brief.tsv.

Priority formula (documented in docs/PRIORITY.md):
  base(severity) + top10_member*15 + cwe_top25*10 + min(corroboration-1,3)*5 + tier1_ref*10
"""
import os, json, glob, yaml, datetime, importlib.util
_spec=importlib.util.spec_from_file_location('bp', os.path.join(os.path.dirname(os.path.abspath(__file__)),'build_profiles.py'))
_bp=importlib.util.module_from_spec(_spec); _spec.loader.exec_module(_bp)
FINGERPRINTS=_bp.FINGERPRINTS
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = {"critical":60,"high":45,"medium":30,"low":15,"info":5}
CWE_TOP25 = {"CWE-79","CWE-89","CWE-352","CWE-862","CWE-787","CWE-22","CWE-78","CWE-94","CWE-287",
 "CWE-434","CWE-476","CWE-502","CWE-190","CWE-798","CWE-416","CWE-306","CWE-362","CWE-918","CWE-77",
 "CWE-732","CWE-611","CWE-119","CWE-943","CWE-125","CWE-400"}
TIER1 = ("ASVS:","MASVS-","MASTG-","WSTG-","Top10:","API","LLM","CS:","SCBP:","SCV:")
PLATFORMS = ["web","api","mobile","android","ios","telegram","cloud","iot","web3","llm","vibe","browser-ext","desktop"]

def compute(c):
    p = BASE.get(c["severity"], 30)
    if any(str(o).startswith("Top10:") or str(o).startswith("API") or str(o).startswith("LLM") for o in c.get("owasp", [])):
        p += 15
    if set(c.get("cwe", [])) & CWE_TOP25:
        p += 10
    p += min(max(c.get("corroboration", 1) - 1, 0), 3) * 5
    if any(str(o).startswith(TIER1) for o in c.get("owasp", [])):
        p += 10
    return max(1, min(100, p))

def _balanced(cards, limit, quota):
    """Round-robin across domains so the fast gate is not all one domain."""
    from collections import Counter
    seen = Counter(); out = []
    for c in cards:                      # already priority-sorted
        if seen[c["domain"]] < quota:
            out.append(c["id"]); seen[c["domain"]] += 1
        if len(out) >= limit: break
    if len(out) < limit:                 # fill remaining if quota left gaps
        have = set(out)
        for c in cards:
            if c["id"] not in have:
                out.append(c["id"]); have.add(c["id"])
            if len(out) >= limit: break
    return out

def main():
    files = glob.glob(os.path.join(ROOT, "checks", "**", "*.yaml"), recursive=True)
    cards = []
    for p in files:
        c = yaml.safe_load(open(p, encoding="utf-8")); c["priority"] = compute(c); c["_p"] = p
        yaml.safe_dump({k: v for k, v in c.items() if k != "_p"}, open(p, "w", encoding="utf-8"),
                       sort_keys=False, allow_unicode=True, width=100)
        cards.append(c)
    cards.sort(key=lambda c: (-c["priority"], c["id"]))

    # shards + brief.tsv
    idx = os.path.join(ROOT, "index"); sh = os.path.join(idx, "by_platform"); os.makedirs(sh, exist_ok=True)
    with open(os.path.join(idx, "brief.tsv"), "w") as f:
        f.write("id\tseverity\tpriority\ttitle\n")
        for c in cards:
            f.write(f"{c['id']}\t{c['severity']}\t{c['priority']}\t{c['title'][:100]}\n")
    for plat in PLATFORMS + ["generic"]:
        sel = [c for c in cards if plat in c["platforms"]]
        with open(os.path.join(sh, plat + ".jsonl"), "w") as f:
            for c in sel:
                f.write(json.dumps({"id": c["id"], "severity": c["severity"], "priority": c["priority"],
                                    "title": c["title"], "check": c["check"]}, ensure_ascii=False) + "\n")

    # profiles with three gates
    for plat in PLATFORMS + ["generic"]:
        sel = [c for c in cards if plat in c["platforms"] or "generic" in c["platforms"]]
        prof = {"name": plat, "description": f"Security launch gate for {plat} targets.",
                "platforms": [plat],
                "detect": FINGERPRINTS.get(plat, {"files": [], "signals": []}),
                "gate": {"fast": _balanced(sel, 25, 3),
                         "standard": [c["id"] for c in sel][:100],
                         "full": [c["id"] for c in sel]},
                "counts": {"fast": min(25, len(sel)), "standard": min(100, len(sel)), "full": len(sel)}}
        yaml.safe_dump(prof, open(os.path.join(ROOT, "profiles", plat + ".yaml"), "w"),
                       sort_keys=False, allow_unicode=True, width=100)

    # playbooks by phase
    pb = os.path.join(ROOT, "playbooks"); os.makedirs(pb, exist_ok=True)
    for name, sel in [("quick-25", cards[:25]),
                      ("pr-review", [c for c in cards if "pr-review" in c["phase"]]),
                      ("pre-launch", [c for c in cards if "pre-launch" in c["phase"]]),
                      ("full-audit", cards)]:
        yaml.safe_dump({"name": name, "description": name, "checks": [c["id"] for c in sel], "count": len(sel)},
                       open(os.path.join(pb, name + ".yaml"), "w"), sort_keys=False, width=100)

    # docs/PRIORITY.md
    os.makedirs(os.path.join(ROOT, "docs"), exist_ok=True)
    open(os.path.join(ROOT, "docs", "PRIORITY.md"), "w").write(f"""# Priority formula

`priority` is computed from the card's own attributes - no hand-tuned magic numbers.

```
priority = base(severity)
         + 15  if the card maps to an OWASP Top 10 / API Top 10 / LLM Top 10 entry
         + 10  if any CWE is in the CWE Top 25 (2024)
         + 5 * min(corroboration - 1, 3)      # independent sources, capped at +15
         + 10  if the card carries a Tier-1 standard ref (ASVS/MASVS/MASTG/WSTG/Top10/API/LLM/CheatSheet)
clamped to 1..100
```

base: critical 60, high 45, medium 30, low 15, info 5.

Severity itself is derived (see build_cards_v2.py): domains auth/injection/access-control/crypto/
secrets/deserialization/ssrf/smart-contract/firmware are high; the OWASP/API/LLM #1 entries and
ASVS L1 critical-domain requirements are critical.

Gates: `fast` = top 25 by priority; `standard` = top 100; `full` = all.
Counts: {dict(Counter(c['severity'] for c in cards))} by severity; {len(cards)} cards total.
""")
    print("cards:", len(cards))
    print("priority buckets:", dict(Counter((c["priority"]//10)*10 for c in cards)))
    print("profiles regenerated; shards:", len(glob.glob(os.path.join(sh,'*.jsonl'))))

if __name__ == "__main__":
    main()
