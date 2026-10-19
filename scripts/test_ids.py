#!/usr/bin/env python3
"""ID-scheme tests: unique ids, every alias resolves, ids are a function of source identity
(so they cannot change when merge decisions change)."""
import os, sys, re, json, glob, yaml, hashlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_CODE = {
 "OWASP/ASVS":"ASVS","OWASP/masvs":"MASVS","OWASP/mastg":"MASTG","OWASP/wstg":"WSTG",
 "OWASP/Top10":"TOP10","OWASP/API-Security":"API",
 "OWASP/www-project-top-10-for-large-language-model-applications":"LLM",
 "OWASP/CheatSheetSeries":"CS","OWASP/owasp-istg":"ISTG",
 "kadenzipfel/smart-contract-vulnerabilities":"SCV","crytic/not-so-smart-contracts":"NSSC",
 "raroque/vibe-security-skill":"VIBE","shieldfy/API-Security-Checklist":"APICHK",
 "yesmayank/secure-coding-baseline":"BASE","mgreiler/secure-code-review-checklist":"SCR",
}

def expected_id(repo, oid, path, anchor):
    code = SRC_CODE.get(repo, "GEN")
    if oid:
        slug = re.sub(r"[^A-Za-z0-9]+", "-", str(oid)).strip("-").upper()
        if slug.startswith(code + "-"): slug = slug[len(code) + 1:]
        return f"SKB-{code}-{slug}"[:80]
    h = hashlib.sha1(f"{repo}|{path}|{anchor}".encode()).hexdigest()[:10].upper()
    return f"SKB-{code}-{h}"

def main():
    cards = [yaml.safe_load(open(p)) for p in sorted(glob.glob(os.path.join(ROOT,"checks","**","*.yaml"), recursive=True))]
    ids = [c["id"] for c in cards]
    dup = [k for k, v in __import__("collections").Counter(ids).items() if v > 1]
    aliases = json.load(open(os.path.join(ROOT, "index", "aliases.json")))
    idset = set(ids)
    unresolved = [a for a, t in aliases.items() if t and t not in idset]
    # structural: id must equal the source-identity formula (authored cards exempt)
    mism = []
    for c in cards:
        if c.get("origin") == "authored": continue
        s = next((x for x in c["sources"] if x.get("type") == "github"), None)
        if not s: continue
        exp = expected_id(s["repo"], (c.get("owasp") or [None])[0], s["path"], s.get("anchor"))
        if c["id"] != exp and not re.match(r"^SKB-[A-Z]+-[0-9A-F]{10}$", c["id"]):
            mism.append((c["id"], exp))
    ok = True
    print(f"cards={len(cards)} unique_ids={len(set(ids))} duplicates={len(dup)}")
    print(f"aliases={len(aliases)} unresolved_targets={len(unresolved)}")
    print(f"id-formula mismatches (excl. collision-hash fallbacks): {len(mism)}")
    for m in mism[:5]: print("   ", m)
    if dup or unresolved or mism: ok = False
    print("ID TESTS:", "PASS" if ok else "FAIL")
    return 0 if ok else 1

if __name__ == "__main__": sys.exit(main())
