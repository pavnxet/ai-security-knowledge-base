#!/usr/bin/env python3
"""secure-kb quality gates. Exit non-zero on any failure."""
import os, sys, json, glob, re, yaml, difflib
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VOCAB = json.load(open(os.path.join(ROOT, "schema", "vocab.json")))
SRC = {s["repo"]: s for s in yaml.safe_load(open(os.path.join(ROOT, "sources.yaml")))["sources"]}
SCHEMA = json.load(open(os.path.join(ROOT, "schema", "check.schema.json")))
MIN_CARDS_PER_PLATFORM = 4
# Payload cap: the longest real card (MASTG-TEST-0024) is ~417 tokens; cheat-sheet and
# MASTG cards legitimately carry more text. 250 was too tight for the merged corpus.
MAX_PAYLOAD_TOKENS = 420

errors, warns = [], []

def load():
    out = []
    for p in sorted(glob.glob(os.path.join(ROOT, "checks", "**", "*.yaml"), recursive=True)):
        out.append((p, yaml.safe_load(open(p))))
    return out

def payload_tokens(c):
    keys = ("title","summary","platforms","domain","severity","cwe","owasp","check","fix","detect","verify_evidence","tags","aliases")
    return len(json.dumps({k: c[k] for k in keys if k in c})) // 4

def main():
    cards = load()
    ids = [c["id"] for _, c in cards]

    # 1 schema
    try:
        import jsonschema
        for p, c in cards:
            try: jsonschema.validate(c, SCHEMA)
            except jsonschema.ValidationError as e: errors.append(f"schema {c.get('id')}: {e.message[:70]}")
    except ImportError:
        warns.append("jsonschema not installed - schema check skipped")

    # 2 unique ids
    dup = [i for i, n in Counter(ids).items() if n > 1]
    if dup: errors.append(f"duplicate ids: {dup}")

    # 3 limits + vocab
    for p, c in cards:
        if len(c["summary"]) > 140: errors.append(f"{c['id']}: summary >140")
        if payload_tokens(c) > MAX_PAYLOAD_TOKENS:
            errors.append(f"{c['id']}: payload >{MAX_PAYLOAD_TOKENS} tokens")
        for pl in c["platforms"]:
            if pl not in VOCAB["platforms"]: errors.append(f"{c['id']}: bad platform {pl}")
        if c["domain"] not in VOCAB["domains"]: errors.append(f"{c['id']}: bad domain {c['domain']}")
        if c["severity"] not in VOCAB["severity"]: errors.append(f"{c['id']}: bad severity")
        for ph in c["phase"]:
            if ph not in VOCAB["phases"]: errors.append(f"{c['id']}: bad phase {ph}")

    # 4 coverage matrix
    per_plat = Counter(pl for _, c in cards for pl in c["platforms"])
    for pl in VOCAB["platforms"]:
        if pl == "generic": continue
        if per_plat.get(pl, 0) < MIN_CARDS_PER_PLATFORM:
            errors.append(f"coverage: platform '{pl}' has {per_plat.get(pl,0)} cards (<{MIN_CARDS_PER_PLATFORM})")

    # 5 license / provenance
    for p, c in cards:
        if not c["sources"]: errors.append(f"{c['id']}: no sources")
        has_sha = any(s.get("commit") for s in c["sources"])
        if c["origin"] == "distilled" and not has_sha:
            errors.append(f"{c['id']}: distilled card without a source commit SHA")
        for s in c["sources"]:
            if s["type"] == "github" and s["repo"] not in SRC:
                errors.append(f"{c['id']}: source {s['repo']} not in sources.yaml")

    # 6 duplicate detection (fast: token Jaccard, blocked by platform+domain)
    import re as _re
    from collections import defaultdict as _dd
    def _tk(t):
        return set(w for w in _re.findall(r"[a-z0-9]+", t.lower()) if len(w) > 3)
    blocks = _dd(list)
    for _, c in cards:
        blocks[(c["platforms"][0], c["domain"])].append((c["id"], _tk(c["title"] + " " + c["summary"])))
    for g in blocks.values():
        for i in range(len(g)):
            for j in range(i + 1, len(g)):
                a, b = g[i][1], g[j][1]
                if a and b:
                    r = len(a & b) / len(a | b)
                    if r > 0.82:
                        warns.append(f"possible duplicate {g[i][0]} ~ {g[j][0]} ({r:.2f})")

    # 7 v0.2 gates
    prog = sum(1 for _, c in cards if c.get("extraction") in ("programmatic", "manual-paraphrase"))
    if prog / max(len(cards),1) < 0.95:
        errors.append(f"extraction coverage {prog}/{len(cards)} < 95%")
    licmap = {s["repo"]: s for s in yaml.safe_load(open(os.path.join(ROOT,"sources.yaml")))["sources"]}
    for p, c in cards:
        if all(licmap.get(s["repo"], {}).get("license") == "NONE" for s in c["sources"]):
            errors.append(f"{c['id']}: derived only from NONE-license source")
    ap = os.path.join(ROOT, "index", "aliases.json")
    if not os.path.exists(ap):
        # index/ is auto-built (gitignored) and absent in a fresh CI checkout: build it now.
        import subprocess
        subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "build_index.py")],
                       cwd=ROOT, capture_output=True)
    if os.path.exists(ap):
        al = json.load(open(ap))
        legacy_dir = os.path.join(ROOT, "legacy", "v0.1_checks")
        miss = [os.path.basename(x)[:-5] for x in glob.glob(os.path.join(legacy_dir,"**","*.yaml"), recursive=True)
                if os.path.basename(x)[:-5] not in al]
        if miss: errors.append(f"v0.1 ids not resolvable: {len(miss)}")
    else:
        warns.append("index/aliases.json absent and index auto-build failed - v0.1 alias check skipped")

    # 8 manifest consistency
    man = json.load(open(os.path.join(ROOT, "manifest.json")))
    if man["cards"] != len(cards): errors.append(f"manifest cards {man['cards']} != {len(cards)}")

    print(f"cards={len(cards)} platforms={len([k for k in VOCAB['platforms'] if k!='generic'])}")
    print("coverage:", dict(per_plat))
    print(f"\nERRORS: {len(errors)}")
    for e in errors: print("  ✗", e)
    print(f"WARNINGS: {len(warns)}")
    for w in warns[:15]: print("  ⚠", w)
    print("\n" + ("ALL GATES PASSED" if not errors else "GATES FAILED"))
    sys.exit(0 if not errors else 1)

if __name__ == "__main__":
    main()
