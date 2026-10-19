#!/usr/bin/env python3
"""Build /index: checks.jsonl, by_*.json, router.json, kb.sqlite (FTS5), manifest.json."""
import os, glob, json, yaml, sqlite3, hashlib, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IDX = os.path.join(ROOT, "index")
os.makedirs(IDX, exist_ok=True)

def load_cards():
    out = []
    for p in sorted(sorted(glob.glob(os.path.join(ROOT, "checks", "**", "*.yaml"), recursive=True))):
        with open(p) as f:
            out.append(yaml.safe_load(f))
    return out

def main():
    cards = load_cards()
    byid = {c["id"]: c for c in cards}

    # checks.jsonl (full cards, one per line)
    with open(os.path.join(IDX, "checks.jsonl"), "w") as f:
        for c in cards:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")

    def invert(keyfn):
        m = {}
        for c in cards:
            for k in keyfn(c):
                m.setdefault(k, []).append(c["id"])
        return {k: sorted(v) for k, v in sorted(m.items())}

    maps = {
        "by_tag.json": invert(lambda c: c.get("tags", [])),
        "by_cwe.json": invert(lambda c: c.get("cwe", [])),
        "by_platform.json": invert(lambda c: c.get("platforms", [])),
        "by_domain.json": invert(lambda c: [c["domain"]]),
        "by_severity.json": invert(lambda c: [c["severity"]]),
        "by_ref.json": invert(lambda c: [r for r in c.get("owasp", []) if ":" in r] + c.get("refs", [])),
    }
    for name, m in maps.items():
        with open(os.path.join(IDX, name), "w") as f:
            json.dump(m, f, indent=0, ensure_ascii=False)

    # router.json from profile fingerprints
    router = {"files": {}, "signals": {}}
    for pf in glob.glob(os.path.join(ROOT, "profiles", "*.yaml")):
        with open(pf) as f:
            prof = yaml.safe_load(f)
        name = prof["name"]
        for g in prof.get("detect", {}).get("files", []):
            router["files"].setdefault(g, []).append(name)
        for s in prof.get("detect", {}).get("signals", []):
            router["signals"].setdefault(s, []).append(name)
    with open(os.path.join(IDX, "router.json"), "w") as f:
        json.dump(router, f, indent=1)

    # SQLite FTS5
    db = os.path.join(IDX, "kb.sqlite")
    if os.path.exists(db):
        os.remove(db)
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE checks (id TEXT PRIMARY KEY, severity TEXT, priority INT, platform TEXT, domain TEXT, json TEXT)")
    con.execute("CREATE VIRTUAL TABLE checks_fts USING fts5(id UNINDEXED, title, summary, tags, aliases, check)")
    for c in cards:
        con.execute("INSERT INTO checks VALUES (?,?,?,?,?,?)",
                    (c["id"], c["severity"], c["priority"], c["platforms"][0], c["domain"], json.dumps(c)))
        con.execute("INSERT INTO checks_fts VALUES (?,?,?,?,?,?)",
                    (c["id"], c["title"], c["summary"], " ".join(c.get("tags", [])),
                     " ".join(c.get("aliases", [])), c["check"]))
    con.commit(); con.close()

    # manifest
    h = hashlib.sha256(open(os.path.join(IDX, "checks.jsonl"), "rb").read()).hexdigest()[:16]
    from collections import Counter
    manifest = {
        "name": "secure-kb", "version": "0.2.1",
        "build_date": datetime.date.today().isoformat(),
        "content_hash": h,
        "cards": len(cards),
        "by_platform": dict(Counter(p for c in cards for p in c["platforms"])),
        "by_severity": dict(Counter(c["severity"] for c in cards)),
        "authored": sum(1 for c in cards if c["origin"] == "authored"),
        "distilled": sum(1 for c in cards if c["origin"] == "distilled"),
        "sources": len(yaml.safe_load(open(os.path.join(ROOT, "sources.yaml")))["sources"]),
        "index_files": sorted(os.path.basename(p) for p in glob.glob(os.path.join(IDX, "*"))),
    }
    with open(os.path.join(ROOT, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    print(json.dumps({k: manifest[k] for k in ("version","content_hash","cards","authored","distilled","sources")}, indent=0))
    print("index files:", manifest["index_files"])

if __name__ == "__main__":
    main()
