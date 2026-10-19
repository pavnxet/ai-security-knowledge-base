#!/usr/bin/env python3
"""Expand short card data -> schema-valid YAML cards under checks/<platform>/<domain>/."""
import os, sys, json, yaml, datetime, re
sys.path.insert(0, os.path.dirname(__file__))
import cards_data_a, cards_data_b, cards_data_c

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TODAY = datetime.date.today().isoformat()

with open(os.path.join(ROOT, "sources.yaml")) as f:
    SRC = {s["id"]: s for s in yaml.safe_load(f)["sources"]}

ALL = cards_data_a.CARDS + cards_data_b.CARDS + cards_data_c.CARDS

def resolve_source(entry):
    if entry.startswith("repo:"):
        sid = entry[5:]
        s = SRC.get(sid)
        if not s:
            return None
        return {"repo": s["repo"], "path": None, "commit": s.get("commit"),
                "url": s["url"], "license": s["license"], "type": "github"}
    if entry.startswith("doc:"):
        rest = entry[4:]
        parts = rest.split("|")
        url = parts[0]; name = parts[1] if len(parts) > 1 else url
        lic = parts[2] if len(parts) > 2 else "Official-doc"
        return {"repo": name, "path": None, "commit": None, "url": url,
                "license": lic, "type": "official-doc"}
    return None

def expand(c):
    plat = c["plat"]
    srcs = [resolve_source(s) for s in c["src"]]
    srcs = [s for s in srcs if s]
    card = {
        "id": c["id"], "title": c["title"], "summary": c["summary"],
        "platforms": plat,
        "stacks": c.get("stacks", ["any"]),
        "domain": c["dom"],
        "phase": c.get("phase", ["pr-review", "pre-launch", "full-audit"]),
        "severity": c["sev"], "priority": c["pri"],
        "cwe": c.get("cwe", []), "owasp": c.get("owasp", []),
        "refs": c.get("refs", []),
        "check": c["check"], "fix": c["fix"],
        "detect": {"grep": c.get("grep", []), "files": c.get("files", []),
                   "semgrep_rules": c.get("semgrep", []), "tools": c.get("tools", [])},
        "verify_evidence": c.get("verify_evidence",
            "Cite the exact file:line or config value inspected to justify pass/fail, or mark unknown."),
        "tags": c.get("tags", []),
        "aliases": c.get("alias", []),
        "sources": srcs,
        "origin": c.get("origin", "distilled"),
        "confidence": c.get("conf", "medium"),
        "last_verified": TODAY,
    }
    if not card["refs"]:
        del card["refs"]
    if not card["detect"]["semgrep_rules"]:
        del card["detect"]["semgrep_rules"]
    if not card["detect"]["tools"]:
        del card["detect"]["tools"]
    if not card["aliases"]:
        del card["aliases"]
    return card

def est_tokens(card):
    """Full-card size estimate (provenance included)."""
    return len(json.dumps(card)) // 4

# Fields an agent actually reads to act. Provenance (id, sources, commit,
# license, origin, confidence, priority, last_verified) is NOT part of the
# 250-token payload budget - it is metadata the agent only needs for audit.
PAYLOAD_KEYS = ("title", "summary", "platforms", "domain", "severity",
                "cwe", "owasp", "check", "fix", "detect", "verify_evidence",
                "tags", "aliases")

def payload_tokens(card):
    return len(json.dumps({k: card[k] for k in PAYLOAD_KEYS if k in card})) // 4

def main():
    seen_ids, seen_titles = {}, {}
    errors, cards = [], []
    for c in ALL:
        card = expand(c)
        if card["id"] in seen_ids:
            errors.append(f"duplicate id {card['id']}")
        seen_ids[card["id"]] = card
        # limits
        if len(card["summary"]) > 140:
            errors.append(f"{card['id']}: summary {len(card['summary'])}>140")
        if payload_tokens(card) > 250:
            errors.append(f"{card['id']}: payload ~{payload_tokens(card)} tokens >250")
        if est_tokens(card) > 520:
            errors.append(f"{card['id']}: full card ~{est_tokens(card)} tokens >520")
        if not card["sources"]:
            errors.append(f"{card['id']}: no resolvable sources")
        cards.append(card)

    # write YAML
    outdir = os.path.join(ROOT, "checks")
    for card in cards:
        plat = card["platforms"][0]
        d = os.path.join(outdir, plat, card["domain"])
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, card["id"] + ".yaml"), "w") as f:
            yaml.safe_dump(card, f, sort_keys=False, allow_unicode=True, width=100)

    # validate with jsonschema
    try:
        import jsonschema
        with open(os.path.join(ROOT, "schema", "check.schema.json")) as f:
            schema = json.load(f)
        for card in cards:
            try:
                jsonschema.validate(card, schema)
            except jsonschema.ValidationError as e:
                errors.append(f"{card['id']}: schema {e.message[:80]}")
    except ImportError:
        print("WARN: jsonschema not installed; skipped schema validation")

    print(f"cards={len(cards)} errors={len(errors)}")
    for e in errors:
        print("  ERR:", e)
    from collections import Counter
    print("by platform:", dict(Counter(p for c in cards for p in c["platforms"])))
    print("by severity:", dict(Counter(c["severity"] for c in cards)))
    print("authored:", sum(1 for c in cards if c["origin"] == "authored"),
          "distilled:", sum(1 for c in cards if c["origin"] == "distilled"))
    if errors:
        sys.exit(1)

if __name__ == "__main__":
    main()
