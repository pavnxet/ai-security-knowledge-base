#!/usr/bin/env python3
"""Summarise trufflehog JSONL. Documents the two known false-positive classes.
Report-only by design: gitleaks (context-aware) is the gating secret scanner in CI.
"""
import json, sys
ALLOWED = {"GitHubOauth2": "40-hex commit SHAs used as provenance in index/checks.jsonl",
           "Postgres": "documentation placeholder (user:password@host)"}
def main(path):
    rows = [json.loads(l) for l in open(path) if l.strip()] if len(sys.argv) > 1 else []
    from collections import Counter
    c = Counter(r.get("DetectorName") for r in rows)
    print("detectors:", dict(c))
    for d in c:
        print(f"  {d}: {'ALLOWED - ' + ALLOWED[d] if d in ALLOWED else 'REVIEW NEEDED'}")
    return 0
if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else ""))
