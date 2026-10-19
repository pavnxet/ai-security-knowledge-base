#!/usr/bin/env python3
"""Gate gitleaks findings: fail on anything that is NOT a documented false-positive shape.

Kept as an explicit, narrow filter (rather than broad gitleaks allowlists) so the scanner is
provably not blinded -- see the CI canary step. Usage: gitleaks_report.py <report.json>
"""
import json, re, sys

# Exact false-positive SHAPES. Anything else fails.
FP_MATCH = [
    re.compile(r"SKB-[A-Z0-9]+-[A-Z0-9]+-[0-9]{4}"),        # card IDs
    re.compile(r"secret_key_base committed"),                # documentation phrase
    re.compile(r"AKIA\[0-9A-Z\]\{16\}"),                     # the AWS pattern literal, as written
    re.compile(r"-----BEGIN \.\*PRIVATE KEY-----"),          # the key pattern literal, as written
]
FP_SECRET = [
    re.compile(r"^eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),   # the canonical jwt.io example token
]

def main(path):
    rows = json.load(open(path)) if path else []
    bad = []
    for r in rows:
        m, s = r.get("Match", ""), r.get("Secret", "")
        if any(p.search(m) for p in FP_MATCH) or any(p.search(s) for p in FP_SECRET):
            continue
        bad.append(r)
    print(f"gitleaks: {len(rows)} findings, {len(bad)} outside documented FP shapes")
    for r in bad[:10]:
        print(f"  FAIL {r.get('RuleID')} {r.get('File')}: {r.get('Secret')!r}")
    sys.exit(1 if bad else 0)

if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else ""))
