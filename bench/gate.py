#!/usr/bin/env python3
"""Regression gate: fail CI if held-out recall drops below a floor.

Floors are set just below the current measured values so a *regression* fails the build
without failing on the honest beta numbers. Update deliberately when metrics improve.
"""
import os, sys, json, subprocess
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FLOORS = {"all": 0.60, "templated": 0.85, "curated_v2": 0.38}

out = subprocess.run([sys.executable, os.path.join(ROOT, "bench", "run_bench.py")],
                     capture_output=True, text=True)
try:
    d = json.load(open(os.path.join(ROOT, "bench", "results.json")))
except Exception as e:
    print("could not read bench/results.json:", e); sys.exit(1)

h = d.get("heldout", {})
bad = []
for k, floor in FLOORS.items():
    v = h.get(k, {}).get("recall@5")
    if v is None: bad.append(f"{k}: metric missing")
    elif v < floor: bad.append(f"{k} recall@5 {v} < floor {floor}")
if bad:
    print("REGRESSION GATE FAILED:"); [print("  -", b) for b in bad]; sys.exit(1)
print("benchmark regression gate OK:", {k: h[k]["recall@5"] for k in FLOORS})
