#!/usr/bin/env python3
"""Regression gate: fail CI if held-out recall drops below a floor.

Floors are set just below the current measured values so a *regression* fails the build
without failing on the honest beta numbers. Update deliberately when metrics improve.
"""
import os, sys, json, subprocess
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FLOORS = {"all": 0.60, "templated": 0.85, "curated_v2": 0.38}

def evaluate(results, floors=FLOORS):
    """Return the list of gate failures for a results document (pure, so it can be unit tested)."""
    h = (results or {}).get("heldout", {})
    bad = []
    for k, floor in floors.items():
        v = h.get(k, {}).get("recall@5")
        if v is None: bad.append(f"{k}: metric missing")
        elif v < floor: bad.append(f"{k} recall@5 {v} < floor {floor}")
    return bad


def main():
    run = subprocess.run([sys.executable, os.path.join(ROOT, "bench", "run_bench.py")],
                         capture_output=True, text=True)
    if run.returncode != 0:
        # Reading results.json after a crashed run would grade yesterday's numbers and pass.
        print("benchmark run failed; refusing to grade stale results.json")
        print((run.stderr or run.stdout or "")[-2000:])
        sys.exit(1)
    try:
        d = json.load(open(os.path.join(ROOT, "bench", "results.json")))
    except Exception as e:
        print("could not read bench/results.json:", e); sys.exit(1)
    bad = evaluate(d)
    if bad:
        print("REGRESSION GATE FAILED:"); [print("  -", b) for b in bad]; sys.exit(1)
    print("benchmark regression gate OK:",
          {k: d["heldout"][k]["recall@5"] for k in FLOORS})


if __name__ == "__main__":
    main()
