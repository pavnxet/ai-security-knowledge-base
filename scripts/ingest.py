#!/usr/bin/env python3
"""One-shot pipeline: rebuild every generated artifact from the card data + sources.

Order matters: sources.yaml -> cards -> profiles -> tools -> fixtures/references -> index -> notice -> benchmark.
Add --online to first refresh sources.yaml from the GitHub API (needs network + token).
"""
import os, sys, subprocess, argparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STEPS = ["build_cards", "build_profiles", "build_tools", "build_fixtures_refs",
         "build_index", "build_notice", "build_benchmark"]

def run(mod, args=()):
    print(f"\n== {mod} ==")
    r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", mod + ".py"), *args])
    if r.returncode != 0:
        print(f"STEP FAILED: {mod}", file=sys.stderr); sys.exit(1)

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--online", action="store_true")
    a = ap.parse_args()
    if a.online:
        run("refresh_sources")
    for s in STEPS:
        run(s)
    print("\n== validate ==")
    r = subprocess.run([sys.executable, os.path.join(ROOT, "tests", "validate.py")])
    sys.exit(r.returncode)

if __name__ == "__main__":
    main()
