#!/usr/bin/env python3
"""Locate the secure-kb knowledge base and print its path.

Resolution order:
  1. $SECURE_KB_HOME
  2. a `secure-kb` executable on PATH (prints the repo root it belongs to)
  3. common clone locations (~/secure-kb, ./secure-kb, ../secure-kb, /opt/secure-kb)

Exit 0 and print the path, or exit 1 with a short message on stderr.
"""
import os, shutil, subprocess, sys
from pathlib import Path

MARKER = Path("cli") / "secure_kb.py"


def is_kb(p: Path) -> bool:
    return (p / MARKER).is_file() and (p / "manifest.json").is_file()


def from_env():
    v = os.environ.get("SECURE_KB_HOME")
    if v and is_kb(Path(v)):
        return Path(v).resolve()
    return None


def from_path():
    exe = shutil.which("secure-kb")
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "--help"], capture_output=True, text=True, timeout=15)
    except Exception:
        return None
    # a `secure-kb` wrapper usually resolves the repo; fall back to inspecting the script
    p = Path(exe).resolve()
    for cand in (p.parent, p.parent.parent):
        if is_kb(cand):
            return cand
    return None


def from_common():
    for c in (Path.home() / "secure-kb", Path.cwd() / "secure-kb",
              Path.cwd().parent / "secure-kb", Path("/opt/secure-kb"),
              Path(__file__).resolve().parents[3]):  # the repo this skill ships inside
        if is_kb(c):
            return c.resolve()
    return None


def main() -> int:
    for fn in (from_env, from_path, from_common):
        p = fn()
        if p:
            print(p)
            return 0
    print("secure-kb not found. Set SECURE_KB_HOME, or:\n"
          '  git clone https://github.com/pavnxet/ai-security-knowledge-base "$HOME/secure-kb"\n'
          '  export SECURE_KB_HOME="$HOME/secure-kb"', file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
