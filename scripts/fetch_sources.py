#!/usr/bin/env python3
"""Deterministic source fetch: download every provenance file at its PINNED commit.

List comes from sources_files.tsv (repo<TAB>commit<TAB>path). Files land in cache/ and are
never committed. Uses raw.githubusercontent.com (public, no auth, commit-pinned).
"""
import os, sys, urllib.request, urllib.parse, concurrent.futures
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(ROOT, "cache")
LIST = os.path.join(ROOT, "sources_files.tsv")

def _safe_join(base, *parts):
    """Join under `base`, refusing anything that would escape it.

    `repo` and `path` come from sources_files.tsv, so a `../` (typo, or a hostile edit in a PR)
    must not be able to write or read outside cache/.
    """
    target = os.path.normpath(os.path.join(base, *parts))
    root = os.path.abspath(base)
    if os.path.commonpath([root, os.path.abspath(target)]) != root:
        raise ValueError(f"refusing path outside {base}: {'/'.join(parts)}")
    return target

def dest(repo, path): return _safe_join(CACHE, repo.replace("/", "__"), path)

def fetch(row):
    repo, commit, path = row
    d = dest(repo, path)
    if os.path.exists(d) and os.path.getsize(d) > 0: return "cached"
    url = f"https://raw.githubusercontent.com/{repo}/{commit}/{urllib.parse.quote(path)}"
    try:
        os.makedirs(os.path.dirname(d), exist_ok=True)
        with urllib.request.urlopen(url, timeout=30) as r: data = r.read()
        tmp = d + ".part"
        with open(tmp, "wb") as f: f.write(data)
        os.replace(tmp, d)                      # never leave a half-written cache file behind
        return "ok"
    except Exception as e:
        return f"FAIL {str(e)[:50]}"

def main():
    rows = [tuple(l.split("\t")) for l in open(LIST).read().splitlines() if l.strip()]
    res = {"ok": 0, "cached": 0}
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        for r in ex.map(fetch, rows):
            res[r.split()[0]] = res.get(r.split()[0], 0) + 1
            if r.startswith("FAIL"): print("  ", r)
    print("fetch:", res, "of", len(rows))

if __name__ == "__main__": main()
