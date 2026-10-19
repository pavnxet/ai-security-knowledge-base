# ACCEPTANCE_v0.3.0.md

Branch `v0.3.0` (PR #2). **R0 (diagnostics) is DONE. R1–R4 are NOT STARTED this pass** — R0 is a
checkpoint and the brief says STOP and report. No merge, no tag, no visibility change.

## Status by sub-phase

| sub-phase | status | evidence |
|---|---|---|
| R0 diagnostics | **DONE** | this file (§1–§5) |
| R1 card kinds + deterministic guidance links | **NOT STARTED** | — |
| R2 retrieval + latency | **NOT STARTED** | — |
| R3 gates + real end-to-end | **NOT STARTED** | — |
| R4 close unverified items | **NOT STARTED** | — |

## 1. Failure taxonomy (frozen v1 + v2) — the "dilution" claim, quantified

`bench/r0.py`. Composition of the **top-5** cards by source, on missed queries:

| set | n | hit | rank of first correct (median / p90) | top-5 source mix on MISSED queries |
|---|---|---|---|---|
| curated v1 | 59 | 22 | 1 / 5 | **cheat-sheet 89, secure-coding-baseline 41**, ASVS 24, vibe 8 |
| curated v2 | 59 | 33 | 3 / 9 | **cheat-sheet 65, secure-coding-baseline 34**, authored 10, ASVS 6 |
| templated | 95 | 77 | 1 / 1 | **cheat-sheet 65**, ASVS 11, baseline 6 |

**Confirmed:** on missed queries the top-5 is dominated by **cheat-sheet guidance** and
**yesmayank `secure-coding-baseline`** cards, which outrank the correct standard card. This is the
dilution, and it directly motivates R1 (`kind=check` restriction).

## 2. Latency profile

| stage | p50 |
|---|---|
| in-process search | 37 ms |
| **`index/checks.jsonl` load** | **212 ms** |
| sqlite open + count | 14 ms |
| query expansion | 0.04 ms |
| cold CLI (process start incl.) | **443 ms** |

**The 76 ms reported earlier was mostly per-query re-scoring over ~2100 cards; the dominant one-off
cost is the 212 ms JSON load.** R2 must move to a single FTS5 query with `bm25()` + LIMIT and lazy
loads.

## 3. Heuristic-CWE audit → rule disabled

Sampled 100 of 356 heuristic tags; precision per rule (broader keyword sets after a first pass):

| rule | precision | kept? |
|---|---|---|
| CWE-639 object authz | 100% (8/8) | ✅ |
| CWE-22 path traversal | 100% (5/5) | ✅ |
| CWE-1021 clickjacking | 100% (4/4) | ✅ |
| CWE-307 brute force | 100% (3/3) | ✅ |
| CWE-79 XSS | 75% | ❌ disabled |
| CWE-89 SQLi | 75% | ❌ |
| CWE-502 deserialization | 75% | ❌ |
| CWE-78 command injection | 75% | ❌ |
| CWE-611 XXE | 67% | ❌ |
| CWE-915 mass assignment | 67% | ❌ |
| CWE-352 CSRF | 60% | ❌ |
| CWE-918 SSRF | 57% | ❌ |
| CWE-770 rate limit | 54% | ❌ |
| CWE-434 file upload | 33% | ❌ |

**Applied:** rules <80% disabled. Cards with a CWE fell **445 → 145** (heuristic **356 → 56**).

**Honest consequence (this is the important one):**

| metric | with all heuristics | after ≥80% prune |
|---|---|---|
| lab coverage (strict) | 96.7% | **73.3%** |
| fast-gate recall (strict) | 50.0% | **23.3%** |

So **most of the v0.2.1 coverage/gate gain came from low-precision tags** and is now correctly
removed. R3 must re-earn lab coverage with real `check` cards, not heuristic tags.

## 4. `bench/v2_dev` — new developer-vocabulary set

`bench/v2_dev/queries.yaml`: **40 questions** (target ≥40), written from standards text, expected =
official refs. **Freeze hash `ca75321344097e04`** (in `bench/v2_dev/FREEZE.txt`). 6 candidate
questions were **dropped as unanswerable** because their expected refs are not in the corpus
(CWE-942, API6:2023, MASTG-TEST-0047, CWE-284, CWE-916, CWE-601) — itself a corpus-gap signal.

**v2_dev recall@5 = 0.25** (n=40). Low; R2 targets ≥0.60.

## 5. Metric honesty — strict vs incl-heuristic

Lab coverage and gate recall are now reported **strict** (only mapped CWEs / official refs; heuristic
CWE tags excluded) as the primary number. Strict: coverage 73.3%, gate 23.3%. (Incl-heuristic would
read 96.7% / 50.0% — no longer used as the headline.)

## 6. Before / after table

| metric | v0.2.0 | v0.2.1 | v0.3.0 (R0) |
|---|---|---|---|
| cards | 832 | 2108 | 2108 |
| cards with CWE | 89 | 445 (356 heur.) | 145 (56 heur.) |
| held-out all recall@5 | 0.70 | 0.61 | **0.584** |
| curated v1 recall@5 | 0.31 | 0.32 | 0.271 |
| curated v2 recall@5 | 0.68* | 0.39 | 0.424 |
| v2_dev recall@5 | — | — | **0.25** |
| templated recall@5 | 0.95* | 0.79 | 0.779 |
| lab coverage (strict) | 36.7% | 96.7% (heur.) | **73.3%** |
| fast-gate recall (strict) | 20.0% | 50.0% (heur.) | **23.3%** |
| p50 latency | 24 ms | 76 ms | 62 ms |

\* v0.2.0 v2/templated were measured on an 832-card corpus and are not comparable.

## 7. Not done / open

- R1–R4: **NOT DONE**.
- `staging/` is gitignored and untracked; a branch switch deleted it, so cards must be rebuilt from
  the `scripts/ingest/` parsers + `/scratch/downloads` cache (a fragility to fix in R1).
- The CWE prune was applied as a post-process; `build_cards_v2.py` CWE_RULES now matches it, but the
  corpus was restored from git, not rebuilt.
