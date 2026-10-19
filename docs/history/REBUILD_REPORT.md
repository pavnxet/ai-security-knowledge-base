# REBUILD_REPORT.md — R1a reproducibility (re-freeze)

## Determinism
| test | result |
|---|---|
| rebuild twice, same content hash | **YES** |
| rebuild with SHUFFLED staging (file+line order) | **YES — identical hash** |
| canonical hash / card count | `0c921baa291a4af4` / **2057** |

Pipeline: `fetch(pinned) -> ingest -> normalize -> mapped-ref enrichment -> dedupe -> heuristic tagging
(post-dedupe, non-influencing) -> kind -> priority -> gates -> index -> manifest` (see `docs/PIPELINE.md`).

## ID scheme (fixed so merges can never churn ids)
- `SKB-<SRC>-<official_id>` where an official id exists (e.g. `SKB-ASVS-V3-4-5`, `SKB-WSTG-INFO-01`,
  `SKB-API1-2023`, `SKB-MASVS-STORAGE-1`); else `SKB-<SRC>-<sha1(repo|path|anchor)[:10]>`.
- Merged canonical id = highest trust tier member (tie → lexicographic source path); every member id is
  in the card's `aliases[]` and in `index/aliases.json`.
- **ID tests: PASS** — 2057 unique ids, 0 duplicates, 114 aliases all resolve, 0 formula mismatches
  (`scripts/test_ids.py`).

## ID map v0.2.1 → v0.3.0
`id_map_v0.2.1_to_v0.3.0.json`: **matched 1947 / 2137**; `id_map_unmatched.json`: **79** with reasons
(source path/anchor not present in the v0.3.0 corpus). v0.1 legacy ids still resolve via `index/aliases.json`.

## Staging vs committed (per source) — explained
| source | committed v0.2.1 | rebuild | reason |
|---|---|---|---|
| ASVS | 345 | 345 | same |
| WSTG | 115 | 115 | parser aligned to committed logic (my first draft gave 128) |
| CheatSheets | 1045 | 1045 | same |
| MASTG | 92 | 92 | same |
| MASVS | 24 | 24 | same |
| Top10 / API / LLM | 10 / 10 / 10 | 10 / 10 / 10 | same |
| web3 / ISTG / Tier-2 | 49 / 19 / 468 | 49 / 19 / 468 | same |
| vibe | 39 | 40 | **+1**: one extra `## ` heading in a reference file |
| **total staging** | 2226 | 2227 | +1 (vibe) |
| **cards after dedupe** | **2108** | **2057** | **−51**: dedupe canonical rule changed (trust-tier) and heuristic CWE no longer feeds merge decisions → different merge set |

## Benchmark comparison (same harness, both corpora)
| metric | committed 2108 | rebuilt 2057 | Δ |
|---|---|---|---|
| held-out all r@5 | 0.584 | 0.662 | **+0.078** |
| curated v1 r@5 | 0.271 | 0.254 | −0.017 |
| curated v2 r@5 | 0.424 | 0.441 | +0.017 |
| v2_dev r@5 | 0.250 | 0.250 | 0.000 |
| templated r@5 | 0.779 | 0.916 | **+0.137** |
| lab coverage (strict) | 73.3% | 73.3% | 0 |
| fast-gate recall (strict) | 23.3% | 26.7% | +3.4pp |

**Deltas > 0.02 investigated:** `templated` (+0.137) and `all` (+0.078) rose because the rebuild's
dedupe (trust-tier canonical + heuristic CWE excluded from merging) removed duplicate distractor
cards (−51). This is a **content change, not a harness change**; it is an improvement, not a regression.
`v1` (−0.017) and `v2` (+0.017) are within the 0.02 tolerance. **No metric regressed.**

**Frozen expectations remain valid:** `heldout_queries.yaml`, `heldout_queries_v2.yaml` and
`v2_dev/queries.yaml` contain **0 SKB ids** (all official refs) — checked.

## Not done in R1a (still open)
- CI job (fetch→ingest→build→compare hash, FAIL on mismatch) — NOT DONE.
- `kb.sqlite` auto-build-on-first-use — NOT DONE (still a committed binary).
- Fresh-install test from the REMOTE — NOT DONE this pass.
