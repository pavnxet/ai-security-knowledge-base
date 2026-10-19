# ACCEPTANCE_v0.2.1.md — honest reconciliation

Scope: the v0.2.1 task (Phases 1–5) and the v0.2 §10 acceptance criteria.
Statuses are **DONE / PARTIAL / NOT DONE**. Nothing is softened. Counts are from the built repo.

## 0. Headline: what changed and what did not

| metric | v0.2.0 | v0.2.1 | direction |
|---|---|---|---|
| cards | 832 | **2108** | ↑ (Phase 2 finally done) |
| held-out recall@5 (all) | 0.70 | **0.61** | **↓ worse** |
| curated v2 recall@5 | 0.68 | **0.39** | **↓ worse** |
| templated recall@5 | 0.95 | **0.79** | **↓ worse** |
| lab coverage | 36.7% | **96.7%** | ↑ |
| fast-gate recall | 20.0% | **50.0%** | ↑ |
| p50 latency | 24 ms | **76 ms** | **↓ worse** |

**Adding the missing cards improved coverage and gate recall but DEGRADED held-out retrieval and
latency.** That is the central honest result of v0.2.1. The 834→832 drop the reviewer flagged was
because v0.2.1 *inherited* v0.2.0's corpus and only added CWE refs; the real ingestion happened now.

## 1. Criterion-by-criterion

| # | criterion | status | evidence | notes |
|---|---|---|---|---|
| P2.1 | ASVS = 346 | **DONE (345)** | see evidence box below | **The "346" was MY error.** The pinned commit's own files say 345. |
| P2.2 | Top 10 = 10 | **DONE** | staging = 10 (`A01..A10`) | was 9; glob `A0*` missed `A10`. Fixed. |
| P2.3 | API Top 10 = 10 | **DONE** | staging = 10 (`API1..API10`) | was 9; 10th file is `0xaa-…`. Fixed. |
| P2.4 | LLM Top 10 = 10 | **DONE** | staging = 10 (`LLM01..LLM10`) | was 9; `LLM00_Preface` dropped. Fixed. |
| P2.5 | MASVS controls | **DONE** | staging = 24 | unchanged from v0.2.0 |
| P2.6 | MASTG tests (complete) | **DONE** | staging = **92 / 92** | was 78 (capped at 8/group). Now all. |
| P2.7 | WSTG test cases | **DONE** | staging = 115 | checklist.json complete |
| P2.8 | CheatSheetSeries (all) | **DONE** | **137 / 137** sheets → 1045 items | was 21 sheets / 169 items. 4 sheets have no H2 → whole-sheet fallback. |
| P2.9 | Web3 / IoT ingestion | **DONE** | kadenzipfel 38, crytic 11, ISTG 19 | — |
| P2.10 | DevOps (sqreen) ingestion | **NOT DONE** | sqreen/DevOpsSecurityChecklist fetch failed (repo not fetchable) | reference-only; not retried |
| P2.11 | Tier-2 derive-licensed checklists | **DONE (3 of 8)** | shieldfy 13, yesmayank 447, mgreiler 8 = 468 items | ingested: MIT + Apache-2.0 + CC-BY-SA. **Skipped 5** (NOASSERTION → reference-only, no text derived): Az0x7, ahmed313x, tanprathan, MahdiMashrur, m14r41, virajkulkarni14, softwaresecured, RedHatInsights |
| P3.1 | Dedupe / merge | **DONE** | 133 merges, 202 borderline (`dedupe_report.md`) | — |
| P4.1 | Rule-based priority + gates | **DONE** | `docs/PRIORITY.md`; fast/standard/full | from v0.2.0 |
| P4.2 | Domain-balanced fast gate | **DONE** | quota 3/domain; web gate spans 9 domains | gate recall 20.0% → 23.3% (before CWE work) |
| P4.3 | Shards + `brief.tsv` | **DONE** | `index/by_platform/*.jsonl`, `index/brief.tsv` | — |
| P4.4 | `synonyms.yaml` + topic hubs | **DONE (implemented)** | `synonyms.yaml` (35 synonym groups + 10 hubs), wired into CLI+bench | **measured effect on frozen v2: −0.034 (0.424 → 0.390)** — NEGATIVE |
| P4.5 | Keyword enrichment / CWE tagging | **DONE** | rule-based CWE on cards: 89 → **445** (356 `heuristic`) | lab coverage 63.3→96.7, gate 23.3→50.0 |
| P4.6 | `fix_refs` (real remediation refs) | **NOT DONE** | `fix` remains a source pointer | not implemented |
| P4.7 | FTS retune at scale | **PARTIAL** | weights unchanged; p50 = **76 ms** at 2108 cards | **latency target (p50 < 50 ms) NOT met at scale** |
| P5.1 | Held-out ≥100 queries, official refs | **DONE** | `bench/heldout_queries.yaml` = 154 | — |
| P5.2 | Lab-coverage set | **DONE** | `bench/labs.yaml` (7 labs, 30 classes) | — |
| P5.3 | End-to-end set on ≥5 real apps | **PARTIAL** | fixture/lab-based, not live apps | gate recall reported (50.0%) |
| P5.4 | v2 freeze | **DONE** | `bench/heldout_queries_v2.yaml`, sha256 `3a96a207224ff8ce`, frozen **2026-10-19** | — |
| P5.5 | Retrieval change BEFORE freeze | **NONE** | v2 was built before any retrieval change | so v2's gain (v1 0.31 → v2 0.68 at 832 cards) is the **benchmark repair**, not retrieval |
| P5.6 | New dev-vocabulary queries ≥ 40 | **DONE** | curated set = **59** | — |
| P5.7 | Worst-15 + failures reported | **DONE** | `bench/results.json` | — |
| A1 | ≥95% programmatic/verified | **DONE** | 2093/2108 = **99.3%** programmatic | — |
| A2 | Standards represented | **DONE** | ASVS/MASVS/MASTG/WSTG/API/Top10/LLM/CheatSheets | — |
| A3 | No card from NONE-license repo | **DONE** | validate gate passes; ConsenSys cards removed | — |
| A4 | Benchmark honest + gate recall | **DONE** | this document + `BUILD_REPORT.md` | — |
| A5 | Latency/token targets | **PARTIAL** | p50 76 ms > 50 ms target | token budgets met (payload ≤250, AGENTS.md ≤1.5k) |
| A6 | v0.1 IDs resolve | **DONE** | `index/aliases.json`; 61 from-memory legacy cards absent from index | see §3 |

## 1a. ASVS 5.0 requirement-count evidence (cross-check at the pinned commit `2b47a9dd`)

Fetched from `OWASP/ASVS@2b47a9dd` (2026-10-19):

| source | statement / count |
|---|---|
| `5.0/en/0x03-What-is-the-ASVS.md` (official prose) | "The ASVS is made up of a total of **around 350 requirements** which are divided into 17 chapters" |
| `5.0/docs_en/…_en.flat.json` (authoritative machine-readable) | **345** requirements (L1 = 70, L2 = 183, L3 = 92) |
| `5.0/docs_en/…_en.csv` (authoritative machine-readable) | **345** data rows |

**Conclusion:** the official prose says "around 350"; the two machine-readable files agree on exactly **345**.
My earlier "346" was an arithmetic slip (347 CSV lines minus header = 346, but the CSV has a trailing newline, so 345 data rows). **345 is correct.**

## 2. Dedupe / merge reconciliation (adds up exactly)

| step | count |
|---|---|
| staged items | **2226** |
| + authored gap cards | +15 → 2241 |
| − dedupe merges | −133 |
| − license drops | −0 (ConsenSys removed in v0.2.0) |
| **= final cards** | **2108** |

Cards by origin: programmatic **2093**, authored **15**. Programmatic share of NON-authored cards:
**2093/2093 = 100%**.

## 3. Legacy cards excluded from default index/search/gates — proof

```
legacy v0.1 ids total: 76
overlapping ids in index: 15   (ALL origin=authored — the gap cards deliberately reuse v0.1 ids)
from-memory legacy cards ABSENT from index: 61
non-authored legacy ids present in index: 0
```
So the 61 hand-written `from-memory` cards are excluded; the 15 overlaps are the *authored* gap
cards (Telegram/browser-ext/desktop) that intentionally kept their v0.1 ids.

## 4. CWE enrichment effect (the one thing that clearly helped)

| metric | before | after |
|---|---|---|
| cards with CWE | 89 | 445 (356 heuristic, `cwe_source: heuristic`) |
| lab coverage | 63.3% | **96.7%** |
| fast-gate recall | 23.3% | **50.0%** |

Rule-based keyword→CWE tagging (e.g. "sql injection"→CWE-89). Marked `cwe_source: heuristic` so it
is never confused with extracted CWEs.

## 5. Lab-class misses (see `lab_miss_analysis.md`)

After enrichment: **15/30 classes still not in the fast gate** — mostly because the class's card is
ranked out of the top-25 gate (e.g. CWE-89 cards exist but sit below higher-priority auth/injection
cards), and a few corpus gaps remain (CWE-601 open-redirect, CWE-352 CSRF have no card carrying the ref).

## 6. Scanner allowlists

`.gitleaks.toml` (narrow — regex on the FP *shape*, no directory allowlists):
card-id regex `SKB-[A-Z0-9]+-[A-Z0-9]+-[0-9]{4}` + three detection-regex *literals*.
`.trufflehog-exclude.txt` = `.git/` only.
Two residual FP shapes (the canonical jwt.io example token; a `secret_key_base committed` doc phrase)
are handled by an explicit narrow filter `scripts/gitleaks_report.py`, **not** a broad allowlist.
**CI canary proves the scanner is not blinded:** a fake AWS key (`AKIA...ASDFGH (canary, redacted)`) makes
`gitleaks_report.py` exit 1. (The AWS *example* key `AKIAIOSFODNN7EXAMPLE` is allowlisted by
gitleaks' own defaults — which is why the canary uses a random key.)

## 7. Unverified items (unchanged from v0.2.1)

- **Tool adapters: 8/12 unverified** — zaproxy (README too thin), ggshield, apkleaks, mobsf, emba,
  helmet, secure_headers, tosint. Reason: not re-fetched against each README this pass (budget), not
  a network block. Verified: gitleaks, trufflehog, semgrep, dependency-check.
- **Telegram `secret_token` claim** — doc reachable; the parameter was not visible in the fetched excerpt.
- **Two project-declared licences** (OWASP/API-Security, OWASP/LLM Top 10).

## 8. Known weaknesses (not softened)

1. **Held-out retrieval regressed** with corpus growth (0.70 → 0.61). Cause: ~1300 added cheat-sheet
   rules dilute BM25; the correct card is pushed below near-duplicates. Dedupe-tighten and a
   bm25-dominant re-rank were tried and did **not** help (measured).
2. **Latency regressed** (24 → 76 ms) — above the 50 ms target at 2108 cards.
3. `synonyms.yaml` **hurt** v2 recall (−0.034).
4. `fix` fields are pointers, not remediation (`fix_refs` NOT DONE).
5. v2 expectations are standards-derived by a crude matcher and are themselves partly noisy.
