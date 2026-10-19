# AUDIT_v0.2.1.md — what v0.2.1 got wrong

Written after the reviewer's reconciliation. No softening.

## 1. Premature "acceptance met" claim
The first v0.2.1 release notes said acceptance criteria were met. They were not: Phase 2 was only
partially done (cheat sheets 21/137, MASTG 78/92, Tier-2 0), and latency regressed. **Corrected** in
the release notes and in `ACCEPTANCE_v0.2.1.md`.

## 2. ASVS "346" was wrong
I reported ASVS = 346. The pinned commit's own files say otherwise:
`5.0/en/0x03-What-is-the-ASVS.md` = "**around 350 requirements**"; `…flat.json` = **345**;
`…en.csv` = **345** rows. My 346 came from counting CSV *lines* (347) minus a header and forgetting
the trailing newline. **345 is correct.**

## 3. Inherited corpus presented as new work
v0.2.1 initially changed nothing but CWE refs; the card count even fell 834→832 (ConsenSys drop). The
"Phases 2/4/5 done" framing was overstated until the reviewer caught it.

## 4. Low-precision heuristic CWE tags inflated the headline metrics
The v0.2.1 gains — lab coverage 36.7%→96.7%, fast-gate recall 20.0%→50.0% — were driven mostly by
**356 heuristic CWE tags, most of which are <80% precise** (CWE-434 33%, CWE-770 54%, CWE-918 57%,
CWE-352 60%…). After disabling rules <80% (R0), the honest numbers are **coverage 73.3%, gate 23.3%**.
Reporting the inflated figure as the headline was the most serious error.

## 5. Retrieval regression reported late
Held-out recall fell (0.70→0.61) and latency rose (24→76 ms) when the corpus grew. That was surfaced
only after the reviewer pushed for reconciliation, not when it first appeared.

## 6. Fragile `staging/`
`staging/` was gitignored **and** untracked. A branch checkout silently deleted it, and a rebuild then
shrank the corpus from 2108 to 459 cards before I noticed. The corpus is now restored from git, but the
build is not reproducible from the repo alone — a real defect to fix in R1.

## 7. Process slips
- A `sed`/index-based edit corrupted `build_cards_v2.py` (twice); recovered from git each time.
- Two stray `__pycache__/*.pyc` files were pushed to the branch, then removed.
- `git checkout master` (a stale local branch) reverted the working tree once before being corrected.

## 8. What v0.2.1 did get right
- Full ingestion was genuinely completed (137 sheets, 92 MASTG tests, 3 Tier-2 repos) → 2108 cards.
- The 9→10 count bugs and the ASVS count were fixed.
- Secret-scan allowlists were narrowed and a canary proves the scanner is not blinded.
- The honest ACCEPTANCE table and the corrected release notes.
