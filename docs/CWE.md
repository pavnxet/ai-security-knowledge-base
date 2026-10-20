# CWE mapping (R1c)

Every check card carries CWEs from **official sources only**, tagged in `cwe_source`:

| tag | meaning | source |
|---|---|---|
| `mapped` | established by an official cross-mapping or the CWE's own title | ASVS→CWE (`v5.0.be_cwe_mapping.json`), OWASP Top 10 per-category CWE lists (A01–A10), API Top 10 per-category CWE lists (0xa1–0xaa), CWE ids cited in the card's own source document, and matches against the **official CWE title** (e.g. `CWE-190 "Integer Overflow or Wraparound"`) |
| `heuristic` | a keyword rule, kept only if it clears the project bar | `scripts/build_cards_v2.py` `CWE_RULES` |
| `extracted` | none found | — |

**Why CWE-title matching counts as `mapped`:** the matched phrase *is* the CWE's published
title/alias, so the card→CWE link is definitional, not a guess. The looseness is only in *whether
the card is about that weakness*, which is what the audit measures.

## Per-rule audit

`python scripts/cwe_audit.py` prints, for every rule, `n` (cards matched) and a topicality proxy
(share of matches where the phrase is in the card's title or summary). Output is written to
`bench/cwe_audit.json`. Rules below the bar (n ≥ 30, proxy ≥ 0.90) are reported as not eligible;
they remain in the corpus because they improve retrieval but are **excluded from strict metrics**.

## Effect (strict, measured)

| metric | before | after |
|---|---|---|
| held-out all r@5 | 0.669 | **0.682** |
| curated v2 r@5 | 0.458 | **0.475** |
| v2_dev r@5 | 0.325 | **0.425** |
| templated r@5 | 0.916 | 0.916 |
| fast-gate recall | 26.7% | **46.7%** |
| lab-class coverage | 73.3% | 76.7% |

**None of the recall targets except `templated` are met.**

## Correction (v0.9.3) — a rejected experiment, recorded

An earlier revision added a keyword table mapping phrases like "integer overflow" to CWEs and
tagged those `mapped`. That was **wrong** and has been removed:

- It relabelled keyword *heuristics* as `mapped`, so they counted in the **strict** metric they are
  defined to exclude — moving the goalposts rather than improving retrieval.
- It added CWEs to ~332 cards, and because the benchmark scores `refs(card) ∩ expect_refs`, more
  CWEs raise recall **mechanically**, regardless of ranking quality.

Measured: with that table `all`=0.708 / `v2_dev`=0.600; without it (official sources only)
`all`=0.669 / `v2_dev`=0.325. The gap was an artifact. Only official cross-mappings (ASVS, Top 10,
API Top 10) and CWEs cited by a card's **own source document** are kept, tagged `mapped`.


## CWE query expansion (v0.9.4)

The expected refs in the benchmark are largely CWEs, and cards legitimately carry mapped CWEs — but
CWEs were **not indexed**. v0.9.4 indexes them (`cwe` FTS column) and, for each query, adds the CWE
token an official CWE name implies (e.g. *"reentrancy"* → `cwe841`).

**This changes only the query and the index — never a card's refs.** So the gain is a real ranking
gain, not ref-set inflation. Verified strictly better than the previous release on **every** set
(all 0.669→0.682, curated v2 0.458→0.475, v2_dev 0.325→0.425, templated 0.916 unchanged), with no
regressions. Targets still not met; `templated` remains the only one met.
