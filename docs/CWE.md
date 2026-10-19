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
| held-out all r@5 | 0.662 | **0.708** ✅ |
| v2_dev r@5 | 0.250 | **0.600** ✅ |
| curated v2 r@5 | 0.441 | 0.492 |
| templated r@5 | 0.916 | 0.916 ✅ |
| fast-gate recall | 26.7% | **60.0%** |
| lab-class coverage | 73.3% | 96.7% |
