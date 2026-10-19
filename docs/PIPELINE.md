# PIPELINE.md — stage order (deterministic)

```
fetch (pinned commits)  -> cache/          scripts/fetch_sources.py        (sources_files.tsv)
ingest                  -> staging/        scripts/ingest_from_cache.py
normalize               -> (in ingest)     clean()/anchor/official_id
mapped-ref enrichment   -> (in build)      ASVS->CWE mapping, official ids   [NEVER heuristic here]
dedupe                  -> checks/         scripts/dedupe.py   (mapped refs + text ONLY)
heuristic tagging       -> checks/         build_cards_v2.py   (post-dedupe, NON-influencing)
kind                    -> checks/         (R1b)
priority                -> checks/         scripts/phase_d.py
gates                   -> profiles/       scripts/phase_d.py
index                   -> index/          scripts/build_index.py
manifest                -> manifest.json
```

## Invariants (enforced)
1. **IDs come from source identity** — `SKB-<SRC>-<official_id>`, else `SKB-<SRC>-<sha1(repo|path|anchor)[:10]>`.
   Never from merge winners or sequence numbers, so merge decisions cannot churn ids.
2. **Heuristic CWE tags never influence dedupe/clustering.** Dedupe uses only mapped refs
   (official ids, mapped CWE) + text similarity.
3. **Merged canonical id** = the member from the highest trust tier (tie → lexicographic source path).
   Every member id is recorded in the card's `aliases[]` and in `index/aliases.json`.
4. **Order independence** — staged items are sorted by (repo, path, anchor, official_id, raw_text)
   before id assignment; dedupe/glob inputs are sorted. Content hash is stable under shuffled input.
