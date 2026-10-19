# Contributing to secure-kb

Thanks for helping. Two kinds of contribution are welcome: **new/improved cards** and **source
ingestion**.

## Ground rules

- **Defensive only.** A card says what to *verify* and how to *fix*. No working exploits, no payload
  lists, no wordlists.
- **Provenance is mandatory.** Every distilled card must carry `sources[].path + anchor + commit`
  pointing at the file the text came from. If you cannot point at a file, mark the card
  `origin: authored` with a verified official-doc URL, or do not add it.
- **One card per concept.** If a concept already exists, add your source to it (`sources[]`) rather
  than creating a duplicate. Dedupe runs in CI (`scripts/dedupe.py`).
- **Budget.** A card's agent-facing payload must stay ≤ 250 tokens; `summary` ≤ 140 chars. CI fails
  otherwise (`tests/validate.py`).

## Add a card

1. Drop a YAML file under `checks/<platform>/<domain>/SKB-*.yaml` (schema: `schema/check.schema.json`).
2. Run `python3 scripts/build_index.py && python3 scripts/phase_d.py && python3 scripts/build_index.py`.
3. Run the gates: `python3 tests/validate.py` (must pass) and `python3 bench/run_bench.py`.
4. Open a PR against `main`. CI must be green.

## Add a source

1. Add it to `sources.yaml` (url, license **read from the repo**, stars, archived, tier, ingest_mode).
   Sources with no licence are `reference-only` — **no text may be derived from them**.
2. Write a parser in `scripts/ingest/` that emits `staging/<source>.jsonl` with
   `source_repo, commit, path, anchor, raw_text, official_id`.
3. Register it in `scripts/build_cards_v2.py` (platform/domain mapping) and rebuild.

## Regenerate everything

```bash
python3 scripts/ingest/run_ingest.py      # staging (needs /scratch/repos/<repo> fetched)
python3 scripts/build_cards_v2.py
python3 scripts/build_authored.py
python3 scripts/dedupe.py
python3 scripts/build_index.py
python3 scripts/phase_d.py
python3 scripts/build_index.py
python3 tests/validate.py
python3 bench/run_bench.py
```

## Licensing of contributions

By contributing you agree your code is MIT and your content is CC BY-SA 4.0 (see `LICENSE` and
`LICENSES/CONTENT.md`). Do not paste text from a source that is not compatible with CC BY-SA 4.0.
