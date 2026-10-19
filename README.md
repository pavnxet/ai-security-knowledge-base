# secure-kb

**An AI-agent-searchable security verification knowledge base.**
2,057 atomic check cards distilled from 67 public security repositories — each traceable to a real
file, anchor and commit.

> **Status: public beta (v0.9.0).** The build is deterministic and reproducible; retrieval targets are
> **not yet met**, so this is deliberately not v1.0.0. See [Benchmarks](#benchmarks) and
> [Known limitations](#known-limitations).

[**Website →**](https://pavnxet.github.io/awesome-vulnerability-tests/) ·
[Releases](https://github.com/pavnxet/awesome-vulnerability-tests/releases) ·
[Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

---

## What it is — and what it is not

**It is** a retrieval layer for AI agents: a merged, normalised corpus of security *checks* with
provenance, a platform router, a fast gate, and a zero-dependency SQLite FTS5 index.

**It is not** a scanner, and it does not replace a professional security audit. It tells an agent
*what to verify*; tool adapters only describe how to invoke external scanners.

## Install in 60 seconds

Zero required dependencies (standard-library Python only). `index/` and `index/kb.sqlite` build
themselves on first use.

```bash
git clone https://github.com/pavnxet/awesome-vulnerability-tests.git
cd awesome-vulnerability-tests

python3 cli/secure_kb.py detect /path/to/project
python3 cli/secure_kb.py profile web --gate fast --format brief
python3 cli/secure_kb.py search "how do I stop sql injection" --k 5
python3 cli/secure_kb.py get SKB-ASVS-V1-2-4 --format md
```

**No-build fallback** — the index ships as shards, so plain tooling works with no build step:

```bash
cat index/checks/*.jsonl | jq -c 'select(.severity=="critical")'
cat index/checks/*.jsonl | grep -c "SKB-ASVS"
```

## The five-step agent workflow

1. **Detect** the stack (`detect`) → ranked platforms.
2. **Profile** it (`profile <platform> --gate fast`).
3. **Gate** — the top checks by priority, domain-balanced, in a small token budget.
4. **Drill down** (`get <id>`, or by CWE / ASVS / MASVS ref).
5. **Report** — pass / fail / n-a / unknown, with evidence. No “pass” without evidence.

## MCP setup

The MCP server exposes `search_checks`, `get_check`, `profile_gate`, `detect_stack`, `report_init`,
`report_validate`.

**Claude Code**

```bash
claude mcp add secure-kb -- python3 /abs/path/to/awesome-vulnerability-tests/mcp/server.py
```

**Claude Desktop** (`claude_desktop_config.json`)

```json
{ "mcpServers": { "secure-kb": {
  "command": "python3",
  "args": ["/abs/path/to/awesome-vulnerability-tests/mcp/server.py"] } } }
```

**Generic MCP client** — JSON-RPC 2.0 over stdio; `initialize` then `tools/call`.

## What's in it

| Source | Cards | Licence |
|---|---|---|
| OWASP ASVS 5.0 | 345 | CC BY-SA 4.0 |
| OWASP Cheat Sheet Series | 1,045 | CC BY-SA 4.0 |
| OWASP MASTG (Android/iOS tests) | 92 | CC BY-SA 4.0 |
| OWASP WSTG | 115 | CC BY-SA 4.0 |
| OWASP MASVS | 24 | CC BY-SA 4.0 |
| OWASP Top 10 / API Top 10 / LLM Top 10 | 30 | CC BY-SA 4.0 |
| Web3 (kadenzipfel, crytic) | 49 | see `LICENSES/` |
| OWASP ISTG (IoT) | 19 | CC BY-SA 4.0 |
| vibe-security-skill, baselines, checklists (Tier-2) | 468 | see `LICENSES/` |
| Authored (Telegram, browser-ext, desktop, IoT gaps) | 15 | CC BY-SA 4.0 |

Cards use **source-identity IDs** — `SKB-<SRC>-<official-id>` (e.g. `SKB-ASVS-V3-4-5`,
`SKB-WSTG-INFO-01`) or a short hash of `repo|path|anchor`. Merged cards keep every member id in
`aliases[]`, so any historical id still resolves. See [`docs/PIPELINE.md`](docs/PIPELINE.md).

## Benchmarks

Held-out sets, frozen. **Strict** metrics (mapped refs only) — reported as measured.

| Set | n | recall@5 | Target | Status |
|---|---|---|---|---|
| Held-out (all) | 154 | **0.66** | ≥ 0.70 | below |
| Curated v2 (standards-derived) | 59 | **0.44** | ≥ 0.60 | below |
| v2_dev (developer vocabulary) | 40 | **0.25** | ≥ 0.60 | below |
| Templated | 95 | **0.92** | ≥ 0.90 | met |
| Fast-gate recall (strict) | 30 | **26.7%** | ≥ 0.70 | below |

Determinism: two consecutive rebuilds — and a rebuild with **shuffled** staging input — produce the
identical `manifest.content_hash` `0c921baa291a4af4`. Reproduce with
`python3 scripts/fetch_sources.py && python3 scripts/ingest_from_cache.py && python3 scripts/build_cards_v2.py`.

## Known limitations

- **Retrieval is below target.** Paraphrase recall is the weak spot; corpus growth added distractors
  that dedupe did not fully remove.
- **First-call index build ≈ 19 s** on a cold checkout (later queries sub-second).
- **Not yet implemented:** `kind: check|guidance`, deterministic `fix_refs`, official-source CWE
  enrichment, real-lab end-to-end evaluation.
- **Unverified:** 8 of 12 tool adapters; the Telegram `secret_token` claim; two project-declared
  licences.
- **Card text is untrusted DATA** — never executable instructions or system policy (see `AGENTS.md`).

## Licence & attribution

- **Content:** CC BY-SA 4.0, where provenance and upstream terms permit; attribution and ShareAlike
  preserved. Unlicensed / reference-only sources are not redistributed.
- **Code:** MIT.
- **Human legal review recommended.** No OWASP endorsement is implied.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). New cards require provenance: source repo, path, anchor,
commit, licence.

## Security

See [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## Citation

See [CITATION.cff](CITATION.cff).
