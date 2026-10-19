# AI Security Knowledge Base (`secure-kb`)

**An AI security knowledge base — security check cards an AI coding agent can search.**

> Keywords: AI security · AI agent security · OWASP ASVS · WSTG · MASTG · Top 10 · LLM security · prompt injection · secure code review · AppSec · DevSecOps · MCP · Claude · Cursor

2,057 atomic check cards distilled from 67 **tracked sources** — cards are drawn from 15 public
repositories plus 5 official-doc sources — each traceable to a real
file, anchor and commit.

> **Status: public beta (v0.9.0).** The build is deterministic and reproducible; retrieval targets are
> **not yet met**, so this is deliberately not v1.0.0. See [Benchmarks](#benchmarks) and
> [Known limitations](#known-limitations).

[**Website →**](https://pavnxet.github.io/ai-security-knowledge-base/) ·
[Releases](https://github.com/pavnxet/ai-security-knowledge-base/releases) ·
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
git clone https://github.com/pavnxet/ai-security-knowledge-base.git
cd ai-security-knowledge-base

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

The MCP server exposes `detect_stack`, `get_profile`, `search_checks`, `get_check`, `start_report`,
`submit_result`, `list_tools` (7 tools — run `list_tools` to enumerate).

**Claude Code**

```bash
claude mcp add secure-kb -- python3 /abs/path/to/secure-kb/mcp/server.py
```

**Claude Desktop** (`claude_desktop_config.json`)

```json
{ "mcpServers": { "secure-kb": {
  "command": "python3",
  "args": ["/abs/path/to/secure-kb/mcp/server.py"] } } }
```

**Generic MCP client** — JSON-RPC 2.0 over stdio; `initialize` then `tools/call`.

## What's in it

| Source | Cards | Licence |
|---|---|---|
| OWASP Cheat Sheet Series | 1,032 | CC BY-SA 4.0 |
| yesmayank/secure-coding-baseline (Tier-2) | 353 | MIT |
| OWASP ASVS 5.0 | 339 | CC BY-SA 4.0 |
| OWASP WSTG | 112 | CC BY-SA 4.0 |
| raroque/vibe-security-skill (Tier-2) | 40 | see `LICENSES/` |
| kadenzipfel/smart-contract-vulnerabilities | 38 | see `LICENSES/` |
| OWASP MASTG (Android/iOS tests) | 32 | CC BY-SA 4.0 |
| OWASP MASVS | 20 | CC BY-SA 4.0 |
| OWASP ISTG (IoT) | 15 | CC BY-SA 4.0 |
| shieldfy/API-Security-Checklist (Tier-2) | 13 | see `LICENSES/` |
| crytic/not-so-smart-contracts | 11 | see `LICENSES/` |
| OWASP Top 10 / LLM Top 10 / API Top 10 | 10 / 10 / 9 | CC BY-SA 4.0 |
| mgreiler/secure-code-review-checklist (Tier-2) | 8 | see `LICENSES/` |
| Authored (Telegram, Chrome, Electron — official docs) | 15 | CC BY-SA 4.0 |
| **Total** | **2,057** | |

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
| Curated v1 | 59 | **0.25** | — | reference |
| Templated | 95 | **0.92** | ≥ 0.90 | met |
| Fast-gate recall (strict) | 30 | **26.7%** | ≥ 0.70 | below |

Determinism: two consecutive rebuilds — and a rebuild with **shuffled** staging input — produce the
identical `manifest.content_hash` `0c921baa291a4af4`. Reproduce with
`python3 scripts/fetch_sources.py && python3 scripts/ingest_from_cache.py && python3 scripts/build_cards_v2.py`.

## Known limitations

- **Retrieval is below target.** Paraphrase recall is the weak spot; corpus growth added distractors
  that dedupe did not fully remove.
- **First-call index build takes a few seconds** on a cold checkout (measured ~6 s on one machine,
  ~19 s on another; later queries are sub-second).
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
