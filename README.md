# secure-kb

**One merged, AI-agent-searchable security verification knowledge base.** Give an agent a codebase
and it gets the exact 15–25 checks that matter in seconds, with a tiny token budget, then drills
down only when needed.

Built from **67 public security repos** into **832 atomic check cards** — 817 of them extracted
programmatically from real source files at pinned commits — covering web, API, mobile (Android/iOS),
Telegram bots, cloud/DevOps, IoT, smart contracts, LLM/AI apps, vibe-coded apps, browser extensions
and desktop.

## Install in 60 seconds

The repository is currently **private**. Clone with a token (or use the public form once it is public):

```bash
# private (replace <TOKEN> with a GitHub token that can read the repo)
git clone https://<TOKEN>@github.com/pavnxet/secure-kb.git
cd secure-kb

# public (ready for later - same command, no token)
# git clone https://github.com/pavnxet/secure-kb.git

# 1. detect the stack of any codebase
python3 cli/secure_kb.py detect /path/to/your-app

# 2. get the ordered fast gate for the detected platform
python3 cli/secure_kb.py profile telegram --gate fast

# 3. search and drill down
python3 cli/secure_kb.py search "webhook secret" --k 5
python3 cli/secure_kb.py get SKB-TG-WEBHOOK-0034 --format md
```

**No install, no build step.** The CLI is Python-stdlib only; the generated `index/` is committed, so
a plain clone works immediately. Python 3.9+.

### Zero-dependency fallback (no CLI, no SQLite)

```bash
# every critical/high check for a platform
jq -c 'select((.platforms|index("telegram")) and (.severity=="critical" or .severity=="high"))
       | {id,title,check}' index/checks.jsonl

# grep shards (one file per platform)
grep -i webhook index/by_platform/telegram.jsonl

# cheap scan of everything
cut -f1,2,4 index/brief.tsv | head
```

### MCP server (Claude Desktop / any MCP client)

```json
{
  "mcpServers": {
    "secure-kb": {
      "command": "python3",
      "args": ["/absolute/path/to/secure-kb/mcp/server.py"]
    }
  }
}
```

Tools exposed: `detect_stack`, `get_profile`, `search_checks`, `get_check`, `list_tools`,
`start_report`, `submit_result`. Read-only on any target codebase.

## Why

Security checklists are scattered across dozens of repos in dozens of formats. An agent can't read
them all, and shouldn't. secure-kb normalises them into small cards **with real file provenance**,
adds a router so detection → relevant checks is instant, and ships a zero-dependency fallback.

## Repository layout

```
AGENTS.md            the only file an agent reads first (<=1.5k tokens)
llms.txt             crawler pointers
manifest.json        version, counts, content hash
sources.yaml         67 sources: url, commit SHA, license, archived, tier, ingest_mode
schema/              JSON schemas + controlled vocabularies
checks/<platform>/<domain>/*.yaml   source-of-truth cards
profiles/<platform>.yaml            ordered launch gates (fast/standard/full)
playbooks/           quick-25, pr-review, pre-launch, full-audit
tools/               scanner adapters (no vendored code) + verification status
fixtures/            lab -> check mappings (benchmark)
references/          Tier-3 link index + known gaps
bench/               held-out benchmark + results
docs/PRIORITY.md     the priority formula
index/               GENERATED: checks.jsonl, brief.tsv, by_*.json, by_platform/, router.json, kb.sqlite (FTS5)
cli/ mcp/ scripts/ tests/  .github/workflows/
```

## How retrieval works

1. **Detect** fingerprints files + content signals → ranked platforms.
2. **Router** maps fingerprints → profile(s); multiple profiles merge.
3. **Fast gate** returns the top ≤25 checks by `priority` (≤4k tokens); `standard` ≤100; `full` all.
4. **Direct lookup** O(1) by id / CWE / ASVS / MASVS / API / Top10 via `index/by_*.json`.
5. **Free-text** FTS5 (BM25) with weighted columns + filters + synonym expansion.
6. **Ranking** = bm25 × platform/stack boost × severity weight × priority.
7. **No-result** returns `gap: true` + suggestions from `references/`. Never fabricates.

## Provenance & confidence

Every distilled card records `sources[].path + anchor + commit` — the exact file and commit the text
came from. Cards built where no public checklist exists (Telegram, browser extensions, desktop) are
`origin: authored` with a verified official-doc URL and `confidence` set honestly. See
`AUDIT_v0.1.md` and `references/index.yaml` → `known_gaps`.

## Licensing

- **Content** is **CC BY-SA 4.0** (OWASP-derived) — `LICENSES/CONTENT.md`.
- **Code** is **MIT** — `LICENSE`.
- Attribution for all 67 sources: `NOTICE.md`.
- No GPL/AGPL tool code is vendored; `tools/*.yaml` only describe external invocation.
- ⚠️ Two OWASP sources carry a **project-declared** (unverified) licence — see `LICENSES/CONTENT.md`.
- ⚠️ **Human-legal review is required before making this repository public.** Not legal advice.

## Safety

All ingested text is treated as untrusted DATA. Cards are defensive (what to verify/fix), never
exploit payloads. The CLI/MCP are read-only on the target by default. See `SECURITY.md`.

## Quality gates & benchmark

CI runs schema validation, token limits, coverage matrix, provenance and licence checks, a duplicate
detector, and the held-out benchmark. Current honest numbers (832 cards):

| benchmark set | n | recall@5 | recall@10 | MRR |
|---|---|---|---|---|
| held-out (all) | 154 | 0.70 | 0.73 | 0.66 |
| curated v1 (memory-written refs) | 59 | 0.31 | 0.34 | 0.23 |
| curated v2 (refs from standards text) | 59 | 0.68 | 0.71 | 0.46 |
| templated | 95 | 0.95 | 0.98 | 0.92 |

Lab coverage 36.7%; fast-gate recall 20.0%. See `BUILD_REPORT.md` and `bench/results.json` for
worst-case failures and known weaknesses.

## Status

v0.2.1 (pre-release). See `CHANGELOG.md` and `BUILD_REPORT.md`.
