# Content license: CC BY-SA 4.0

The **content** of secure-kb — the check cards under `checks/`, the `profiles/`, `playbooks/`,
`fixtures/` and the generated `index/` — is licensed under the
**Creative Commons Attribution-ShareAlike 4.0 International License (CC BY-SA 4.0)**.

- License deed: https://creativecommons.org/licenses/by-sa/4.0/
- Full legal code: https://creativecommons.org/licenses/by-sa/4.0/legalcode

## Why CC BY-SA
A large share of the distilled content derives from OWASP documents (OWASP Top 10, ASVS, WSTG,
Cheat Sheet Series, MASVS/MASTG, API Security Top 10, LLM Top 10, ISTG), which are themselves
CC BY-SA 4.0. The ShareAlike term requires derivatives to carry the same license, so the KB content
inherits CC BY-SA 4.0. Attribution for every source is in `NOTICE.md`; each card also records its
source repo and commit SHA in its `sources` field.

## What this means for you
- You may copy, adapt and use commercially, **with attribution** and **under the same license**.
- If you build on the content, license your derivative under CC BY-SA 4.0 (or compatible).

## Code
The code (`cli/`, `mcp/`, `scripts/`, `tests/`) is MIT — see the root `LICENSE`.

## Third-party tools
No GPL/AGPL tool code is vendored. `tools/*.yaml` only describe how to invoke tools externally;
those tools keep their own licenses (see `NOTICE.md`).

## Not legal advice
⚠️ This is a good-faith licensing decision, **not legal advice**. Obtain human-legal review before
publishing or redistributing.

## Sources whose licence is only *project-declared*

GitHub's licence detector returns `NOASSERTION` for some OWASP repositories that nonetheless ship a
licence file. Where we could read the file we corrected it; where the repo was too large to fetch we
recorded the licence as **project-declared (unverified)**:

| source | licence recorded | how verified |
|---|---|---|
| OWASP/Top10 | CC BY-SA 4.0 | LICENSE file read |
| OWASP/owasp-istg | CC BY-SA 4.0 | LICENSE file read |
| OWASP/API-Security | CC BY-SA 4.0 | **project-declared** (repo too large to fetch) |
| OWASP/…LLM Top 10 | CC BY-SA 4.0 | **project-declared** (repo too large to fetch) |
| ConsenSysDiligence/smart-contract-best-practices | NONE | no LICENSE file → reference-only, no text derived |

These two project-declared entries are the only licence claims in `sources.yaml` not backed by a file
we read. Confirm them before any public release.
