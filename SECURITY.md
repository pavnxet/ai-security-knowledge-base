# Security Policy

## What this repository is

secure-kb is a **knowledge base of security checks** plus a small read-only CLI and MCP server. It
runs no service, holds no user data, and executes nothing against any target. The "vulnerabilities"
it discusses are defensive checks, not exploits.

That shapes this policy: the realistic risks here are a leaked credential, a poisoned corpus, or a
tool that can be talked into reading something it should not — not a remote exploit.

## Supported versions

Only the latest release receives security fixes. Pre-releases are marked as such and are not
supported.

| Version | Supported | Notes |
|---|---|---|
| `0.9.x` (current beta) | ✅ | Security fixes land on the latest tag only |
| `1.0.x` | — | Not released yet; see the acceptance criteria in `RELEASE_CANDIDATE.md` |
| `< 0.9` | ❌ | Superseded by the v0.9 re-freeze (corpus and ID scheme changed) |

## Reporting a vulnerability

**Please do not open a public issue for a security problem.** Use GitHub's private reporting:

➡️ **[Report a vulnerability](https://github.com/pavnxet/ai-security-knowledge-base/security/advisories/new)**
(Security tab → Advisories). If you cannot use that, open a public issue containing only "security
report — please contact me" and nothing else, and a maintainer will open a private channel.

**What to include**

- What you found, and the file path or risk ID it relates to.
- Steps to reproduce, or the exact input that triggers it.
- For a leaked credential: whether it is **still live** (this changes the response from "purge" to
  "rotate first").
- Affected version (`cat VERSION`) or commit.

**What to expect**

| Stage | Target |
|---|---|
| Acknowledgement | within **48 hours** |
| Initial assessment (valid / invalid / needs info) | within **5 working days** |
| Live credential rotated | within **48 hours** of confirmation |
| Fix — critical | **14 days** |
| Fix — high | **30 days** |
| Fix — medium / low | **90 days** |

If a fix will take longer, we will say so and explain why rather than let the report go quiet.

## Disclosure policy

We follow **coordinated disclosure**. We will work with you on a timeline, credit you in the advisory
unless you prefer otherwise, and ask that you give us the window above before publishing. If we miss
the window without explanation, publishing is fair.

We will publish a GitHub Security Advisory for anything that affects users of the CLI, the MCP server
or the shipped corpus, and reference the CVE if one is assigned.

## Scope — what counts as a security issue *here*

- A **leaked credential** committed to this repo (scripts, bench, index, docs, git history).
- A card containing **working exploit code, payload lists, or weaponised content** — cards are
  defensive by policy, so this should never happen.
- A **prompt-injection payload** in ingested source text that was not neutralised (all ingested text
  is treated as data; see `AGENTS.md`).
- A **tooling flaw** in the CLI or MCP server that can be abused — path traversal when reading a
  target, a cache that can be poisoned, an attestation that verifies when it should not.
- A **corpus integrity** failure: a way to make `content_hash` match while the cards differ.

**Out of scope**

- The accuracy or completeness of a third-party source we ingest.
- Vulnerabilities in the tools we *describe* in `tools/*.yaml` — report those to that project.
- The security of any codebase you audit with this KB. It tells you what to check; it does not make
  the code safe.
- Risks already listed as `accepted` in the register, *unless* you believe the acceptance is wrong —
  in that case say so, citing the risk ID, and that is a valid report.

## Threat model and accepted risks

What this project protects, what it assumes, and what it deliberately does not protect is in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — 16 risks (`R-001` … `R-016`), each with a mitigation
or an explicit acceptance, and a way to verify the control still works.

The machine-readable twin is [`risk-register.yaml`](risk-register.yaml): one entry per risk with the
justification, the artefact that verifies it, and the date it must be re-decided. CI fails if an
"accepted" risk has no reason, if a "mitigated" risk points at a test or CI job that does not exist,
or if a review date has lapsed.

## Known limitations

The benchmark numbers, the retrieval ceiling and the corpus defects we have not fixed are stated
plainly in [`KNOWN_LIMITATIONS.md`](KNOWN_LIMITATIONS.md) — with the measured values, checked against
`bench/results.json` by a test so the page cannot drift. None of it is a secret; publishing it is the
point.

## What we do on our side

- **Secret scanning** (gitleaks + trufflehog) runs in CI and over git history — see
  `PRE_PUBLIC_CHECKLIST.md`.
- **Ingested text is untrusted data.** It is never executed, and neither the CLI nor the MCP server
  follows instructions found inside card text. Normalisation strips markdown and control noise but
  deliberately does **not** remove instruction-like phrases, because some cards quote prompt-injection
  examples. `AGENTS.md` states this policy.
- **The CLI and MCP server are read-only** on any target codebase.
- **The corpus is content-hashed** and rebuilt in CI; a mismatch fails the build.
- **Every accepted risk is registered** with a reason and a review date, enforced by
  `scripts/check_risks.py`.

## Security updates

Fixes ship as a new tag on `main` with a CHANGELOG entry and, where relevant, a GitHub Security
Advisory. There is no mailing list; watch the repository's releases if you need to know.

Because this is a local, single-user tool with no server component, there is no runtime to patch —
updating is `git pull`, and the corpus hash tells you whether the cards changed.
