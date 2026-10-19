# RELEASE_CANDIDATE — secure-kb v0.9.0 (public beta)
| criterion | status | evidence |
|---|---|---|
| No secrets/credentials in tree | DONE | gitleaks+trufflehog 0 real (docs/history/PRE_PUBLIC_CHECKLIST.md) |
| No absolute local paths in code | DONE | legacy ingest scripts removed; grep clean |
| user_queries excluded | DONE | excluded from release tree |
| No NONE-license derived text | DONE | ConsenSys cards dropped earlier |
| index sharded <=800KB | DONE | 5 shards, max 779KB |
| build deterministic + shuffle-stable | DONE | hash 0c921baa291a4af4 (docs/history/REBUILD_REPORT.md) |
| curated v2 recall >= 0.60 | **NOT DONE** | measured 0.44 |
| all held-out recall >= 0.70 | **NOT DONE** | measured 0.66 |
| v2_dev recall >= 0.60 | **NOT DONE** | measured 0.25 |
| R1b kind/guidance | NOT DONE | |
| R1c official CWE | NOT DONE | |
| R3 real-lab e2e | NOT DONE | |
| R4 integrations | PARTIAL | Telegram secret_token unverified; 8 tool adapters unverified |
**Decision: v0.9.0 public beta.** Performance/integration targets unmet -> not v1.0.0.
**Human legal review recommended.**
