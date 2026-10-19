# PUBLIC_LAUNCH_CHECKLIST
## Launch
1. Create public repo `secure-kb`; push release tree as ONE clean commit (no history).
2. Create release `v0.9.0` (pre-release) with zip + SHA256SUMS.
3. Anonymous verify: clone, detect, profile --gate fast, search, get, MCP, jq fallback.
## Expected
- clone succeeds anonymously; manifest.content_hash = 0c921baa291a4af4; 2057 cards.
## Rollback
- Settings → Danger Zone → Change visibility → Private. (Cannot undo clones/forks/caches.)
## Monitoring (48h)
- security alerts, new issues, unexpected forks, licensing/content reports.
