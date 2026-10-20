# Priority formula

`priority` is computed from the card's own attributes - no hand-tuned magic numbers.

```
priority = base(severity)
         + 15  if the card maps to an OWASP Top 10 / API Top 10 / LLM Top 10 entry
         + 10  if any CWE is in the CWE Top 25 (2024)
         + 5 * min(corroboration - 1, 3)      # independent sources, capped at +15
         + 10  if the card carries a Tier-1 standard ref (ASVS/MASVS/MASTG/WSTG/Top10/API/LLM/CheatSheet)
clamped to 1..100
```

base: critical 60, high 45, medium 30, low 15, info 5.

Severity itself is derived (see build_cards_v2.py): domains auth/injection/access-control/crypto/
secrets/deserialization/ssrf/smart-contract/firmware are high; the OWASP/API/LLM #1 entries and
ASVS L1 critical-domain requirements are critical.

Gates: `fast` = top 25 by priority; `standard` = top 100; `full` = all.
Counts: {'critical': 36, 'high': 1235, 'medium': 781} by severity; 2052 cards total.
