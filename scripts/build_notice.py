#!/usr/bin/env python3
"""Generate NOTICE.md (attribution) and a source-accounting table from sources.yaml."""
import os, yaml
from collections import defaultdict, Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src = yaml.safe_load(open(os.path.join(ROOT, "sources.yaml")))["sources"]

by_lic = defaultdict(list)
for s in src:
    by_lic[s["license"]].append(s)
mode_counts = Counter(s["ingest_mode"] for s in src)

lines = ["# NOTICE — attribution", "",
         "secure-kb content is **distilled** from the public repositories below. Each card cites the",
         "specific source repo and the commit SHA resolved at ingestion. No source code is vendored.",
         "", f"Total sources: **{len(src)}**", "",
         "## Source accounting",
         "", "| ingest_mode | count |", "|---|---|"]
for m, c in sorted(mode_counts.items()):
    lines.append(f"| {m} | {c} |")
lines += ["", "## Licenses represented", "",
          "| license | count | repos |", "|---|---|---|"]
for lic, items in sorted(by_lic.items(), key=lambda kv: -len(kv[1])):
    names = ", ".join(s["repo"] for s in items)
    lines.append(f"| {lic} | {len(items)} | {names} |")

lines += ["", "## All sources", "", "| repo | license | commit | tier | mode | archived |", "|---|---|---|---|---|---|"]
for s in sorted(src, key=lambda x: x["repo"].lower()):
    c = (s.get("commit") or "")[:12]
    lines.append(f"| {s['repo']} | {s['license']} | `{c}` | {s['trust_tier']} | {s['ingest_mode']} | {'yes' if s['archived'] else 'no'} |")

lines += ["", "## Notes",
          "- OWASP docs (CC BY-SA 4.0) are quoted/summarised; ShareAlike is respected by licensing KB content CC BY-SA 4.0.",
          "- `NOASSERTION` means GitHub could not detect a standard license. These were used for reference/mining only unless permissive.",
          "- Tool repos with GPL/AGPL licenses are NOT copied — `tools/*.yaml` describe external invocation only.",
          "- ⚠️ Human-legal review is required before any public release. This file is not legal advice."]

open(os.path.join(ROOT, "NOTICE.md"), "w").write("\n".join(lines) + "\n")
print("NOTICE.md written;", len(src), "sources;", dict(mode_counts))
