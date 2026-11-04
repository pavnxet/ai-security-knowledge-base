"""Check that relative links in the repo's markdown actually resolve.

Broken links are how documentation rots silently: the file moves, the anchor is renamed, and nobody
notices until a reader hits a 404. This walks the docs people actually land on and verifies both the
target file and, for `#anchors`, that a heading producing that slug exists.
"""
import glob
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Documents a reader is expected to land on. CHANGELOG is excluded: it is an append-only log and
# legitimately references things that no longer exist.
DOCS = ["README.md", "SECURITY.md", "CONTRIBUTING.md", "AGENTS.md"] + [
    os.path.relpath(p, ROOT) for p in glob.glob(os.path.join(ROOT, "docs", "*.md"))
]


def _slug(heading: str) -> str:
    """GitHub-style heading slug."""
    s = heading.strip().lower()
    s = re.sub(r"[^\w\s-]", "", s)
    return re.sub(r"\s+", "-", s).strip("-")


def _anchors(path: str) -> set:
    out = set()
    for line in open(path, encoding="utf-8"):
        m = re.match(r"^#{1,6}\s+(.*)$", line)
        if m:
            out.add(_slug(m.group(1)))
    return out


def _links(text: str):
    """Yield (target, anchor) for relative markdown links, skipping images and external URLs."""
    for m in re.finditer(r"(?<!!)\[[^\]]*\]\(([^)\s]+)\)", text):
        target = m.group(1)
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        path, _, anchor = target.partition("#")
        yield path, anchor


@pytest.mark.parametrize("doc", DOCS)
def test_relative_links_resolve(doc):
    full = os.path.join(ROOT, doc)
    assert os.path.exists(full), f"{doc} is missing"
    base = os.path.dirname(full)
    for path, anchor in _links(open(full, encoding="utf-8").read()):
        if not path:                                    # pure in-page anchor
            target = full
        else:
            target = os.path.normpath(os.path.join(base, path))
            assert os.path.exists(target), f"{doc}: broken link -> {path}"
        if anchor and target.endswith(".md"):
            assert anchor in _anchors(target), (
                f"{doc}: anchor #{anchor} not found in {os.path.relpath(target, ROOT)}")


def test_security_md_has_the_required_sections():
    """The standard content set: what to report, how, what to expect, and what is supported."""
    text = open(os.path.join(ROOT, "SECURITY.md"), encoding="utf-8").read()
    for heading in ("Supported versions", "Reporting a vulnerability",
                    "Disclosure policy", "Scope", "Threat model"):
        assert re.search(rf"^##+ .*{heading}", text, re.M | re.I), f"SECURITY.md lacks '{heading}'"
    assert "advisories/new" in text, "SECURITY.md should point at GitHub private reporting"


def test_threat_model_and_register_are_linked():
    for doc in ("README.md", "SECURITY.md"):
        text = open(os.path.join(ROOT, doc), encoding="utf-8").read()
        assert "docs/THREAT_MODEL.md" in text, f"{doc} does not link the threat model"
        assert "risk-register.yaml" in text, f"{doc} does not link the risk register"


# ---------- Phase 6: the posture must be discoverable from every front door ----------
POSTURE_DOCS = ["docs/THREAT_MODEL.md", "risk-register.yaml", "KNOWN_LIMITATIONS.md", "SECURITY.md"]


@pytest.mark.parametrize("doc", ["README.md", "AGENTS.md", "llms.txt"])
def test_front_doors_link_the_whole_posture(doc):
    text = open(os.path.join(ROOT, doc), encoding="utf-8").read()
    for target in POSTURE_DOCS:
        assert target in text, f"{doc} does not link {target}"


def test_readme_has_a_consolidated_posture_section():
    text = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
    assert re.search(r"^## Security posture", text, re.M), "README needs a 'Security posture' section"


def test_site_has_a_posture_section():
    html = open(os.path.join(ROOT, "docs", "index.html"), encoding="utf-8").read()
    assert 'id="posture"' in html, "the website should surface the security posture"
    for name in ("THREAT_MODEL.md", "risk-register.yaml", "KNOWN_LIMITATIONS.md", "SECURITY.md"):
        assert name in html, f"the site does not link {name}"


def test_mcp_tool_lists_match_the_server():
    """AGENTS.md and llms.txt must advertise exactly the tools mcp/server.py exposes."""
    server = open(os.path.join(ROOT, "mcp", "server.py"), encoding="utf-8").read()
    tools = re.findall(r'\{"name": "([a-z_]+)"', server)
    assert len(tools) >= 9, f"expected the full tool set, parsed {tools}"
    for doc in ("AGENTS.md", "llms.txt"):
        text = open(os.path.join(ROOT, doc), encoding="utf-8").read()
        missing = [t for t in tools if t not in text]
        assert not missing, f"{doc} is missing MCP tools: {missing}"
