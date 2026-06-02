from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_required_docs_exist_and_are_nonempty():
    for rel in [
        "README.md",
        "docs/architecture.md",
        "docs/onboarding/getting-started.md",
        "docs/onboarding/anatomy-of-a-slice.md",
        "docs/onboarding/adding-a-new-slice.md",
    ]:
        p = ROOT / rel
        assert p.exists(), rel
        assert len(p.read_text().strip()) > 200, f"{rel} looks like a stub"


def test_no_drafting_tool_references_in_authored_docs():
    # Scope to user-facing authored docs. docs/superpowers/ holds internal drafting
    # artifacts that legitimately credit the upstream community repo and quote this check,
    # so they are intentionally excluded. Attribution to upstream lives in NOTICE.md.
    banned = ["claude", "anthropic", "co-authored-by"]
    authored = [ROOT / "README.md"]
    authored += [p for p in (ROOT / "docs").rglob("*.md") if "superpowers" not in p.parts]
    for p in authored:
        text = p.read_text().lower()
        for word in banned:
            assert word not in text, f"{p} contains banned reference '{word}'"
