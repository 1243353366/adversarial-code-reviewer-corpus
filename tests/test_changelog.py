"""The changelog is a claim about the repository, so it gets tested like one.

Four rules, each enforced rather than stated:

1. Every registry entry has a changelog row, and every row has a registry entry.
2. Every row cites a reproduction that runs, in both directions: the defect reproduces on
   the historical state, and the guard does not fire on the current tree.
3. Every cited regression test exists.
4. Every methodological change carries a justification.
"""
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import repro as R  # noqa: E402

CHANGELOG = (ROOT / "CHANGELOG.md").read_text()


def _rows() -> list[dict]:
    rows = []
    for line in CHANGELOG.splitlines():
        if not re.match(r"^\| R\d\d \|", line):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split(" | ")]
        if len(cells) != 6:
            raise AssertionError(f"row has {len(cells)} cells, expected 6: {line[:80]}")
        rid, defect, repro, fix, test, why = cells
        rows.append(
            {"id": rid, "defect": defect, "repro": repro, "fix": fix, "test": test, "why": why}
        )
    return rows


ROWS = _rows()
ROWS_BY_ID = {r["id"]: r for r in ROWS}


@pytest.mark.parametrize("entry", R.REGISTRY, ids=[e.id for e in R.REGISTRY])
def test_repro_reproduces_then_is_caught(entry):
    """Rule 2. A reproduction that only sees the fixed state proves nothing."""
    assert entry.run(entry.historical()), (
        f"{entry.id}: the defect does not reproduce on the historical state, so the row "
        f"claims something the repro does not show"
    )
    assert entry.run(entry.current()) == [], (
        f"{entry.id}: the guard fires on the current tree, so the fix does not hold"
    )


def test_every_registry_entry_has_a_changelog_row():
    """Rule 1, both directions."""
    missing = [e.id for e in R.REGISTRY if e.id not in ROWS_BY_ID]
    assert not missing, f"repro entries with no changelog row: {missing}"
    extra = [r["id"] for r in ROWS if r["id"] not in R.BY_ID]
    assert not extra, f"changelog rows with no repro entry: {extra}"


def test_every_row_cites_its_own_reproduction():
    for row in ROWS:
        assert f"tools/repro.py {row['id']}" in row["repro"], (
            f"{row['id']}: reproduction does not invoke its own repro id"
        )


def test_every_cited_test_exists():
    """Rule 3. A test id nobody can run is a wish."""
    for row in ROWS:
        for ref in re.findall(r"`(tests/[\w./]+\.py::[\w\[\]\.\-]+)`", row["test"]):
            path, node = ref.split("::")
            name = re.sub(r"\[.*\]$", "", node)
            body = (ROOT / path).read_text()
            assert re.search(rf"^def {re.escape(name)}\(", body, re.M), (
                f"{row['id']}: cited test {ref} does not exist"
            )


def test_methodological_rows_carry_a_justification():
    """Rule 4. Method changes need a reason, not just a footnote."""
    method_rows = [r for r in ROWS if r["why"].startswith("**Method.")]
    assert len(method_rows) >= 8, (
        f"only {len(method_rows)} methodological rows marked; the harness changes are "
        f"methodological and must be justified as such"
    )
    for row in method_rows:
        assert len(row["why"]) > 80, f"{row['id']}: justification is too thin"


def test_gaps_section_lists_the_unguarded_classes():
    """Rule 4, the honest half: what has no guard must be named."""
    gaps = CHANGELOG.split("## Known gaps")[1]
    assert "prose" in gaps.lower()
    assert "invented locator" in gaps.lower()


def test_changelog_states_its_own_rules():
    """The rules are what the tests above enforce, so they have to be visible."""
    assert "A row without a passing repro is a claim" in CHANGELOG
    assert "Every fix cites a regression test" in CHANGELOG
    assert "Every methodological change carries a justification" in CHANGELOG
