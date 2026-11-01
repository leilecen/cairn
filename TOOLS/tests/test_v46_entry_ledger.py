"""Keep the v4.6 exposed-entry closure ledger tied to executable tests."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LEDGER = ROOT / "data" / "v46_entry_ledger.json"
REQUIRED_FIELDS = {"id", "level", "entrypoint", "consumer", "fresh_db_test", "boundary_test"}


def _referenced_test_exists(reference: str) -> bool:
    filename, test_name = reference.split("::", maxsplit=1)
    source = ROOT / filename
    return source.is_file() and f"def {test_name}(" in source.read_text(encoding="utf-8")


def test_v46_entry_ledger_is_complete_and_points_to_live_tests():
    entries = json.loads(LEDGER.read_text(encoding="utf-8"))
    assert isinstance(entries, list) and entries
    assert {entry["id"] for entry in entries} == {
        "fresh_init",
        "baseline",
        "source_intel",
        "ct_search",
        "candidate_brief",
        "recon_plan",
        "insight_accept",
        "experience_harvest",
        "experience_reuse",
    }
    for entry in entries:
        assert REQUIRED_FIELDS <= set(entry)
        assert entry["level"] in {"L0", "L3", "operator"}
        assert _referenced_test_exists(entry["fresh_db_test"])
        assert _referenced_test_exists(entry["boundary_test"])
