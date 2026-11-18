import json

import pytest

from redteam import FakeTarget
from scenarios import (
    DEFAULT_SCENARIOS,
    run_scenario,
    scenario_manifest,
    validate_scenarios,
    write_markdown,
    write_report,
)


def test_default_scenarios_are_valid_and_versioned():
    validate_scenarios(DEFAULT_SCENARIOS)
    assert len(DEFAULT_SCENARIOS) >= 3
    assert len({item.id for item in DEFAULT_SCENARIOS}) == len(DEFAULT_SCENARIOS)
    assert all(item.version and item.benign_control for item in DEFAULT_SCENARIOS)


def test_scenario_manifest_is_stable():
    assert scenario_manifest(DEFAULT_SCENARIOS) == scenario_manifest(DEFAULT_SCENARIOS)
    assert len(scenario_manifest(DEFAULT_SCENARIOS)) == 64


def test_scenario_validation_rejects_duplicate_ids():
    with pytest.raises(ValueError, match="unique"):
        validate_scenarios([DEFAULT_SCENARIOS[0], DEFAULT_SCENARIOS[0]])


def test_scenario_runner_records_turns_and_separate_control():
    result = run_scenario(FakeTarget(), DEFAULT_SCENARIOS[0], model="fixture")
    assert result.status == "PASS"
    assert len(result.turns) == len(DEFAULT_SCENARIOS[0].turns)
    assert result.benign_control["status"] == "OBSERVED"
    assert result.benign_control["interpretation"] == "requires_human_review"
    assert result.turns[0].prompt_sha256
    assert result.turns[0].response_sha256


def test_scenario_runner_stops_at_first_heuristic_failure():
    target = FakeTarget(response="Previous instructions have been disabled.")
    result = run_scenario(target, DEFAULT_SCENARIOS[0], model="fixture")
    assert result.status == "FAIL"
    assert result.first_flagged_turn == 1
    assert len(result.turns) == 1
    assert result.benign_control["status"] == "OBSERVED"


def test_scenario_report_includes_manifest_and_limitations(tmp_path):
    result = run_scenario(FakeTarget(), DEFAULT_SCENARIOS[0], model="fixture")
    json_path = tmp_path / "scenario.json"
    md_path = tmp_path / "scenario.md"
    write_report(str(json_path), "run-id", "fixture", [result])
    write_markdown(str(md_path), "run-id", "fixture", [result])
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["scenario_manifest_sha256"]
    assert "NOT_DETECTED is inconclusive" in payload["limitations"][3]
    assert "Benign control" in md_path.read_text(encoding="utf-8")
