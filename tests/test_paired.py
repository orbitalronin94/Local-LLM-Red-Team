from paired import CONTROLS, PAIRS, run
from redteam import FakeTarget


def test_paired_suite_has_equal_english_and_spanish_coverage():
    assert len(PAIRS) >= 5
    assert set(CONTROLS) == {"en", "es"}


def test_paired_suite_records_pairs_controls_and_hashes():
    payload = run(FakeTarget(), "fixture")
    assert payload["probe_count"] == len(PAIRS) * 2
    assert len(payload["benign_controls"]) == 2
    for pair_id, _, _, _ in PAIRS:
        languages = {item["language"] for item in payload["records"] if item["pair_id"] == pair_id}
        assert languages == {"en", "es"}
    assert all(item["prompt_sha256"] and item["response_sha256"] for item in payload["records"])
    assert all(item["review_state"] == "REQUIRES_HUMAN_REVIEW" for item in payload["benign_controls"])
