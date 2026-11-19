from paired import CONTROLS, PAIRS, run
from redteam import FakeTarget, TargetResponse


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



def test_paired_suite_marks_truncated_outputs_for_review():
    class TruncatedTarget:
        name = "truncated-fixture"

        def generate(self, messages, model=None):
            return TargetResponse(
                text="partial response",
                latency_ms=1.0,
                provenance={"finish_reason": "length"},
            )

    payload = run(TruncatedTarget(), "fixture")

    assert payload["records"][0]["truncated"] is True
    assert payload["records"][0]["review_required"] is True
    assert payload["records"][0]["provenance"]["finish_reason"] == "length"
    assert all(item["truncated"] for item in payload["benign_controls"])
