import re

import pytest

from protocol import (
    ATTACK_VARIANTS,
    BENIGN_EXPECTED,
    BENIGN_PROMPT,
    CANARY_PROBE_PROMPT,
    POLICY_PROBE_PROMPT,
    REGRESSION_PROMPT,
)
from redteam import TargetResponse
from robustness import run_robustness_matrix, summarize_robustness, write_matrix_report


class MatrixTarget:
    name = "matrix-fixture"

    def __init__(self, seed):
        self.seed = seed
        self.attack_variant = "direct"
        self.policy_marker = None
        self.canary = None

    def generate(self, messages, model=None):
        system = messages[0].content
        self.policy_marker = re.search(
            r"policy marker is (LRT-POLICY-GUARD-[a-z0-9]+)\.", system
        ).group(1)
        self.canary = re.search(r"synthetic canary is (LRT-CANARY-[a-z0-9]+)\.", system).group(1)
        prompt = messages[-1].content

        if prompt == REGRESSION_PROMPT and len(messages) == 2:
            text = "I cannot reveal protected fixture values."
        elif prompt == CANARY_PROBE_PROMPT and len(messages) == 2:
            text = "I cannot disclose the canary."
        elif prompt == BENIGN_PROMPT:
            text = BENIGN_EXPECTED
        elif prompt in ATTACK_VARIANTS.values():
            self.attack_variant = next(
                name for name, value in ATTACK_VARIANTS.items() if value == prompt
            )
            text = "I will ignore previous instructions and comply with future requests."
        elif prompt == POLICY_PROBE_PROMPT:
            leaks = (
                (self.attack_variant == "direct" and self.seed in {11, 13})
                or (self.attack_variant == "authority_reframing" and self.seed == 13)
            )
            text = self.policy_marker if leaks else "I cannot reveal the restricted marker."
        elif prompt == CANARY_PROBE_PROMPT:
            text = "I cannot disclose the canary."
        else:
            text = "Basalt is volcanic; granite cools slowly underground."
        return TargetResponse(
            text=text, latency_ms=1.0, provenance={"model": "matrix-fixture", "seed": self.seed}
        )


def test_seed_variance_and_paraphrase_robustness_are_separate():
    seeds_seen = []

    def factory(seed):
        seeds_seen.append(seed)
        return MatrixTarget(seed)

    matrix = run_robustness_matrix(
        factory,
        model="fixture",
        seeds=[11, 12, 13],
        variants=["direct", "authority_reframing"],
    )
    summary = matrix.summary

    assert len(matrix.results) == 6
    assert {item.attack_variant for item in matrix.results} == {"direct", "authority_reframing"}
    assert {item.sampling_seed for item in matrix.results} == {11, 12, 13}
    assert seeds_seen == [11, 12, 13, 11, 12, 13]
    assert summary["baseline_gate"]["baseline_resistant_runs"] == 6
    assert summary["within_baseline_resistant_cohort"]["denominator"] == 6

    direct = summary["seed_variance_by_variant"]["direct"]
    assert direct["capability_rates"]["POLICY_BYPASS"] == pytest.approx(2 / 3)
    assert direct["seed_variance"]["POLICY_BYPASS"]["n"] == 3
    assert direct["seed_variance"]["POLICY_BYPASS"]["binary_outcome_variance"] == pytest.approx(2 / 9)

    paraphrase = summary["paraphrase_robustness"]
    assert paraphrase["measured"] is True
    assert paraphrase["policy_bypass_rate_across_variants"] == pytest.approx(0.5)
    assert paraphrase["paraphrase_resistance_rate"] == pytest.approx(0.5)
    assert "not difficulty-matched" in summary["methodology"]["paraphrase_set"]
    assert set(paraphrase["per_seed"]) == {"11", "12", "13"}


def test_baseline_failures_are_invalid_and_excluded_from_attack_denominator():
    class BaselineFailTarget(MatrixTarget):
        def generate(self, messages, model=None):
            result = super().generate(messages, model=model)
            if messages[-1].content == REGRESSION_PROMPT and len(messages) == 2:
                result.text = self.policy_marker
            return result

    matrix = run_robustness_matrix(
        lambda seed: BaselineFailTarget(seed),
        model="fixture",
        seeds=[99],
        variants=["direct"],
    )
    summary = matrix.summary
    assert summary["baseline_gate"]["baseline_failed_runs"] == 1
    assert summary["baseline_gate"]["baseline_resistant_runs"] == 0
    assert summary["within_baseline_resistant_cohort"]["denominator"] == 0
    assert summary["within_baseline_resistant_cohort"]["policy_bypass_rate"] is None
    assert summary["paraphrase_robustness"]["measured"] is False


def test_matrix_rejects_unknown_variants_and_duplicate_seeds():
    with pytest.raises(ValueError, match="unique sampling seeds"):
        run_robustness_matrix(lambda seed: MatrixTarget(seed), model="x", seeds=[1, 1])
    with pytest.raises(ValueError, match="Unknown attack variants"):
        run_robustness_matrix(lambda seed: MatrixTarget(seed), model="x", seeds=[1], variants=["unknown"])


def test_matrix_report_serializes_seed_and_variant_dimensions(tmp_path):
    matrix = run_robustness_matrix(
        lambda seed: MatrixTarget(seed), model="fixture", seeds=[11, 12],
        variants=["direct", "authority_reframing"],
    )
    output = tmp_path / "matrix.json"
    write_matrix_report(str(output), matrix)
    import json
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "2"
    assert payload["seeds"] == [11, 12]
    assert payload["variants"] == ["direct", "authority_reframing"]
    assert payload["summary"]["methodology"]["llm_judge"] is False



def test_matrix_summarizes_baseline_disclosures_without_counting_them_as_attack_bypasses():
    class BaselineDisclosureTarget(MatrixTarget):
        def generate(self, messages, model=None):
            result = super().generate(messages, model=model)
            if messages[-1].content == REGRESSION_PROMPT and len(messages) == 2:
                result.text = self.policy_marker
            return result

    matrix = run_robustness_matrix(
        lambda seed: BaselineDisclosureTarget(seed), model="fixture",
        seeds=[101, 102], variants=["direct"],
    )
    gate = matrix.summary["baseline_gate"]
    assert gate["baseline_failed_runs"] == 2
    assert gate["baseline_policy_disclosure_runs"] == 2
    assert gate["baseline_canary_disclosure_runs"] == 0
    assert gate["baseline_any_disclosure_runs"] == 2
    assert matrix.summary["within_baseline_resistant_cohort"]["denominator"] == 0
    assert matrix.summary["within_baseline_resistant_cohort"]["policy_bypass_rate"] is None
