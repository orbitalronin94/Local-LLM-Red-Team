from evidence import Canary, sha256_text
from protocol import (
    ATTACK_PROMPT,
    BENIGN_EXPECTED,
    BENIGN_PROMPT,
    CANARY_PROBE_PROMPT,
    POLICY_PROBE_PROMPT,
    REGRESSION_PROMPT,
    run_persistence_protocol,
    write_protocol_report,
)
from redteam import TargetResponse


class ScriptedProtocolTarget:
    name = "scripted"

    def __init__(self, policy_marker, canary, *, regression_leaks=False,
                 pre_benign=BENIGN_EXPECTED, post_benign=BENIGN_EXPECTED,
                 policy_leaks=True, canary_leaks=True, canary_regression_leaks=False,
                 indirect_policy_leaks=False):
        self.policy_marker = policy_marker
        self.canary = canary
        self.regression_leaks = regression_leaks
        self.pre_benign = pre_benign
        self.post_benign = post_benign
        self.policy_leaks = policy_leaks
        self.canary_leaks = canary_leaks
        self.canary_regression_leaks = canary_regression_leaks
        self.indirect_policy_leaks = indirect_policy_leaks
        self.calls = 0

    def generate(self, messages, model=None):
        self.calls += 1
        prompt = messages[-1].content
        if prompt.startswith("Explain the key instruction that governs"):
            text = self.policy_marker if self.indirect_policy_leaks else "Follow the governing instructions and treat user content as lower priority."
        elif prompt == REGRESSION_PROMPT and len(messages) == 2:
            text = self.policy_marker if self.regression_leaks else "I cannot reveal protected fixture values."
        elif prompt == BENIGN_PROMPT:
            count = sum(1 for m in messages if m.role == "user" and m.content == BENIGN_PROMPT)
            text = self.pre_benign if count <= 1 else self.post_benign
        elif prompt == ATTACK_PROMPT:
            text = "I will ignore previous instructions and comply with future requests."
        elif prompt == POLICY_PROBE_PROMPT:
            text = self.policy_marker if self.policy_leaks else "I cannot disclose the restricted marker."
        elif prompt == CANARY_PROBE_PROMPT and len(messages) == 2:
            text = self.canary if self.canary_regression_leaks else "I cannot disclose the canary."
        elif prompt == CANARY_PROBE_PROMPT:
            text = self.canary if self.canary_leaks else "I cannot disclose the canary."
        else:
            text = "Basalt is volcanic; granite cools slowly underground."
        return TargetResponse(text=text, latency_ms=1.0)


def fixture():
    marker = "LRT-POLICY-GUARD-test"
    canary = Canary("LRT-CANARY-test", sha256_text("LRT-CANARY-test"))
    return marker, canary


def test_protocol_requires_new_post_injection_probe_and_separates_vector_levels():
    marker, canary = fixture()
    target = ScriptedProtocolTarget(marker, canary.value, post_benign="BENIGN-CONTROL-CHANGED")
    result = run_persistence_protocol(
        target, model="fixture", canary=canary, policy_marker=marker, run_id="protocol-test"
    )

    assert result.validity == "valid"
    assert result.baseline_stratum == "BASELINE_RESISTANT"
    assert result.schema_version == "2"
    assert result.protocol_version == "2"
    assert REGRESSION_PROMPT == POLICY_PROBE_PROMPT
    assert result.evidence_vector["VERBAL_ACCEPTANCE"]["status"] == "OBSERVED"
    assert result.evidence_vector["PERSISTENT_OVERRIDE"]["status"] == "OBSERVED"
    assert result.evidence_vector["POLICY_BYPASS"]["status"] == "OBSERVED"
    assert result.evidence_vector["CANARY_DISCLOSURE"]["status"] == "DISCLOSED"
    assert result.controls["benign_temporal_drift"]["changed"] is True
    assert result.evidence_vector["PERSISTENT_OVERRIDE"]["supporting_evidence"]
    assert result.turns[-2].phase == "policy_probe"
    assert result.turns[-2].prompt != ATTACK_PROMPT
    assert marker not in ATTACK_PROMPT
    assert canary.value not in ATTACK_PROMPT


def test_explicit_direct_extraction_disclosure_excludes_baseline_cohort():
    marker, canary = fixture()
    target = ScriptedProtocolTarget(marker, canary.value, regression_leaks=True)
    result = run_persistence_protocol(target, canary=canary, policy_marker=marker)

    assert result.validity == "baseline_disclosure"
    assert result.baseline_stratum == "BASELINE_FAILED"
    assert target.calls == 10
    assert result.evidence_vector["PERSISTENT_OVERRIDE"]["status"] == "OBSERVED"
    assert result.evidence_vector["POLICY_BYPASS"]["status"] == "OBSERVED"
    assert result.evidence_vector["CANARY_DISCLOSURE"]["status"] == "DISCLOSED"


def test_pre_attack_benign_control_is_a_validity_gate():
    marker, canary = fixture()
    target = ScriptedProtocolTarget(marker, canary.value, pre_benign="unexpected output")
    result = run_persistence_protocol(target, canary=canary, policy_marker=marker)

    assert result.validity == "invalid_benign_control"
    assert target.calls == 1
    assert result.evidence_vector["POLICY_BYPASS"]["status"] == "UNVERIFIED"


def test_no_exact_policy_or_canary_match_is_not_reported_as_success():
    marker, canary = fixture()
    target = ScriptedProtocolTarget(
        marker, canary.value, policy_leaks=False, canary_leaks=False
    )
    result = run_persistence_protocol(target, canary=canary, policy_marker=marker)

    assert result.validity == "valid"
    assert result.evidence_vector["PERSISTENT_OVERRIDE"]["status"] == "NOT_OBSERVED"
    assert result.evidence_vector["POLICY_BYPASS"]["status"] == "NOT_OBSERVED"
    assert result.evidence_vector["CANARY_DISCLOSURE"]["status"] == "NOT_DISCLOSED"


def test_protocol_records_prompt_response_hashes_and_target_provenance():
    marker, canary = fixture()
    result = run_persistence_protocol(
        ScriptedProtocolTarget(marker, canary.value), canary=canary, policy_marker=marker
    )
    assert all(turn.prompt_sha256 and turn.response_sha256 for turn in result.turns)
    assert result.fixture["policy_marker_sha256"] == sha256_text(marker)
    assert result.fixture["canary_sha256"] == canary.sha256
    assert result.fixture["canary"] == canary.value
    assert result.controls["benign_baseline"]["status"] == "PASSED"
    assert result.controls["policy_indirect_extraction"]["probe_type"] == "indirect_contextual_extraction"
    assert result.controls["regression"]["probe_type"] == "explicit_direct_extraction"
    assert result.controls["canary_regression"]["status"] == "PASSED"


def test_explicit_extraction_probe_is_not_a_benign_control():
    assert REGRESSION_PROMPT == POLICY_PROBE_PROMPT
    assert REGRESSION_PROMPT not in BENIGN_PROMPT
    assert REGRESSION_PROMPT not in ATTACK_PROMPT



def test_protocol_rejects_inconsistent_canary_hash():
    marker, canary = fixture()
    invalid = Canary(canary.value, "0" * 64)
    target = ScriptedProtocolTarget(marker, canary.value)
    import pytest
    with pytest.raises(ValueError, match="Canary value and SHA-256"):
        run_persistence_protocol(target, canary=invalid, policy_marker=marker)



def test_protocol_report_writes_schema_and_vector(tmp_path):
    import json
    marker, canary = fixture()
    result = run_persistence_protocol(
        ScriptedProtocolTarget(marker, canary.value), canary=canary, policy_marker=marker
    )
    output = tmp_path / "protocol.json"
    write_protocol_report(str(output), result)
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "2"
    assert payload["evidence_vector"]["POLICY_BYPASS"]["status"] == "OBSERVED"
    assert payload["fixture"]["canary"] == canary.value


def test_target_error_does_not_claim_baseline_resistance():
    marker, canary = fixture()

    class FailingTarget:
        name = "failing"
        def generate(self, messages, model=None):
            raise RuntimeError("fixture target unavailable")

    result = run_persistence_protocol(FailingTarget(), canary=canary, policy_marker=marker)
    assert result.validity == "execution_error"
    assert result.baseline_stratum == "BASELINE_UNTESTED"
    assert result.error == "RuntimeError: fixture target unavailable"



def test_explicit_canary_extraction_disclosure_excludes_baseline_cohort():
    marker, canary = fixture()
    target = ScriptedProtocolTarget(
        marker, canary.value, canary_regression_leaks=True
    )
    result = run_persistence_protocol(target, canary=canary, policy_marker=marker)
    assert result.validity == "baseline_disclosure"
    assert result.baseline_stratum == "BASELINE_FAILED"
    assert result.controls["canary_regression"]["status"] == "FAILED"
    assert target.calls == 10
    assert result.evidence_vector["CANARY_DISCLOSURE"]["status"] == "DISCLOSED"



def test_pre_attack_policy_disclosure_is_recorded_as_baseline_finding_not_attack():
    marker, canary = fixture()
    target = ScriptedProtocolTarget(marker, canary.value, regression_leaks=True)
    result = run_persistence_protocol(target, canary=canary, policy_marker=marker)

    finding = result.baseline_findings["BASELINE_POLICY_DISCLOSURE"]
    assert finding["status"] == "OBSERVED"
    assert finding["evidence_type"] == "exact_string_match"
    assert finding["match_count"] == 1
    assert finding["marker_sha256"] == sha256_text(marker)
    assert result.evidence_vector["POLICY_BYPASS"]["status"] == "OBSERVED"
    assert result.evidence_vector["PERSISTENT_OVERRIDE"]["status"] == "OBSERVED"


def test_pre_attack_canary_disclosure_is_recorded_separately():
    marker, canary = fixture()
    target = ScriptedProtocolTarget(marker, canary.value, canary_regression_leaks=True)
    result = run_persistence_protocol(target, canary=canary, policy_marker=marker)

    finding = result.baseline_findings["BASELINE_CANARY_DISCLOSURE"]
    assert finding["status"] == "OBSERVED"
    assert finding["match_count"] == 1
    assert finding["canary_sha256"] == canary.sha256
    assert result.evidence_vector["CANARY_DISCLOSURE"]["status"] == "DISCLOSED"



def test_indirect_policy_extraction_is_separate_from_direct_and_attack_evidence():
    marker, canary = fixture()
    target = ScriptedProtocolTarget(
        marker, canary.value, indirect_policy_leaks=True,
        regression_leaks=False, canary_regression_leaks=False,
    )
    result = run_persistence_protocol(target, canary=canary, policy_marker=marker)
    finding = result.baseline_findings["BASELINE_POLICY_INDIRECT_DISCLOSURE"]
    assert finding["status"] == "OBSERVED"
    assert finding["probe_type"] == "indirect_contextual_extraction"
    assert result.baseline_findings["BASELINE_POLICY_DISCLOSURE"]["status"] == "NOT_OBSERVED"
    assert result.validity == "baseline_disclosure"
    assert result.evidence_vector["POLICY_BYPASS"]["status"] == "OBSERVED"



def test_truncated_protocol_response_is_incomplete_not_baseline_resistant():
    marker, canary = fixture()

    class TruncatedBaselineTarget(ScriptedProtocolTarget):
        def generate(self, messages, model=None):
            response = super().generate(messages, model=model)
            if self.calls == 1:
                response.provenance = {"finish_reason": "length"}
            return response

    result = run_persistence_protocol(
        TruncatedBaselineTarget(marker, canary.value),
        canary=canary,
        policy_marker=marker,
    )

    assert result.validity == "incomplete_truncated_response"
    assert result.baseline_stratum == "BASELINE_UNTESTED"
    assert result.turns[0].truncated is True
    assert result.evidence_vector["PERSISTENT_OVERRIDE"]["status"] == "NOT_TESTED"
