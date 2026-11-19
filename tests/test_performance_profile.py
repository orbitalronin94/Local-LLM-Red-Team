import json
import pytest
import redteam
from redteam import Message, OllamaTarget, OpenAICompatibleTarget, select_profile_attacks, DEFAULT_ATTACKS

class FakeHTTPResponse:
    def __init__(self, payload): self.payload = payload
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self): return json.dumps(self.payload).encode("utf-8")

def capture_request(monkeypatch, payload):
    captured = {}
    def fake_open(request, timeout):
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        return FakeHTTPResponse(payload)
    monkeypatch.setattr(redteam, "open_http_request", fake_open)
    return captured

def test_openai_target_applies_optional_generation_cap(monkeypatch):
    captured = capture_request(monkeypatch, {"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]})
    OpenAICompatibleTarget(max_output_tokens=96).generate([Message("user", "test")], model="fixture")
    assert captured["payload"]["max_tokens"] == 96

def test_ollama_target_maps_generation_cap_to_num_predict(monkeypatch):
    captured = capture_request(monkeypatch, {"message": {"content": "ok"}, "done_reason": "length"})
    response = OllamaTarget(max_output_tokens=64).generate([Message("user", "test")], model="fixture")
    assert captured["payload"]["options"]["num_predict"] == 64
    assert response.provenance["finish_reason"] == "length"

def test_generation_cap_is_omitted_by_default(monkeypatch):
    captured = capture_request(monkeypatch, {"choices": [{"message": {"content": "ok"}}]})
    OpenAICompatibleTarget().generate([Message("user", "test")], model="fixture")
    assert "max_tokens" not in captured["payload"]

def test_generation_cap_must_be_positive():
    with pytest.raises(ValueError, match="positive integer"):
        OpenAICompatibleTarget(max_output_tokens=0)

def test_quick_profile_is_fixed_balanced_subset_and_full_is_unchanged():
    quick = select_profile_attacks("quick", DEFAULT_ATTACKS)
    assert len(quick) == 8
    assert len(select_profile_attacks("full", DEFAULT_ATTACKS)) == len(DEFAULT_ATTACKS)
    assert len({item.id for item in quick}) == len(quick)
    assert {item.category for item in quick} == {"jailbreak", "instruction_override", "system_extraction", "prompt_injection", "persistence"}
    assert any(item.id.startswith("es-") for item in quick)

def test_unknown_profile_is_rejected():
    with pytest.raises(ValueError, match="profile"):
        select_profile_attacks("typo", DEFAULT_ATTACKS)
