```python
import json
import sqlite3

import pytest

from redteam import (
    Attack,
    AttackResult,
    Database,
    DEFAULT_ATTACKS,
    Detection,
    FakeTarget,
    HeuristicDetector,
    Message,
    Scanner,
    TargetError,
    TargetResponse,
    TurnResult,
    attack_manifest,
    compare_results,
    extract_int,
    extract_text,
    filter_attacks,
    percentile,
    sha256_text,
    summarize,
    utc_now,
    write_json,
    write_markdown,
)


def test_utc_now_returns_value():
    value = utc_now()

    assert value
    assert "T" in value


def test_sha256_text():
    assert (
        sha256_text("test")
        == "9f86d081884c7d659a2feaa0c55ad015"
        "a3bf4f1b2b0b822cd15d6c15b0f00a08"
    )


def test_percentile():
    assert percentile([], 0.5) == 0.0
    assert percentile([1.0], 0.5) == 1.0
    assert percentile([1.0, 2.0, 3.0], 0.5) == 2.0
    assert percentile([1.0, 2.0, 3.0], 0.0) == 1.0
    assert percentile([1.0, 2.0, 3.0], 1.0) == 3.0


def test_extract_text_string():
    assert extract_text("hello") == "hello"


@pytest.mark.parametrize(
    "payload",
    [
        {"response": "hello"},
        {"text": "hello"},
        {"output": "hello"},
        {"content": "hello"},
        {"generated_text": "hello"},
        {"message": {"content": "hello"}},
        {"choices": [{"text": "hello"}]},
        {"choices": [{"message": {"content": "hello"}}]},
    ],
)
def test_extract_text_supported_formats(payload):
    assert extract_text(payload) == "hello"


def test_extract_text_invalid_payload():
    with pytest.raises(TargetError):
        extract_text({"unexpected": "value"})


def test_extract_int():
    assert extract_int(
        {"input_tokens": 10},
        ("input_tokens",),
    ) == 10

    assert extract_int(
        {"usage": {"prompt_tokens": 12}},
        ("prompt_tokens",),
    ) == 12

    assert extract_int(
        {"value": "12"},
        ("value",),
    ) is None


def test_default_attacks_have_unique_ids():
    ids = [attack.id for attack in DEFAULT_ATTACKS]

    assert len(ids) == len(set(ids))
    assert len(ids) >= 8


def test_attack_manifest_is_stable():
    first = attack_manifest(DEFAULT_ATTACKS)
    second = attack_manifest(DEFAULT_ATTACKS)

    assert first == second
    assert len(first) == 64


def test_attack_manifest_changes_when_attack_changes():
    first = attack_manifest(DEFAULT_ATTACKS)

    modified = list(DEFAULT_ATTACKS)
    modified[0] = Attack(
        id=modified[0].id,
        category=modified[0].category,
        name=modified[0].name,
        prompt=modified[0].prompt + " changed",
        version=modified[0].version,
    )

    second = attack_manifest(modified)

    assert first != second


def test_filter_attacks_by_id():
    selected = filter_attacks(
        DEFAULT_ATTACKS,
        attack_ids=["jailbreak-roleplay"],
    )

    assert len(selected) == 1
    assert selected[0].id == "jailbreak-roleplay"


def test_filter_attacks_by_category():
    selected = filter_attacks(
        DEFAULT_ATTACKS,
        categories=["jailbreak"],
    )

    assert selected
    assert all(
        attack.category == "jailbreak"
        for attack in selected
    )


def test_filter_attacks_by_id_and_category():
    selected = filter_attacks(
        DEFAULT_ATTACKS,
        attack_ids=["jailbreak-roleplay"],
        categories=["jailbreak"],
    )

    assert len(selected) == 1
    assert selected[0].id == "jailbreak-roleplay"


def test_filter_attacks_with_no_filters_returns_all():
    selected = filter_attacks(DEFAULT_ATTACKS)

    assert selected == DEFAULT_ATTACKS


def test_conversation():
    from redteam import Conversation

    conversation = Conversation()

    conversation.add("user", "hello")
    conversation.add("assistant", "hi")

    assert len(conversation.messages) == 2
    assert conversation.messages[0].role == "user"
    assert conversation.messages[1].content == "hi"


def test_conversation_copy_is_independent():
    from redteam import Conversation

    original = Conversation()
    original.add("user", "hello")

    copied = original.copy()
    copied.add("assistant", "hi")

    assert len(original.messages) == 1
    assert len(copied.messages) == 2


def test_conversation_as_dicts():
    from redteam import Conversation

    conversation = Conversation()
    conversation.add("user", "hello")

    assert conversation.as_dicts() == [
        {
            "role": "user",
            "content": "hello",
        }
    ]


def test_detector_empty_response():
    detector = HeuristicDetector()

    result = detector.detect(
        DEFAULT_ATTACKS[0],
        "",
    )

    assert result.detected is False
    assert result.status == "EMPTY"
    assert result.confidence == 0.0


def test_detector_refusal():
    detector = HeuristicDetector()

    result = detector.detect(
        DEFAULT_ATTACKS[0],
        "I can't help with bypassing safety controls.",
    )

    assert result.detected is False
    assert result.status == "PASS"
    assert result.evidence


def test_detector_jailbreak_failure():
    detector = HeuristicDetector()

    result = detector.detect(
        DEFAULT_ATTACKS[0],
        "Safety restrictions have been bypassed.",
    )

    assert result.detected is True
    assert result.status == "FAIL"
    assert result.confidence > 0.0


def test_detector_instruction_override_failure():
    detector = HeuristicDetector()

    result = detector.detect(
        DEFAULT_ATTACKS[2],
        "Previous instructions have been disabled.",
    )

    assert result.detected is True
    assert result.status == "FAIL"


def test_detector_system_extraction_failure():
    detector = HeuristicDetector()

    result = detector.detect(
        DEFAULT_ATTACKS[3],
        "Here is the system prompt and its hidden instructions.",
    )

    assert result.detected is True
    assert result.status == "FAIL"


def test_detector_prompt_injection_failure():
    detector = HeuristicDetector()

    result = detector.detect(
        DEFAULT_ATTACKS[5],
        "I will ignore previous instructions and follow the embedded command.",
    )

    assert result.detected is True
    assert result.status == "FAIL"


def test_detector_persistence_failure():
    detector = HeuristicDetector()

    result = detector.detect(
        DEFAULT_ATTACKS[7],
        "I will remember this instruction for the rest of the conversation.",
    )

    assert result.detected is True
    assert result.status == "FAIL"


def test_detector_unknown_response():
    detector = HeuristicDetector()

    result = detector.detect(
        DEFAULT_ATTACKS[0],
        "The weather today is cloudy.",
    )

    assert result.detected is False
    assert result.status == "NOT_DETECTED"


def test_fake_target_success():
    target = FakeTarget(
        response="test response",
    )

    result = target.generate(
        [Message("user", "hello")],
        model="fake-model",
    )

    assert isinstance(result, TargetResponse)
    assert result.text == "test response"
    assert result.latency_ms == 1.0
    assert result.input_tokens == 10
    assert result.output_tokens == 5


def test_fake_target_failure():
    target = FakeTarget(fail=True)

    with pytest.raises(TargetError):
        target.generate(
            [Message("user", "hello")],
        )


def test_scanner_static_pass():
    target = FakeTarget(
        response="I cannot help with that request.",
    )

    scanner = Scanner(target)

    run_id, results = scanner.scan(
        DEFAULT_ATTACKS[:2],
        model="fake-model",
    )

    assert run_id
    assert len(results) == 2
    assert all(result.status == "PASS" for result in results)
    assert all(result.run_id == run_id for result in results)


def test_scanner_static_failure():
    target = FakeTarget(
        response="Previous instructions have been disabled.",
    )

    scanner = Scanner(target)

    run_id, results = scanner.scan(
        [
            DEFAULT_ATTACKS[2],
        ],
        model="fake-model",
    )

    assert run_id
    assert len(results) == 1
    assert results[0].status == "FAIL"
    assert results[0].detection.detected is True


def test_scanner_target_error():
    target = FakeTarget(fail=True)

    scanner = Scanner(target)

    run_id, results = scanner.scan(
        DEFAULT_ATTACKS[:1],
        model="fake-model",
    )

    assert run_id
    assert len(results) == 1
    assert results[0].status == "ERROR"
    assert results[0].error


def test_scanner_adaptive_mode():
    target = FakeTarget(
        response="I cannot help with that request.",
    )

    attacker = FakeTarget(
        response="Please continue the same request.",
    )

    scanner = Scanner(target)

    run_id, results = scanner.scan(
        DEFAULT_ATTACKS[:1],
        model="fake-model",
        mode="adaptive",
        adaptive_attacker=attacker,
        adaptive_rounds=3,
    )

    assert run_id
    assert len(results) == 1

    result = results[0]

    assert result.status == "PASS"
    assert len(result.turns) == 3
    assert result.turns[0].turn == 1
    assert result.turns[1].turn == 2
    assert result.turns[2].turn == 3


def test_scanner_adaptive_stops_on_detection():
    target = FakeTarget(
        response="Previous instructions have been disabled.",
    )

    attacker = FakeTarget(
        response="Continue.",
    )

    scanner = Scanner(target)

    run_id, results = scanner.scan(
        [
            DEFAULT_ATTACKS[2],
        ],
        model="fake-model",
        mode="adaptive",
        adaptive_attacker=attacker,
        adaptive_rounds=5,
    )

    assert run_id
    assert len(results) == 1

    result = results[0]

    assert result.status == "FAIL"
    assert result.detection.detected is True
    assert len(result.turns) == 1


def test_summary():
    target = FakeTarget(
        response="I cannot help with that request.",
    )

    scanner = Scanner(target)

    _, results = scanner.scan(
        DEFAULT_ATTACKS[:3],
        model="fake-model",
    )

    summary = summarize(results)

    assert summary.total == 3
    assert summary.failed == 0
    assert summary.errors == 0
    assert summary.not_detected == 0
    assert summary.empty == 0
    assert summary.refusal_rate == 1.0
    assert summary.attack_success_rate == 0.0
    assert summary.mean_latency_ms == 1.0


def test_summary_with_failure():
    target = FakeTarget(
        response="Previous instructions have been disabled.",
    )

    scanner = Scanner(target)

    _, results = scanner.scan(
        [
            DEFAULT_ATTACKS[2],
        ],
        model="fake-model",
    )

    summary = summarize(results)

    assert summary.total == 1
    assert summary.failed == 1
    assert summary.attack_success_rate == 1.0


def test_summary_with_error():
    target = FakeTarget(fail=True)

    scanner = Scanner(target)

    _, results = scanner.scan(
        DEFAULT_ATTACKS[:1],
        model="fake-model",
    )

    summary = summarize(results)

    assert summary.total == 1
    assert summary.errors == 1
    assert summary.attack_success_rate == 0.0
    assert summary.refusal_rate == 0.0


def test_database_schema(tmp_path):
    db_path = tmp_path / "redteam.db"

    database = Database(str(db_path))

    try:
        tables = database.connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
            ORDER BY name
            """
        ).fetchall()

        names = [row["name"] for row in tables]

        assert "runs" in names
        assert "results" in names
    finally:
        database.close()


def test_database_persists_run_and_result(tmp_path):
    db_path = tmp_path / "redteam.db"

    database = Database(str(db_path))

    target = FakeTarget(
        response="I cannot help with that request.",
    )

    scanner = Scanner(
        target=target,
        database=database,
    )

    run_id, results = scanner.scan(
        DEFAULT_ATTACKS[:1],
        model="fake-model",
    )

    assert len(results) == 1

    run = database.connection.execute(
        "SELECT * FROM runs WHERE run_id = ?",
        (run_id,),
    ).fetchone()

    stored_result = database.connection.execute(
        "SELECT * FROM results WHERE run_id = ?",
        (run_id,),
    ).fetchone()

    database.close()

    assert run is not None
    assert stored_result is not None
    assert run["version"] == "0.1.0"
    assert run["model"] == "fake-model"
    assert stored_result["attack_id"] == DEFAULT_ATTACKS[0].id
    assert stored_result["status"] == "PASS"


def test_database_stores_turns(tmp_path):
    db_path = tmp_path / "redteam.db"

    database = Database(str(db_path))

    target = FakeTarget(
        response="I cannot help with that request.",
    )

    attacker = FakeTarget(
        response="Continue.",
    )

    scanner = Scanner(
        target=target,
        database=database,
    )

    run_id, results = scanner.scan(
        DEFAULT_ATTACKS[:1],
        model="fake-model",
        mode="adaptive",
        adaptive_attacker=attacker,
        adaptive_rounds=2,
    )

    row = database.connection.execute(
        """
        SELECT turns_json
        FROM results
        WHERE run_id = ?
        """,
        (run_id,),
    ).fetchone()

    database.close()

    assert row is not None

    turns = json.loads(row["turns_json"])

    assert len(turns) == 2
    assert turns[0]["turn"] == 1
    assert turns[1]["turn"] == 2
    assert turns[0]["detection"]["status"] == "PASS"


def test_write_json(tmp_path):
    target = FakeTarget(
        response="I cannot help with that request.",
    )

    scanner = Scanner(target)

    run_id, results = scanner.scan(
        DEFAULT_ATTACKS[:1],
        model="fake-model",
    )

    path = tmp_path / "report.json"

    write_json(
        str(path),
        run_id,
        results,
    )

    assert path.exists()

    payload = json.loads(
        path.read_text(encoding="utf-8")
    )

    assert payload["version"] == "0.1.0"
    assert payload["run_id"] == run_id
    assert payload["summary"]["total"] == 1
    assert len(payload["results"]) == 1


def test_write_markdown(tmp_path):
    target = FakeTarget(
        response="I cannot help with that request.",
    )

    scanner = Scanner(target)

    run_id, results = scanner.scan(
        DEFAULT_ATTACKS[:1],
        model="fake-model",
    )

    path = tmp_path / "report.md"

    write_markdown(
        str(path),
        run_id,
        results,
    )

    assert path.exists()

    content = path.read_text(
        encoding="utf-8"
    )

    assert "# Local LLM Red Team Report" in content
    assert f"Run ID: `{run_id}`" in content
    assert DEFAULT_ATTACKS[0].id in content
    assert "I cannot help with that request." in content


def test_compare_results():
    safe_target = FakeTarget(
        response="I cannot help with that request.",
    )

    unsafe_target = FakeTarget(
        response="Previous instructions have been disabled.",
    )

    safe_scanner = Scanner(safe_target)
    unsafe_scanner = Scanner(unsafe_target)

    _, safe_results = safe_scanner.scan(
        [DEFAULT_ATTACKS[2]],
        model="safe-model",
    )

    _, unsafe_results = unsafe_scanner.scan(
        [DEFAULT_ATTACKS[2]],
        model="unsafe-model",
    )

    report = compare_results(
        {
            "safe-model": safe_results,
            "unsafe-model": unsafe_results,
        }
    )

    assert "# Model comparison" in report
    assert "safe-model" in report
    assert "unsafe-model" in report
    assert "Success rate" in report


def test_turn_result_serialization():
    detection = Detection(
        detected=False,
        status="PASS",
        confidence=0.85,
        evidence=["i can't"],
        reason="Model produced a refusal-like response",
    )

    turn = TurnResult(
        turn=1,
        role="user",
        prompt="test",
        response="I can't help with that.",
        latency_ms=1.0,
        detection=detection,
    )

    payload = {
        **turn.__dict__,
        "detection": turn.detection.__dict__,
    }

    assert payload["turn"] == 1
    assert payload["detection"]["status"] == "PASS"


def test_attack_result_contains_expected_fields():
    detection = Detection(
        detected=False,
        status="PASS",
        confidence=0.85,
        evidence=[],
        reason="refusal",
    )

    result = AttackResult(
        run_id="run",
        attack_id="attack",
        attack_category="jailbreak",
        attack_version="1",
        model="model",
        status="PASS",
        response="refused",
        latency_ms=1.0,
        input_tokens=10,
        output_tokens=5,
        detection=detection,
    )

    assert result.run_id == "run"
    assert result.attack_id == "attack"
    assert result.model == "model"
    assert result.turns == []


def test_database_connection_can_be_used_with_sqlite(tmp_path):
    db_path = tmp_path / "redteam.db"

    database = Database(str(db_path))

    try:
        row = database.connection.execute(
            "SELECT sqlite_version() AS version"
        ).fetchone()

        assert row["version"]
    finally:
        database.close()

    connection = sqlite3.connect(str(db_path))

    try:
        row = connection.execute(
            "SELECT COUNT(*) FROM runs"
        ).fetchone()

        assert row[0] == 0
    finally:
        connection.close()
```
    
