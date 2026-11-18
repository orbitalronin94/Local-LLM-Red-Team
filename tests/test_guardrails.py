import pytest

from guardrails import ActionRequest, ActionScope, Decision, evaluate_action


@pytest.fixture
def scope():
    return ActionScope({
        "calendar": frozenset({"read", "create"}),
        "mail": frozenset({"draft", "send"}),
    })


@pytest.mark.parametrize("source", [
    "retrieved_content", "document", "web_page", "tool_output", "memory",
])
def test_untrusted_content_cannot_authorize_action(scope, source):
    result = evaluate_action(
        ActionRequest("mail", "send", instruction_source=source),
        scope,
        user_confirmed=True,
    )
    assert result.decision is Decision.DENY
    assert result.reason == "untrusted_content_cannot_grant_authority"


def test_out_of_scope_action_is_denied_even_if_user_confirmed(scope):
    result = evaluate_action(ActionRequest("shell", "execute"), scope, user_confirmed=True)
    assert result.decision is Decision.DENY
    assert result.reason == "outside_explicit_task_scope"


def test_model_proposal_within_scope_can_read(scope):
    assert evaluate_action(ActionRequest("calendar", "read"), scope).decision is Decision.ALLOW


def test_side_effect_requires_explicit_confirmation(scope):
    assert evaluate_action(ActionRequest("mail", "send"), scope).decision is Decision.REQUIRES_CONFIRMATION


def test_confirmation_allows_only_pre_authorized_action(scope):
    assert evaluate_action(
        ActionRequest("mail", "send"), scope, user_confirmed=True
    ).decision is Decision.ALLOW


def test_explicit_request_confirmation_applies_to_safe_operation(scope):
    assert evaluate_action(
        ActionRequest("calendar", "read", requires_confirmation=True), scope
    ).decision is Decision.REQUIRES_CONFIRMATION


def test_unknown_source_is_denied(scope):
    result = evaluate_action(
        ActionRequest("calendar", "read", instruction_source="plugin_magic"), scope
    )
    assert result.decision is Decision.DENY
    assert result.reason == "unknown_instruction_source"


def test_empty_tool_or_operation_is_denied(scope):
    assert evaluate_action(ActionRequest("", "read"), scope).decision is Decision.DENY
    assert evaluate_action(ActionRequest("calendar", " "), scope).decision is Decision.DENY


def test_result_is_json_friendly(scope):
    result = evaluate_action(ActionRequest("calendar", "read"), scope)
    assert result.as_dict() == {
        "decision": "ALLOW",
        "reason": "within_scope_and_authorized",
        "tool": "calendar",
        "operation": "read",
    }
