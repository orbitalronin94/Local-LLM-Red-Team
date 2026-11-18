"""Deterministic reference guardrail for tool actions.

This module never executes tools. It only decides whether an application may
forward a proposed action to its own tool adapter. The caller remains
responsible for authenticating the user and obtaining a real confirmation.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRES_CONFIRMATION = "REQUIRES_CONFIRMATION"


UNTRUSTED_INSTRUCTION_SOURCES = frozenset({
    "retrieved_content", "document", "web_page", "tool_output", "memory",
})
DEFAULT_CONFIRMATION_OPERATIONS = frozenset({
    "send", "delete", "write", "execute", "purchase", "publish",
})


@dataclass(frozen=True)
class ActionRequest:
    tool: str
    operation: str
    instruction_source: str = "model"
    requires_confirmation: bool = False


@dataclass(frozen=True)
class ActionScope:
    """Capabilities explicitly authorized by the trusted user task."""
    allowed_operations: Mapping[str, frozenset[str]]
    confirmation_operations: frozenset[str] = DEFAULT_CONFIRMATION_OPERATIONS


@dataclass(frozen=True)
class GuardrailResult:
    decision: Decision
    reason: str
    tool: str
    operation: str

    def as_dict(self) -> dict[str, str]:
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "tool": self.tool,
            "operation": self.operation,
        }


def evaluate_action(
    request: ActionRequest,
    scope: ActionScope,
    *,
    user_confirmed: bool = False,
) -> GuardrailResult:
    """Evaluate a proposed action without executing it.

    Authority comes from the explicit task scope, never from retrieved
    documents, web pages, memory, or tool output. A model-generated proposal
    can be considered only when it stays inside that pre-authorized scope.
    """
    tool = request.tool.strip()
    operation = request.operation.strip().lower()

    def result(decision: Decision, reason: str) -> GuardrailResult:
        return GuardrailResult(decision, reason, tool, operation)

    if not tool or not operation:
        return result(Decision.DENY, "missing_tool_or_operation")

    source = request.instruction_source.strip().lower()
    if source in UNTRUSTED_INSTRUCTION_SOURCES:
        return result(Decision.DENY, "untrusted_content_cannot_grant_authority")
    if source != "model":
        return result(Decision.DENY, "unknown_instruction_source")

    allowed = scope.allowed_operations.get(tool, frozenset())
    if operation not in allowed:
        return result(Decision.DENY, "outside_explicit_task_scope")

    needs_confirmation = (
        request.requires_confirmation
        or operation in scope.confirmation_operations
    )
    if needs_confirmation and user_confirmed is not True:
        return result(Decision.REQUIRES_CONFIRMATION, "explicit_user_confirmation_required")

    return result(Decision.ALLOW, "within_scope_and_authorized")
