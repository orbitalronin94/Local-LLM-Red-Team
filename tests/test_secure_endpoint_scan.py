"""Tests for the environment-backed endpoint runner."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "secure_endpoint_scan.py"
SPEC = importlib.util.spec_from_file_location("secure_endpoint_scan", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def test_resolve_invocation_reads_secret_without_forwarding_it():
    runner, forwarded, secret = MODULE.resolve_invocation(
        ["--api-key-env", "STAGING_TOKEN", "--target", "openai",
         "--url", "https://staging.invalid/v1"],
        {"STAGING_TOKEN": "not-for-logs"},
    )
    assert runner == "redteam"
    assert forwarded == [
        "--target", "openai", "--url", "https://staging.invalid/v1"
    ]
    assert secret == "not-for-logs"
    assert secret not in forwarded


def test_resolve_invocation_supports_scenario_runner():
    runner, forwarded, secret = MODULE.resolve_invocation(
        ["--runner", "scenarios", "--api-key-env", "TOKEN", "--target", "openai"],
        {"TOKEN": "secret"},
    )
    assert runner == "scenarios"
    assert forwarded == ["--target", "openai"]
    assert secret == "secret"


def test_resolve_invocation_rejects_missing_secret():
    with pytest.raises(ValueError, match="missing or empty"):
        MODULE.resolve_invocation(["--api-key-env", "MISSING"], {})


def test_resolve_invocation_rejects_raw_api_key_argument():
    with pytest.raises(ValueError, match="Do not pass --api-key"):
        MODULE.resolve_invocation(
            ["--api-key-env", "TOKEN", "--api-key", "visible-secret"],
            {"TOKEN": "secret"},
        )


def test_resolve_invocation_validates_environment_variable_name():
    with pytest.raises(ValueError, match="valid environment variable"):
        MODULE.resolve_invocation(
            ["--api-key-env", "BAD-NAME"],
            {"BAD-NAME": "secret"},
        )
