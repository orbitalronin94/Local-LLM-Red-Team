#!/usr/bin/env python3
"""Run a scan with an API key loaded from the environment, not argv.

Usage:
  python scripts/secure_endpoint_scan.py --api-key-env REDTEAM_API_KEY \
      --target openai --url https://staging.example.invalid/v1 --model staging-bot

Use --runner scenarios to run the deterministic multi-turn suite instead.
The wrapper never prints the credential. The key is passed to the existing
scanner in-process; it is not included in the operating-system command line.
"""
from __future__ import annotations

import argparse
import os
import re
import runpy
import sys
from pathlib import Path


def resolve_invocation(argv: list[str], environ: dict[str, str]):
    parser = argparse.ArgumentParser(
        description="Run Local LLM Red Team using an environment-backed API key."
    )
    parser.add_argument(
        "--api-key-env",
        default="LOCAL_LLM_REDTEAM_API_KEY",
        help="environment variable containing the API key (default: LOCAL_LLM_REDTEAM_API_KEY)",
    )
    parser.add_argument(
        "--runner",
        choices=("redteam", "scenarios"),
        default="redteam",
        help="test suite to run (default: redteam)",
    )
    wrapper, forwarded = parser.parse_known_args(argv)

    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", wrapper.api_key_env):
        raise ValueError("--api-key-env must be a valid environment variable name")
    if any(arg == "--api-key" or arg.startswith("--api-key=") for arg in forwarded):
        raise ValueError("Do not pass --api-key to this wrapper; use --api-key-env")
    secret = environ.get(wrapper.api_key_env)
    if not secret:
        raise ValueError(
            f"Environment variable {wrapper.api_key_env!r} is missing or empty"
        )
    return wrapper.runner, forwarded, secret


def main(argv: list[str] | None = None) -> int:
    runner, forwarded, secret = resolve_invocation(
        list(sys.argv[1:] if argv is None else argv),
        os.environ,
    )
    root = Path(__file__).resolve().parents[1]
    target_script = root / ("redteam.py" if runner == "redteam" else "scenarios.py")
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    original_argv = sys.argv
    try:
        # The secret exists in Python process memory but not the OS process
        # command line. Never print argv or include it in report metadata.
        sys.argv = [str(target_script), *forwarded, "--api-key", secret]
        runpy.run_path(str(target_script), run_name="__main__")
    finally:
        sys.argv = original_argv
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
