"""Replay one static attack from a previous JSON report.

Replay preserves the original prompt and verifies its recorded hash. The target
endpoint, model revision and runtime must still be supplied by the operator.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from redteam import Attack, HeuristicDetector, Message, build_target, detector_fingerprint, sha256_text


REPLAY_SCHEMA_VERSION = "1"


def load_source_attack(
    report_path: str,
    attack_id: str,
    source_run_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load one attack record and verify its prompt digest when present."""
    try:
        payload = json.loads(Path(report_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read source report: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise ValueError("Source report must contain a results array")
    run_id = payload.get("run_id")
    if source_run_id and run_id != source_run_id:
        raise ValueError("Source run ID does not match the requested run ID")
    matches = [
        item for item in payload["results"]
        if isinstance(item, dict) and item.get("attack_id") == attack_id
    ]
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one result for attack {attack_id!r}; found {len(matches)}")
    record = matches[0]
    prompt = record.get("prompt")
    if not isinstance(prompt, str) or not prompt:
        raise ValueError("Source result does not contain the original prompt")
    recorded_hash = record.get("prompt_sha256")
    actual_hash = sha256_text(prompt)
    if recorded_hash and recorded_hash != actual_hash:
        raise ValueError("Source prompt SHA-256 does not match the stored prompt")
    source = {
        "run_id": run_id,
        "run_metadata": payload.get("run_metadata", {}),
        "prompt_hash_verified": bool(recorded_hash),
        "prompt_sha256": actual_hash,
        "response_sha256": record.get("response_sha256"),
    }
    attack = {
        "id": attack_id,
        "category": record.get("attack_category", "unknown"),
        "name": attack_id,
        "version": str(record.get("attack_version", "1")),
        "prompt": prompt,
    }
    return source, attack


def replay_attack(
    source: dict[str, Any],
    attack_data: dict[str, Any],
    target: Any,
    *,
    model: str | None = None,
    seed: int = 42,
    temperature: float = 0.0,
) -> dict[str, Any]:
    """Replay the stored prompt once and return a provenance-rich record."""
    attack = Attack(**attack_data)
    response = target.generate([Message(role="user", content=attack.prompt)], model=model)
    detection = HeuristicDetector().detect(attack, response.text)
    return {
        "schema_version": REPLAY_SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "attack": asdict(attack),
        "target": {
            "type": target.name,
            "model": model,
            "seed": seed,
            "temperature": temperature,
        },
        "detector": {
            "name": "heuristic",
            "fingerprint_sha256": detector_fingerprint(),
        },
        "prompt_sha256": sha256_text(attack.prompt),
        "response": response.text,
        "response_sha256": sha256_text(response.text),
        "latency_ms": response.latency_ms,
        "input_tokens": response.input_tokens,
        "output_tokens": response.output_tokens,
        "target_provenance": response.provenance,
        "detection": asdict(detection),
        "interpretation": (
            "A replay is a new execution, not a byte-for-byte reproduction of model output. "
            "Compare target identity and runtime settings before interpreting differences."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay one static attack from a JSON report")
    parser.add_argument("--report", required=True, help="Original JSON report")
    parser.add_argument("--attack-id", required=True)
    parser.add_argument("--source-run-id")
    parser.add_argument("--target", choices=["ollama", "openai", "http"])
    parser.add_argument("--model")
    parser.add_argument("--url")
    parser.add_argument("--api-key", default=os.environ.get("REDTEAM_API_KEY"))
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--temperature", type=float)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--output", default="replay.json")
    args = parser.parse_args()

    try:
        source, attack_data = load_source_attack(args.report, args.attack_id, args.source_run_id)
        metadata = source.get("run_metadata") or {}
        identity = metadata.get("target_identity") or {}
        args.target = args.target or metadata.get("target_type") or "ollama"
        args.model = args.model or metadata.get("model")
        args.temperature = args.temperature if args.temperature is not None else identity.get("temperature", 0.0)
        args.seed = args.seed if args.seed is not None else identity.get("seed", 42)
        target = build_target(args)
        result = replay_attack(
            source, attack_data, target, model=args.model,
            seed=args.seed, temperature=args.temperature,
        )
        Path(args.output).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"Replay failed: {exc}", file=sys.stderr)
        return 2

    print(f"Replayed {args.attack_id}; JSON: {args.output}")
    print(f"Source prompt hash verified: {source['prompt_hash_verified']}")
    print(f"New response SHA-256: {result['response_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
