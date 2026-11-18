"""Export machine findings into an explicit human-review worksheet."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from redteam import DEFAULT_ATTACKS


VERDICTS = (
    "NOT_REVIEWED",
    "CONFIRMED_COMPLIANCE",
    "REFUSED",
    "QUOTED_OR_ANALYTICAL",
    "PARTIAL_COMPLIANCE",
    "AMBIGUOUS",
)


def csv_safe_cell(value: Any) -> Any:
    """Neutralize spreadsheet formulas in untrusted report/reviewer text.

    CSV quoting alone does not prevent spreadsheet formula execution. Prefix
    potentially executable cells with an apostrophe while leaving ordinary
    values unchanged; the original report JSON remains the authoritative copy.
    """
    if not isinstance(value, str) or not value:
        return value
    first = value.lstrip(" \t\r\n")
    if value[0] in "\t\r\n" or (first and first[0] in "=+-@"):
        return "'" + value
    return value


def export_review(input_paths: list[str], output_path: str) -> int:
    prompts = {item.id: item.prompt for item in DEFAULT_ATTACKS}
    rows = []
    for input_path in input_paths:
        payload = json.loads(Path(input_path).read_text(encoding="utf-8"))
        metadata = payload.get("run_metadata", {})
        for result in payload.get("results", []):
            if "scenario_id" in result:
                continue
            turns = result.get("turns") or []
            prompt = turns[0].get("prompt", "") if turns else prompts.get(result.get("attack_id"), "")
            rows.append({
                "run_id": result.get("run_id", payload.get("run_id", "")),
                "mode": metadata.get("mode", "unknown"),
                "model": result.get("model", metadata.get("model", "")),
                "catalog_model_id": payload.get("model_metadata", metadata).get("catalog_model_id", ""),
                "model_repo_id": payload.get("model_metadata", metadata).get("model_repo_id", ""),
                "model_revision_requested": payload.get("model_metadata", metadata).get("model_revision_requested", ""),
                "model_revision_resolved": payload.get("model_metadata", metadata).get("model_revision_resolved", ""),
                "model_resolved_url": payload.get("model_metadata", metadata).get("model_resolved_url", ""),
                "quantization": payload.get("model_metadata", metadata).get("quantization", ""),
                "upstream_model": payload.get("model_metadata", metadata).get("upstream_model", ""),
                "model_sha256": payload.get("model_metadata", metadata).get("model_sha256", ""),
                "inference_engine": payload.get("model_metadata", metadata).get("inference_engine", ""),
                "inference_engine_commit": payload.get("model_metadata", metadata).get("inference_engine_commit", ""),
                "attack_id": result.get("attack_id", ""),
                "category": result.get("attack_category", ""),
                "heuristic_status": result.get("status", ""),
                "review_required": str(
                    result.get("detection", {}).get("review_required", False)
                    or result.get("status") in {"FAIL", "NOT_DETECTED"}
                ).lower(),
                "prompt": prompt,
                "response": result.get("response", ""),
                "detector_evidence": " | ".join(result.get("detection", {}).get("evidence", [])),
                "detector_reason": result.get("detection", {}).get("reason", ""),
                "detector_confidence": result.get("detection", {}).get("confidence", ""),
                "scanner_version": payload.get("scanner_version", payload.get("version", "")),
                "detector_name": metadata.get("detector", ""),
                "attack_version": result.get("attack_version", ""),
                "prompt_sha256": result.get("prompt_sha256", turns[0].get("prompt_sha256", "") if turns else ""),
                "response_sha256": result.get("response_sha256", turns[-1].get("response_sha256", "") if turns else ""),
                "turn_count": len(turns) if turns else 1,
                "reviewer_verdict": "NOT_REVIEWED",
                "reviewer_notes": "",
                "reviewed_by": "",
                "reviewed_at": "",
            })
        for result in payload.get("records", []):
            rows.append({
                "run_id": payload.get("run_id", ""),
                "mode": "paired-language",
                "model": payload.get("model", ""),
                "catalog_model_id": payload.get("model_metadata", {}).get("catalog_model_id", ""),
                "model_repo_id": payload.get("model_metadata", {}).get("model_repo_id", ""),
                "model_revision_requested": payload.get("model_metadata", {}).get("model_revision_requested", ""),
                "model_revision_resolved": payload.get("model_metadata", {}).get("model_revision_resolved", ""),
                "model_resolved_url": payload.get("model_metadata", {}).get("model_resolved_url", ""),
                "quantization": payload.get("model_metadata", {}).get("quantization", ""),
                "upstream_model": payload.get("model_metadata", {}).get("upstream_model", ""),
                "model_sha256": payload.get("model_metadata", {}).get("model_sha256", ""),
                "inference_engine": payload.get("model_metadata", {}).get("inference_engine", ""),
                "inference_engine_commit": payload.get("model_metadata", {}).get("inference_engine_commit", ""),
                "attack_id": result.get("attack_id", ""),
                "category": result.get("category", ""),
                "heuristic_status": result.get("status", ""),
                "review_required": str(result.get("review_required", True)).lower(),
                "prompt": result.get("prompt", ""),
                "response": result.get("response", ""),
                "detector_evidence": " | ".join(result.get("evidence", [])),
                "detector_reason": result.get("reason", ""),
                "detector_confidence": result.get("confidence", ""),
                "scanner_version": payload.get("scanner_version", payload.get("version", "")),
                "detector_name": payload.get("detector", ""),
                "attack_version": result.get("attack_version", ""),
                "prompt_sha256": result.get("prompt_sha256", ""),
                "response_sha256": result.get("response_sha256", ""),
                "turn_count": 1,
                "reviewer_verdict": "NOT_REVIEWED",
                "reviewer_notes": "",
                "reviewed_by": "",
                "reviewed_at": "",
            })
        for control in payload.get("benign_controls", []):
            rows.append({
                "run_id": payload.get("run_id", ""),
                "mode": "paired-benign-control",
                "model": payload.get("model", ""),
                "catalog_model_id": payload.get("model_metadata", {}).get("catalog_model_id", ""),
                "model_repo_id": payload.get("model_metadata", {}).get("model_repo_id", ""),
                "model_revision_requested": payload.get("model_metadata", {}).get("model_revision_requested", ""),
                "model_revision_resolved": payload.get("model_metadata", {}).get("model_revision_resolved", ""),
                "model_resolved_url": payload.get("model_metadata", {}).get("model_resolved_url", ""),
                "quantization": payload.get("model_metadata", {}).get("quantization", ""),
                "upstream_model": payload.get("model_metadata", {}).get("upstream_model", ""),
                "model_sha256": payload.get("model_metadata", {}).get("model_sha256", ""),
                "inference_engine": payload.get("model_metadata", {}).get("inference_engine", ""),
                "inference_engine_commit": payload.get("model_metadata", {}).get("inference_engine_commit", ""),
                "attack_id": f"benign-control-{control.get('language', 'unknown')}",
                "category": "benign_control",
                "heuristic_status": control.get("review_state", "UNKNOWN"),
                "review_required": "true",
                "prompt": control.get("prompt", ""),
                "response": control.get("response", ""),
                "detector_evidence": "",
                "detector_reason": "",
                "detector_confidence": "",
                "scanner_version": payload.get("scanner_version", payload.get("version", "")),
                "detector_name": payload.get("detector", ""),
                "attack_version": "",
                "prompt_sha256": control.get("prompt_sha256", ""),
                "response_sha256": control.get("response_sha256", ""),
                "turn_count": 1,
                "reviewer_verdict": "NOT_REVIEWED",
                "reviewer_notes": "",
                "reviewed_by": "",
                "reviewed_at": "",
            })
        for result in payload.get("results", []):
            if "scenario_id" not in result:
                continue
            turns = result.get("turns", [])
            rows.append({
                "run_id": payload.get("run_id", ""),
                "mode": "multi-turn-scenario",
                "model": payload.get("model", ""),
                "catalog_model_id": payload.get("model_metadata", {}).get("catalog_model_id", ""),
                "model_repo_id": payload.get("model_metadata", {}).get("model_repo_id", ""),
                "model_revision_requested": payload.get("model_metadata", {}).get("model_revision_requested", ""),
                "model_revision_resolved": payload.get("model_metadata", {}).get("model_revision_resolved", ""),
                "model_resolved_url": payload.get("model_metadata", {}).get("model_resolved_url", ""),
                "quantization": payload.get("model_metadata", {}).get("quantization", ""),
                "upstream_model": payload.get("model_metadata", {}).get("upstream_model", ""),
                "model_sha256": payload.get("model_metadata", {}).get("model_sha256", ""),
                "inference_engine": payload.get("model_metadata", {}).get("inference_engine", ""),
                "inference_engine_commit": payload.get("model_metadata", {}).get("inference_engine_commit", ""),
                "attack_id": result.get("scenario_id", ""),
                "category": result.get("category", ""),
                "heuristic_status": result.get("status", ""),
                "review_required": "true",
                "prompt": "\n".join(turn.get("prompt", "") for turn in turns),
                "response": "\n".join(turn.get("response", "") for turn in turns),
                "detector_evidence": " | ".join(
                    evidence for turn in turns for evidence in turn.get("detector_evidence", [])
                ),
                "detector_reason": " | ".join(turn.get("reason", "") for turn in turns if turn.get("reason")),
                "detector_confidence": "",
                "scanner_version": payload.get("scanner_version", payload.get("version", "")),
                "detector_name": payload.get("detector", ""),
                "attack_version": result.get("scenario_version", ""),
                "prompt_sha256": turns[0].get("prompt_sha256", "") if turns else "",
                "response_sha256": turns[-1].get("response_sha256", "") if turns else "",
                "turn_count": len(turns),
                "reviewer_verdict": "NOT_REVIEWED",
                "reviewer_notes": "",
                "reviewed_by": "",
                "reviewed_at": "",
            })
            control = result.get("benign_control", {})
            rows.append({
                "run_id": payload.get("run_id", ""),
                "mode": "scenario-benign-control",
                "model": payload.get("model", ""),
                "catalog_model_id": payload.get("model_metadata", {}).get("catalog_model_id", ""),
                "model_repo_id": payload.get("model_metadata", {}).get("model_repo_id", ""),
                "model_revision_requested": payload.get("model_metadata", {}).get("model_revision_requested", ""),
                "model_revision_resolved": payload.get("model_metadata", {}).get("model_revision_resolved", ""),
                "model_resolved_url": payload.get("model_metadata", {}).get("model_resolved_url", ""),
                "quantization": payload.get("model_metadata", {}).get("quantization", ""),
                "upstream_model": payload.get("model_metadata", {}).get("upstream_model", ""),
                "model_sha256": payload.get("model_metadata", {}).get("model_sha256", ""),
                "inference_engine": payload.get("model_metadata", {}).get("inference_engine", ""),
                "inference_engine_commit": payload.get("model_metadata", {}).get("inference_engine_commit", ""),
                "attack_id": f"control-{result.get('scenario_id', '')}",
                "category": "benign_control",
                "heuristic_status": control.get("status", "UNKNOWN"),
                "review_required": "true",
                "prompt": control.get("prompt", ""),
                "response": control.get("response", ""),
                "detector_evidence": "",
                "detector_reason": "",
                "detector_confidence": "",
                "scanner_version": payload.get("scanner_version", payload.get("version", "")),
                "detector_name": payload.get("detector", ""),
                "attack_version": "",
                "prompt_sha256": control.get("prompt_sha256", ""),
                "response_sha256": control.get("response_sha256", ""),
                "turn_count": 1,
                "reviewer_verdict": "NOT_REVIEWED",
                "reviewer_notes": "",
                "reviewed_by": "",
                "reviewed_at": "",
            })
    fields = [
        "run_id", "mode", "model", "catalog_model_id", "model_repo_id",
        "model_revision_requested", "model_revision_resolved", "model_resolved_url",
        "quantization", "upstream_model", "model_sha256", "inference_engine",
        "inference_engine_commit", "attack_id", "category",
        "heuristic_status", "review_required", "prompt", "response",
        "detector_evidence", "detector_reason", "detector_confidence",
        "scanner_version", "detector_name", "attack_version",
        "prompt_sha256", "response_sha256", "turn_count",
        "reviewer_verdict", "reviewer_notes",
        "reviewed_by", "reviewed_at",
    ]
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(
            {key: csv_safe_cell(value) for key, value in row.items()}
            for row in rows
        )
    return len(rows)


def validate_review_csv(path: str) -> dict:
    """Validate an annotated worksheet and summarize explicit human verdicts."""
    counts = {verdict: 0 for verdict in VERDICTS}
    total = 0
    errors = []
    with Path(path).open(encoding="utf-8-sig", newline="") as stream:
        for line, row in enumerate(csv.DictReader(stream), start=2):
            total += 1
            verdict = (row.get("reviewer_verdict") or "NOT_REVIEWED").strip()
            if verdict not in VERDICTS:
                errors.append(f"line {line}: unsupported reviewer_verdict {verdict!r}")
                continue
            counts[verdict] += 1
            if verdict != "NOT_REVIEWED":
                if not (row.get("reviewed_by") or "").strip():
                    errors.append(f"line {line}: reviewed_by is required for {verdict}")
                if not (row.get("reviewer_notes") or "").strip():
                    errors.append(f"line {line}: reviewer_notes is required for {verdict}")
                if not (row.get("reviewed_at") or "").strip():
                    errors.append(f"line {line}: reviewed_at is required for {verdict}")
    return {"total_rows": total, "verdict_counts": counts, "errors": errors,
            "valid": not errors}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--input", action="append", help="Report JSON; repeat for multiple reports")
    mode.add_argument("--validate-csv", help="Validate a manually annotated review CSV")
    parser.add_argument("--output", default="reports/human-review.csv")
    parser.add_argument("--summary-json", help="Optional path for machine-readable validation summary")
    args = parser.parse_args()
    if args.validate_csv:
        summary = validate_review_csv(args.validate_csv)
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        if args.summary_json:
            Path(args.summary_json).parent.mkdir(parents=True, exist_ok=True)
            Path(args.summary_json).write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return 0 if summary["valid"] else 2
    count = export_review(args.input, args.output)
    print(f"Human-review worksheet: {args.output} ({count} cases)")
    print("Annotate reviewer_verdict, reviewer_notes, reviewed_by and reviewed_at, then run:")
    print(f"  python review.py --validate-csv {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
