"""Export machine findings into an explicit human-review worksheet."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from redteam import DEFAULT_ATTACKS


VERDICTS = (
    "NOT_REVIEWED",
    "CONFIRMED_COMPLIANCE",
    "REFUSED",
    "QUOTED_OR_ANALYTICAL",
    "PARTIAL_COMPLIANCE",
    "AMBIGUOUS",
)


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
                "scanner_version": payload.get("version", ""),
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
                "attack_id": result.get("attack_id", ""),
                "category": result.get("category", ""),
                "heuristic_status": result.get("status", ""),
                "review_required": str(result.get("review_required", True)).lower(),
                "prompt": result.get("prompt", ""),
                "response": result.get("response", ""),
                "detector_evidence": " | ".join(result.get("evidence", [])),
                "detector_reason": result.get("reason", ""),
                "detector_confidence": result.get("confidence", ""),
                "scanner_version": payload.get("version", ""),
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
                "attack_id": f"benign-control-{control.get('language', 'unknown')}",
                "category": "benign_control",
                "heuristic_status": control.get("review_state", "UNKNOWN"),
                "review_required": "true",
                "prompt": control.get("prompt", ""),
                "response": control.get("response", ""),
                "detector_evidence": "",
                "detector_reason": "",
                "detector_confidence": "",
                "scanner_version": payload.get("version", ""),
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
                "attack_id": result.get("scenario_id", ""),
                "category": result.get("category", ""),
                "heuristic_status": result.get("status", ""),
                "review_required": "true",
                "prompt": "\\n".join(turn.get("prompt", "") for turn in turns),
                "response": "\\n".join(turn.get("response", "") for turn in turns),
                "detector_evidence": " | ".join(
                    evidence for turn in turns for evidence in turn.get("detector_evidence", [])
                ),
                "detector_reason": " | ".join(turn.get("reason", "") for turn in turns if turn.get("reason")),
                "detector_confidence": "",
                "scanner_version": payload.get("version", ""),
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
                "attack_id": f"control-{result.get('scenario_id', '')}",
                "category": "benign_control",
                "heuristic_status": control.get("status", "UNKNOWN"),
                "review_required": "true",
                "prompt": control.get("prompt", ""),
                "response": control.get("response", ""),
                "detector_evidence": "",
                "detector_reason": "",
                "detector_confidence": "",
                "scanner_version": payload.get("version", ""),
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
        "run_id", "mode", "model", "attack_id", "category",
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
        writer.writerows(rows)
    return len(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", action="append", required=True, help="Report JSON; repeat for multiple reports")
    parser.add_argument("--output", default="reports/human-review.csv")
    args = parser.parse_args()
    count = export_review(args.input, args.output)
    print(f"Human-review worksheet: {args.output} ({count} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
