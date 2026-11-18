#!/usr/bin/env python3
"""Aggregate model benchmark JSON into a per-run findings catalogue."""
from __future__ import annotations
import argparse, csv, json
from pathlib import Path
from typing import Any

STATUSES = {"FAIL", "NOT_DETECTED", "PASS", "ERROR", "EMPTY"}

def load_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None

def identity(payload: dict[str, Any], path: Path) -> dict[str, Any]:
    meta = payload.get("model_metadata") or payload.get("run_metadata") or {}
    return {
        "model_id": meta.get("catalog_model_id") or path.name.split("-")[0],
        "model_repo_id": meta.get("model_repo_id", ""),
        "model_revision": meta.get("model_revision_resolved") or meta.get("model_revision_requested", ""),
        "model_sha256": meta.get("model_sha256", ""),
        "quantization": meta.get("quantization", ""),
        "inference_engine": meta.get("inference_engine", ""),
        "inference_engine_commit": meta.get("inference_engine_commit", ""),
        "run_id": payload.get("run_id", ""),
    }

def make_row(base: dict[str, Any], item: dict[str, Any], path: Path,
             mode: str, attack_id: str, category: str, prompt: str = "") -> dict[str, Any]:
    detection = item.get("detection") or {}
    turns = item.get("turns") or []
    return {
        **base, "source": path.name, "mode": mode, "attack_id": attack_id,
        "category": category, "status": item.get("status", "UNKNOWN"),
        "prompt": prompt or item.get("prompt", "") or (turns[0].get("prompt", "") if turns else ""),
        "prompt_sha256": item.get("prompt_sha256", ""),
        "response": item.get("response", ""), "response_sha256": item.get("response_sha256", ""),
        "evidence": detection.get("evidence", item.get("detector_evidence", item.get("evidence", []))),
        "confidence": detection.get("confidence", item.get("confidence")),
        "turns": turns, "review_state": "PENDING",
    }

def collect(input_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    positives, review, invalid_controls = [], [], []
    for path in sorted(input_dir.rglob("*.json")):
        if path.name in {"model-provenance.json", "warmup.json"}:
            continue
        payload = load_json(path)
        if not payload:
            continue
        base = identity(payload, path)
        if isinstance(payload.get("results"), list):
            mode = payload.get("run_metadata", {}).get("mode")
            if not mode:
                mode = "scenario" if "scenario_count" in payload else "unknown"
            for item in payload["results"]:
                status = item.get("status")
                if status not in STATUSES:
                    continue
                row = make_row(base, item, path, mode,
                               item.get("attack_id", item.get("scenario_id", "")),
                               item.get("attack_category", item.get("category", "")))
                row["validity"] = item.get("validity", "valid")
                if row["validity"] == "invalid_control":
                    invalid_controls.append(row)
                    continue
                if status == "FAIL":
                    positives.append(row)
                elif status == "NOT_DETECTED" and item.get("human_review_required", True):
                    review.append(row)
        if isinstance(payload.get("records"), list):
            for item in payload["records"]:
                status = item.get("status")
                if status not in STATUSES:
                    continue
                row = make_row(base, item, path, "paired-language",
                               item.get("attack_id", item.get("pair_id", "")),
                               item.get("category", ""))
                row["language"] = item.get("language", "")
                if status == "FAIL":
                    positives.append(row)
                elif status == "NOT_DETECTED" and item.get("review_required", True):
                    review.append(row)
    def dedupe(rows):
        seen, result = set(), []
        for row in rows:
            key = (row["model_id"], row["run_id"], row["source"], row["attack_id"],
                   row["prompt_sha256"], row["response_sha256"])
            if key not in seen:
                seen.add(key)
                result.append(row)
        return result
    return dedupe(positives), dedupe(review), dedupe(invalid_controls)

def render(positives: list[dict[str, Any]], review: list[dict[str, Any]],
           invalid_controls: list[dict[str, Any]], run_label: str) -> str:
    lines = [
        "# Automated Red-Team Findings Catalogue", "",
        f"- Benchmark run: {run_label or 'not supplied'}",
        f"- Heuristic positive findings (FAIL): {len(positives)}",
        f"- Inconclusive human-review candidates (NOT_DETECTED): {len(review)}", "",
        "> FAIL means the current heuristic detector matched a signal; it is not proof of a real exploit or impact. NOT_DETECTED is inconclusive, not evidence of safety. No case is human-confirmed until a reviewer records that decision.", "",
        "## Positive heuristic findings", "",
    ]
    if not positives:
        lines += ["No FAIL findings were present.", ""]
    for n, row in enumerate(positives, 1):
        lines += [
            f"### {n}. {row['model_id']} — {row['attack_id']}", "",
            f"- Category: {row['category']}",
            f"- Mode/source: {row['mode']} / {row['source']}",
            f"- Model repository: {row['model_repo_id'] or 'not recorded'}",
            f"- Revision: {row['model_revision'] or 'not resolved'}",
            f"- Model SHA-256: {row['model_sha256'] or 'not recorded'}",
            f"- Run ID: {row['run_id'] or 'not recorded'}",
            f"- Prompt SHA-256: {row['prompt_sha256'] or 'not recorded'}",
            f"- Confidence: {row['confidence']}", "",
            "**Prompt**", "", "    " + row["prompt"].replace("\n", "\n    "), "",
            "**Model response**", "", "    " + row["response"].replace("\n", "\n    "), "",
            "**Detector evidence:** " + (", ".join(map(str, row["evidence"])) if row["evidence"] else "none supplied"), "",
        ]
        if row["turns"]:
            lines += ["**Conversation turns (JSON)**", "",
                      json.dumps(row["turns"], ensure_ascii=False, indent=2), ""]
    lines += ["## Inconclusive cases for human review", "",
              "These cases may represent missed unsafe compliance, harmless ambiguity, or detector false negatives. They are not counted as positive findings.", ""]
    for n, row in enumerate(review, 1):
        lines += [f"### {n}. {row['model_id']} — {row['attack_id']}",
                  f"- Source: {row['source']} · category: {row['category']} · run: {row['run_id']}", "",
                  "**Prompt**", "", "    " + row["prompt"].replace("\n", "\n    "), "",
                  "**Response**", "", "    " + row["response"].replace("\n", "\n    "), ""]
    lines += ["## Excluded: invalid benign controls", "",
              "These scenario runs failed their benign recall/control check and are excluded from findings and any effectiveness-rate aggregation.", ""]
    for row in invalid_controls:
        lines += [f"- {row['model_id']} / {row['attack_id']} · run {row['run_id']} · {row['status']} (invalid_control)", ""]
    lines += ["## Limitations", "",
              "- Prompt-level evidence only: no proof of tool execution, secret access, state change, or production impact.",
              "- Review FAIL entries manually before calling them confirmed vulnerabilities.",
              "- Missing immutable model revisions or hashes remain explicitly unresolved.",
              "- Original per-model JSON artifacts remain the primary evidence; this file is a generated index.", ""]
    return "\n".join(lines)

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--run-label", default="")
    args = parser.parse_args()
    positives, review, invalid_controls = collect(args.input_dir)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    payload = {"schema_version": 1, "benchmark_run": args.run_label,
               "positive_findings": positives, "human_review_queue": review,
               "invalid_controls_excluded": invalid_controls}
    (args.output_dir / "findings-catalog.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (args.output_dir / "findings-catalog.md").write_text(
        render(positives, review, invalid_controls, args.run_label), encoding="utf-8")
    fields = ["model_id", "model_repo_id", "model_revision", "model_sha256", "run_id",
              "source", "mode", "attack_id", "category", "status", "language",
              "prompt_sha256", "prompt", "response", "confidence", "evidence", "review_state", "validity"]
    with (args.output_dir / "findings-catalog.csv").open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in positives + review + invalid_controls:
            writer.writerow({**row, "evidence": json.dumps(row["evidence"], ensure_ascii=False)})
    print(f"catalogue: {len(positives)} heuristic positives; {len(review)} inconclusive review candidates")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
