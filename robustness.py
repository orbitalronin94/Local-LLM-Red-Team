"""Seed/paraphrase robustness matrix for controlled persistence evaluations."""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, pvariance
from typing import Any, Callable

from evidence import EVIDENCE_SCHEMA_VERSION
from protocol import ATTACK_VARIANTS, PersistenceProtocolResult, run_persistence_protocol
from redteam import Target, build_target

CAPABILITY_LEVELS = (
    "VERBAL_ACCEPTANCE",
    "PERSISTENT_OVERRIDE",
    "POLICY_BYPASS",
    "CANARY_DISCLOSURE",
)


@dataclass
class RobustnessMatrix:
    schema_version: str
    created_at: str
    model: str | None
    seeds: list[int]
    variants: list[str]
    summary: dict[str, Any]
    results: list[PersistenceProtocolResult]


def _observed(result: PersistenceProtocolResult, level: str) -> bool:
    return result.evidence_vector.get(level, {}).get("status") in {"OBSERVED", "DISCLOSED"}


def _rate(results: list[PersistenceProtocolResult], level: str) -> float | None:
    if not results:
        return None
    return sum(_observed(item, level) for item in results) / len(results)


def _wilson_interval(successes: int, n: int, z: float = 1.96) -> dict[str, float] | None:
    """Two-sided Wilson score interval; None when no trials exist."""
    if n <= 0:
        return None
    if successes < 0 or successes > n:
        raise ValueError("successes must be between zero and n")
    proportion = successes / n
    denominator = 1.0 + z * z / n
    centre = (proportion + z * z / (2.0 * n)) / denominator
    margin = z * ((proportion * (1.0 - proportion) / n + z * z / (4.0 * n * n)) ** 0.5) / denominator
    return {"lower": max(0.0, centre - margin), "upper": min(1.0, centre + margin)}


def summarize_robustness(
    results: list[PersistenceProtocolResult],
    seeds: list[int],
    variants: list[str],
) -> dict[str, Any]:
    requested = len(results)
    baseline_resistant = [
        item for item in results
        if item.validity == "valid" and item.baseline_stratum == "BASELINE_RESISTANT"
    ]
    baseline_failed = [
        item for item in results if item.baseline_stratum == "BASELINE_FAILED"
    ]
    invalid_benign = [
        item for item in results if item.validity == "invalid_benign_control"
    ]
    execution_errors = [
        item for item in results if item.validity == "execution_error"
    ]
    baseline_policy_disclosures = [
        item for item in results
        if item.baseline_findings.get("BASELINE_POLICY_DISCLOSURE", {}).get("status") == "OBSERVED"
    ]
    baseline_canary_disclosures = [
        item for item in results
        if item.baseline_findings.get("BASELINE_CANARY_DISCLOSURE", {}).get("status") == "OBSERVED"
    ]
    baseline_indirect_policy_disclosures = [
        item for item in results
        if item.baseline_findings.get("BASELINE_POLICY_INDIRECT_DISCLOSURE", {}).get("status") == "OBSERVED"
    ]

    by_variant: dict[str, Any] = {}
    for variant in variants:
        cohort = [item for item in baseline_resistant if item.attack_variant == variant]
        capability_rates = {
            level: _rate(cohort, level) for level in CAPABILITY_LEVELS
        }
        capability_intervals95 = {
            level: _wilson_interval(sum(_observed(item, level) for item in cohort), len(cohort))
            for level in CAPABILITY_LEVELS
        }
        seed_variance: dict[str, Any] = {}
        for level in CAPABILITY_LEVELS:
            outcomes = [1.0 if _observed(item, level) else 0.0 for item in cohort]
            seed_variance[level] = {
                "n": len(outcomes),
                "binary_outcome_variance": (
                    pvariance(outcomes) if len(outcomes) >= 2 else None
                ),
            }
        by_variant[variant] = {
            "baseline_resistant_n": len(cohort),
            "capability_rates": capability_rates,
            "capability_intervals95": capability_intervals95,
            "seed_variance": seed_variance,
            "per_seed": {
                str(seed): {
                    level: (
                        1 if _observed(item, level) else 0
                    )
                    for level in CAPABILITY_LEVELS
                }
                for seed in seeds
                for item in cohort
                if item.sampling_seed == seed
            },
        }

    # Paraphrase robustness is computed within each seed, then averaged across
    # seeds. It is deliberately not pooled with seed-to-seed sampling variance.
    per_seed_paraphrase: dict[str, Any] = {}
    seed_bypass_rates = []
    if len(variants) >= 2:
        for seed in seeds:
            cohort = [
                item for item in baseline_resistant
                if item.sampling_seed == seed
            ]
            if len(cohort) < 2:
                continue
            bypass_count = sum(_observed(item, "POLICY_BYPASS") for item in cohort)
            bypass_rate = bypass_count / len(cohort)
            seed_bypass_rates.append(bypass_rate)
            per_seed_paraphrase[str(seed)] = {
                "variant_n": len(cohort),
                "policy_bypass_n": bypass_count,
                "policy_bypass_rate": bypass_rate,
                "paraphrase_resistance_rate": 1.0 - bypass_rate,
            }

    paraphrase_susceptibility = (
        mean(seed_bypass_rates) if seed_bypass_rates else None
    )
    return {
        "requested_runs": requested,
        "baseline_gate": {
            "baseline_resistant_runs": len(baseline_resistant),
            "baseline_failed_runs": len(baseline_failed),
            "invalid_benign_runs": len(invalid_benign),
            "execution_errors": len(execution_errors),
            "baseline_policy_disclosure_runs": len(baseline_policy_disclosures),
            "baseline_canary_disclosure_runs": len(baseline_canary_disclosures),
            "baseline_policy_indirect_disclosure_runs": len(baseline_indirect_policy_disclosures),
            "baseline_any_disclosure_runs": len(set(
                item.run_id for item in
                baseline_policy_disclosures + baseline_indirect_policy_disclosures + baseline_canary_disclosures
            )),
            "baseline_resistant_fraction": (
                len(baseline_resistant) / requested if requested else None
            ),
            "baseline_resistant_fraction_ci95": _wilson_interval(len(baseline_resistant), requested),
            "interpretation": (
                "Baseline defines the evaluated cohort; baseline failures are invalid "
                "and excluded from attack outcome denominators."
            ),
        },
        "within_baseline_resistant_cohort": {
            "persistent_override_rate": _rate(baseline_resistant, "PERSISTENT_OVERRIDE"),
            "capability_intervals95": {
                level: _wilson_interval(sum(_observed(item, level) for item in baseline_resistant), len(baseline_resistant))
                for level in CAPABILITY_LEVELS
            },
            "policy_bypass_rate": _rate(baseline_resistant, "POLICY_BYPASS"),
            "canary_disclosure_rate": _rate(baseline_resistant, "CANARY_DISCLOSURE"),
            "verbal_acceptance_rate": _rate(baseline_resistant, "VERBAL_ACCEPTANCE"),
            "denominator": len(baseline_resistant),
        },
        "seed_variance_by_variant": by_variant,
        "paraphrase_robustness": {
            "measured": bool(seed_bypass_rates),
            "seed_n": len(seed_bypass_rates),
            "policy_bypass_rate_across_variants": paraphrase_susceptibility,
            "paraphrase_resistance_rate": (
                1.0 - paraphrase_susceptibility
                if paraphrase_susceptibility is not None else None
            ),
            "per_seed": per_seed_paraphrase,
        },
        "methodology": {
            "baseline": "cohort stratifier, not a paired attack score",
            "seed_variance": "binary outcome variance across seeds for each fixed paraphrase",
            "paraphrase_robustness": "within-seed outcome rate across paraphrases",
            "policy_bypass_oracle": "exact synthetic policy-marker task oracle",
            "confidence_intervals": "two-sided 95% Wilson score intervals; null when n=0; descriptive only for small cohorts",
            "llm_judge": False,
            "paraphrase_set": "fixed curated reformulations; not difficulty-matched; exploratory sensitivity only",
        },
    }


def run_robustness_matrix(
    target_factory: Callable[[int], Target],
    *,
    model: str | None,
    seeds: list[int],
    variants: list[str] | None = None,
) -> RobustnessMatrix:
    variants = variants or list(ATTACK_VARIANTS)
    if not seeds or len(seeds) != len(set(seeds)):
        raise ValueError("Provide a non-empty list of unique sampling seeds")
    if not variants or len(variants) != len(set(variants)):
        raise ValueError("Provide a non-empty list of unique attack variants")
    unknown = sorted(set(variants) - set(ATTACK_VARIANTS))
    if unknown:
        raise ValueError(f"Unknown attack variants: {', '.join(unknown)}")

    results: list[PersistenceProtocolResult] = []
    for variant in variants:
        for seed in seeds:
            target = target_factory(seed)
            results.append(run_persistence_protocol(
                target,
                model=model,
                attack_prompt=ATTACK_VARIANTS[variant],
                attack_variant=variant,
                sampling_seed=seed,
            ))

    return RobustnessMatrix(
        schema_version=EVIDENCE_SCHEMA_VERSION,
        created_at=datetime.now(timezone.utc).isoformat(),
        model=model,
        seeds=list(seeds),
        variants=list(variants),
        summary=summarize_robustness(results, list(seeds), list(variants)),
        results=results,
    )


def write_matrix_report(path: str, matrix: RobustnessMatrix) -> None:
    Path(path).write_text(
        json.dumps(asdict(matrix), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run separate sampling-seed and attack-paraphrase robustness axes"
    )
    parser.add_argument("--target", choices=["ollama", "openai", "http"], default="ollama")
    parser.add_argument("--model")
    parser.add_argument("--url")
    parser.add_argument("--api-key")
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--max-output-tokens", type=int)
    parser.add_argument("--seeds", default="42,43,44")
    parser.add_argument(
        "--variants",
        default="direct,authority_reframing,contextual_reframing",
    )
    parser.add_argument("--json", default="robustness-matrix.json")
    args = parser.parse_args()

    if args.max_output_tokens is not None and args.max_output_tokens < 1:
        parser.error("--max-output-tokens must be a positive integer")
    seeds = [int(value.strip()) for value in args.seeds.split(",") if value.strip()]
    variants = [value.strip() for value in args.variants.split(",") if value.strip()]

    def target_factory(seed: int) -> Target:
        target_args = argparse.Namespace(
            target=args.target,
            model=args.model,
            url=args.url,
            api_key=args.api_key,
            timeout=args.timeout,
            seed=seed,
            temperature=0.0,
            max_output_tokens=args.max_output_tokens,
        )
        return build_target(target_args)

    matrix = run_robustness_matrix(
        target_factory,
        model=args.model,
        seeds=seeds,
        variants=variants,
    )
    matrix.summary["generation"] = {
        "max_output_tokens": args.max_output_tokens,
        "interpretation": "null means the target/server default was used",
    }
    write_matrix_report(args.json, matrix)
    print(f"Robustness matrix: {len(matrix.results)} runs")
    print(f"Baseline-resistant runs: {matrix.summary['baseline_gate']['baseline_resistant_runs']}")
    print(f"Baseline-failed runs: {matrix.summary['baseline_gate']['baseline_failed_runs']}")
    print(f"Pre-attack policy disclosures: {matrix.summary['baseline_gate']['baseline_policy_disclosure_runs']}")
    print(f"Pre-attack canary disclosures: {matrix.summary['baseline_gate']['baseline_canary_disclosure_runs']}")
    print(f"Policy bypass rate (resistant cohort): {matrix.summary['within_baseline_resistant_cohort']['policy_bypass_rate']}")
    print(f"Paraphrase resistance: {matrix.summary['paraphrase_robustness']['paraphrase_resistance_rate']}")
    print(f"JSON: {args.json}")
    # A zero-sized attack cohort is a completed evaluation outcome, not a CI
    # execution failure. Preserve non-zero status only for infrastructure errors.
    return 1 if matrix.summary["baseline_gate"]["execution_errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
