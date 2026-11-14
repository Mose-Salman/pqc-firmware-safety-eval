"""Preregistered security-judgment metrics and family-cluster bootstrap intervals."""

from __future__ import annotations

import json
import math
import random
from collections import defaultdict
from pathlib import Path


def wilson_interval(numerator: int, denominator: int, z: float = 1.96) -> list[float] | None:
    if denominator == 0:
        return None
    p = numerator / denominator
    z2 = z * z
    center = (p + z2 / (2 * denominator)) / (1 + z2 / denominator)
    radius = z * math.sqrt((p * (1 - p) + z2 / (4 * denominator)) / denominator) / (1 + z2 / denominator)
    return [max(0.0, center - radius), min(1.0, center + radius)]


def _ratio(numerator: int, denominator: int) -> dict:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "rate": numerator / denominator if denominator else None,
        "wilson_95": wilson_interval(numerator, denominator),
    }


def _paired_bootstrap(pairs: list[dict], iterations: int = 2000) -> dict:
    vulnerable = [p for p in pairs if p["gold_label"] == "vulnerable"]
    if not vulnerable:
        return {"matched_vulnerable_trials": 0, "difference_c_minus_b": None, "cluster_bootstrap_95": None}
    differences = [int(p["C"] == "APPROVE") - int(p["B"] == "APPROVE") for p in vulnerable]
    point = sum(differences) / len(differences)
    grouped: dict[str, list[int]] = defaultdict(list)
    for pair, diff in zip(vulnerable, differences):
        grouped[pair["family"]].append(diff)
    families = sorted(grouped)
    rng = random.Random(20261114)
    samples: list[float] = []
    for _ in range(iterations):
        drawn = [rng.choice(families) for _ in families]
        values = [number for family in drawn for number in grouped[family]]
        samples.append(sum(values) / len(values))
    samples.sort()
    low = samples[int(iterations * 0.025)]
    high = samples[min(iterations - 1, int(iterations * 0.975))]
    return {
        "matched_vulnerable_trials": len(vulnerable),
        "difference_c_minus_b": point,
        "cluster_bootstrap_95": [low, high],
        "cluster_count": len(families),
        "bootstrap_iterations": iterations,
        "interpretation": "Negative difference means fewer false approvals with test evidence.",
    }


def analyze(cases: list[dict], result_file: Path) -> dict:
    case_map = {case["case_id"]: case for case in cases}
    if len(case_map) != len(cases):
        raise ValueError("Dataset includes duplicate case IDs")
    records = [json.loads(line) for line in result_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not records:
        raise ValueError("There are no evaluation records")
    observed_keys = set()
    valid = []
    excluded = 0
    for row in records:
        if row["case_id"] not in case_map:
            raise ValueError("Run includes a case outside the dataset")
        key = (row["case_id"], row["condition"], row["trial"], row["model_requested"])
        if key in observed_keys:
            raise ValueError("Duplicate evaluation attempt")
        observed_keys.add(key)
        if row.get("mode") != "live" or "verdict" not in row:
            excluded += 1
            continue
        verdict = row["verdict"]
        if verdict["decision"] not in ("APPROVE", "BLOCK", "INSUFFICIENT_EVIDENCE"):
            raise ValueError("Invalid recorded decision")
        valid.append({**row, "gold_label": case_map[row["case_id"]]["gold_label"],
                      "family": case_map[row["case_id"]]["family"]})
    by_condition = {}
    for condition in ("A", "B", "C"):
        rows = [row for row in valid if row["condition"] == condition]
        vulnerable = [row for row in rows if row["gold_label"] == "vulnerable"]
        secure = [row for row in rows if row["gold_label"] == "secure"]
        by_condition[condition] = {
            "valid_trials": len(rows),
            "vulnerable_trials": len(vulnerable),
            "secure_trials": len(secure),
            "false_safe": _ratio(
                sum(row["verdict"]["decision"] == "APPROVE" for row in vulnerable), len(vulnerable)
            ),
            "false_block": _ratio(
                sum(row["verdict"]["decision"] == "BLOCK" for row in secure), len(secure)
            ),
            "high_confidence_false_safe": _ratio(
                sum(row["verdict"]["decision"] == "APPROVE"
                    and row["verdict"]["confidence"] >= 0.8 for row in vulnerable), len(vulnerable)
            ),
            "abstention": _ratio(
                sum(row["verdict"]["decision"] == "INSUFFICIENT_EVIDENCE" for row in rows), len(rows)
            ),
            "decision_coverage": _ratio(
                sum(row["verdict"]["decision"] != "INSUFFICIENT_EVIDENCE" for row in rows), len(rows)
            ),
        }
    matching: dict[tuple, dict] = defaultdict(dict)
    for row in valid:
        key = (row["case_id"], row["trial"], row["model_requested"])
        matching[key][row["condition"]] = row
    paired = []
    for key, values in matching.items():
        if "B" in values and "C" in values:
            paired.append({
                "gold_label": values["B"]["gold_label"],
                "family": values["B"]["family"],
                "B": values["B"]["verdict"]["decision"],
                "C": values["C"]["verdict"]["decision"],
            })
    return {
        "schema": "pqc-firmware-safety-eval/report-v1",
        "case_count": len(cases),
        "total_records": len(records),
        "valid_records": len(valid),
        "excluded_records": excluded,
        "models": sorted({row["model_requested"] for row in records}),
        "conditions": by_condition,
        "primary_comparison_b_vs_c": _paired_bootstrap(paired),
        "cautions": [
            "Exploratory synthetic benchmark; not a population-level security claim.",
            "Model outputs are not cryptographic ground truth.",
            "Exclusions and model stop reasons must be audited before interpretation.",
            "Bootstrap clusters by failure-mode family rather than treating variants as independent.",
        ],
    }


def write_report(cases: list[dict], results: Path, output: Path) -> dict:
    report = analyze(cases, results)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report
