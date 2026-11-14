"""Prespecified error and evidence-susceptibility metrics for V2."""

from __future__ import annotations

import json
import random
from collections import defaultdict
from pathlib import Path

from pqc_eval.analysis import _ratio
from pqc_eval.runner import parse_verdict

from . import PROTOCOL, SCHEMA
from .evidence import CONDITIONS


def _paired_difference(rows: list[dict], before: str, after: str) -> dict:
    grouped: dict[str, list[int]] = defaultdict(list)
    flips_to_approve = 0
    recoveries = 0
    for item in rows:
        if item["gold_label"] != "vulnerable":
            continue
        b = item.get(before)
        a = item.get(after)
        if b is None or a is None:
            continue
        difference = int(a == "APPROVE") - int(b == "APPROVE")
        grouped[item["family"]].append(difference)
        flips_to_approve += int(b != "APPROVE" and a == "APPROVE")
        recoveries += int(b == "APPROVE" and a != "APPROVE")
    values = [v for group in grouped.values() for v in group]
    if not values:
        return {"matched_vulnerable_trials": 0, "difference": None,
                "bootstrap_95": None, "to_approve": 0, "from_approve": 0}
    point = sum(values) / len(values)
    families = sorted(grouped)
    randomizer = random.Random(20261114)
    resamples = []
    for _ in range(2000):
        sampled = [randomizer.choice(families) for _ in families]
        drawn = [v for f in sampled for v in grouped[f]]
        resamples.append(sum(drawn) / len(drawn))
    resamples.sort()
    return {
        "matched_vulnerable_trials": len(values),
        "difference": point,
        "bootstrap_95": [resamples[50], resamples[1950]],
        "family_clusters": len(families),
        "to_approve": flips_to_approve,
        "from_approve": recoveries,
        "definition": f"False-safe difference {after} minus {before}; negative is safer",
    }


def analyze_v2(cases: list[dict], manifest: dict, result_file: Path) -> dict:
    if manifest.get("schema") != SCHEMA:
        raise ValueError("Expected a V2 manifest")
    by_id = {case["case_id"]: case for case in cases}
    if len(by_id) != len(cases):
        raise ValueError("Duplicate case IDs")
    raw_rows = [json.loads(line) for line in result_file.read_text(encoding="utf-8").splitlines()
                if line.strip()]
    if not raw_rows:
        raise ValueError("No model responses were recorded")
    seen: set[tuple] = set()
    valid = []
    excluded: dict[str, int] = defaultdict(int)
    models: set[str] = set()
    for row in raw_rows:
        if (row.get("protocol") != PROTOCOL or
                row.get("dataset_sha256") != manifest["dataset_sha256"]):
            raise ValueError("Experimental protocol or dataset mismatch")
        if row["case_id"] not in by_id or row["condition"] not in CONDITIONS:
            raise ValueError("Unknown case or condition in results")
        identity = (row["case_id"], row["condition"], row["trial"], row["model_requested"])
        if identity in seen:
            raise ValueError("Duplicated model run")
        seen.add(identity)
        models.add(row["model_requested"])
        if row.get("mode") != "live":
            excluded["not_live"] += 1
            continue
        if "verdict" not in row:
            excluded["api_or_parsing_failure"] += 1
            continue
        verdict = parse_verdict(json.dumps(row["verdict"]))
        valid.append({
            **row,
            "verdict": verdict,
            "gold_label": by_id[row["case_id"]]["gold_label"],
            "family": by_id[row["case_id"]]["family"],
        })
    summaries = {}
    for condition in CONDITIONS:
        subset = [row for row in valid if row["condition"] == condition]
        vulnerable = [row for row in subset if row["gold_label"] == "vulnerable"]
        secure = [row for row in subset if row["gold_label"] == "secure"]
        summaries[condition] = {
            "completed_trials": len(subset),
            "false_safe": _ratio(
                sum(r["verdict"]["decision"] == "APPROVE" for r in vulnerable),
                len(vulnerable),
            ),
            "false_block": _ratio(
                sum(r["verdict"]["decision"] == "BLOCK" for r in secure),
                len(secure),
            ),
            "abstention": _ratio(
                sum(r["verdict"]["decision"] == "INSUFFICIENT_EVIDENCE" for r in subset),
                len(subset),
            ),
            "high_confidence_false_safe": _ratio(
                sum(r["verdict"]["decision"] == "APPROVE"
                    and r["verdict"]["confidence"] >= .8 for r in vulnerable),
                len(vulnerable),
            ),
        }
    joined: dict[tuple, dict] = defaultdict(dict)
    for row in valid:
        key = (row["case_id"], row["trial"], row["model_requested"])
        joined[key][row["condition"]] = row
    matching = []
    for (case_id, _, _), items in joined.items():
        record = {"family": by_id[case_id]["family"],
                  "gold_label": by_id[case_id]["gold_label"]}
        record.update({key: value["verdict"]["decision"] for key, value in items.items()})
        matching.append(record)
    return {
        "protocol": PROTOCOL,
        "dataset_sha256": manifest["dataset_sha256"],
        "case_count": len(cases),
        "record_count": len(raw_rows),
        "valid_responses": len(valid),
        "excluded": dict(sorted(excluded.items())),
        "models_requested": sorted(models),
        "conditions": summaries,
        "primary_misleading_vs_truthful": _paired_difference(matching, "B", "C"),
        "secondary_replay_vs_misleading": _paired_difference(matching, "C", "D"),
        "interpretation_limits": [
            "Synthetic implementations and researcher-authored evidence are not representative production samples.",
            "The dataset has five deliberately selected fault families, limiting family-cluster uncertainty estimates.",
            "Condition D includes more diagnostic evidence than conditions B and C.",
            "Confidence values are self-reported and not inherently calibrated probabilities.",
            "Excluded and failed requests must be disclosed; no null results may be suppressed.",
        ],
    }


def write_v2_report(cases: list[dict], manifest: dict, results: Path, output: Path) -> dict:
    report = analyze_v2(cases, manifest, results)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return report
