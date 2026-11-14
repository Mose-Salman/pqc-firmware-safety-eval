"""Opt-in V2 experiment runner with dataset-bound, resumable trial records."""

from __future__ import annotations

import hashlib
import json
import os
import random
from datetime import datetime, timezone
from pathlib import Path

from pqc_eval.runner import API_VERSION, _call_claude, parse_verdict

from . import PROTOCOL, SCHEMA
from .evidence import CONDITIONS
from .prompts import prompt_for


def _hash_json(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _identity(model: str, dataset_sha: str, case_id: str, condition: str, trial: int) -> str:
    return _hash_json([PROTOCOL, model, dataset_sha, case_id, condition, trial])[:24]


def run_v2(
    cases: list[dict],
    manifest: dict,
    output: Path,
    model: str,
    *,
    conditions: tuple[str, ...] = CONDITIONS,
    trials: int = 2,
    live: bool = False,
    confirm_billing: bool = False,
    limit: int | None = None,
    client=None,
) -> dict:
    """Preview prompts or execute explicitly authorized paid model requests.

    Resume identifiers include a frozen dataset digest. Existing malformed or
    incompatible files are rejected instead of being silently appended to.
    """
    if manifest.get("schema") != SCHEMA or not manifest.get("dataset_sha256"):
        raise ValueError("A validated V2 dataset manifest is required")
    if not isinstance(model, str) or not model.strip():
        raise ValueError("An explicit model ID is required")
    if trials < 1 or not conditions or len(set(conditions)) != len(conditions):
        raise ValueError("Invalid trial count or duplicate conditions")
    if any(condition not in CONDITIONS for condition in conditions):
        raise ValueError("Unrecognized experimental condition")
    if limit is not None and limit < 1:
        raise ValueError("The maximum number of requests must be positive")
    if live and not confirm_billing:
        raise ValueError("Live API calls require --confirm-billing")
    if live and client is None and not os.environ.get("ANTHROPIC_API_KEY"):
        raise RuntimeError("Set ANTHROPIC_API_KEY to run a paid Claude evaluation")

    sha = manifest["dataset_sha256"]
    if not live and output.exists():
        raise FileExistsError("Preview output already exists; provide a new output path")
    prior: dict[str, dict] = {}
    if live and output.exists():
        for line in output.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            run_id = record.get("run_id")
            if (record.get("protocol") != PROTOCOL
                    or record.get("dataset_sha256") != sha
                    or record.get("model_requested") != model
                    or record.get("mode") != "live"
                    or not isinstance(run_id, str)
                    or run_id in prior):
                raise ValueError("Existing experiment results are incompatible or duplicated")
            expected_id = _identity(
                model, sha, record["case_id"], record["condition"], record["trial"]
            )
            if run_id != expected_id:
                raise ValueError("Recorded run identifier failed integrity validation")
            prior[run_id] = record

    queue: list[tuple[dict, str, int, str]] = []
    ids = set()
    for case in cases:
        if case.get("schema") != SCHEMA:
            raise ValueError("Mixed dataset schema")
        if case["case_id"] in ids:
            raise ValueError("Duplicate case in dataset")
        ids.add(case["case_id"])
        for condition in conditions:
            for trial in range(trials):
                ident = _identity(model, sha, case["case_id"], condition, trial)
                queue.append((case, condition, trial, ident))
    random.Random(20261114).shuffle(queue)
    # Verify prompt stability before skipping any previous record.
    for case, condition, trial, run_id in queue:
        if run_id in prior:
            digest = _hash_json(prompt_for(case, condition))
            if prior[run_id].get("prompt_sha256") != digest:
                raise ValueError("Prompt changed for a previously recorded trial")
    pending = [entry for entry in queue if entry[3] not in prior]
    if limit is not None:
        pending = pending[:limit]
    output.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with output.open("a" if live else "w", encoding="utf-8") as stream:
        for case, condition, trial, run_id in pending:
            prompt = prompt_for(case, condition)
            record = {
                "protocol": PROTOCOL,
                "dataset_sha256": sha,
                "run_id": run_id,
                "case_id": case["case_id"],
                "condition": condition,
                "trial": trial,
                "model_requested": model,
                "prompt_sha256": _hash_json(prompt),
                "api_version": API_VERSION,
                "recorded_utc": datetime.now(timezone.utc).isoformat(),
                "mode": "live" if live else "preview",
            }
            if live:
                try:
                    response = (client or _call_claude)(model, prompt)
                    raw = "".join(
                        block.get("text", "")
                        for block in response.get("content", [])
                        if block.get("type") == "text"
                    )
                    record.update({
                        "response_id": response.get("id"),
                        "model_returned": response.get("model"),
                        "stop_reason": response.get("stop_reason"),
                        "usage": response.get("usage", {}),
                        "raw": raw,
                    })
                    if response.get("stop_reason") != "end_turn":
                        record["parse_error"] = "API response ended without end_turn"
                    else:
                        try:
                            record["verdict"] = parse_verdict(raw)
                        except (ValueError, TypeError) as exc:
                            record["parse_error"] = str(exc)
                except RuntimeError as exc:
                    record["api_error"] = str(exc)
            else:
                record.update({"prompt": prompt})
            stream.write(json.dumps(record, sort_keys=True) + "\n")
            stream.flush()
            written += 1
    return {
        "protocol": PROTOCOL,
        "mode": "live" if live else "preview",
        "total_planned": len(queue),
        "previously_recorded": len(prior),
        "written": written,
        "dataset_sha256": sha,
    }
