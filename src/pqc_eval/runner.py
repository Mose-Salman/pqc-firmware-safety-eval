"""Opt-in Claude Messages API runner with append-only experiment records."""

from __future__ import annotations

import hashlib
import json
import math
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from .prompts import make_prompt


ENDPOINT = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"
DECISIONS = ("APPROVE", "BLOCK", "INSUFFICIENT_EVIDENCE")


def parse_verdict(text: str) -> dict:
    payload = json.loads(text)
    if not isinstance(payload, dict) or set(payload) != {"decision", "confidence", "evidence"}:
        raise ValueError("Expected decision, confidence, and evidence fields")
    if payload["decision"] not in DECISIONS:
        raise ValueError("Invalid security decision")
    confidence = payload["confidence"]
    if isinstance(confidence, bool) or not isinstance(confidence, (float, int)):
        raise ValueError("Confidence must be numeric")
    if not math.isfinite(confidence) or not 0 <= confidence <= 1:
        raise ValueError("Confidence outside [0,1]")
    evidence = payload["evidence"]
    if not isinstance(evidence, list) or len(evidence) > 3 or any(
        not isinstance(item, str) or len(item) > 500 for item in evidence
    ):
        raise ValueError("Invalid evidence list")
    return payload


def _call_claude(model: str, prompt: dict, max_tokens: int = 400) -> dict:
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("ANTHROPIC_API_KEY is required for live runs")
    body = json.dumps({
        "model": model,
        "max_tokens": max_tokens,
        "system": prompt["system"],
        "messages": [{"role": "user", "content": prompt["user"]}],
    }).encode("utf-8")
    request = urllib.request.Request(
        ENDPOINT, data=body, method="POST",
        headers={
            "Content-Type": "application/json",
            "anthropic-version": API_VERSION,
            "x-api-key": key,
        },
    )
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code not in (408, 409, 429, 500, 502, 503, 504) or attempt == 3:
                raise RuntimeError(f"Claude API returned HTTP {exc.code}") from None
            time.sleep(min(2 ** attempt, 8))
        except (urllib.error.URLError, TimeoutError) as exc:
            if attempt == 3:
                raise RuntimeError("Claude API connection failed") from exc
            time.sleep(min(2 ** attempt, 8))
    raise RuntimeError("Claude API retry budget exhausted")


def run_experiment(
    cases: list[dict],
    output: Path,
    model: str,
    conditions: tuple[str, ...] = ("A", "B", "C"),
    trials: int = 2,
    *,
    live: bool = False,
    confirm_billing: bool = False,
    limit: int | None = None,
    client=None,
) -> dict:
    if not model.strip() or trials < 1 or any(c not in ("A", "B", "C") for c in conditions):
        raise ValueError("Invalid experiment configuration")
    if limit is not None and limit < 1:
        raise ValueError("limit must be positive")
    if live and not confirm_billing:
        raise ValueError("Live API requests require --confirm-billing")
    if live and client is None and not os.environ.get("ANTHROPIC_API_KEY"):
        raise RuntimeError("ANTHROPIC_API_KEY is required for live runs")
    if not live and output.exists():
        raise ValueError("Preview output already exists; use a new path")
    existing: set[str] = set()
    if live and output.exists():
        for line in output.read_text(encoding="utf-8").splitlines():
            if line.strip():
                existing.add(json.loads(line)["run_id"])
    pending: list[tuple[dict, str, int, str]] = []
    for case in sorted(cases, key=lambda item: item["case_id"]):
        for condition in conditions:
            for trial in range(trials):
                run_id = hashlib.sha256(
                    json.dumps(
                        [model, case["case_id"], condition, trial],
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest()[:20]
                if run_id not in existing:
                    pending.append((case, condition, trial, run_id))
    if limit is not None:
        pending = pending[:limit]
    output.parent.mkdir(parents=True, exist_ok=True)
    completed = 0
    with output.open("a" if live else "w", encoding="utf-8") as destination:
        for case, condition, trial, run_id in pending:
            prompt = make_prompt(case, condition)
            prompt_hash = hashlib.sha256(
                json.dumps(prompt, sort_keys=True).encode("utf-8")
            ).hexdigest()
            row = {
                "run_id": run_id,
                "case_id": case["case_id"],
                "condition": condition,
                "trial": trial,
                "model_requested": model,
                "prompt_sha256": prompt_hash,
                "api_version": API_VERSION,
                "recorded_utc": datetime.now(timezone.utc).isoformat(),
            }
            if not live:
                row.update({
                    "mode": "preview",
                    "system": prompt["system"],
                    "user": prompt["user"],
                })
            else:
                try:
                    response = (client or _call_claude)(model, prompt)
                    raw = "".join(
                        block.get("text", "") for block in response.get("content", [])
                        if block.get("type") == "text"
                    )
                    row.update({
                        "mode": "live",
                        "response_id": response.get("id"),
                        "model_returned": response.get("model"),
                        "stop_reason": response.get("stop_reason"),
                        "usage": response.get("usage", {}),
                        "raw": raw,
                    })
                    if response.get("stop_reason") != "end_turn":
                        row["parse_error"] = "Response did not finish normally"
                    else:
                        try:
                            row["verdict"] = parse_verdict(raw)
                        except (ValueError, TypeError, json.JSONDecodeError) as exc:
                            row["parse_error"] = str(exc)
                except RuntimeError as exc:
                    row["api_error"] = str(exc)
            destination.write(json.dumps(row, sort_keys=True) + "\n")
            destination.flush()
            completed += 1
    return {"written": completed, "total_planned": len(cases) * len(conditions) * trials,
            "already_present": len(existing), "mode": "live" if live else "preview"}
