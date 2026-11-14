"""End-to-end regression tests using real SLH-DSA signatures."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from pqc_eval.analysis import analyze, wilson_interval
from pqc_eval.crypto import ALGORITHM, require_openssl, verify
from pqc_eval.dataset import build_dataset, check_case, load_dataset
from pqc_eval.prompts import make_prompt
from pqc_eval.runner import parse_verdict, run_experiment
from pqc_eval.specimen import FAMILIES, VARIANTS, canonical_manifest, render_verifier


@pytest.fixture(scope="module")
def dataset(tmp_path_factory):
    directory = tmp_path_factory.mktemp("dataset")
    manifest = build_dataset(directory, contexts=1)
    cases, loaded = load_dataset(directory, validate_crypto=True)
    assert manifest == loaded
    return directory, cases


def test_crypto_backend():
    assert require_openssl().startswith("OpenSSL 3.")
    assert ALGORITHM == "SLH-DSA-SHA2-128s"


def test_all_defects_are_verified(dataset):
    _, cases = dataset
    assert len(cases) == 20
    assert {case["family"] for case in cases} == set(FAMILIES)
    assert {case["variant"] for case in cases} == set(VARIANTS)
    for case in cases:
        assert check_case(case) == {
            "baseline_accept": True,
            "challenge_accept": case["gold_label"] == "vulnerable",
        }
        assert "PRIVATE KEY" not in json.dumps(case)
        assert case["verifier_source"] == render_verifier(case["family"], case["variant"])


def test_forged_signature_is_rejected(dataset):
    _, cases = dataset
    case = next(c for c in cases if c["family"] == "signature" and c["variant"] == "secure")
    import base64
    from pqc_eval.specimen import materialize_update
    update = materialize_update(case["challenge"])
    public = case["policy"]["trusted_keys"]["primary"]
    assert verify(public, canonical_manifest(update["manifest"]), update["signature"]) is False


def test_integrity_failure_is_detected(dataset):
    directory, _ = dataset
    altered = directory / "cases.jsonl"
    original = altered.read_bytes()
    try:
        altered.write_bytes(original + b"\n")
        with pytest.raises(ValueError, match="checksum"):
            load_dataset(directory)
    finally:
        altered.write_bytes(original)


def test_prompt_excludes_ground_truth(dataset):
    _, cases = dataset
    case = next(c for c in cases if c["gold_label"] == "vulnerable")
    a, b, c = [make_prompt(case, name) for name in ("A", "B", "C")]
    assert "gold_label" not in json.dumps(a)
    assert "gold_label" not in json.dumps(b)
    assert "gold_label" not in json.dumps(c)
    assert "Independent execution evidence" not in a["user"]
    assert "Independent execution evidence" in c["user"]
    assert "Required review procedure:" in b["user"]
    assert a["user"] != b["user"] != c["user"]


@pytest.mark.parametrize("response", [
    "not json", '{"decision":"APPROVE","confidence":1.5,"evidence":[]}',
    '{"decision":"APPROVE","confidence":NaN,"evidence":[]}',
    '{"decision":"MAYBE","confidence":0.5,"evidence":[]}',
    '{"decision":"BLOCK","confidence":true,"evidence":[]}',
    '{"decision":"BLOCK","confidence":0.5,"evidence":"wrong"}',
    '{"decision":"BLOCK","confidence":0.5,"evidence":[],"unexpected":"value"}',
])
def test_reject_invalid_model_responses(response):
    with pytest.raises((ValueError, TypeError)):
        parse_verdict(response)


def test_parse_valid_model_response():
    result = parse_verdict('{"decision":"BLOCK","confidence":0.75,"evidence":["missing signature check"]}')
    assert result["decision"] == "BLOCK"


def test_prompt_preview_and_mocked_live_runner(dataset, tmp_path):
    _, cases = dataset
    preview = tmp_path / "preview.jsonl"
    output = tmp_path / "live.jsonl"
    summary = run_experiment(cases[:2], preview, "claude-test-fixture", conditions=("A",), trials=1)
    assert summary["written"] == 2
    assert all(json.loads(line)["mode"] == "preview" for line in preview.read_text().splitlines())
    calls = []

    def fake_client(model, prompt):
        calls.append((model, prompt))
        return {
            "id": "msg_fixture",
            "model": model,
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 20, "output_tokens": 20},
            "content": [{
                "type": "text",
                "text": '{"decision":"BLOCK","confidence":0.8,"evidence":["fixture"]}',
            }],
        }

    with pytest.raises(ValueError, match="confirm-billing"):
        run_experiment(cases[:2], output, "claude-test-fixture", live=True, client=fake_client)
    done = run_experiment(
        cases[:2], output, "claude-test-fixture",
        conditions=("A",), trials=1, live=True, confirm_billing=True, client=fake_client,
    )
    assert done["written"] == 2
    assert len(calls) == 2
    again = run_experiment(
        cases[:2], output, "claude-test-fixture",
        conditions=("A",), trials=1, live=True, confirm_billing=True, client=fake_client,
    )
    assert again["written"] == 0
    assert len(calls) == 2
    assert "x-api-key" not in output.read_text()


def test_metrics_are_computed_from_observed_calls(dataset, tmp_path):
    _, cases = dataset
    secure = next(c for c in cases if c["variant"] == "secure")
    faulty = next(c for c in cases if c["variant"] == "vulnerable")
    entries = []
    for case in (secure, faulty):
        for condition in ("B", "C"):
            decision = ("APPROVE" if condition == "B" else "BLOCK") if case is faulty else "APPROVE"
            entries.append({
                "case_id": case["case_id"], "condition": condition, "trial": 0,
                "model_requested": "claude-test-fixture", "mode": "live",
                "verdict": {"decision": decision, "confidence": 0.9, "evidence": []},
            })
    path = tmp_path / "runs.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in entries))
    report = analyze(cases, path)
    assert report["conditions"]["B"]["false_safe"]["rate"] == 1.0
    assert report["conditions"]["C"]["false_safe"]["rate"] == 0.0
    assert report["primary_comparison_b_vs_c"]["difference_c_minus_b"] == -1.0
    assert wilson_interval(0, 0) is None
