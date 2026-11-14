"""V2 corpus, evidence and analysis tests; no live Anthropic API is used."""

from __future__ import annotations

import json

import pytest

from pqc_eval.v2.analysis import analyze_v2
from pqc_eval.v2.dataset import build_v2, load_v2, validate_case
from pqc_eval.v2.evidence import audit_report, evidence_for
from pqc_eval.v2.prompts import prompt_for
from pqc_eval.v2.runner import run_v2
from pqc_eval.v2.variants import STYLES, render_style


@pytest.fixture(scope="module")
def sample(tmp_path_factory):
    root = tmp_path_factory.mktemp("v2")
    manifest = build_v2(root, contexts=1)
    cases, loaded = load_v2(root, cryptographic=True)
    assert manifest == loaded
    return root, cases, manifest


def test_dataset_balanced_and_oracle_verified(sample):
    _, cases, _ = sample
    assert len(cases) == 50
    assert len({case["case_id"] for case in cases}) == len(cases)
    for case in cases:
        assert validate_case(case) == {
            "baseline_accepted": True,
            "challenge_accepted": case["variant"] == "vulnerable",
        }
        assert "PRIVATE KEY" not in json.dumps(case)


def test_five_distinct_implementations(sample):
    _, cases, _ = sample
    for family in ("signature", "rollback", "key_binding", "image_hash", "channel"):
        sources = [render_style(family, "vulnerable", style) for style in STYLES]
        assert len(set(sources)) == 5
        assert all("def approve(" in source for source in sources)
    assert len({case["style"] for case in cases}) == 5


def test_evidence_is_paired_and_auditable(sample):
    _, cases, _ = sample
    for case in cases:
        assert evidence_for(case, "A") is None
        b = evidence_for(case, "B")
        c = evidence_for(case, "C")
        d = evidence_for(case, "D")
        assert b["executed_tests"] == c["executed_tests"]
        assert b["executed_count"] == c["executed_count"] == 1
        assert b["summary"] != c["summary"]
        assert "independent_replay" not in c
        assert d["independent_replay"]["positive"]["observed_accepted"] is True
        assert d["independent_replay"]["additional_probe"]["observed_accepted"] == (
            case["variant"] == "vulnerable"
        )
        for condition, report in [("A", None), ("B", b), ("C", c), ("D", d)]:
            audit_report(case, condition, report)


def test_tampered_evidence_rejected(sample):
    _, cases, _ = sample
    report = evidence_for(cases[0], "B")
    report["passed_count"] = 0
    with pytest.raises(ValueError, match="Evidence report"):
        audit_report(cases[0], "B", report)


def test_prompt_metadata_is_blinded(sample):
    _, cases, _ = sample
    case = next(c for c in cases if c["variant"] == "vulnerable")
    for condition in ("A", "B", "C", "D"):
        prompt = prompt_for(case, condition)
        representation = json.dumps(prompt)
        assert "gold_label" not in representation
        assert '"variant"' not in representation
        assert case["case_id"] not in representation
        assert "vulnerable" not in representation.lower()
    assert "External test report" not in prompt_for(case, "A")["user"]


def test_sha_and_source_tampering_detected(sample):
    root, cases, _ = sample
    original = (root / "cases.jsonl").read_bytes()
    try:
        (root / "cases.jsonl").write_bytes(original + b"\n")
        with pytest.raises(ValueError, match="checksum"):
            load_v2(root)
    finally:
        (root / "cases.jsonl").write_bytes(original)
    case = dict(cases[0])
    case["source"] += "\n# modified"
    with pytest.raises(ValueError, match="Verifier source mismatch"):
        validate_case(case, cryptographic=False)


def test_generation_rejects_overwrite(sample):
    root, _, _ = sample
    with pytest.raises(FileExistsError):
        build_v2(root, contexts=1)


def test_preview_and_paid_guard(sample, tmp_path):
    _, cases, manifest = sample
    preview_path = tmp_path / "preview.jsonl"
    result = run_v2(
        cases[:2], manifest, preview_path, "claude-fixture",
        trials=1, conditions=("A", "B"), limit=2,
    )
    assert result["written"] == 2
    assert all(json.loads(line)["mode"] == "preview"
               for line in preview_path.read_text().splitlines())
    with pytest.raises(ValueError, match="confirm-billing"):
        run_v2(cases[:2], manifest, tmp_path / "paid.jsonl",
               "claude-fixture", live=True, client=lambda m, p: {})


def test_mock_live_and_resume_integrity(sample, tmp_path):
    _, cases, manifest = sample
    output = tmp_path / "live.jsonl"
    calls = []

    def fake_client(model, prompt):
        calls.append(model)
        return {
            "id": "msg_test",
            "model": model,
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 8, "output_tokens": 12},
            "content": [{"type": "text", "text": json.dumps({
                "decision": "BLOCK", "confidence": 0.8, "evidence": ["test fixture"],
            })}],
        }

    result = run_v2(
        cases[:2], manifest, output, "claude-fixture",
        conditions=("B",), trials=1, live=True,
        confirm_billing=True, client=fake_client,
    )
    assert result["written"] == 2
    assert len(calls) == 2
    again = run_v2(
        cases[:2], manifest, output, "claude-fixture",
        conditions=("B",), trials=1, live=True,
        confirm_billing=True, client=fake_client,
    )
    assert again["written"] == 0
    assert len(calls) == 2
    assert "ANTHROPIC_API_KEY" not in output.read_text()
    with pytest.raises(ValueError, match="incompatible"):
        run_v2(cases[:2], {**manifest, "dataset_sha256": "0" * 64},
               output, "claude-fixture", conditions=("B",), trials=1,
               live=True, confirm_billing=True, client=fake_client)


def test_paired_analysis_uses_only_mock_observations(sample, tmp_path):
    _, cases, manifest = sample
    chosen = [next(c for c in cases if c["variant"] == v) for v in ("secure", "vulnerable")]
    records = []
    for case in chosen:
        for condition in ("A", "B", "C", "D"):
            if case["variant"] == "vulnerable":
                decision = "APPROVE" if condition == "C" else "BLOCK"
            else:
                decision = "APPROVE"
            records.append({
                "protocol": "evidence-oversight-v2",
                "dataset_sha256": manifest["dataset_sha256"],
                "case_id": case["case_id"],
                "condition": condition,
                "trial": 0,
                "model_requested": "test-model",
                "mode": "live",
                "verdict": {"decision": decision, "confidence": 0.8, "evidence": []},
            })
    results = tmp_path / "synthetic-unit-test-fixture.jsonl"
    results.write_text("".join(json.dumps(r) + "\n" for r in records))
    report = analyze_v2(cases, manifest, results)
    assert report["valid_responses"] == 8
    assert report["primary_misleading_vs_truthful"]["difference"] == 1.0
    assert report["secondary_replay_vs_misleading"]["difference"] == -1.0
    assert report["conditions"]["C"]["false_safe"]["rate"] == 1.0
    assert report["conditions"]["D"]["false_safe"]["rate"] == 0.0


def test_preview_is_not_a_research_result(sample, tmp_path):
    _, cases, manifest = sample
    path = tmp_path / "preview.jsonl"
    run_v2(cases[:1], manifest, path, "claude-fixture",
           conditions=("A",), trials=1)
    report = analyze_v2(cases, manifest, path)
    assert report["valid_responses"] == 0
    assert report["excluded"]["not_live"] == 1
