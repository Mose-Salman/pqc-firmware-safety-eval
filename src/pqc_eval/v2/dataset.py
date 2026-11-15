"""Cryptographically validated, paired V2 firmware verifier dataset."""

from __future__ import annotations

import hashlib
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from pqc_eval.crypto import require_openssl, verify
from pqc_eval.dataset import _challenge, _make_context
from pqc_eval.specimen import FAMILIES, VARIANTS

from . import SCHEMA
from .variants import STYLES, execute_style, render_style, source_digest


STUDIED_FAMILIES = ("signature", "image_hash", "rollback", "key_binding", "channel")
DEFAULT_CONTEXTS = 4


def validate_case(case: dict, *, cryptographic: bool = True) -> dict:
    if case.get("schema") != SCHEMA:
        raise ValueError("Unexpected V2 case schema")
    family, style, variant = case["family"], case["style"], case["variant"]
    if family not in STUDIED_FAMILIES or style not in STYLES or variant not in VARIANTS:
        raise ValueError("Invalid family, style or variant")
    if case["gold_label"] != variant:
        raise ValueError("Case label and source variant disagree")
    source = render_style(family, variant, style)
    if case["source"] != source or case["source_sha256"] != source_digest(source):
        raise ValueError("Verifier source mismatch")
    if case["case_id"] != f"{case['context_id']}-{family}-{style}-{variant}":
        raise ValueError("Unexpected case identifier")
    if not cryptographic:
        return {"checked_source": True}
    observed = {
        "baseline_accepted": execute_style(
            family, variant, style, case["baseline"], case["policy"], verify
        ),
        "challenge_accepted": execute_style(
            family, variant, style, case["challenge"], case["policy"], verify
        ),
    }
    expected = {
        "baseline_accepted": True,
        "challenge_accepted": variant == "vulnerable",
    }
    if observed != expected:
        raise ValueError(f"Case oracle mismatch in {case['case_id']}: {observed}")
    return observed


def build_v2(output: Path, *, contexts: int = DEFAULT_CONTEXTS) -> dict:
    if contexts < 1 or contexts > 16:
        raise ValueError("contexts must be from 1 to 16")
    version = require_openssl()
    if output.exists() and any(output.iterdir()):
        raise FileExistsError("Refusing to overwrite a generated benchmark")
    output.mkdir(parents=True, exist_ok=True)
    cases: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="pqc-v2-private-") as temp:
        for index in range(contexts):
            policy, baseline, secret = _make_context(index, Path(temp))
            context_id = f"context-{index:02d}"
            for family in STUDIED_FAMILIES:
                challenge = _challenge(family, policy, baseline, secret)
                for style in STYLES:
                    for variant in VARIANTS:
                        source = render_style(family, variant, style)
                        case = {
                            "schema": SCHEMA,
                            "case_id": f"{context_id}-{family}-{style}-{variant}",
                            "context_id": context_id,
                            "family": family,
                            "style": style,
                            "variant": variant,
                            "gold_label": variant,
                            "source": source,
                            "source_sha256": source_digest(source),
                            "policy": policy,
                            "baseline": baseline,
                            "challenge": challenge,
                        }
                        validate_case(case)
                        cases.append(case)
    dataset_file = output / "cases.jsonl"
    dataset_file.write_text(
        "".join(json.dumps(case, separators=(",", ":"), sort_keys=True) + "\n"
                for case in cases), encoding="utf-8"
    )
    manifest = {
        "schema": SCHEMA,
        "contexts": contexts,
        "families": list(STUDIED_FAMILIES),
        "styles": list(STYLES),
        "case_count": len(cases),
        "dataset_sha256": hashlib.sha256(dataset_file.read_bytes()).hexdigest(),
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "openssl_version": version,
        "private_keys": "Ephemeral keys removed after benchmark creation",
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def load_v2(directory: Path, *, cryptographic: bool = False) -> tuple[list[dict], dict]:
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema") != SCHEMA:
        raise ValueError("Invalid V2 manifest schema")
    data = (directory / "cases.jsonl").read_bytes()
    if hashlib.sha256(data).hexdigest() != manifest["dataset_sha256"]:
        raise ValueError("V2 dataset checksum mismatch")
    cases = [json.loads(line) for line in data.decode("utf-8").splitlines() if line.strip()]
    if len(cases) != manifest["case_count"]:
        raise ValueError("Unexpected number of cases")
    expected_count = manifest["contexts"] * len(STUDIED_FAMILIES) * len(STYLES) * len(VARIANTS)
    if len(cases) != expected_count:
        raise ValueError("Incomplete balanced study design")
    if manifest["families"] != list(STUDIED_FAMILIES) or manifest["styles"] != list(STYLES):
        raise ValueError("Unsupported study design")
    seen: set[str] = set()
    for case in cases:
        if case["case_id"] in seen:
            raise ValueError("Duplicate V2 case ID")
        seen.add(case["case_id"])
        validate_case(case, cryptographic=cryptographic)
    return cases, manifest
