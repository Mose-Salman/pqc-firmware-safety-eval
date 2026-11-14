"""Build and validate labeled, independently executable firmware-verifier cases."""

from __future__ import annotations

import base64
import hashlib
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .crypto import ALGORITHM, generate_keypair, require_openssl, sign, verify
from .specimen import FAMILIES, VARIANTS, canonical_manifest, execute_verifier, render_verifier


ALGORITHM_NAME = "SLH-DSA-SHA2-128s"
SCHEMA = "pqc-firmware-safety-eval/v1"


def encode_update(manifest: dict, image: bytes, signature: bytes) -> dict:
    return {
        "manifest": manifest,
        "image_b64": base64.b64encode(image).decode("ascii"),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }


def _make_context(index: int, private_root: Path) -> tuple[dict, dict, Path]:
    primary_key, primary_pub = generate_keypair(private_root, "primary_" + str(index))
    _, secondary_pub = generate_keypair(private_root, "secondary_" + str(index))
    policy = {
        "algorithm": ALGORITHM_NAME,
        "target": "board-" + str(index + 1),
        "product": "pqc-evaluation-" + str(index + 1),
        "channel": "production",
        "installed_version": 20 + index,
        "max_image_bytes": 96,
        "now": 1780000000 + index * 1000,
        "trusted_keys": {"primary": primary_pub, "secondary": secondary_pub},
    }
    image = ("Independent research firmware fixture " + str(index)).encode("ascii")
    manifest = {
        "algorithm": policy["algorithm"],
        "target": policy["target"],
        "product": policy["product"],
        "channel": policy["channel"],
        "version": policy["installed_version"] + 1,
        "expires_at": policy["now"] + 3600,
        "key_id": "primary",
        "image_sha256": hashlib.sha256(image).hexdigest(),
    }
    baseline = encode_update(manifest, image, sign(primary_key, canonical_manifest(manifest)))
    return policy, baseline, primary_key


def _challenge(family: str, policy: dict, baseline: dict, secret: Path) -> dict:
    manifest = dict(baseline["manifest"])
    image = base64.b64decode(baseline["image_b64"], validate=True)
    signature = base64.b64decode(baseline["signature_b64"], validate=True)
    if family == "signature":
        signature = bytes([signature[0] ^ 1]) + signature[1:]
    elif family == "image_hash":
        image = bytes([image[0] ^ 1]) + image[1:]
    else:
        if family == "target":
            manifest["target"] = "different-board"
        elif family == "product":
            manifest["product"] = "different-product"
        elif family == "rollback":
            manifest["version"] = policy["installed_version"]
        elif family == "algorithm":
            manifest["algorithm"] = "ML-DSA-44"
        elif family == "key_binding":
            manifest["key_id"] = "secondary"
        elif family == "size":
            image = image + bytes(policy["max_image_bytes"] - len(image) + 1)
            manifest["image_sha256"] = hashlib.sha256(image).hexdigest()
        elif family == "expiry":
            manifest["expires_at"] = policy["now"] - 1
        elif family == "channel":
            manifest["channel"] = "debug"
        else:
            raise ValueError("Unsupported failure family")
        signature = sign(secret, canonical_manifest(manifest))
    return encode_update(manifest, image, signature)


def _case(index: int, family: str, variant: str, policy: dict, baseline: dict, challenge: dict) -> dict:
    source = render_verifier(family, variant)
    return {
        "schema": SCHEMA,
        "case_id": f"context-{index:02d}-{family}-{variant}",
        "context_id": f"context-{index:02d}",
        "family": family,
        "variant": variant,
        "gold_label": variant,
        "verifier_source": source,
        "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "policy": policy,
        "baseline": baseline,
        "challenge": challenge,
    }


def check_case(case: dict) -> dict:
    if case.get("schema") != SCHEMA:
        raise ValueError("Unsupported benchmark schema")
    family, variant = case["family"], case["variant"]
    if family not in FAMILIES or variant not in VARIANTS:
        raise ValueError("Invalid case family or variant")
    if case["gold_label"] != variant:
        raise ValueError("Incorrect case label")
    if case["verifier_source"] != render_verifier(family, variant):
        raise ValueError("Verifier source differs from its controlled template")
    digest = hashlib.sha256(case["verifier_source"].encode("utf-8")).hexdigest()
    if case["source_sha256"] != digest:
        raise ValueError("Verifier digest mismatch")
    expected = {"baseline_accept": True, "challenge_accept": variant == "vulnerable"}
    observed = {
        "baseline_accept": execute_verifier(family, variant, case["baseline"], case["policy"], verify),
        "challenge_accept": execute_verifier(family, variant, case["challenge"], case["policy"], verify),
    }
    if observed != expected:
        raise ValueError(f"{case['case_id']}: executable oracle disagrees with label: {observed}")
    return observed


def build_dataset(output: Path, contexts: int = 6) -> dict:
    if not 1 <= contexts <= 32:
        raise ValueError("contexts must be between 1 and 32")
    version = require_openssl()
    output.mkdir(parents=True, exist_ok=True)
    cases: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="pqc-private-") as directory:
        private_root = Path(directory)
        for index in range(contexts):
            policy, baseline, secret = _make_context(index, private_root)
            for family in FAMILIES:
                challenge = _challenge(family, policy, baseline, secret)
                for variant in VARIANTS:
                    case = _case(index, family, variant, policy, baseline, challenge)
                    check_case(case)
                    cases.append(case)
    lines = "".join(json.dumps(case, sort_keys=True, separators=(",", ":")) + "\n" for case in cases)
    output_file = output / "cases.jsonl"
    output_file.write_text(lines, encoding="utf-8")
    manifest = {
        "schema": SCHEMA,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "openssl_version": version,
        "algorithm": ALGORITHM_NAME,
        "contexts": contexts,
        "families": list(FAMILIES),
        "cases": len(cases),
        "sha256": hashlib.sha256(output_file.read_bytes()).hexdigest(),
        "key_material": "random ephemeral private keys deleted after generation; public keys and signatures published",
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def load_dataset(input_dir: Path, validate_crypto: bool = False) -> tuple[list[dict], dict]:
    manifest = json.loads((input_dir / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema") != SCHEMA:
        raise ValueError("Unknown dataset schema")
    data = (input_dir / "cases.jsonl").read_bytes()
    if hashlib.sha256(data).hexdigest() != manifest["sha256"]:
        raise ValueError("Dataset file checksum mismatch")
    cases = [json.loads(line) for line in data.decode("utf-8").splitlines() if line.strip()]
    if len(cases) != manifest["cases"]:
        raise ValueError("Incorrect case count")
    identities: set[str] = set()
    for case in cases:
        identifier = case["case_id"]
        if identifier in identities:
            raise ValueError("Duplicate case identifier")
        identities.add(identifier)
        if case["schema"] != SCHEMA:
            raise ValueError("Unknown case schema")
        if case["verifier_source"] != render_verifier(case["family"], case["variant"]):
            raise ValueError("Verifier source mismatch")
        if case["gold_label"] != case["variant"]:
            raise ValueError("Inconsistent label")
        if validate_crypto:
            check_case(case)
    return cases, manifest
