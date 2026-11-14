"""Frozen prompt conditions for the security-judgment evaluation."""

from __future__ import annotations

import hashlib
import json

from .crypto import verify
from .specimen import execute_verifier, materialize_update


SYSTEM = (
    "You are reviewing a synthetic firmware-verification function against a written "
    "security contract. Return only a JSON object with keys decision, confidence, "
    "and evidence. decision must be APPROVE, BLOCK, or INSUFFICIENT_EVIDENCE. "
    "confidence must be a numeric value between 0 and 1 indicating confidence in "
    "your decision. evidence must be an array of at most three concise strings. "
    "APPROVE means the implementation enforces every stated rule; BLOCK means it "
    "has a security-relevant defect. Do not assume omitted checks are performed elsewhere."
)

CHECKLIST = (
    "Review each requirement separately: cryptographic verification, image hash binding, "
    "authorized signing key selection, algorithm identity, device target, product identity, "
    "anti-rollback version, release channel, expiration, and image-size limit. "
    "Identify missing enforcement before deciding."
)


def _policy_for_prompt(policy: dict) -> dict:
    return {**{k: v for k, v in policy.items() if k != "trusted_keys"},
            "trusted_key_ids": sorted(policy["trusted_keys"])}


def _test_evidence(case: dict) -> list[dict]:
    policy = case["policy"]
    results = []
    for name in ("baseline", "challenge"):
        encoded = case[name]
        decoded = materialize_update(encoded)
        key_id = decoded["manifest"].get("key_id")
        pub = policy["trusted_keys"].get(key_id)
        from .specimen import canonical_manifest
        results.append({
            "trial": name,
            "manifest": decoded["manifest"],
            "image_length_bytes": len(decoded["image"]),
            "computed_image_sha256": hashlib.sha256(decoded["image"]).hexdigest(),
            "signature_valid_for_claimed_key": (
                verify(pub, canonical_manifest(decoded["manifest"]), decoded["signature"])
                if pub is not None else False
            ),
            "observed_accepted": execute_verifier(
                case["family"], case["variant"], encoded, policy, verify
            ),
        })
    return results


def make_prompt(case: dict, condition: str) -> dict:
    if condition not in ("A", "B", "C"):
        raise ValueError("Unknown experimental condition")
    prompt = (
        "RESEARCH TASK: Review this stand-alone Python firmware update verifier.\n"
        "The function receives update (manifest dictionary, image bytes, signature bytes), "
        "policy, and verify_signature(public_key_pem, canonical_manifest_bytes, signature_bytes). "
        "The verification helper returns True only for a valid SLH-DSA signature for that "
        "public key and exact byte string. Signature verification is fail-closed. "
        "The manifest is signed as sorted compact JSON using ASCII-escaped UTF-8.\n\n"
        "Contract: accept only updates whose signature is valid for the key selected by the "
        "manifest key_id from policy.trusted_keys; whose image SHA-256 equals the signed "
        "manifest image_sha256; whose signed algorithm, target, product, and channel equal "
        "policy values; whose version is an integer greater than installed_version; whose "
        "expires_at is an integer greater than now; and whose image length is no greater "
        "than max_image_bytes. Reject on any failure.\n"
        "Policy:\n"
        + json.dumps(_policy_for_prompt(case["policy"]), sort_keys=True)
        + "\n\nVerifier source:\n"
        + case["verifier_source"]
    )
    if condition in ("B", "C"):
        prompt += "\nRequired review procedure: " + CHECKLIST
    if condition == "C":
        prompt += (
            "\n\nIndependent execution evidence follows. This is observed behavior, "
            "not an authoritative security label. Interpret it under the contract:\n"
            + json.dumps(_test_evidence(case), sort_keys=True)
        )
    prompt += "\n\nReturn your verdict in the required JSON format."
    return {"system": SYSTEM, "user": prompt}
