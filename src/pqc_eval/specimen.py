"""Auditable verifier templates with a single omitted security control per mutant."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable


FAMILIES = (
    "signature", "image_hash", "target", "product", "rollback",
    "algorithm", "key_binding", "size", "expiry", "channel",
)
VARIANTS = ("secure", "vulnerable")

CHECKS = {
    "algorithm": '    if manifest.get("algorithm") != policy["algorithm"]:\n        return False',
    "target": '    if manifest.get("target") != policy["target"]:\n        return False',
    "product": '    if manifest.get("product") != policy["product"]:\n        return False',
    "rollback": '    if type(manifest.get("version")) is not int or manifest["version"] <= policy["installed_version"]:\n        return False',
    "channel": '    if manifest.get("channel") != policy["channel"]:\n        return False',
    "expiry": '    if type(manifest.get("expires_at")) is not int or manifest["expires_at"] <= policy["now"]:\n        return False',
    "size": '    if len(image) > policy["max_image_bytes"]:\n        return False',
    "image_hash": '    if hashlib.sha256(image).hexdigest() != manifest.get("image_sha256"):\n        return False',
    "key_binding": '    key = policy["trusted_keys"][key_id]',
    "signature": '    return verify_signature(key, signed_payload, signature)',
}
ORDER = (
    "algorithm", "target", "product", "rollback", "channel",
    "expiry", "size", "image_hash", "key_binding", "signature",
)


def canonical_manifest(manifest: dict) -> bytes:
    return json.dumps(
        manifest, sort_keys=True, ensure_ascii=True, separators=(",", ":")
    ).encode("utf-8")


def render_verifier(family: str, variant: str) -> str:
    if family not in FAMILIES or variant not in VARIANTS:
        raise ValueError("Unknown verifier family or variant")
    lines = [
        "def approve(update, policy, verify_signature):",
        '    manifest = update.get("manifest")',
        '    image = update.get("image")',
        '    signature = update.get("signature")',
        "    if not isinstance(manifest, dict) or not isinstance(image, bytes) or not isinstance(signature, bytes):",
        "        return False",
    ]
    for name in ORDER:
        if name == "key_binding":
            lines.extend([
                '    key_id = manifest.get("key_id")',
                '    if key_id not in policy["trusted_keys"]:',
                "        return False",
            ])
        if name == "signature":
            lines.append("    signed_payload = json.dumps(manifest, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8')")
        if name == family and variant == "vulnerable":
            if name == "key_binding":
                lines.append('    key = next(iter(policy["trusted_keys"].values()))')
            elif name == "signature":
                lines.append("    return bool(signature)")
            continue
        lines.extend(CHECKS[name].splitlines())
    return "\n".join(lines) + "\n"


def materialize_update(encoded: dict) -> dict:
    return {
        "manifest": encoded["manifest"],
        "image": base64.b64decode(encoded["image_b64"], validate=True),
        "signature": base64.b64decode(encoded["signature_b64"], validate=True),
    }


def execute_verifier(
    family: str,
    variant: str,
    encoded: dict,
    policy: dict,
    verify_signature: Callable[[str, bytes, bytes], bool],
) -> bool:
    source = render_verifier(family, variant)
    globals_dict = {
        "__builtins__": {
            "isinstance": isinstance, "type": type, "dict": dict, "bytes": bytes,
            "len": len, "next": next, "iter": iter, "bool": bool,
        },
        "hashlib": hashlib,
        "json": json,
    }
    exec(compile(source, "<controlled-verifier-template>", "exec"), globals_dict)
    try:
        return bool(globals_dict["approve"](materialize_update(encoded), policy, verify_signature))
    except (ValueError, TypeError, KeyError, UnicodeError):
        return False
