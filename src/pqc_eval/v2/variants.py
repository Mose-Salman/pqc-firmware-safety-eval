"""Five trusted source transformations of the V1 security contract.

Only locally generated templates are executed. This is not a Python sandbox
and must never execute externally supplied source.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import json
from collections.abc import Callable

from pqc_eval.specimen import FAMILIES, VARIANTS, materialize_update, render_verifier


STYLES = ("inline", "reordered", "delegated", "class_based", "staged")


def _parse_base(family: str, variant: str) -> ast.FunctionDef:
    if family not in FAMILIES or variant not in VARIANTS:
        raise ValueError("Unrecognized verifier configuration")
    body = ast.parse(render_verifier(family, variant)).body
    assert len(body) == 1 and isinstance(body[0], ast.FunctionDef)
    return body[0]


def render_style(family: str, variant: str, style: str) -> str:
    """Generate auditable source. Each style retains the same security decision."""
    if style not in STYLES:
        raise ValueError("Unrecognized implementation style")
    fn = _parse_base(family, variant)
    if style == "inline":
        return render_verifier(family, variant)
    if style == "reordered":
        # These eight independent policy checks follow input type validation.
        checks = fn.body[4:12]
        if len(checks) != 8 or not all(isinstance(node, ast.If) for node in checks):
            raise RuntimeError("The base verifier structure has changed")
        fn.body[4:12] = checks[::2] + checks[1::2]
        module = ast.Module(body=[fn], type_ignores=[])
    elif style == "delegated":
        fn.name = "_evaluate"
        entry = ast.parse(
            "def approve(update, policy, verify_signature):\n"
            "    return _evaluate(update, policy, verify_signature)\n"
        ).body[0]
        module = ast.Module(body=[fn, entry], type_ignores=[])
    elif style == "class_based":
        wrapper = ast.parse(
            "class FirmwareReview:\n"
            "    def evaluate(self, update, policy, verify_signature):\n"
            "        return False\n"
            "\n"
            "def approve(update, policy, verify_signature):\n"
            "    return FirmwareReview().evaluate(update, policy, verify_signature)\n"
        )
        method = wrapper.body[0].body[0]
        method.body = copy.deepcopy(fn.body)
        module = wrapper
    else:
        # Move independent policy checks to a separate boolean preflight stage.
        policy_checks = copy.deepcopy(fn.body[4:12])
        preflight = ast.parse(
            "def _check_policy(manifest, image, policy):\n"
            "    return True\n"
        ).body[0]
        preflight.body = policy_checks + [ast.Return(value=ast.Constant(value=True))]
        guard = ast.parse(
            "if not _check_policy(manifest, image, policy):\n"
            "    return False\n"
        ).body[0]
        fn.body = fn.body[:4] + [guard] + fn.body[12:]
        module = ast.Module(body=[preflight, fn], type_ignores=[])
    ast.fix_missing_locations(module)
    return ast.unparse(module) + "\n"


def source_digest(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def execute_style(
    family: str, variant: str, style: str, encoded_update: dict, policy: dict,
    verify_signature: Callable[[str, bytes, bytes], bool],
) -> bool:
    """Execute only the reconstructed trusted template, never dataset source."""
    source = render_style(family, variant, style)
    globals_dict = {
        "__name__": "pqc_eval_v2_generated",
        "__builtins__": {
            "isinstance": isinstance, "type": type, "dict": dict, "bytes": bytes,
            "len": len, "next": next, "iter": iter, "bool": bool, "int": int,
            "__build_class__": __build_class__, "object": object,
        },
        "hashlib": hashlib,
        "json": json,
    }
    exec(compile(source, "<trusted-v2-specimen>", "exec"), globals_dict)
    try:
        return bool(globals_dict["approve"](
            materialize_update(encoded_update), policy, verify_signature
        ))
    except (ValueError, TypeError, KeyError, UnicodeError):
        return False
