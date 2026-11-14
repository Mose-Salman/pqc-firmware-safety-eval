"""FIPS 205 SLH-DSA operations through OpenSSL 3.5 or later.

This module is research infrastructure, not a production firmware verifier.
The private key exists only in a temporary directory during benchmark creation.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path


ALGORITHM = "SLH-DSA-SHA2-128s"


class CryptoError(RuntimeError):
    """A cryptographic operation or required dependency failed."""


def _call(*args: str, timeout: int = 90) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            ["openssl", *args], capture_output=True, check=False, timeout=timeout
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CryptoError("OpenSSL invocation failed") from exc


def require_openssl() -> str:
    result = _call("version")
    version = result.stdout.decode("ascii", errors="replace").strip()
    match = re.match(r"OpenSSL\s+(\d+)\.(\d+)\.(\d+)", version)
    if result.returncode != 0 or match is None or tuple(map(int, match.groups())) < (3, 5, 0):
        raise CryptoError("OpenSSL >= 3.5.0 with SLH-DSA support is required")
    algorithms = _call("list", "-signature-algorithms")
    if algorithms.returncode != 0 or b"SLH-DSA-SHA2-128s" not in algorithms.stdout:
        raise CryptoError("The OpenSSL provider does not expose SLH-DSA-SHA2-128s")
    return version


def generate_keypair(directory: Path, identifier: str) -> tuple[Path, str]:
    if not re.fullmatch(r"[a-z][a-z0-9_-]*", identifier):
        raise ValueError("Invalid key identifier")
    directory.mkdir(parents=True, exist_ok=True)
    secret_path = directory / (identifier + ".private.pem")
    public_path = directory / (identifier + ".public.pem")
    result = _call("genpkey", "-algorithm", ALGORITHM, "-out", str(secret_path))
    if result.returncode != 0:
        raise CryptoError("SLH-DSA key generation failed")
    secret_path.chmod(0o600)
    result = _call("pkey", "-in", str(secret_path), "-pubout", "-out", str(public_path))
    if result.returncode != 0:
        raise CryptoError("SLH-DSA public-key export failed")
    return secret_path, public_path.read_text(encoding="ascii")


def sign(secret_key: Path, payload: bytes) -> bytes:
    with tempfile.TemporaryDirectory(prefix="pqc-sign-") as temporary:
        root = Path(temporary)
        (root / "message.bin").write_bytes(payload)
        result = _call(
            "pkeyutl", "-sign", "-rawin", "-inkey", str(secret_key),
            "-in", str(root / "message.bin"), "-out", str(root / "signature.bin"),
        )
        if result.returncode != 0:
            raise CryptoError("SLH-DSA signing failed")
        return (root / "signature.bin").read_bytes()


def verify(public_key: str, payload: bytes, signature: bytes) -> bool:
    if not public_key.startswith("-----BEGIN PUBLIC KEY-----"):
        raise ValueError("Expected a PEM-encoded public key")
    with tempfile.TemporaryDirectory(prefix="pqc-verify-") as temporary:
        root = Path(temporary)
        (root / "public.pem").write_text(public_key, encoding="ascii")
        (root / "message.bin").write_bytes(payload)
        (root / "signature.bin").write_bytes(signature)
        result = _call(
            "pkeyutl", "-verify", "-rawin", "-pubin",
            "-inkey", str(root / "public.pem"),
            "-in", str(root / "message.bin"), "-sigfile", str(root / "signature.bin"),
        )
        if result.returncode == 0:
            return True
        if result.returncode == 1 and b"Signature Verification Failure" in result.stdout + result.stderr:
            return False
        raise CryptoError("SLH-DSA verification operation failed")
