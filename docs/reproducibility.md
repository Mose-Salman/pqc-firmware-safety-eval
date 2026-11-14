# Reproducibility and provenance

## Environment

Run on Python >= 3.11 with OpenSSL >= 3.5 exposing SLH-DSA-SHA2-128s. CI uses an Ubuntu 26.04 container. The Python runtime has no third-party runtime dependencies; pytest is needed only for the tests.

Record the commit SHA, operating-system image, Python version, OpenSSL version, exact Claude model identifier, API version, and the SHA-256 of the frozen dataset.

## Generation and freezing

1. Run the test suite.
2. Build a full dataset with `pqc-eval build --contexts 6 --out benchmark/generated`.
3. Run `pqc-eval validate --dataset benchmark/generated` to cryptographically replay every case.
4. Preserve `cases.jsonl` and `manifest.json` together as a frozen, versioned research artifact.
5. Perform a human review of a representative sample from each failure family before executing any live API calls.

Key generation is cryptographically random. Therefore, rebuilding produces different key material, signature bytes, and file hashes; **exact-byte replication requires the frozen dataset artifact**. The case construction, security outcomes, and numerical study design can be reproduced independently with newly generated keys.

No private keys are stored in the dataset; the key generation directory is removed on exit.

## API experiment

The preview runner requires no API access. Live runs require an explicit `--live --confirm-billing` pair and `ANTHROPIC_API_KEY` in the environment. Do not put keys in files, git history, shell logs, screenshots, or Issues. Before a full run, make a limited paid pilot and verify the returned schema and incurred usage.

The runner writes append-only JSON Lines records, including failed requests. Reruns skip saved run IDs. Editing or deleting records constitutes a documented deviation, not a transparent continuation.

## Scoring and reporting

The `analyze` command consumes the frozen dataset and actual live-result records. It does not generate hypothetical model outputs. Preserve the raw, permission-compatible responses and the analysis script revision that produced any reported figures.

Where permitted by provider terms and privacy rules, release the original responses, validation notes, and aggregated report alongside the frozen benchmark. If output cannot be redistributed, release prompt hashes, scoring code, configuration, aggregate metrics, and rerun instructions.

## Known limits

The ten failure modes are intentionally authored and relatively conspicuous. Cases share templates across contexts and cannot be assumed statistically independent. The reference cryptographic implementation is OpenSSL; the project does not independently validate its cryptographic proofs. Structured responses may not express genuine calibrated confidence. A model's approval is not a security certification.

## External reference specifications

- NIST FIPS 205: https://csrc.nist.gov/pubs/fips/205/final
- OpenSSL SLH-DSA provider: https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-SLH-DSA/
- Anthropic Messages API: https://platform.claude.com/docs/en/api/messages/create
