# Related work and methodological position

This document identifies public material used to define the benchmark's cryptographic contract and experimental methodology. These sources are not incorporated as copyrighted benchmark data.

## Cryptographic ground truth

- **NIST FIPS 205 — Stateless Hash-Based Digital Signature Standard.** Defines SLH-DSA and its standardized parameter sets. The research oracle uses SLH-DSA-SHA2-128s through OpenSSL 3.5. https://csrc.nist.gov/pubs/fips/205/final
- **OpenSSL SLH-DSA provider.** Supplies key generation, signature creation, and signature verification through the OpenSSL command-line interface. https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-SLH-DSA/
- **MCUboot.** A publicly documented reference for secure firmware update architecture and threat-model vocabulary. Its actual code and device-specific vulnerabilities are not used as research targets. https://github.com/mcu-tools/mcuboot

The project does not claim equivalence between older SPHINCS+ implementations and FIPS 205's standardized SLH-DSA byte formats. No LMS implementation is used in this evaluation.

## AI security evaluation methodology

- **BaxBench.** Motivates evaluating functionality and security separately rather than treating working code as secure code. https://baxbench.com/
- **SecCodePLT.** Provides an example of executable secure-code evaluation. https://github.com/ucsb-mlsec/SeCodePLT
- **CyberSecEval / Purple Llama.** Provides context on model cybersecurity evaluations and task design. https://github.com/meta-llama/PurpleLlama
- **Anthropic Alignment Science research directions.** Supports studying model reliability, evaluation validity, and oversight mechanisms. https://alignment.anthropic.com/2025/recommended-directions/

These are methodological references, not direct comparison baselines. The current implementation does not execute or claim reproduction of those published benchmarks.

## Novelty and limits

The project's contribution is a fully executable, cryptography-backed and tightly paired set of synthetic firmware-verification control omissions, with three review conditions and reported false assurances under a specified contract.

This is **not** a representative sample of all embedded firmware vulnerabilities. Several vulnerabilities have obvious missing checks, making this an initial validation benchmark with potential ceiling effects. Strong performance on it cannot justify claims about model performance on real-world firmware or cryptographic protocol review.

A subsequent study would require independently sourced, held-out implementations; expert validation; greater code diversity; and additional baselines. Such work is not claimed as complete in this repository.
