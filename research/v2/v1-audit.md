# Baseline Project 01 methodology audit

Audit performed against version 1 source and documentation in the public repository before implementing version 2.

## Finding 1 — Partial answer leakage in test-backed condition

The original C condition includes execution results for the designed challenge. It exposes observed acceptance and related cryptographic evidence. This can reveal the outcome the model is supposed to infer from code and policy.

**Resolution in Project 02:** Evidence reports B and C share one normal positive-path test. The core experimental contrast manipulates only the reliability of its summary claim. The independent challenge replay appears only in condition D and is interpreted as a distinct richer-evidence treatment.

**Project 01 disposition:** Do not change or retroactively relabel the frozen Project 01 conditions. The original results, if collected, should be interpreted with this limitation.

## Finding 2 — Source-template correlation

Project 01 reuses a small function template, varying one missing control and device metadata. The generated cases are not independent samples of firmware source code.

**Resolution:** Project 02 adds five auditable structural transformations and five selected defect families, with executable equivalence checks. These transformations are still related and do not eliminate the shared-template limitation.

## Finding 3 — Resume and provenance concerns

Project 01's run identifiers depend on model, case, condition and trial but do not explicitly include a frozen dataset SHA. Reusing identifiers with regenerated cryptographic fixtures could mix experimental versions.

**Resolution:** Project 02 includes the dataset digest and protocol identifier in each run's identity, checks prompt digests when resuming, and rejects mismatched result files. Project 01 remains unchanged to preserve its original protocol.

## Finding 4 — Statistical independence and interpretation

Neither related variants nor repeated calls should be treated as independent vulnerability discoveries. The original uncertainty intervals provide exploratory summaries, not population-generalizable claims.

**Resolution:** Project 02 pairs conditions by case/model/trial, resamples at the security-control-family level, discloses the small number of clusters, and treats all findings as exploratory.

## Findings not claimed

No actual Claude responses or model-performance improvements are demonstrated by the repository's offline CI. Synthetic examples and deliberately misleading summaries are experimental materials, not real vulnerability disclosures or evidence of malicious model behavior.
