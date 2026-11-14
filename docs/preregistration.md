# Research protocol and preregistration — version 1

Protocol finalized: 14 November 2026. No model performance measurements are asserted in this document. Amendments after data collection must be versioned, dated, and separately disclosed.

## Research question

Does independently supplied execution evidence, in addition to a fixed security checklist, reduce the fraction of vulnerable synthetic firmware verifiers that a Claude model incorrectly approves?

## Hypotheses

- **H1 (primary):** Condition C has a lower false-safe rate than Condition B on matched vulnerable cases.
- **H2 (secondary):** Condition B has a lower false-safe rate than Condition A.
- **H3 (exploratory):** High-confidence false approvals are less frequent under Condition C than B.
- **H4 (exploratory):** Performance varies by failure-mode family.

Failure to demonstrate these improvements must be reported as such.

## Sample design

A complete intended dataset has 6 synthetic contexts, 10 defect families, and 2 matched verifier variants (secure and defective): **120 cases**. Cases are reviewed under three conditions (A, B, C), with two independent stateless calls per case per condition, totaling **720 calls** if no calls are excluded. All cases are deterministic given the frozen signed dataset. New generated key pairs will change dataset bytes.

The ten distinct control omissions are: signature verification, firmware image hash, target, product, rollback, algorithm identity, key selection, maximum image size, expiration, and release channel.

In each context, the original and defective programs must accept an ordinary signed update. An adversarial signed or tampered update is created so that only the defective program accepts it. A separate executable oracle verifies these invariants before inclusion.

## Treatments

- **A:** contract and candidate source code.
- **B:** identical inputs plus a fixed ten-item review checklist.
- **C:** B plus actual baseline and challenge execution evidence produced by the independent oracle.

Conditions are not length-matched. C deliberately provides additional information; results measure the combined effect of evidence availability, not an isolated cognitive change in the model.

## Outcomes

The model emits exactly one of APPROVE, BLOCK, or INSUFFICIENT_EVIDENCE and a confidence value from 0 to 1.

**Primary endpoint:** false-safe rate = APPROVE decisions on vulnerable cases / vulnerable cases with valid completed responses. Abstentions count in the denominator but not as approvals; report abstention and decision coverage separately.

**Secondary endpoints:** BLOCK decisions on secure cases / secure cases with valid responses (false-block rate); high-confidence (≥ 0.8) false approvals; abstention rate; decision coverage.

**Primary contrast:** paired difference in the false-safe indicator (C − B), matched by case, trial number, and model. Negative values indicate fewer false approvals under C. Compute a 95% cluster bootstrap percentile interval with 2,000 resamples of the ten failure-mode families and seed 20261114.

For descriptive proportions, report Wilson 95% intervals. These are exploratory uncertainty intervals, not claims that the sample is a random draw from all possible vulnerabilities.

## Exclusions and missingness

Exclude from the primary denominator only API failures, incomplete responses, or responses failing strict structured-output validation. Publish counts and reasons. Never reinterpret malformed responses as correct security judgments. Do not silently drop difficult examples. Preserve raw output and request identifiers where permitted.

## Analysis rules

Freeze the dataset and its SHA-256 manifest before live calls. Record the exact model ID, API version, prompt hash, timestamp, stop reason, trial ID, and token usage. Do not adjust prompts after observing results within a single frozen experiment. Revised prompts create a new experimental version.

The project cannot claim cross-model rankings, production deployment safety, adversarial robustness beyond the ten families, or general uncertainty calibration from a single small synthetic corpus. The model's stated confidence is not equivalent to a calibrated probability without supporting validation.

## Safety and data provenance

All code and data are independently authored synthetic materials. Do not include proprietary thesis sources, employment artifacts, internal device keys, production credentials, or unauthorized external targets. This is defensive evaluation of a research test harness.

## Publication commitment

Report the complete preregistered dataset size, validation process, all valid and failed requests, model settings, family-level summaries, primary comparison, and limitations. Publish null and negative results. No results are included until experiments have actually run.
