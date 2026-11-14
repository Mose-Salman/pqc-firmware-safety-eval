# External Researcher Access — proposal material

**Applicant:** Independent security researcher with experience in post-quantum firmware authentication, PKI/HSM operations and embedded engineering.

**Project:** Evaluating overconfident AI security judgments in post-quantum firmware verification.

**Status:** Infrastructure implemented and cryptographic regression tests verified. No live Claude evaluations or performance findings are claimed in this proposal.

## Research abstract

Language models are increasingly used to review code whose security depends on several interacting verification requirements. In secure firmware updates, a valid cryptographic signature is not sufficient unless the implementation also binds the intended firmware image, authorized verification key, target hardware, update policy, and validity period.

This independent project measures whether a language model can distinguish correctly enforced post-quantum firmware-verification policies from superficially plausible implementations with one critical check omitted. The study uses executable, synthetic Python verifiers and FIPS 205 SLH-DSA signatures to produce independently validated ground truth.

Three controlled review conditions compare direct code review with structured checklist review and independently observed test evidence. The primary outcome is the rate of vulnerable implementations incorrectly approved as secure. Secondary outcomes quantify false rejections, abstentions, and high-confidence false approvals. The paired design is intended to examine whether external test evidence improves model oversight in a narrowly defined security-critical task.

## Contribution to AI safety research

The core research problem is *unsafe assurance* rather than digital-signature performance. An incorrect APPROVE decision can encourage downstream reliance on a defective implementation. The model's ability to say INSUFFICIENT_EVIDENCE and its response to fallible or partial external evidence are directly relevant to effective AI-assisted oversight.

The preregistered comparison tests whether providing verifiable observations reduces false approvals relative to a review checklist alone. It does not assume that better prompt formatting proves greater model alignment or that a single security benchmark is a sufficient general safety evaluation.

## Existing independently verifiable work

- Public code implements the ten control-failure families and secure counterparts.
- Every synthetic ground-truth case is executable and checked against signed firmware artifacts.
- Cryptographic signing and verification use the OpenSSL 3.5 SLH-DSA provider.
- CI checks the complete 120-case generated corpus.
- Claude prompts, run manifests, parsing, and statistical analysis are version controlled.

These are software validation facts, not results about Claude's behavior.

## Planned API-credit use

A complete study has 120 cases × 3 conditions × 2 trials = 720 Claude requests, before any pilot or replication. The specific model must be selected from the models actually available to the researcher.

Credits would support a limited initial pilot for output-schema validation followed by the preregistered full comparison. Request counts, prompt sizes, returned token usage, and price calculations will be documented. The study will not request access to restricted models or claim a specific spend before actual usage is measured.

## Public outputs and research ethics

Deliverables include the source code, frozen synthetic dataset and checksums, preregistration, execution logs where redistribution is allowed, aggregate statistical report, and a technical note documenting null, negative, and positive outcomes alike.

No proprietary employer code, signing keys, production firmware, real exploit targets, or third-party credentials will be used. The study is intended for defensive, authorized research only.

## Research limitations

Cases are synthetic and drawn from ten researcher-authored fault families; variants across contexts share common templates. Test-backed review conditions receive more information than direct review, and differences cannot be attributed exclusively to reasoning quality. Confidence responses are self-reported, and the dataset does not establish global calibration. These limitations will be stated in the final report.

## Immediate next milestone

After freezing a reviewed dataset and selecting an available Claude model, conduct a small paid pilot, inspect the output schema, and verify API usage accounting before the full experiment. Do not enter results in the application that have not been observed.
