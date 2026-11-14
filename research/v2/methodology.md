# Project 02: Methodology, data provenance and execution

## Research provenance

Project 02 extends the independently generated SLH-DSA firmware-verification testbed from Project 01. It is a new evaluation protocol and new dataset namespace. It must not be pooled with or silently substituted for the earlier A/B/C study.

The five selected families test whether the verifier enforces all rules in the signed update manifest and local policy. Each defective version omits or misapplies exactly one named control. Test-artifact signatures are real FIPS 205 SLH-DSA-SHA2-128s signatures created by the OpenSSL 3.5 provider.

The generation process uses independently designed synthetic artifacts and private keys in a temporary directory. Generated public keys, manifest data, signatures and toy image bytes may be included in a frozen research artifact. Real private or production signing keys must not be present.

## Execution

Requirements: Python ≥3.11, OpenSSL ≥3.5 with SLH-DSA, pytest for tests.

```sh
PYTHONPATH=src python3 -m pytest -q
PYTHONPATH=src python3 -m pqc_eval.v2 build --contexts 4 --out benchmark/v2-generated
PYTHONPATH=src python3 -m pqc_eval.v2 validate --dataset benchmark/v2-generated
PYTHONPATH=src python3 -m pqc_eval.v2 run --dataset benchmark/v2-generated \
  --model YOUR_AVAILABLE_CLAUDE_MODEL_ID --conditions A,B,C,D \
  --trials 2 --limit 4 --out results/v2-preview.jsonl
```

The preview requires no Anthropic account and produces **no Claude responses**.

For a small, explicitly paid live pilot, keep the credentials outside the repository, choose an available model identifier, and separately invoke:

```sh
export ANTHROPIC_API_KEY='set-this-in-your-local-shell'
PYTHONPATH=src python3 -m pqc_eval.v2 run --dataset benchmark/v2-generated \
  --model YOUR_AVAILABLE_CLAUDE_MODEL_ID --conditions A,B,C,D \
  --trials 2 --limit 4 --live --confirm-billing \
  --out results/v2-pilot.jsonl
```

**Important:** Pilot outputs must not be mixed with preregistered main-study results. For the full study use a separate output path and a frozen dataset. Model requests use Anthropic's documented Messages endpoint; each call is independently billable.

```sh
PYTHONPATH=src python3 -m pqc_eval.v2 analyze \
  --dataset benchmark/v2-generated --results results/v2-main.jsonl \
  --out results/v2-report.json
```

The analysis command reads real live records only. Preview records are counted as excluded, not interpreted as model performance. Tests use named synthetic fixtures; their example decisions are not research findings.

## Dataset freezing

The generator refuses to overwrite a nonempty output directory. A manifest records the exact JSONL SHA-256, OpenSSL version, context count and case count. Random cryptographic key generation means **a rebuilt dataset is semantically equivalent but not byte-identical**. Archive the frozen dataset externally with its manifest and source commit before collecting model responses.

## Verifier reconstruction and trust boundary

The dataset includes readable implementation source for model review, but the executable oracle regenerates a trusted verifier template for each known family/style/variant. It checks that the dataset source matches the trusted template byte-for-byte before execution. No arbitrary downloaded source or user-provided Python should be executed through this benchmark.

The research report is also generated from independently observed execution; it cannot be read as evidence that any real commercial firmware product is secure or vulnerable.

## Audit checklist before model calls

1. Inspect each source style for semantic equivalence.
2. Confirm all 200 baseline/challenge expectations with the OpenSSL oracle.
3. Inspect evidence reports B/C side by side and confirm only the summary's truthfulness changes.
4. Confirm D replay tests carry no hidden gold labels in model prompts.
5. Human-review a sample of positive and negative examples, ideally without access to expected labels.
6. Freeze data, exact prompts, and model configuration.
7. Complete a limited paid pilot outside the primary study and audit parser failures.
8. Execute the full experiment only with explicitly authorized API access and budget.
9. Publish all valid, invalid, and excluded counts.
