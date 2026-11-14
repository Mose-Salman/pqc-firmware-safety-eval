"""Command-line interface for benchmark construction, evaluation and analysis."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analysis import write_report
from .dataset import build_dataset, load_dataset
from .runner import run_experiment


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pqc-eval", description="SLH-DSA firmware AI safety evaluation")
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="Build and cryptographically validate synthetic benchmark")
    build.add_argument("--out", type=Path, default=Path("benchmark/generated"))
    build.add_argument("--contexts", type=int, default=6)
    validate = commands.add_parser("validate", help="Check hashes and replay the cryptographic oracle")
    validate.add_argument("--dataset", type=Path, default=Path("benchmark/generated"))
    run = commands.add_parser("run", help="Preview prompts or call the Claude API")
    run.add_argument("--dataset", type=Path, default=Path("benchmark/generated"))
    run.add_argument("--out", type=Path, default=Path("results/preview.jsonl"))
    run.add_argument("--model", required=True, help="Exact Claude model identifier")
    run.add_argument("--conditions", default="A,B,C", help="Comma-separated condition letters")
    run.add_argument("--trials", type=int, default=2)
    run.add_argument("--limit", type=int)
    run.add_argument("--live", action="store_true", help="Make paid API requests")
    run.add_argument("--confirm-billing", action="store_true", help="Explicitly authorize API usage charges")
    report = commands.add_parser("analyze", help="Analyze completed model responses")
    report.add_argument("--dataset", type=Path, default=Path("benchmark/generated"))
    report.add_argument("--results", type=Path, required=True)
    report.add_argument("--out", type=Path, default=Path("results/report.json"))
    args = parser.parse_args(argv)
    if args.command == "build":
        result = build_dataset(args.out, contexts=args.contexts)
    elif args.command == "validate":
        cases, manifest = load_dataset(args.dataset, validate_crypto=True)
        result = {"validated_cases": len(cases), "dataset_sha256": manifest["sha256"]}
    elif args.command == "run":
        cases, _ = load_dataset(args.dataset)
        result = run_experiment(
            cases, args.out, model=args.model,
            conditions=tuple(part.strip() for part in args.conditions.split(",")),
            trials=args.trials, limit=args.limit,
            live=args.live, confirm_billing=args.confirm_billing,
        )
    elif args.command == "analyze":
        cases, _ = load_dataset(args.dataset)
        result = write_report(cases, args.results, args.out)
    else:
        parser.error("Unknown command")
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
