"""Versioned V2 command line interface; does not change the V1 protocol."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analysis import write_v2_report
from .dataset import build_v2, load_v2
from .runner import run_v2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m pqc_eval.v2",
        description="Evidence reliability research on SLH-DSA firmware verification",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build", help="Generate paired V2 benchmark")
    build.add_argument("--out", type=Path, default=Path("benchmark/v2-generated"))
    build.add_argument("--contexts", type=int, default=4)
    validate = sub.add_parser("validate", help="Replay cryptographic oracle for V2 cases")
    validate.add_argument("--dataset", type=Path, default=Path("benchmark/v2-generated"))
    run = sub.add_parser("run", help="Preview or run V2 Claude experiment")
    run.add_argument("--dataset", type=Path, default=Path("benchmark/v2-generated"))
    run.add_argument("--out", type=Path, default=Path("results/v2-preview.jsonl"))
    run.add_argument("--model", required=True, help="Exact available Claude model ID")
    run.add_argument("--conditions", default="A,B,C,D")
    run.add_argument("--trials", type=int, default=2)
    run.add_argument("--limit", type=int)
    run.add_argument("--live", action="store_true")
    run.add_argument("--confirm-billing", action="store_true")
    report = sub.add_parser("analyze", help="Analyze observed V2 API responses only")
    report.add_argument("--dataset", type=Path, default=Path("benchmark/v2-generated"))
    report.add_argument("--results", type=Path, required=True)
    report.add_argument("--out", type=Path, default=Path("results/v2-report.json"))
    args = parser.parse_args(argv)
    if args.command == "build":
        value = build_v2(args.out, contexts=args.contexts)
    elif args.command == "validate":
        cases, manifest = load_v2(args.dataset, cryptographic=True)
        value = {
            "validated_cases": len(cases),
            "dataset_sha256": manifest["dataset_sha256"],
        }
    elif args.command == "run":
        cases, manifest = load_v2(args.dataset, cryptographic=True)
        value = run_v2(
            cases, manifest, args.out, model=args.model,
            conditions=tuple(s.strip() for s in args.conditions.split(",")),
            trials=args.trials, live=args.live, confirm_billing=args.confirm_billing,
            limit=args.limit,
        )
    else:
        cases, manifest = load_v2(args.dataset, cryptographic=True)
        value = write_v2_report(cases, manifest, args.results, args.out)
    print(json.dumps(value, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
