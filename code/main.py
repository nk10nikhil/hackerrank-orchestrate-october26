"""Command-line entry point for the deletion audit agent."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from audit_agent import DeletionAuditAgent, validate_output, write_audit_report


def _root() -> Path:
    return Path(__file__).resolve().parents[1]


def _parse_args() -> argparse.Namespace:
    root = _root()
    parser = argparse.ArgumentParser(description="Audit deletion requests against participant-facing evidence.")
    parser.add_argument("--dataset", type=Path, default=root / "dataset", help="Dataset directory (default: ./dataset)")
    parser.add_argument("--output", type=Path, default=root / "output.csv", help="Prediction CSV path (default: ./output.csv)")
    parser.add_argument("--audit-report", type=Path, default=root / "evaluation" / "audit_report.md", help="Aggregate audit report path")
    parser.add_argument("--skip-evaluation", action="store_true", help="Skip public sample evaluation")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="WARNING")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(levelname)s %(message)s")
    dataset = args.dataset.resolve()
    output = args.output.resolve()
    agent = DeletionAuditAgent(dataset)
    results = agent.analyze_all()
    agent.write_output(results, output)
    validation = validate_output(output, agent.requests)
    write_audit_report(args.audit_report.resolve(), agent, results)

    print(f"Processed {validation['rows']} requests; serialized {validation['steps']} steps.")
    print(f"Predictions: {output}")
    print(f"Statuses: {agent.audit_summary(results)['statuses']}")
    print(f"Evidence observations: {len(agent.observations)} from {len(agent.sources)} manifest files.")
    print(f"Audit summary: {args.audit_report.resolve()}")

    if not args.skip_evaluation:
        # Import after the current script directory has been established by Python.
        from evaluation.main import run_sample_evaluation, write_usage_report

        report_path = _root() / "evaluation" / "evaluation_report.md"
        report = run_sample_evaluation(agent)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(report, encoding="utf-8")
        image_count = sum(source.path.suffix.casefold() in {".png", ".jpg", ".jpeg", ".tif", ".tiff"} for source in agent.sources)
        write_usage_report(report_path.parent / "usage_report.md", len(agent.requests), image_calls=image_count)
        print(f"Public sample evaluation: {report_path}")
        print(f"Usage summary: {report_path.parent / 'usage_report.md'}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        logging.getLogger("ghost_data_audit").error("Run failed: %s: %s", type(exc).__name__, exc)
        raise SystemExit(2)

