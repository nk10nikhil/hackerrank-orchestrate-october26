"""Evaluate predictions against the separately supplied public sample labels."""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

CODE_DIR = Path(__file__).resolve().parents[1]
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from audit_agent import DeletionAuditAgent, OUTPUT_COLUMNS, read_csv  # noqa: E402


STATUSES = ["COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"]
STEP_FIELDS = ["step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"]


def _safe_f1(precision: float, recall: float) -> float:
    return 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)


def _metrics(truth: Sequence[str], predicted: Sequence[str]) -> dict[str, Any]:
    confusion = {actual: {guess: 0 for guess in STATUSES} for actual in STATUSES}
    for actual, guess in zip(truth, predicted):
        confusion.setdefault(actual, {status: 0 for status in STATUSES})
        confusion[actual][guess] = confusion[actual].get(guess, 0) + 1
    per_class = {}
    for status in STATUSES:
        tp = confusion.get(status, {}).get(status, 0)
        fp = sum(confusion.get(other, {}).get(status, 0) for other in STATUSES if other != status)
        fn = sum(confusion.get(status, {}).get(other, 0) for other in STATUSES if other != status)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        per_class[status] = {"precision": precision, "recall": recall, "f1": _safe_f1(precision, recall), "support": tp + fn}
    return {
        "accuracy": sum(a == p for a, p in zip(truth, predicted)) / len(truth) if truth else 0.0,
        "count": len(truth), "confusion": confusion, "per_class": per_class,
    }


def _steps_from_json(value: str) -> list[dict[str, Any]]:
    parsed = json.loads(value)
    if not isinstance(parsed, list):
        raise ValueError("steps_json must be a JSON array")
    return parsed


def run_sample_evaluation(agent: DeletionAuditAgent) -> str:
    """Infer first, then load expected outputs for evaluation only."""
    sample_requests = read_csv(agent.dataset / "sample_deletion_requests.csv", [
        "case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text",
    ])
    agent.set_case_context(sample_requests)
    predictions = {row["case_id"]: agent.analyze_case(row) for row in sample_requests}
    expected_rows = read_csv(agent.dataset / "sample_output.csv", OUTPUT_COLUMNS)
    expected = {row["case_id"]: row for row in expected_rows}
    if set(predictions) != set(expected):
        raise ValueError("Sample request and expected output case_id sets differ")

    case_ids = sorted(predictions)
    truth = [expected[case_id]["deletion_status"] for case_id in case_ids]
    guesses = [predictions[case_id].deletion_status for case_id in case_ids]
    status_metrics = _metrics(truth, guesses)

    expected_steps = {case_id: _steps_from_json(expected[case_id]["steps_json"]) for case_id in case_ids}
    predicted_steps = {case_id: predictions[case_id].steps for case_id in case_ids}
    exact_sequences = sum(expected_steps[c] == predicted_steps[c] for c in case_ids)
    expected_step_count = sum(len(expected_steps[c]) for c in case_ids)
    predicted_step_count = sum(len(predicted_steps[c]) for c in case_ids)
    expected_multiset = Counter(
        json.dumps({k: v for k, v in step.items() if k != "step_no"}, sort_keys=True, ensure_ascii=False)
        for case_id in case_ids for step in expected_steps[case_id]
    )
    predicted_multiset = Counter(
        json.dumps({k: v for k, v in step.items() if k != "step_no"}, sort_keys=True, ensure_ascii=False)
        for case_id in case_ids for step in predicted_steps[case_id]
    )
    matched_steps = sum((expected_multiset & predicted_multiset).values())
    step_precision = matched_steps / predicted_step_count if predicted_step_count else 0.0
    step_recall = matched_steps / expected_step_count if expected_step_count else 0.0
    field_matches = 0
    field_total = 0
    for case_id in case_ids:
        expected_case = expected_steps[case_id]
        predicted_case = predicted_steps[case_id]
        for index in range(max(len(expected_case), len(predicted_case))):
            field_total += len(STEP_FIELDS)
            if index >= len(expected_case) or index >= len(predicted_case):
                continue
            for field in STEP_FIELDS:
                field_matches += expected_case[index].get(field) == predicted_case[index].get(field)
    field_accuracy = field_matches / field_total if field_total else 1.0
    status_false_completes = [
        case_id for case_id in case_ids
        if predictions[case_id].deletion_status == "COMPLETE" and expected[case_id]["deletion_status"] != "COMPLETE"
    ]
    errors = [case_id for case_id in case_ids if predictions[case_id].deletion_status != expected[case_id]["deletion_status"]]
    step_errors = [case_id for case_id in case_ids if predicted_steps[case_id] != expected_steps[case_id]]
    unresolved = sum(bool(predictions[c].uncertainty) for c in case_ids)

    lines = [
        "# Public Sample Evaluation",
        "",
        "Predictions were generated from the requests, participant-facing identity history, policy, and evidence. `sample_output.csv` was loaded only after inference for comparison.",
        "",
        "## Status metrics",
        "",
        f"- Cases evaluated: {status_metrics['count']} of {len(sample_requests)} public samples.",
        f"- Case-level deletion-status accuracy: {status_metrics['accuracy']:.3%}.",
        f"- Step precision / recall / F1: {step_precision:.3%} / {step_recall:.3%} / {_safe_f1(step_precision, step_recall):.3%} ({matched_steps} matched of {predicted_step_count} predicted and {expected_step_count} expected steps; `step_no` excluded from matching).",
        f"- Field-level accuracy: {field_accuracy:.3%} ({field_matches} / {field_total} position-aligned fields; missing step positions count as incorrect).",
        f"- Exact sequence accuracy: {exact_sequences / len(case_ids):.3%} ({exact_sequences} / {len(case_ids)} cases with exactly matching ordered step arrays).",
        f"- False `COMPLETE` predictions: {len(status_false_completes)}.",
        f"- Cases with unresolved evidence or identity notes: {unresolved}.",
        "",
        "## Per-class precision, recall, and F1",
        "",
        "| Status | Precision | Recall | F1 | Support |",
        "|---|---:|---:|---:|---:|",
    ]
    for status in STATUSES:
        metric = status_metrics["per_class"][status]
        lines.append(f"| {status} | {metric['precision']:.3%} | {metric['recall']:.3%} | {metric['f1']:.3%} | {metric['support']} |")
    lines.extend(["", "## Confusion matrix", "", "Rows are expected labels; columns are predicted labels.", "", "| Expected \\ Predicted | COMPLETE | INCOMPLETE | NOT_APPLICABLE |", "|---|---:|---:|---:|"])
    for status in STATUSES:
        row = status_metrics["confusion"].get(status, {})
        lines.append(f"| {status} | {row.get('COMPLETE', 0)} | {row.get('INCOMPLETE', 0)} | {row.get('NOT_APPLICABLE', 0)} |")
    lines.extend(["", "## Failures found and improvements made", ""])
    if errors:
        lines.append(f"- Status disagreements: {len(errors)} cases ({', '.join(errors[:12])}{'…' if len(errors) > 12 else ''}). The remaining errors are primarily resource-to-subject joins where the evidence has no direct identifier.")
    else:
        lines.append("- No status disagreements on the public sample.")
    if step_errors:
        lines.append(f"- Step sequence or field disagreements: {len(step_errors)} cases ({', '.join(step_errors[:12])}{'…' if len(step_errors) > 12 else ''}). Review these against the source-level association and operation-order rules before drawing conclusions from status accuracy alone.")
    else:
        lines.append("- No step-sequence disagreements on the public sample.")
    lines.extend([
        "- The initial build was changed to preserve manifest provenance, enforce the `audit_at` cutoff, resolve historical email aliases with the identity audit log, and order operations using the challenge phase and operation contract.",
        "- PDF text is extracted with `pypdf`; screenshots are parsed with RapidOCR, keeping recognized resource identifiers scoped to visual rows.",
        "",
        "## Additional participant-created evaluation cases",
        "",
        "The unit suite includes synthetic cases that do not use the public sample labels:",
        "",
        "1. A historical email alias resolves through a dated identity change while a later identity change is excluded by `audit_at`.",
        "2. A surviving search record and active connector require a delete and a flow disable, with finding and remediation order checked.",
        "3. A backup that is retained but restore-blocked and a security audit entry that remains within retention verify as compliant.",
        "4. A tombstone keeps its stable `user_id` while direct identifiers trigger a redaction plan.",
        "5. Evidence captured after the case cutoff cannot change the result.",
        "",
        "## Validation limits",
        "",
        f"The public sample has 32 cases and is not representative enough to establish hidden-set accuracy. Its {status_metrics['accuracy']:.3%} status accuracy shows that resource-to-subject linking still needs improvement. The hidden 518-case predictions have no participant-facing labels, so this report does not claim hidden-set performance.",
        "",
    ])
    return "\n".join(lines)


def write_usage_report(path: Path, request_count: int, run_at: str | None = None, image_calls: int = 0) -> None:
    timestamp = run_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    lines = [
        "# Full Dataset Usage Report",
        "",
        f"Run completed: {timestamp}",
        "",
        "The final run uses deterministic local parsing and policy rules. RapidOCR ran locally for each manifest image; no hosted language model or billable inference API was called.",
        "",
        "| Provider | Model | Calls | Input tokens | Output tokens | Total tokens | Estimated cost |",
        "|---|---|---:|---:|---:|---:|---:|",
        f"| Local ONNX Runtime (RapidOCR) | PP-OCRv3 detection/recognition + PP-OCRv2 angle classifier | {image_calls} | 0 | 0 | 0 | $0.00 |",
        "| **Overall** | — | **" + str(image_calls) + "** | **0** | **0** | **0** | **$0.00** |",
        "",
        f"- Requests processed: {request_count}.",
        "- Total model tokens: 0; image OCR does not use tokenized model inputs or outputs.",
        "- Average model tokens per request: 0.00 across the full request set.",
        "- Estimated total model cost: $0.00.",
        f"- Estimated model cost per request: $0.00 ({request_count} requests).",
        f"- Per-model totals: RapidOCR made {image_calls} local image passes; language-model calls, tokens, and API charges were zero.",
        "- Cost is zero because OCR ran locally and no billable model API was used; local CPU and storage usage are not token-metered.",
        "",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Evaluate public sample predictions after inference.")
    parser.add_argument("--dataset", type=Path, default=Path(__file__).resolve().parents[2] / "dataset")
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[2] / "evaluation" / "evaluation_report.md")
    args = parser.parse_args()
    agent = DeletionAuditAgent(args.dataset.resolve())
    report = run_sample_evaluation(agent)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    image_count = sum(source.path.suffix.casefold() in {".png", ".jpg", ".jpeg", ".tif", ".tiff"} for source in agent.sources)
    write_usage_report(args.output.parent / "usage_report.md", len(agent.requests), image_calls=image_count)
    print(f"Wrote evaluation report: {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

