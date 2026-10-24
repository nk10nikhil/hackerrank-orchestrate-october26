# Public Sample Evaluation

Predictions were generated from the requests, participant-facing identity history, policy, and evidence. `sample_output.csv` was loaded only after inference for comparison.

## Status metrics

- Cases evaluated: 32 of 32 public samples.
- Case-level deletion-status accuracy: 75.000%.
- Step precision / recall / F1: 76.966% / 70.984% / 73.854% (137 matched of 178 predicted and 193 expected steps; `step_no` excluded from matching).
- Field-level accuracy: 64.426% (920 / 1428 position-aligned fields; missing step positions count as incorrect).
- Exact sequence accuracy: 28.125% (9 / 32 cases with exactly matching ordered step arrays).
- False `COMPLETE` predictions: 1.
- Cases with unresolved evidence or identity notes: 7.

## Per-class precision, recall, and F1

| Status | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| COMPLETE | 75.000% | 30.000% | 42.857% | 10 |
| INCOMPLETE | 75.000% | 95.455% | 84.000% | 22 |
| NOT_APPLICABLE | 0.000% | 0.000% | 0.000% | 0 |

## Confusion matrix

Rows are expected labels; columns are predicted labels.

| Expected \ Predicted | COMPLETE | INCOMPLETE | NOT_APPLICABLE |
|---|---:|---:|---:|
| COMPLETE | 3 | 7 | 0 |
| INCOMPLETE | 1 | 21 | 0 |
| NOT_APPLICABLE | 0 | 0 | 0 |

## Failures found and improvements made

- Status disagreements: 8 cases (case_04, case_17, case_21, case_25, case_26, case_27, case_28, case_31). The remaining errors are primarily resource-to-subject joins where the evidence has no direct identifier.
- Step sequence or field disagreements: 23 cases (case_03, case_04, case_09, case_10, case_11, case_12, case_15, case_17, case_18, case_19, case_20, case_21…). Review these against the source-level association and operation-order rules before drawing conclusions from status accuracy alone.
- The initial build was changed to preserve manifest provenance, enforce the `audit_at` cutoff, resolve historical email aliases with the identity audit log, and order operations using the challenge phase and operation contract.
- PDF text is extracted with `pypdf`; screenshots are parsed with RapidOCR, keeping recognized resource identifiers scoped to visual rows.

## Additional participant-created evaluation cases

The unit suite includes synthetic cases that do not use the public sample labels:

1. A historical email alias resolves through a dated identity change while a later identity change is excluded by `audit_at`.
2. A surviving search record and active connector require a delete and a flow disable, with finding and remediation order checked.
3. A backup that is retained but restore-blocked and a security audit entry that remains within retention verify as compliant.
4. A tombstone keeps its stable `user_id` while direct identifiers trigger a redaction plan.
5. Evidence captured after the case cutoff cannot change the result.

## Validation limits

The public sample has 32 cases and is not representative enough to establish hidden-set accuracy. Its 75.000% status accuracy shows that resource-to-subject linking still needs improvement. The hidden 518-case predictions have no participant-facing labels, so this report does not claim hidden-set performance.
