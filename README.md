# Ghost Data Still Exists — Deletion Audit Agent

This submission analyzes each deletion request against the supplied identity history, deletion policy, activity stream, and evidence files. It writes the required root `output.csv`, evaluates separately against the 32 public examples, and records aggregate run and extraction information.

## Run the full workflow

Use Python 3.10 or newer from the repository root. Install the document and screenshot parsers, then run the workflow command:

```powershell
python -m pip install -r code/requirements.txt
python code/main.py
```

The command validates the input schemas, parses available participant-facing evidence, resolves current and historical email identifiers at each `audit_at`, applies the policy, writes and validates `output.csv`, evaluates predictions against the public sample labels after inference, and writes these reports:

- `output.csv` — 518 predictions sorted by `case_id`.
- `evaluation/evaluation_report.md` — public-sample metrics, confusion matrix, custom test scenarios, and observed limitations.
- `evaluation/usage_report.md` — model-call and token/cost totals for the full run.
- `evaluation/audit_report.md` — aggregate processing and extraction summary without subject-level personal data.

Optional paths and output checks are available from the CLI:

```powershell
python code/main.py --dataset .\dataset --output .\output.csv --audit-report .\code\evaluation\audit_report.md --log-level INFO
python code/main.py --skip-evaluation
```

To run the synthetic unit and integration tests:

```powershell
python -m unittest discover -s code/tests -v
```

To create and verify the submission archive:

```powershell
python code/package.py
```

`code.zip` contains the root README, `code/`, and `evaluation/`; it intentionally excludes `dataset/`, the generated root `output.csv`, environment directories, caches, and nested archives. Run it after extracting the code into the challenge checkout, where the challenge dataset is available.

## Architecture

The solution is a deterministic, offline evidence pipeline. It does not make external calls or mutate the fictional production systems.

1. **Load and validate inputs.** CSV headers, required files, duplicate case IDs, and output coverage are checked explicitly. Identifiers are preserved as strings.
2. **Resolve identity.** The supplied current identity snapshot and dated `user_audit_log.csv` are joined by exact email values. Identity history after a case cutoff is excluded. Email, phone, email hash, and stable user references provide evidence links; names alone do not.
3. **Index evidence once.** The evidence manifest supplies provenance and capture times. The scanner handles nested JSON, SQL snapshot tables in a restricted in-memory SQLite database, structured and key/value logs, handover text, PDF text, and screenshot text through RapidOCR. It tracks timestamps and record/system/category fields for each observation.
4. **Apply policy and reconstruct state.** Policy actions come from `deletion_rules.csv`. The agent distinguishes remaining records, exposed identifiers, active data flows, restore risks, retained records, anonymized analytics, and compliant tombstones. Evidence captured or observed after `audit_at` is excluded.
5. **Plan and serialize.** Incomplete cases receive evidence-cited findings, dependency-ordered remediation, and future checks with empty evidence IDs. Complete cases receive only evidence-backed verification steps. The writer enforces the allowed phases, operations, states, step numbering, and exact CSV schema.
6. **Evaluate after inference.** Public sample labels are loaded only after predictions are generated. Synthetic tests cover identity history, policy behavior, time cutoffs, ordering, output validation, and scanner discovery.

## Policy and evidence handling

Policy categories map to the supplied required actions: delete ordinary profiles, search results, exports, and sole-subject attachments; redact shared support conversations, email-bearing logs, and direct identifiers on account tombstones; anonymize attributable analytics; retain required security and legal records; and retain backups only when their restore path is blocked. Active integration flows are disabled before dependent records are changed.

The evidence reader accepts the manifest as the citation source. Each finding points to a participant-visible `file_id`. Activity results are not treated as proof of the resulting resource state. SQL evidence runs only in an in-memory database with an authorizer that permits table creation, inserts, reads, selects, and table metadata while rejecting other SQL actions.

PDF text is extracted through `pypdf`. Screenshots are parsed with RapidOCR, and each recognized resource is scoped to its visible result row so another row's identifiers are not attached to it. If OCR cannot load or decode an image, the audit report lists the affected evidence ID.

## Model and reproducibility

This build uses no language model. The supplied evidence is predominantly structured, and deterministic parsing makes the final classifications and steps reproducible. Accordingly, the usage report records zero model calls, tokens, and inference cost. If a future version adds an authorized model service for genuinely ambiguous documents, its structured output must remain evidence-grounded and pass the same deterministic policy and schema validation.

## Repository and artifacts

```text
README.md
code/
├── audit_agent.py
├── main.py
├── package.py
├── requirements.txt
├── evaluation/
│   ├── __init__.py
│   └── main.py
└── tests/
evaluation/
├── evaluation_report.md
├── usage_report.md
└── audit_report.md
```

The root `log.txt` is the coding-session transcript required by this checkout's `AGENTS.md`. Upload that file through the challenge interface as the chat transcript. The actual upload and AI interview still require the HackerRank interface.

## Current limitations

- The public sample has 32 cases and cannot establish hidden-set accuracy.
- Evidence without a direct current or historical identifier link is not joined by name similarity. Some incomplete predictions have no findings because the evidence did not establish a subject-to-resource link.
- Screenshot OCR can miss small or low-contrast text; recognized lines retain the source evidence ID and are subject to the same audit cutoff.
- The final output is a recommendation/audit result. It never executes deletion, redaction, synchronization, or restore-blocking actions against source evidence or external systems.

