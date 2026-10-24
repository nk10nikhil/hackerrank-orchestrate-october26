# Full Dataset Usage Report

Run completed: 2026-10-24 15:07:09Z

The final run uses deterministic local parsing and policy rules. RapidOCR ran locally for each manifest image; no hosted language model or billable inference API was called.

| Provider | Model | Calls | Input tokens | Output tokens | Total tokens | Estimated cost |
|---|---|---:|---:|---:|---:|---:|
| Local ONNX Runtime (RapidOCR) | PP-OCRv3 detection/recognition + PP-OCRv2 angle classifier | 11 | 0 | 0 | 0 | $0.00 |
| **Overall** | — | **11** | **0** | **0** | **0** | **$0.00** |

- Requests processed: 518.
- Total model tokens: 0; image OCR does not use tokenized model inputs or outputs.
- Average model tokens per request: 0.00 across the full request set.
- Estimated total model cost: $0.00.
- Estimated model cost per request: $0.00 (518 requests).
- Per-model totals: RapidOCR made 11 local image passes; language-model calls, tokens, and API charges were zero.
- Cost is zero because OCR ran locally and no billable model API was used; local CPU and storage usage are not token-metered.
