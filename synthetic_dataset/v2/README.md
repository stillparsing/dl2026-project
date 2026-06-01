# Synthetic DL2026 Test Split v2

This adversarial split focuses on deterministic prefilter false positives.
Unlike v1, it includes accepted error responses: cases where the final command
should be rejected and the observed rejection is therefore labeled `pass`.

## Counts

- total: 11
- labels: `{"fail": 5, "pass": 6}`
- categories: `{"correct_rejection": 6, "data_path_success_trap": 2, "success_trap": 3}`

## Run

```bash
python tools/audit_rule_prefilter.py --dataset-dir synthetic_dataset/v2/testcases --label-path synthetic_dataset/v2/label.jsonl
```
