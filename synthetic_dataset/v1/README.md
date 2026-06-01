# Synthetic DL2026 Test Split v1

This split was generated from the public examples without modifying the original `dataset/` folder.
It is intended for prompt debugging, not as a substitute for the hidden grader.

## Files

- `testcases/tc*.json`: evaluator-compatible testcase files.
- `label.jsonl`: evaluator-compatible labels.
- `metadata.jsonl`: one metadata record per testcase, with category, source, target, tags, and rationale.
- `summary.json`: aggregate counts.

## Counts

- total: 314
- labels: `{"fail": 189, "pass": 125}`
- categories: `{"bad_host_challenge_success_trap": 4, "closed_session_before_target": 3, "long_context_pair_swap": 32, "missing_required_context": 6, "paired_target_output_swap": 16, "pre_target_opposite_distractor": 20, "pre_target_properties_noise": 40, "prefix_properties_noise": 80, "public_clone": 20, "session_id_variation": 12, "success_status_control": 9, "target_data_result_mutation": 7, "target_status_mutation": 65}`

## Run

From the project root:

```bash
python tools/run_prompt_eval.py --dataset-dir synthetic_dataset/v1/testcases --label-path synthetic_dataset/v1/label.jsonl
```

After evaluation, group errors with:

```bash
python tools/analyze_synthetic_results.py --dataset synthetic_dataset/v1 --predictions skeleton/predictions.jsonl
```

## Interpretation

The useful file is `metadata.jsonl`.
When the model misses a case, inspect its `category`, `tags`, and `rationale`.
Those fields are written to show which prompt rule probably needs to be strengthened.
