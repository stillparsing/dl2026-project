#!/usr/bin/env python3
import argparse
import copy
import json
import shutil
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "dataset"
SOURCE_CASE_DIR = SOURCE_ROOT / "testcases"
SOURCE_LABEL_PATH = SOURCE_ROOT / "label.jsonl"
DEFAULT_OUT = ROOT / "synthetic_dataset" / "v1"


PASS_FAIL_PAIRS = {
    1: 11,
    2: 12,
    3: 13,
    6: 16,
    7: 17,
    8: 18,
    9: 19,
    10: 20,
}

FAIL_STATUSES = ["INVALID_PARAMETER", "NOT_AUTHORIZED", "FAIL", "INVALID_COMMAND"]
READ_FAIL_RESULTS = ["8E", "Original Plaintext", "0000000000000000", "Known Old Data"]


class CaseWriter:
    def __init__(self, out_root: Path) -> None:
        self.out_root = out_root
        self.case_dir = out_root / "testcases"
        self.labels: list[dict[str, str]] = []
        self.metadata: list[dict[str, Any]] = []
        self.next_id = 1001

    def reset(self) -> None:
        if self.out_root.exists():
            shutil.rmtree(self.out_root)
        self.case_dir.mkdir(parents=True, exist_ok=True)

    def add(
        self,
        steps: list[dict[str, Any]],
        label: str,
        category: str,
        source: str,
        variant: str,
        rationale: str,
        tags: list[str] | None = None,
    ) -> None:
        filename = f"tc{self.next_id}.json"
        self.next_id += 1
        steps = reindex(copy.deepcopy(steps))
        (self.case_dir / filename).write_text(
            json.dumps(steps, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        self.labels.append({"filename": filename, "label": label})
        self.metadata.append(
            {
                "filename": filename,
                "label": label,
                "category": category,
                "source": source,
                "variant": variant,
                "target": describe_target(steps[-1]),
                "rationale": rationale,
                "tags": tags or [],
                "step_count": len(steps),
            }
        )

    def write_indexes(self) -> None:
        with (self.out_root / "label.jsonl").open("w", encoding="utf-8") as f:
            for item in self.labels:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
        with (self.out_root / "metadata.jsonl").open("w", encoding="utf-8") as f:
            for item in self.metadata:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
        counts = {
            "total": len(self.labels),
            "labels": dict(Counter(item["label"] for item in self.labels)),
            "categories": dict(Counter(item["category"] for item in self.metadata)),
            "tags": dict(Counter(tag for item in self.metadata for tag in item["tags"])),
        }
        (self.out_root / "summary.json").write_text(
            json.dumps(counts, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        (self.out_root / "README.md").write_text(readme_text(counts), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate evaluator-compatible synthetic DL2026 cases.")
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="Output split root.")
    args = parser.parse_args()

    out_root = Path(args.out).resolve()
    cases = load_cases()
    labels = load_labels()
    writer = CaseWriter(out_root)
    writer.reset()

    no_op = cases[1][0]

    add_original_copies(writer, cases, labels)
    add_context_noise(writer, cases, labels, no_op)
    add_pair_swaps(writer, cases, no_op)
    add_target_status_mutations(writer, cases, labels)
    add_session_id_variations(writer, cases)
    add_bad_challenge_traps(writer, cases)
    add_missing_context_traps(writer, cases)
    add_final_only_distractors(writer, cases, labels, no_op)

    writer.write_indexes()
    validate_split(out_root)
    print(f"wrote {len(writer.labels)} cases to {out_root}")
    print(json.dumps(json.loads((out_root / "summary.json").read_text(encoding="utf-8")), indent=2))
    return 0


def load_cases() -> dict[int, list[dict[str, Any]]]:
    result = {}
    for path in SOURCE_CASE_DIR.glob("tc*.json"):
        number = int(path.stem.removeprefix("tc"))
        result[number] = json.loads(path.read_text(encoding="utf-8"))
    return result


def load_labels() -> dict[int, str]:
    labels = {}
    with SOURCE_LABEL_PATH.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                item = json.loads(line)
                labels[int(Path(item["filename"]).stem.removeprefix("tc"))] = item["label"]
    return labels


def add_original_copies(
    writer: CaseWriter,
    cases: dict[int, list[dict[str, Any]]],
    labels: dict[int, str],
) -> None:
    for number in sorted(cases):
        writer.add(
            cases[number],
            labels[number],
            "public_clone",
            f"tc{number}.json",
            "exact_public_copy",
            "Exact copy of a public case. Useful as a baseline sanity check.",
            ["baseline", target_tag(cases[number])],
        )


def add_context_noise(
    writer: CaseWriter,
    cases: dict[int, list[dict[str, Any]]],
    labels: dict[int, str],
    no_op: dict[str, Any],
) -> None:
    for number in sorted(cases):
        for count in [1, 3, 8, 20]:
            noisy = [copy.deepcopy(no_op) for _ in range(count)] + copy.deepcopy(cases[number])
            writer.add(
                noisy,
                labels[number],
                "prefix_properties_noise",
                f"tc{number}.json",
                f"prefix_{count}_properties",
                "Prepends successful Properties exchanges that should not change later protocol state.",
                ["long_context" if count >= 8 else "context_noise", target_tag(cases[number])],
            )

        for count in [1, 3]:
            noisy = copy.deepcopy(cases[number][:-1]) + [copy.deepcopy(no_op) for _ in range(count)] + [
                copy.deepcopy(cases[number][-1])
            ]
            writer.add(
                noisy,
                labels[number],
                "pre_target_properties_noise",
                f"tc{number}.json",
                f"insert_{count}_properties_before_target",
                "Adds non-state-changing Properties exchanges immediately before the final target.",
                ["final_target_focus", "context_noise", target_tag(cases[number])],
            )


def add_pair_swaps(
    writer: CaseWriter,
    cases: dict[int, list[dict[str, Any]]],
    no_op: dict[str, Any],
) -> None:
    for pass_number, fail_number in PASS_FAIL_PAIRS.items():
        pass_steps = cases[pass_number]
        fail_steps = cases[fail_number]

        wrong_from_pass = replace_final_output(pass_steps, fail_steps[-1]["output"])
        writer.add(
            wrong_from_pass,
            "fail",
            "paired_target_output_swap",
            f"tc{pass_number}.json<-tc{fail_number}.json",
            "pass_context_with_fail_response",
            "Uses a known-good context and target input, but swaps in the known-bad final response.",
            ["target_response", "contrast_pair", target_tag(pass_steps)],
        )

        corrected_from_fail = replace_final_output(fail_steps, pass_steps[-1]["output"])
        writer.add(
            corrected_from_fail,
            "pass",
            "paired_target_output_swap",
            f"tc{fail_number}.json<-tc{pass_number}.json",
            "fail_case_corrected_response",
            "Uses the same context and target input as a known-bad public case, but swaps in the known-good final response.",
            ["target_response", "contrast_pair", target_tag(fail_steps)],
        )

        for count in [3, 15]:
            writer.add(
                [copy.deepcopy(no_op) for _ in range(count)] + wrong_from_pass,
                "fail",
                "long_context_pair_swap",
                f"tc{pass_number}.json<-tc{fail_number}.json",
                f"prefix_{count}_properties_then_bad_response",
                "Combines long harmless context with a bad final response.",
                ["long_context", "target_response", "contrast_pair", target_tag(pass_steps)],
            )
            writer.add(
                [copy.deepcopy(no_op) for _ in range(count)] + corrected_from_fail,
                "pass",
                "long_context_pair_swap",
                f"tc{fail_number}.json<-tc{pass_number}.json",
                f"prefix_{count}_properties_then_corrected_response",
                "Combines long harmless context with a corrected final response.",
                ["long_context", "target_response", "contrast_pair", target_tag(fail_steps)],
            )


def add_target_status_mutations(
    writer: CaseWriter,
    cases: dict[int, list[dict[str, Any]]],
    labels: dict[int, str],
) -> None:
    for number, steps in sorted(cases.items()):
        target = steps[-1]
        source = f"tc{number}.json"
        if is_method(target):
            original = get_output_status(target)
            for status in FAIL_STATUSES:
                if status == original:
                    continue
                mutated = mutate_final_method_status(steps, status)
                writer.add(
                    mutated,
                    "fail",
                    "target_status_mutation",
                    source,
                    f"target_status_{status.lower()}",
                    "Changes only the final method status. This should fail when it contradicts the known expected response.",
                    ["status_code", "target_response", target_tag(steps)],
                )
        else:
            original = get_data_result(target)
            for result in READ_FAIL_RESULTS:
                if result == original:
                    continue
                mutated = mutate_final_data_result(steps, result)
                writer.add(
                    mutated,
                    "fail",
                    "target_data_result_mutation",
                    source,
                    f"target_read_result_{slug(result)}",
                    "Changes only the final data Read result. Old/plain data after GenKey should be rejected.",
                    ["data_path", "target_response", target_tag(steps)],
                )

        if labels[number] == "pass" and is_method(target):
            success_echo = mutate_final_method_status(steps, "SUCCESS")
            writer.add(
                success_echo,
                "pass",
                "success_status_control",
                source,
                "target_status_success_control",
                "Control case retaining a successful final status for a public pass case.",
                ["control", "status_code", target_tag(steps)],
            )


def add_session_id_variations(writer: CaseWriter, cases: dict[int, list[dict[str, Any]]]) -> None:
    for number in [3, 4, 5, 7]:
        for session_id in ["00001234", "0000ABCD", "00007001"]:
            steps = copy.deepcopy(cases[number])
            final = steps[-1]
            output = final.setdefault("output", {})
            required = output.setdefault("return_values", {}).setdefault("required", {})
            required["HostSessionID"] = "00000001"
            required["SPSessionID"] = session_id
            method_args = output.setdefault("method", {}).setdefault("args", {}).setdefault("required", {})
            method_args["HostSessionID"] = "00000001"
            method_args["SPSessionID"] = session_id
            writer.add(
                steps,
                "pass",
                "session_id_variation",
                f"tc{number}.json",
                f"spsessionid_{session_id.lower()}",
                "StartSession success may return different session identifiers; the prompt should not memorize exact IDs.",
                ["session_auth", "anti_memorization", target_tag(steps)],
            )


def add_bad_challenge_traps(writer: CaseWriter, cases: dict[int, list[dict[str, Any]]]) -> None:
    for number, challenge in [(3, "a"), (4, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), (5, "xyz"), (7, "12345")]:
        steps = copy.deepcopy(cases[number])
        optional = steps[-1]["input"]["method"]["args"].setdefault("optional", {})
        optional["HostChallenge"] = challenge
        writer.add(
            steps,
            "fail",
            "bad_host_challenge_success_trap",
            f"tc{number}.json",
            f"bad_challenge_{slug(challenge)}",
            "Final StartSession still reports SUCCESS, but the HostChallenge is malformed and should not authenticate.",
            ["session_auth", "last_status_trap", "input_validation", target_tag(steps)],
        )


def add_missing_context_traps(writer: CaseWriter, cases: dict[int, list[dict[str, Any]]]) -> None:
    remove_specs = [
        (2, "remove_active_session", lambda s: [step for step in s if step is not s[0]]),
        (5, "remove_sp_activation", lambda s: [step for step in s if not is_named_method(step, "Activate")]),
        (6, "remove_locking_session_before_set", lambda s: remove_last_method_before_target(s, "StartSession")),
        (7, "remove_user_pin_set", lambda s: remove_last_method_before_target(s, "Set")),
        (8, "remove_locking_session_before_get", lambda s: remove_last_method_before_target(s, "StartSession")),
        (9, "remove_locking_session_before_mbr_get", lambda s: remove_last_method_before_target(s, "StartSession")),
    ]
    for number, variant, transform in remove_specs:
        steps = transform(copy.deepcopy(cases[number]))
        writer.add(
            steps,
            "fail",
            "missing_required_context",
            f"tc{number}.json",
            variant,
            "Removes a prior state-establishing step while keeping the final SUCCESS response, so state tracking should reject it.",
            ["state_tracking", "last_status_trap", target_tag(steps)],
        )

    for number in [2, 6, 8, 9]:
        steps = copy.deepcopy(cases[number])
        end_session = find_method_step(cases[number], "EndSession")
        if end_session:
            trapped = steps[:-1] + [copy.deepcopy(end_session)] + [steps[-1]]
            writer.add(
                trapped,
                "fail",
                "closed_session_before_target",
                f"tc{number}.json",
                "insert_end_session_before_final_method",
                "Closes the active session immediately before a final method that still reports SUCCESS.",
                ["state_tracking", "session_lifecycle", "last_status_trap", target_tag(steps)],
            )


def add_final_only_distractors(
    writer: CaseWriter,
    cases: dict[int, list[dict[str, Any]]],
    labels: dict[int, str],
    no_op: dict[str, Any],
) -> None:
    bad_properties = copy.deepcopy(cases[11][0])
    good_properties = copy.deepcopy(no_op)
    for number in sorted(cases):
        distractor = bad_properties if labels[number] == "pass" else good_properties
        steps = copy.deepcopy(cases[number][:-1]) + [copy.deepcopy(distractor)] + [copy.deepcopy(cases[number][-1])]
        writer.add(
            steps,
            labels[number],
            "pre_target_opposite_distractor",
            f"tc{number}.json",
            "insert_opposite_properties_before_final",
            "Adds a pass/fail-looking Properties response before the target; only the final step should determine the label.",
            ["final_target_focus", "distractor", target_tag(steps)],
        )


def replace_final_output(steps: list[dict[str, Any]], output: dict[str, Any]) -> list[dict[str, Any]]:
    result = copy.deepcopy(steps)
    result[-1]["output"] = copy.deepcopy(output)
    return result


def mutate_final_method_status(steps: list[dict[str, Any]], status: str) -> list[dict[str, Any]]:
    result = copy.deepcopy(steps)
    output = result[-1].setdefault("output", {})
    output["status_codes"] = status
    if status != "SUCCESS":
        if result[-1]["input"]["method"]["name"] == "StartSession":
            output.setdefault("method", {}).setdefault("args", {})["required"] = {}
            output.setdefault("method", {}).setdefault("args", {})["optional"] = {}
            output["return_values"] = {"required": {}, "optional": {}}
        else:
            output["return_values"] = []
    return result


def mutate_final_data_result(steps: list[dict[str, Any]], result_value: str) -> list[dict[str, Any]]:
    result = copy.deepcopy(steps)
    output = result[-1].setdefault("output", {})
    args = output.setdefault("args", {})
    args["result"] = result_value
    output.pop("result", None)
    return result


def remove_last_method_before_target(steps: list[dict[str, Any]], method_name: str) -> list[dict[str, Any]]:
    for idx in range(len(steps) - 2, -1, -1):
        if is_named_method(steps[idx], method_name):
            return steps[:idx] + steps[idx + 1 :]
    return steps


def reindex(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for idx, step in enumerate(steps, start=1):
        step["index"] = idx
    return steps


def validate_split(out_root: Path) -> None:
    labels = []
    with (out_root / "label.jsonl").open(encoding="utf-8") as f:
        for line in f:
            labels.append(json.loads(line))
    filenames = {item["filename"] for item in labels}
    case_files = {path.name for path in (out_root / "testcases").glob("tc*.json")}
    if filenames != case_files:
        missing_cases = sorted(filenames - case_files)
        missing_labels = sorted(case_files - filenames)
        raise RuntimeError(f"split mismatch missing_cases={missing_cases} missing_labels={missing_labels}")
    for path in (out_root / "testcases").glob("tc*.json"):
        steps = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(steps, list) or not steps:
            raise RuntimeError(f"invalid testcase shape: {path}")
        for expected, step in enumerate(steps, start=1):
            if step.get("index") != expected:
                raise RuntimeError(f"bad index in {path}: expected {expected}, got {step.get('index')}")


def is_method(step: dict[str, Any]) -> bool:
    return "method" in step.get("input", {})


def is_named_method(step: dict[str, Any], method_name: str) -> bool:
    return step.get("input", {}).get("method", {}).get("name") == method_name


def find_method_step(steps: list[dict[str, Any]], method_name: str) -> dict[str, Any] | None:
    for step in steps:
        if is_named_method(step, method_name):
            return step
    return None


def get_output_status(step: dict[str, Any]) -> str | None:
    return step.get("output", {}).get("status_codes")


def get_data_result(step: dict[str, Any]) -> Any:
    output = step.get("output", {})
    if "result" in output:
        return output["result"]
    return output.get("args", {}).get("result")


def describe_target(step: dict[str, Any]) -> dict[str, Any]:
    if is_method(step):
        return {
            "kind": "method",
            "op": step["input"]["method"].get("name"),
            "object": step["input"].get("invoking_id", {}).get("name"),
            "status": step.get("output", {}).get("status_codes"),
        }
    return {
        "kind": "data",
        "op": step.get("input", {}).get("command"),
        "args": step.get("input", {}).get("args"),
        "result": get_data_result(step),
    }


def target_tag(steps: list[dict[str, Any]]) -> str:
    target = describe_target(steps[-1])
    if target["kind"] == "data":
        return "target_data_read"
    op = str(target.get("op", "unknown")).lower()
    obj = str(target.get("object", "unknown")).lower().replace(" ", "_")
    return f"target_{op}_{obj}"


def slug(text: Any) -> str:
    value = str(text).lower()
    result = []
    for ch in value:
        result.append(ch if ch.isalnum() else "_")
    return "_".join(part for part in "".join(result).split("_") if part)[:60] or "value"


def readme_text(counts: dict[str, Any]) -> str:
    return f"""# Synthetic DL2026 Test Split v1

This split was generated from the public examples without modifying the original `dataset/` folder.
It is intended for prompt debugging, not as a substitute for the hidden grader.

## Files

- `testcases/tc*.json`: evaluator-compatible testcase files.
- `label.jsonl`: evaluator-compatible labels.
- `metadata.jsonl`: one metadata record per testcase, with category, source, target, tags, and rationale.
- `summary.json`: aggregate counts.

## Counts

- total: {counts["total"]}
- labels: `{json.dumps(counts["labels"], sort_keys=True)}`
- categories: `{json.dumps(counts["categories"], sort_keys=True)}`

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
"""


if __name__ == "__main__":
    raise SystemExit(main())
