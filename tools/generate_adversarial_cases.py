#!/usr/bin/env python3
import argparse
import copy
import json
import shutil
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SOURCE_CASE_DIR = ROOT / "dataset" / "testcases"
DEFAULT_OUT = ROOT / "synthetic_dataset" / "v2"


class CaseWriter:
    def __init__(self, out_root: Path) -> None:
        self.out_root = out_root
        self.case_dir = out_root / "testcases"
        self.labels: list[dict[str, str]] = []
        self.metadata: list[dict[str, Any]] = []
        self.next_id = 2001

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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate adversarial cases for prefilter false-positive audits.")
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="Output split root.")
    args = parser.parse_args(argv)

    cases = load_cases()
    writer = CaseWriter(Path(args.out).resolve())
    writer.reset()

    add_correct_rejection_cases(writer, cases)
    add_success_trap_cases(writer, cases)
    add_data_path_traps(writer, cases)

    writer.write_indexes()
    validate_split(writer.out_root)
    print(f"wrote {len(writer.labels)} cases to {writer.out_root}")
    print(json.dumps(json.loads((writer.out_root / "summary.json").read_text(encoding="utf-8")), indent=2))
    return 0


def load_cases() -> dict[int, list[dict[str, Any]]]:
    result = {}
    for path in SOURCE_CASE_DIR.glob("tc*.json"):
        number = int(path.stem.removeprefix("tc"))
        result[number] = json.loads(path.read_text(encoding="utf-8"))
    return result


def add_correct_rejection_cases(writer: CaseWriter, cases: dict[int, list[dict[str, Any]]]) -> None:
    # These are labeled pass because the final device rejection is the expected safe behavior.
    writer.add(
        mutate_final_method_status(remove_methods(cases[5], "Activate"), "NOT_AUTHORIZED"),
        "pass",
        "correct_rejection",
        "tc5.json",
        "locking_sp_start_before_activation_rejected",
        "Starting LockingSP before activation should be rejected, so NOT_AUTHORIZED is a correct final response.",
        ["accepted_error", "session_auth", "state_tracking"],
    )
    writer.add(
        mutate_final_method_status(close_before_target(cases[6]), "NOT_AUTHORIZED"),
        "pass",
        "correct_rejection",
        "tc6.json",
        "set_authority_without_active_session_rejected",
        "A Set without an active session should be rejected, so NOT_AUTHORIZED is a correct final response.",
        ["accepted_error", "session_lifecycle", "acl"],
    )
    writer.add(
        mutate_final_method_status(close_before_target(cases[8]), "NOT_AUTHORIZED"),
        "pass",
        "correct_rejection",
        "tc8.json",
        "get_locking_without_active_session_rejected",
        "A Get without an active session should be rejected, so NOT_AUTHORIZED is a correct final response.",
        ["accepted_error", "session_lifecycle", "acl"],
    )
    writer.add(
        mutate_final_method_status(close_before_target(cases[10]), "NOT_AUTHORIZED"),
        "pass",
        "correct_rejection",
        "tc10.json",
        "genkey_without_active_session_rejected",
        "A GenKey without an active session should be rejected, so NOT_AUTHORIZED is a correct final response.",
        ["accepted_error", "session_lifecycle", "crypto"],
    )
    writer.add(
        mutate_final_method_status(mutate_final_host_challenge(cases[3], "not-hex-challenge"), "INVALID_PARAMETER"),
        "pass",
        "correct_rejection",
        "tc3.json",
        "malformed_host_challenge_rejected",
        "A malformed HostChallenge should not authenticate, so INVALID_PARAMETER is a correct final response.",
        ["accepted_error", "input_validation", "session_auth"],
    )
    writer.add(
        mutate_final_method_status(make_malformed_properties_request(cases[1]), "INVALID_PARAMETER"),
        "pass",
        "correct_rejection",
        "tc1.json",
        "malformed_properties_rejected",
        "A malformed Properties request with missing HostProperties should be rejected with no return values.",
        ["accepted_error", "properties"],
    )


def add_success_trap_cases(writer: CaseWriter, cases: dict[int, list[dict[str, Any]]]) -> None:
    # These stay fail because the final success contradicts the state.
    writer.add(
        remove_methods(cases[5], "Activate"),
        "fail",
        "success_trap",
        "tc5.json",
        "locking_sp_start_before_activation_success",
        "LockingSP StartSession reports SUCCESS even though activation was removed.",
        ["last_status_trap", "session_auth", "state_tracking"],
    )
    writer.add(
        close_before_target(cases[6]),
        "fail",
        "success_trap",
        "tc6.json",
        "set_authority_closed_session_success",
        "Set reports SUCCESS after the active session was closed.",
        ["last_status_trap", "session_lifecycle", "acl"],
    )
    writer.add(
        mutate_final_host_challenge(cases[3], "not-hex-challenge"),
        "fail",
        "success_trap",
        "tc3.json",
        "malformed_host_challenge_success",
        "StartSession reports SUCCESS despite a malformed HostChallenge.",
        ["last_status_trap", "input_validation", "session_auth"],
    )


def add_data_path_traps(writer: CaseWriter, cases: dict[int, list[dict[str, Any]]]) -> None:
    writer.add(
        remove_last_method_before_target(cases[10], "GenKey"),
        "fail",
        "data_path_success_trap",
        "tc10.json",
        "random_data_without_genkey",
        "Read returns Random Data even though the final GenKey state transition was removed.",
        ["data_path", "crypto", "state_tracking"],
    )
    writer.add(
        mutate_final_data_result(cases[10], "Pattern 8E"),
        "fail",
        "data_path_success_trap",
        "tc10.json",
        "old_pattern_after_genkey",
        "Read reveals old data after GenKey, which contradicts the expected randomization.",
        ["data_path", "crypto", "last_status_trap"],
    )


def mutate_final_method_status(steps: list[dict[str, Any]], status: str) -> list[dict[str, Any]]:
    result = copy.deepcopy(steps)
    output = result[-1].setdefault("output", {})
    output["status_codes"] = status
    if status != "SUCCESS":
        output["return_values"] = {"required": {}, "optional": {}} if is_start_session(result[-1]) else []
        output.setdefault("method", {}).setdefault("args", {})["required"] = {}
        output.setdefault("method", {}).setdefault("args", {})["optional"] = {}
    return result


def mutate_final_data_result(steps: list[dict[str, Any]], result_value: str) -> list[dict[str, Any]]:
    result = copy.deepcopy(steps)
    output = result[-1].setdefault("output", {})
    output.setdefault("args", {})["result"] = result_value
    output.pop("result", None)
    return result


def mutate_final_host_challenge(steps: list[dict[str, Any]], value: str) -> list[dict[str, Any]]:
    result = copy.deepcopy(steps)
    optional = result[-1]["input"]["method"]["args"].setdefault("optional", {})
    optional["HostChallenge"] = value
    return result


def make_malformed_properties_request(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = copy.deepcopy(steps)
    args = result[-1]["input"]["method"].setdefault("args", [])
    if isinstance(args, list) and args:
        args[0] = {"UnsupportedHostProperties": args[0].get("HostProperties", {})}
    else:
        result[-1]["input"]["method"]["args"] = [{"UnsupportedHostProperties": {}}]
    return result


def close_before_target(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    end_session = find_method_step(steps, "EndSession")
    if not end_session:
        return copy.deepcopy(steps)
    result = copy.deepcopy(steps)
    return result[:-1] + [copy.deepcopy(end_session), result[-1]]


def remove_methods(steps: list[dict[str, Any]], method_name: str) -> list[dict[str, Any]]:
    return [copy.deepcopy(step) for step in steps if not is_named_method(step, method_name)]


def remove_last_method_before_target(steps: list[dict[str, Any]], method_name: str) -> list[dict[str, Any]]:
    result = copy.deepcopy(steps)
    for idx in range(len(result) - 2, -1, -1):
        if is_named_method(result[idx], method_name):
            return result[:idx] + result[idx + 1 :]
    return result


def find_method_step(steps: list[dict[str, Any]], method_name: str) -> dict[str, Any] | None:
    for step in steps:
        if is_named_method(step, method_name):
            return step
    return None


def is_named_method(step: dict[str, Any], method_name: str) -> bool:
    return step.get("input", {}).get("method", {}).get("name") == method_name


def is_start_session(step: dict[str, Any]) -> bool:
    return is_named_method(step, "StartSession")


def describe_target(step: dict[str, Any]) -> dict[str, Any]:
    if "method" in step.get("input", {}):
        return {
            "kind": "method",
            "op": step["input"]["method"].get("name"),
            "object": step["input"].get("invoking_id", {}).get("name"),
            "status": step.get("output", {}).get("status_codes"),
        }
    output = step.get("output", {})
    return {
        "kind": "data",
        "op": step.get("input", {}).get("command"),
        "args": step.get("input", {}).get("args"),
        "result": output.get("result", output.get("args", {}).get("result")),
    }


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
        raise RuntimeError(f"split mismatch missing_cases={sorted(filenames - case_files)}")


def readme_text(counts: dict[str, Any]) -> str:
    return f"""# Synthetic DL2026 Test Split v2

This adversarial split focuses on deterministic prefilter false positives.
Unlike v1, it includes accepted error responses: cases where the final command
should be rejected and the observed rejection is therefore labeled `pass`.

## Counts

- total: {counts["total"]}
- labels: `{json.dumps(counts["labels"], sort_keys=True)}`
- categories: `{json.dumps(counts["categories"], sort_keys=True)}`

## Run

```bash
python tools/audit_rule_prefilter.py --dataset-dir synthetic_dataset/v2/testcases --label-path synthetic_dataset/v2/label.jsonl
```
"""


if __name__ == "__main__":
    raise SystemExit(main())
