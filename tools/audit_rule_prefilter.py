#!/usr/bin/env python3
import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SKELETON_DIR = ROOT / "skeleton"
DEFAULT_DATASET_DIR = ROOT / "synthetic_dataset" / "v1" / "testcases"
DEFAULT_LABEL_PATH = ROOT / "synthetic_dataset" / "v1" / "label.jsonl"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit deterministic rule-prefilter coverage and precision without loading torch/model."
    )
    parser.add_argument("--dataset-dir", default=str(DEFAULT_DATASET_DIR))
    parser.add_argument("--label-path", default=str(DEFAULT_LABEL_PATH))
    parser.add_argument(
        "--metadata-path",
        default=None,
        help="Optional metadata.jsonl path. Defaults to label-path sibling metadata.jsonl when present.",
    )
    parser.add_argument("--show", type=int, default=20, help="Maximum covered mistakes/uncovered cases to print.")
    args = parser.parse_args(argv)

    dataset_dir = Path(args.dataset_dir)
    label_path = Path(args.label_path)
    metadata_path = Path(args.metadata_path) if args.metadata_path else label_path.parent / "metadata.jsonl"

    import sys

    sys.path.insert(0, str(SKELETON_DIR))
    from src.preprocess import build_case_summary, prejudge_obvious_case

    labels = read_labels(label_path)
    metadata = read_metadata(metadata_path) if metadata_path.exists() else {}

    covered = 0
    covered_correct = 0
    covered_wrong: list[dict[str, Any]] = []
    uncovered: list[dict[str, Any]] = []
    covered_by_label = Counter()
    wrong_by_label = Counter()
    uncovered_by_label = Counter()
    covered_by_category = Counter()
    wrong_by_category = Counter()
    uncovered_by_category = Counter()
    covered_by_target = Counter()
    wrong_by_target = Counter()
    uncovered_by_target = Counter()

    for filename, answer in sorted(labels.items(), key=lambda item: case_sort_key(item[0])):
        case_path = dataset_dir / filename
        steps = json.loads(case_path.read_text(encoding="utf-8"))
        verdict = prejudge_obvious_case(steps)
        meta = metadata.get(filename, {})
        category = meta.get("category", "unknown")
        target = target_name(meta) if meta else infer_target_name(build_case_summary(steps).get("final_target", {}))

        if verdict is None:
            uncovered.append({"filename": filename, "expected": answer, "category": category, "target": target})
            uncovered_by_label[answer] += 1
            uncovered_by_category[category] += 1
            uncovered_by_target[target] += 1
            continue

        covered += 1
        covered_by_label[answer] += 1
        covered_by_category[category] += 1
        covered_by_target[target] += 1
        if verdict == answer:
            covered_correct += 1
        else:
            wrong = {
                "filename": filename,
                "expected": answer,
                "predicted": verdict,
                "category": category,
                "target": target,
                "rationale": meta.get("rationale"),
                "tags": meta.get("tags", []),
            }
            covered_wrong.append(wrong)
            wrong_by_label[answer] += 1
            wrong_by_category[category] += 1
            wrong_by_target[target] += 1

    total = len(labels)
    precision = 100.0 * covered_correct / covered if covered else 0.0
    coverage = 100.0 * covered / total if total else 0.0

    print(f"total={total}")
    print(f"covered={covered} coverage={coverage:.2f}%")
    print(f"covered_correct={covered_correct} precision={precision:.2f}%")
    print(f"covered_wrong={len(covered_wrong)}")
    print(f"uncovered={len(uncovered)}")
    print()
    print_counter("Covered by label", covered_by_label)
    print_counter("Wrong covered by label", wrong_by_label)
    print()
    print_group("Covered by category", covered_by_category, wrong_by_category)
    print()
    print_group("Uncovered by category", uncovered_by_category)
    print()
    print_group("Covered by target", covered_by_target, wrong_by_target, limit=30)
    print()
    print_group("Uncovered by target", uncovered_by_target, limit=30)

    if covered_wrong:
        print()
        print("Covered mistakes")
        print("----------------")
        for item in covered_wrong[: args.show]:
            print(
                f"{item['filename']} expected={item['expected']} predicted={item['predicted']} "
                f"category={item['category']} target={item['target']}"
            )
            if item.get("rationale"):
                print(f"  rationale={item['rationale']}")
            if item.get("tags"):
                print(f"  tags={', '.join(item['tags'])}")

    if uncovered:
        print()
        print("Uncovered examples")
        print("------------------")
        for item in uncovered[: args.show]:
            print(
                f"{item['filename']} expected={item['expected']} "
                f"category={item['category']} target={item['target']}"
            )

    return 1 if covered_wrong else 0


def read_labels(path: Path) -> dict[str, str]:
    labels = {}
    with path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                item = json.loads(line)
                labels[item["filename"]] = item["label"].strip().lower()
    return labels


def read_metadata(path: Path) -> dict[str, dict[str, Any]]:
    result = {}
    with path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                item = json.loads(line)
                result[item["filename"]] = item
    return result


def print_counter(title: str, counter: Counter) -> None:
    print(title)
    print("-" * len(title))
    if not counter:
        print("  none")
        return
    for key, count in sorted(counter.items(), key=lambda item: (-item[1], item[0])):
        print(f"  {key}: {count}")


def print_group(title: str, totals: Counter, misses: Counter | None = None, limit: int = 20) -> None:
    print(title)
    print("-" * len(title))
    if not totals:
        print("  none")
        return
    rows = []
    for key, total in totals.items():
        miss = misses[key] if misses else 0
        rows.append((miss, total, key))
    for miss, total, key in sorted(rows, key=lambda row: (-row[1], -row[0], row[2]))[:limit]:
        if misses:
            print(f"  {key}: total={total} wrong={miss}")
        else:
            print(f"  {key}: {total}")


def target_name(item: dict[str, Any]) -> str:
    target = item.get("target", {})
    if target.get("kind") == "data":
        return f"data:{target.get('op')}:{target.get('result')}"
    return f"method:{target.get('op')}:{target.get('object')}:{target.get('status')}"


def infer_target_name(target: dict[str, Any]) -> str:
    if target.get("kind") == "data":
        return f"data:{target.get('op')}:{target.get('result')}"
    return f"method:{target.get('op')}:{target.get('object')}:{target.get('output_status')}"


def case_sort_key(case_id: str) -> tuple[int, str]:
    stem = Path(case_id).stem
    number = stem.removeprefix("tc").split("_")[0]
    try:
        return int(number), case_id
    except ValueError:
        return 10**9, case_id


if __name__ == "__main__":
    raise SystemExit(main())
