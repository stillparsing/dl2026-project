#!/usr/bin/env python3
import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description="Group synthetic evaluation mistakes by category and tags.")
    parser.add_argument("--dataset", default=str(ROOT / "synthetic_dataset" / "v1"))
    parser.add_argument("--predictions", default=str(ROOT / "skeleton" / "predictions.jsonl"))
    parser.add_argument("--show", type=int, default=40, help="Maximum individual mistakes to print.")
    args = parser.parse_args()

    dataset = Path(args.dataset)
    prediction_path = Path(args.predictions)

    labels = read_label_jsonl(dataset / "label.jsonl")
    metadata = {item["filename"]: item for item in read_jsonl(dataset / "metadata.jsonl")}
    predictions = read_prediction_jsonl(prediction_path)

    missing_meta = sorted(set(labels) - set(metadata))
    if missing_meta:
        raise RuntimeError(f"metadata missing for {len(missing_meta)} cases, first={missing_meta[:5]}")

    total = len(labels)
    correct = 0
    misses: list[dict[str, Any]] = []
    category_totals = Counter()
    category_misses = Counter()
    tag_totals = Counter()
    tag_misses = Counter()
    target_totals = Counter()
    target_misses = Counter()

    for filename, answer in labels.items():
        meta = metadata[filename]
        pred = predictions.get(filename, "missing").strip().lower()
        ok = pred == answer
        correct += int(ok)

        category = meta["category"]
        category_totals[category] += 1
        target_key = target_name(meta)
        target_totals[target_key] += 1
        for tag in meta.get("tags", []):
            tag_totals[tag] += 1

        if not ok:
            item = dict(meta)
            item["expected"] = answer
            item["predicted"] = pred
            misses.append(item)
            category_misses[category] += 1
            target_misses[target_key] += 1
            for tag in meta.get("tags", []):
                tag_misses[tag] += 1

    print(f"score={100.0 * correct / total:.2f} correct={correct}/{total}")
    print()
    print_group("By category", category_totals, category_misses)
    print()
    print_group("By target", target_totals, target_misses)
    print()
    print_group("By tag", tag_totals, tag_misses)
    print()
    print("Mistakes")
    print("--------")
    for item in misses[: args.show]:
        print(
            f"{item['filename']} expected={item['expected']} predicted={item['predicted']} "
            f"category={item['category']} source={item['source']} variant={item['variant']}"
        )
        print(f"  target={target_name(item)}")
        print(f"  rationale={item['rationale']}")
        if item.get("tags"):
            print(f"  tags={', '.join(item['tags'])}")

    if len(misses) > args.show:
        print(f"... {len(misses) - args.show} more mistakes omitted")

    return 0


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def read_label_jsonl(path: Path) -> dict[str, str]:
    return {item["filename"]: item["label"].strip().lower() for item in read_jsonl(path)}


def read_prediction_jsonl(path: Path) -> dict[str, str]:
    if not path.exists():
        raise FileNotFoundError(f"prediction file not found: {path}")
    rows = read_jsonl(path)
    predictions = {}
    for item in rows:
        case_id = item.get("id") or item.get("filename")
        predictions[case_id] = item["prediction"].strip().lower()
    return predictions


def print_group(title: str, totals: Counter, misses: Counter) -> None:
    print(title)
    print("-" * len(title))
    rows = []
    for key, total in totals.items():
        miss = misses[key]
        acc = 100.0 * (total - miss) / total if total else 0.0
        rows.append((miss, total, acc, key))
    for miss, total, acc, key in sorted(rows, key=lambda row: (-row[0], row[3])):
        print(f"{key:42} acc={acc:6.2f} miss={miss:3}/{total:3}")


def target_name(item: dict[str, Any]) -> str:
    target = item.get("target", {})
    if target.get("kind") == "data":
        return f"data:{target.get('op')}:{target.get('result')}"
    return f"method:{target.get('op')}:{target.get('object')}:{target.get('status')}"


if __name__ == "__main__":
    raise SystemExit(main())
