#!/usr/bin/env python3
import json
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parent
from src.solver import Solver


_DATASET_ROOT = Path(os.environ.get("DATASET_DIR", "/workspace/dataset"))
DATASET_DIR = _DATASET_ROOT / "testcases"
LABEL_PATH = Path(os.environ.get("LABEL_PATH", _DATASET_ROOT / "label.jsonl"))


def case_number(path):
    return int(path.stem.removeprefix("tc").split("_")[0])


def load_json(path):
    with path.open() as f:
        return json.load(f)


def load_dataset(dataset_dir):
    """Load all testcases as [{"id": str, "steps": list}, ...] sorted by case number."""
    return [
        {"id": path.name, "steps": load_json(path)}
        for path in sorted(dataset_dir.glob("tc*.json"), key=case_number)
    ]


def load_labels(path):
    """JSONL: one {"filename": ..., "label": ...} record per line."""
    labels = {}
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            labels[record["filename"]] = record["label"]
    return labels


def main():
    dataset = load_dataset(DATASET_DIR)
    labels = load_labels(LABEL_PATH)
    solver = Solver()

    predictions = solver.predict(dataset)

    correct = 0
    total = 0
    with open("predictions.jsonl", "w") as pred_file:
        for item in dataset:
            case_id = item["id"]
            prediction = predictions.get(case_id, "fail")
            answer = labels[case_id].strip().lower()
            correct += int(prediction == answer)
            total += 1
            pred_file.write(json.dumps({"id": case_id, "prediction": prediction}) + "\n")

    score = 100.0 * correct / total if total else 0.0
    with open("scores.json", "w") as score_file:
        json.dump({"score": score}, score_file)
        score_file.write("\n")

    print(f"score={score:.2f}")


if __name__ == "__main__":
    main()
