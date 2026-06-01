#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKELETON_DIR = ROOT / "skeleton"
DEFAULT_DATASET_DIR = ROOT / "dataset" / "testcases"
DEFAULT_LABEL_PATH = ROOT / "dataset" / "label.jsonl"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run or inspect the prompt-based DL2026 evaluator.")
    parser.add_argument("--dataset-dir", default=str(DEFAULT_DATASET_DIR))
    parser.add_argument("--label-path", default=str(DEFAULT_LABEL_PATH))
    parser.add_argument("--model-name", default=os.environ.get("MODEL_NAME", "Qwen/Qwen3.5-0.8B"))
    parser.add_argument("--max-input-tokens", default=os.environ.get("MAX_INPUT_TOKENS", "4096"))
    parser.add_argument("--max-new-tokens", default=os.environ.get("MAX_NEW_TOKENS", "32"))
    parser.add_argument("--spec-top-k", default=os.environ.get("SPEC_TOP_K", "7"))
    parser.add_argument("--spec-max-chars", default=os.environ.get("SPEC_MAX_CHARS", "5200"))
    parser.add_argument("--prompt-template", default=str(SKELETON_DIR / "artifacts" / "prompt_template.md"))
    parser.add_argument("--preview", metavar="TC_JSON", help="Render prompt context for one testcase without loading the model.")
    parser.add_argument("--limit-output", type=int, default=12000, help="Maximum stdout/stderr characters to print.")
    args = parser.parse_args(argv)

    if args.preview:
        return preview_prompt(Path(args.preview), args)

    return run_evaluate(args)


def run_evaluate(args: argparse.Namespace) -> int:
    env = os.environ.copy()
    dataset_root = Path(args.dataset_dir).resolve().parent
    env.update(
        {
            "DATASET_DIR": str(dataset_root),
            "LABEL_PATH": str(Path(args.label_path).resolve()),
            "MODEL_NAME": args.model_name,
            "MAX_INPUT_TOKENS": str(args.max_input_tokens),
            "MAX_NEW_TOKENS": str(args.max_new_tokens),
            "SPEC_TOP_K": str(args.spec_top_k),
            "SPEC_MAX_CHARS": str(args.spec_max_chars),
            "PROMPT_TEMPLATE": str(Path(args.prompt_template).resolve()),
        }
    )

    command = [sys.executable, "evaluate.py"]
    print("Running:", " ".join(command))
    print("cwd:", SKELETON_DIR)
    print("MODEL_NAME:", env["MODEL_NAME"])
    print("DATASET_DIR:", env["DATASET_DIR"])
    print("LABEL_PATH:", env["LABEL_PATH"])
    print()

    proc = subprocess.run(
        command,
        cwd=SKELETON_DIR,
        env=env,
        text=True,
        capture_output=True,
    )

    print_limited("stdout", proc.stdout, args.limit_output)
    print_limited("stderr", proc.stderr, args.limit_output)
    summarize_results(Path(args.label_path), SKELETON_DIR / "predictions.jsonl", SKELETON_DIR / "scores.json")
    return proc.returncode


def preview_prompt(testcase_path: Path, args: argparse.Namespace) -> int:
    testcase_path = resolve_case_path(testcase_path)
    sys.path.insert(0, str(SKELETON_DIR))

    from src.document_retriever import retrieve_relevant_specs
    from src.preprocess import render_case_summary

    with testcase_path.open(encoding="utf-8") as f:
        steps = json.load(f)

    case_summary = render_case_summary(steps)
    spec_context = retrieve_relevant_specs(
        steps,
        top_k=int(args.spec_top_k),
        max_chars=int(args.spec_max_chars),
    )
    template = Path(args.prompt_template).read_text(encoding="utf-8")
    prompt = template.replace("$spec_context", spec_context).replace("$case_summary", case_summary)

    print(prompt)
    return 0


def resolve_case_path(path: Path) -> Path:
    if path.exists():
        return path
    candidate = DEFAULT_DATASET_DIR / path
    if candidate.exists():
        return candidate
    if path.suffix != ".json":
        candidate = DEFAULT_DATASET_DIR / f"{path}.json"
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"testcase not found: {path}")


def summarize_results(label_path: Path, prediction_path: Path, score_path: Path) -> None:
    print("----")
    if score_path.exists():
        try:
            score = json.loads(score_path.read_text(encoding="utf-8")).get("score")
            print(f"score: {score}")
        except json.JSONDecodeError:
            print(f"score file exists but is not valid JSON: {score_path}")
    else:
        print(f"score file missing: {score_path}")

    if not prediction_path.exists() or not label_path.exists():
        return

    labels = {}
    with label_path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                item = json.loads(line)
                labels[item["filename"]] = item["label"].strip().lower()

    predictions = {}
    with prediction_path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                item = json.loads(line)
                predictions[item["id"]] = item["prediction"].strip().lower()

    misses = [
        (case_id, labels[case_id], predictions.get(case_id, "missing"))
        for case_id in sorted(labels, key=case_sort_key)
        if predictions.get(case_id, "missing") != labels[case_id]
    ]
    print(f"mistakes: {len(misses)} / {len(labels)}")
    for case_id, answer, pred in misses[:20]:
        print(f"  {case_id}: expected={answer} predicted={pred}")

    metadata_path = label_path.parent / "metadata.jsonl"
    if metadata_path.exists():
        summarize_metadata_misses(metadata_path, labels, predictions)


def print_limited(name: str, text: str, limit: int) -> None:
    if not text:
        return
    print(f"---- {name} ----")
    if len(text) <= limit:
        print(text.rstrip())
    else:
        print(text[:limit].rstrip())
        print(f"... truncated {len(text) - limit} characters ...")


def summarize_metadata_misses(metadata_path: Path, labels: dict[str, str], predictions: dict[str, str]) -> None:
    metadata = {}
    with metadata_path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                item = json.loads(line)
                metadata[item["filename"]] = item

    category_totals = {}
    category_misses = {}
    tag_totals = {}
    tag_misses = {}
    examples = []

    for case_id, answer in labels.items():
        item = metadata.get(case_id)
        if not item:
            continue
        pred = predictions.get(case_id, "missing")
        category = item.get("category", "unknown")
        category_totals[category] = category_totals.get(category, 0) + 1
        for tag in item.get("tags", []):
            tag_totals[tag] = tag_totals.get(tag, 0) + 1
        if pred != answer:
            category_misses[category] = category_misses.get(category, 0) + 1
            for tag in item.get("tags", []):
                tag_misses[tag] = tag_misses.get(tag, 0) + 1
            examples.append((case_id, answer, pred, item))

    print("---- metadata groups ----")
    print_grouped_misses("category", category_totals, category_misses)
    print_grouped_misses("tag", tag_totals, tag_misses, limit=12)
    if examples:
        print("metadata examples:")
        for case_id, answer, pred, item in examples[:8]:
            print(
                f"  {case_id}: expected={answer} predicted={pred} "
                f"category={item.get('category')} variant={item.get('variant')}"
            )
            print(f"    rationale={item.get('rationale')}")


def print_grouped_misses(name: str, totals: dict[str, int], misses: dict[str, int], limit: int = 20) -> None:
    rows = []
    for key, total in totals.items():
        miss = misses.get(key, 0)
        if miss:
            accuracy = 100.0 * (total - miss) / total if total else 0.0
            rows.append((miss, total, accuracy, key))
    print(f"{name} misses:")
    if not rows:
        print("  none")
        return
    for miss, total, accuracy, key in sorted(rows, key=lambda item: (-item[0], item[3]))[:limit]:
        print(f"  {key}: miss={miss}/{total} acc={accuracy:.2f}")


def case_sort_key(case_id: str) -> tuple[int, str]:
    stem = Path(case_id).stem
    number = stem.removeprefix("tc").split("_")[0]
    try:
        return int(number), case_id
    except ValueError:
        return 10**9, case_id


if __name__ == "__main__":
    raise SystemExit(main())
