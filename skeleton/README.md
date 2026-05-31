# DL2026 Project Skeleton

Starting template for the course project. The solver reads a sequence of
steps and returns a single lowercase token, either `pass` or `fail`.
Other forms (`PASS`, `True`, etc.) are rejected by the grader.

## Layout

```text
.
├── README.md
├── setup.sh             # Phase 1: prepare the runtime environment
├── pyproject.toml
├── uv.lock
├── evaluate.py          # Local self-check entrypoint
├── artifacts/           # Auxiliary assets bundled with the solver
└── src/
    ├── __init__.py
    └── solver.py        # The file you are expected to modify
```

`src/solver.py` defines a `Solver` class with a `predict(steps)` method
returning `"pass"` or `"fail"`. Changes outside `src/` are allowed as
long as the submission contract below is preserved.

## Baseline

A minimal LLM-based solver that loads a small model, formats the input
as a prompt, and decodes a single-token answer. It exists to verify the
GPU and inference path, not to be competitive.

## Local Self-check

```bash
cd <your project root>
bash setup.sh
python evaluate.py
```

Runs the solver against the public split and writes `predictions.jsonl`
and `scores.json` to the current directory.

### Dataset Locations

- In the development container, the public split is mounted at
  `/dl2026/dataset/{testcases/, label.jsonl}`.
- Override with `DATASET_DIR` (split root) and `LABEL_PATH` (label file):

```bash
DATASET_DIR=/path/to/split-root LABEL_PATH=/path/to/label.jsonl \
    python evaluate.py
```

A different baseline model may be selected through `MODEL_NAME`:

```bash
MODEL_NAME=Qwen/Qwen3.5-0.8B python evaluate.py
```

## Submission

Submissions are made through the `submit` command, preinstalled in the
development container.

```bash
submit                                                  # Submit the current directory
submit --job-name baseline-v1                           # Attach a human-readable name
submit --dir /workspace/project --job-name v2-tuned     # Submit a different directory
submit --list                                           # List prior submissions
```

### Archive Contents

| Path              | Required  | Notes                                            |
|-------------------|-----------|--------------------------------------------------|
| `src/`            | yes       | Solver source code                               |
| `setup.sh`        | yes       | Environment setup script (Phase 1)               |
| `pyproject.toml`  | yes       | Python project metadata                          |
| `uv.lock`         | yes       | Locked dependency manifest                       |
| `artifacts/`      | optional  | Auxiliary assets bundled alongside the solver    |

Files outside this whitelist — including `evaluate.py`,
`predictions.jsonl`, `__pycache__/`, `.venv/`, and `.git/` — are not
transmitted.

## artifacts/

The `artifacts/` directory carries auxiliary files the solver references
at runtime, such as fine-tuned weights, augmented data, or checkpoints.
It is included in the submission archive when present and may be left
empty. We provided parsed pdf tcg spec documents into skeleton project.

### Path Conventions

The working directory differs between the development and grading
environments:

- Development container: `/workspace/project/`
- Grading container: `/workspace/submission/`

Anchor auxiliary paths against the source file rather than hardcoding
absolute paths:

```python
from pathlib import Path

ARTIFACTS_DIR = Path(__file__).resolve().parents[1] / "artifacts"
my_model = ARTIFACTS_DIR / "my-finetune"
```

`Path(__file__).resolve().parents[1]` resolves to the project root in
both environments.

### Constraints

- **HuggingFace cache.** `HF_HOME=/workspace/cache/hf_cache` is a
  *shared* cache at evaluation process. Team-specific fine-tuned outputs must go in
  `artifacts/` instead.
- **Network access during evaluation.** The grading process runs without network access.
   Required weights must be bundled in `artifacts/` or
  downloaded during `setup.sh` (which has network access).
- **Archive size.** The compressed submission archive is limited to
  12 GB. Load base model weights from the shared HuggingFace cache and
  bundle only fine-tuning differences (e.g. LoRA adapters).

## Environment Variables

The container preconfigures caches for HuggingFace, Torch, UV, pip,
Triton, TorchInductor, and matplotlib. These are part of the grading
contract and should not be overridden in `setup.sh` or solver code.

## Submission Simulations

You can check how submission process is operated by `/dl2026/scripts/{setup.sh,evaluate.sh}`.
When you face problems related to environment setup, path problem, etc., check the scripts.
