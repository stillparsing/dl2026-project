#!/bin/bash

set -euo pipefail

uv sync

uv run python - <<'PY'
import os
from huggingface_hub import snapshot_download

model_name = os.environ.get("MODEL_NAME", "Qwen/Qwen3.5-0.8B")
snapshot_download(repo_id=model_name)
PY
