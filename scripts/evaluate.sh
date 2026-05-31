#!/bin/bash
# Phase 2 — student-side mirror of scripts/private/evaluate.sh. Runs the
# project's own evaluate.py against the public dataset / label so the
# student gets a score before submitting.
#
# Assumes `bash /dl2026/scripts/setup.sh` has already built the venv at
# ${VENV_DIR}. Re-runs of evaluate.sh skip the setup work — the venv is
# reused and only the predict step runs.
set -euo pipefail

PROJECT_DIR=${PROJECT_DIR:-/workspace/project}
VENV_DIR=${VENV_DIR:-${PROJECT_DIR}/.venv}
DATASET_ROOT=${DATASET_ROOT:-/dl2026/dataset}
DATASET_DIR=${DATASET_DIR:-${DATASET_ROOT}/dataset}
LABEL_PATH=${LABEL_PATH:-${DATASET_ROOT}/label.json}

cd "${PROJECT_DIR}"

UV_PROJECT_ENVIRONMENT="${VENV_DIR}" \
PYTHONDONTWRITEBYTECODE=1 \
DATASET_DIR="${DATASET_DIR}" \
LABEL_PATH="${LABEL_PATH}" \
uv run --no-sync python evaluate.py

echo "----"
echo "PROJECT_DIR: ${PROJECT_DIR}"
echo "predictions: ${PROJECT_DIR}/predictions.jsonl"
echo "scores: ${PROJECT_DIR}/scores.json"
