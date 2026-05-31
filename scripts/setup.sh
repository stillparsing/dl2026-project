#!/bin/bash
# Phase 1 — student-side mirror of scripts/private/setup.sh. Builds the
# venv inside the student's project directory by running their own
# setup.sh, with UV_PROJECT_ENVIRONMENT pinning the venv location so the
# subsequent `bash /dl2026/scripts/evaluate.sh` can reuse it.
#
# Runs as the student user (no root, no chown) — jupyter container has
# no root and the project dir is already student-owned.
set -euo pipefail

PROJECT_DIR=${PROJECT_DIR:-/workspace/project}
VENV_DIR=${VENV_DIR:-${PROJECT_DIR}/.venv}

cd "${PROJECT_DIR}"
UV_PROJECT_ENVIRONMENT="${VENV_DIR}" bash setup.sh
