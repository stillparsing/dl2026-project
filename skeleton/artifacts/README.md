# artifacts/

This directory carries auxiliary files that the solver references at
runtime. The `submit` command includes the directory in the submission
archive automatically when it is present; submissions remain valid when
the directory is empty or absent.

## What belongs here

- Fine-tuned model weights (LoRA adapters, partial layer states, etc.)
- Augmented training data produced offline
- Initial checkpoints used for test-time adaptation
- Any other supporting files that `src/` code reads at runtime
- Reference documents (e.g., the TCG specifications under `documents/`)

## What does not belong here

- HuggingFace base models. The container's shared cache (`HF_HOME`)
  already holds them; bundling them again would quickly exceed the
  12 GB archive limit.
- Debugging logs and intermediate artefacts that are not consumed by
  the grading run.

For path conventions and other constraints, refer to the
"`artifacts/`" section of the project [README](../README.md).
