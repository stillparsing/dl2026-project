import os
import re
import sys
from string import Template
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_DIR = Path(__file__).resolve().parents[1] / ".packages"
if PACKAGE_DIR.exists():
    sys.path.insert(0, str(PACKAGE_DIR))

from src.document_retriever import retrieve_relevant_specs
from src.preprocess import prejudge_obvious_case, render_case_summary


class Solver:
    def __init__(self):
        self.model_name = os.environ.get("MODEL_NAME", "Qwen/Qwen3.5-0.8B")
        self.max_input_tokens = int(os.environ.get("MAX_INPUT_TOKENS", "4096"))
        self.max_new_tokens = int(os.environ.get("MAX_NEW_TOKENS", "32"))
        self.spec_top_k = int(os.environ.get("SPEC_TOP_K", "7"))
        self.spec_max_chars = int(os.environ.get("SPEC_MAX_CHARS", "5200"))
        self.debug_generation = os.environ.get("DEBUG_GENERATION", "").lower() in {"1", "true", "yes"}
        self.debug_prompt = os.environ.get("DEBUG_PROMPT", "").lower() in {"1", "true", "yes"}
        self.debug_prompt_limit = int(os.environ.get("DEBUG_PROMPT_LIMIT", "20000"))
        self.debug_rules = os.environ.get("DEBUG_RULES", "").lower() in {"1", "true", "yes"}
        self.use_rule_prefilter = os.environ.get("USE_RULE_PREFILTER", "1").lower() not in {"0", "false", "no"}
        self.prompt_template = self.load_prompt_template()
        self.device = None
        self.tokenizer = None
        self.model = None
        self.torch = None

        print(f"solver_model={self.model_name} (lazy)")
        print(f"spec_top_k={self.spec_top_k}")
        print(f"spec_max_chars={self.spec_max_chars}")

    def predict(self, dataset):
        """Predict labels for the full dataset.

        dataset: list of {"id": str, "steps": list[dict]}.
        returns: dict mapping id -> "pass" or "fail".

        Override this method to do cross-trajectory inference, retrieval
        over the whole dataset, or batched generation. The baseline just
        loops case-by-case via predict_one.
        """
        predictions = {}
        for item in dataset:
            predictions[item["id"]] = self.predict_one(item["steps"])
        return predictions

    def predict_one(self, steps):
        if not steps:
            return "fail"

        if self.use_rule_prefilter:
            verdict = prejudge_obvious_case(steps)
            if verdict:
                if self.debug_rules or self.debug_generation:
                    print(f"rule_prefilter={verdict}")
                return verdict

        self.ensure_model_loaded()
        prompt = self.make_prompt(steps)
        if self.debug_prompt:
            print("---- prompt begin ----")
            print(prompt[: self.debug_prompt_limit])
            if len(prompt) > self.debug_prompt_limit:
                print(f"... prompt truncated {len(prompt) - self.debug_prompt_limit} characters ...")
            print("---- prompt end ----")

        inputs = self.tokenizer(
            prompt,
            return_tensors="pt",
            truncation=True,
            max_length=self.max_input_tokens,
        ).to(self.device)

        with self.torch.inference_mode():
            output_ids = self.model.generate(
                **inputs,
                do_sample=False,
                max_new_tokens=self.max_new_tokens,
                pad_token_id=self.tokenizer.eos_token_id,
            )

        new_ids = output_ids[0, inputs["input_ids"].shape[-1]:]
        text = self.tokenizer.decode(new_ids, skip_special_tokens=True).strip().lower()
        if self.debug_generation:
            print(f"raw_generation={text!r}")
        return self.parse_answer(text)

    def ensure_model_loaded(self):
        if self.model is not None:
            return

        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        self.torch = torch
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.tokenizer = AutoTokenizer.from_pretrained(
            self.model_name,
            trust_remote_code=True,
        )
        self.model = AutoModelForCausalLM.from_pretrained(
            self.model_name,
            torch_dtype=torch.bfloat16 if self.device.type == "cuda" else torch.float32,
            trust_remote_code=True,
        ).to(self.device)
        self.model.eval()

        print(f"solver_model_loaded={self.model_name}")
        print(f"solver_device={self.device}")

    def make_prompt(self, steps):
        if self.tokenizer is None:
            raise RuntimeError("model/tokenizer must be loaded before building chat prompt")

        case_summary = render_case_summary(steps)
        spec_context = retrieve_relevant_specs(
            steps,
            top_k=self.spec_top_k,
            max_chars=self.spec_max_chars,
        )
        user_prompt = self.prompt_template.safe_substitute(
            case_summary=case_summary,
            spec_context=spec_context,
        )

        messages = [
            {
                "role": "system",
                "content": (
                    "You are an SSD TCG protocol judge using a deterministic state ledger. "
                    "Judge only whether the final target response is allowed by state_before_target. "
                    "Do not be a pessimistic auditor: output pass when the observed final response "
                    "is a normal allowed response for the ledger state. "
                    "Output fail only when the final response contradicts the testcase facts or protocol rules. "
                    "A device rejection is not automatically fail: if the final request should be rejected "
                    "in state_before_target, an error response is the correct response and must be pass. "
                    "Conversely, if the final request should be rejected, a SUCCESS response is fail. "
                    "Use target_judgment_focus and the provided reference snippets as protocol guidance. "
                    "Do not explain your reasoning. Do not use markdown. "
                    "Answer with exactly one lowercase word: pass or fail."
                ),
            },
            {
                "role": "user",
                "content": user_prompt,
            },
        ]

        if getattr(self.tokenizer, "chat_template", None):
            try:
                return self.tokenizer.apply_chat_template(
                    messages,
                    tokenize=False,
                    add_generation_prompt=True,
                    enable_thinking=False,
                )
            except TypeError:
                return self.tokenizer.apply_chat_template(
                    messages,
                    tokenize=False,
                    add_generation_prompt=True,
                )

        system = messages[0]["content"]
        user = messages[1]["content"]
        return f"System: {system}\nUser: {user}\nAssistant:"

    def load_prompt_template(self):
        prompt_path = Path(os.environ.get("PROMPT_TEMPLATE", PROJECT_ROOT / "artifacts" / "prompt_template.md"))
        try:
            return Template(prompt_path.read_text(encoding="utf-8"))
        except OSError:
            return Template(
                "Reference snippets:\n$spec_context\n\n"
                "Compressed testcase:\n$case_summary\n\n"
                "Answer with exactly one lowercase word: pass or fail.\nVerdict:"
            )

    def parse_answer(self, text):
        text = re.sub(r"<think>.*?</think>", " ", text, flags=re.DOTALL)
        matches = re.findall(r"\b(pass|fail)\b", text)
        if matches:
            return matches[-1]
        return "fail"
