import json
import re
import sys
from pathlib import Path
from typing import Any


SPID_NAMES = {
    "0000020500000001": "AdminSP",
    "0000020500000002": "LockingSP",
}

AUTHORITY_NAMES = {
    "0000000900000006": "SID",
    "0000000900010001": "Admin1",
    "0000000900030001": "User1",
}

SUCCESS_STATUSES = {"SUCCESS", "SUCCESSFUL"}
DATA_SUCCESS = {"PASS", "SUCCESS"}


class ValueAliases:
    """Replace long repeated secrets/byte strings with stable short aliases."""

    def __init__(self):
        self._aliases: dict[str, str] = {}

    def simplify(self, value: Any, key: str = "") -> Any:
        if isinstance(value, dict):
            return {str(k): self.simplify(v, str(k)) for k, v in value.items()}
        if isinstance(value, list):
            return [self.simplify(item, key) for item in value]
        if not isinstance(value, str):
            return value

        compact = value.replace(" ", "")
        key_lower = key.lower()
        if key_lower in {"uid", "spid", "hostsigningauthority"}:
            return symbolic_uid(compact)
        if len(value) <= 24:
            return value
        if _looks_like_secret_or_blob(value):
            return self._alias_for(value)
        return value

    def _alias_for(self, value: str) -> str:
        if value not in self._aliases:
            self._aliases[value] = f"<V{len(self._aliases) + 1}>"
        return self._aliases[value]


def build_case_summary(steps: list[dict[str, Any]], max_context_steps: int = 80) -> dict[str, Any]:
    """Build a compact, prompt-ready summary for one testcase trajectory."""
    aliases = ValueAliases()
    compressed = [
        compress_step(step, aliases, is_target=(idx == len(steps) - 1))
        for idx, step in enumerate(steps)
    ]

    context = compressed[:-1]
    if len(context) > max_context_steps:
        context = context[:20] + [{"omitted_context_steps": len(context) - 40}] + context[-20:]

    target = compressed[-1] if compressed else {}
    return {
        "task": "Judge only the final target response. Earlier steps are context for protocol state.",
        "target_family": classify_target(target, compressed),
        "final_target": target,
        "state_hints": build_state_hints(compressed),
        "context_timeline": context,
    }


def render_case_summary(steps: list[dict[str, Any]], max_context_steps: int = 80) -> str:
    summary = build_case_summary(steps, max_context_steps=max_context_steps)
    return json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=False)


def compress_step(
    step: dict[str, Any],
    aliases: ValueAliases | None = None,
    is_target: bool = False,
) -> dict[str, Any]:
    aliases = aliases or ValueAliases()
    input_part = step.get("input", {}) or {}
    output_part = step.get("output", {}) or {}

    if "method" in input_part:
        compact = _compress_method_step(step, input_part, output_part, aliases)
    else:
        compact = _compress_data_step(step, input_part, output_part, aliases)

    if is_target:
        compact["role"] = "target"
        compact["observed_response"] = describe_observed_response(compact)
        compact.pop("effect", None)
    return compact


def build_state_hints(compressed_steps: list[dict[str, Any]]) -> list[str]:
    hints: list[str] = []
    active_session: dict[str, Any] | None = None

    for step in compressed_steps[:-1]:
        op = step.get("op")
        status = normalize_status(step.get("output_status"))
        success = is_success_status(status)
        effect = step.get("effect")

        if effect:
            hints.append(f"#{step.get('i')}: {effect}")

        if op == "StartSession" and success:
            active_session = {
                "sp": step.get("sp"),
                "write": step.get("write"),
                "authority": step.get("authority"),
                "authenticated": bool(step.get("authority")),
            }
        elif op == "EndSession" and success:
            active_session = None

    if active_session:
        auth = active_session.get("authority") or "Anybody/unauthenticated"
        hints.append(
            "Final context has an active "
            f"{active_session.get('sp')} session, write={active_session.get('write')}, authority={auth}."
        )
    else:
        hints.append("Final context has no active session unless the target StartSession succeeds.")

    return _dedupe_keep_order(hints)


def classify_target(target: dict[str, Any], compressed_steps: list[dict[str, Any]]) -> str:
    op = target.get("op")
    obj = target.get("object")
    if op == "Read":
        if any(step.get("op") == "GenKey" and is_success_status(step.get("output_status")) for step in compressed_steps):
            return "data_read_after_genkey"
        return "data_read"
    if op == "Write":
        return "data_write"
    if op == "StartSession":
        return "session_authentication"
    if op == "Set":
        return f"set_{obj or 'object'}"
    if op == "Get":
        return f"get_{obj or 'object'}"
    if op == "Activate":
        return "sp_activation"
    if op == "GenKey":
        return "key_generation"
    return str(op or "unknown")


def _compress_method_step(
    step: dict[str, Any],
    input_part: dict[str, Any],
    output_part: dict[str, Any],
    aliases: ValueAliases,
) -> dict[str, Any]:
    method = input_part.get("method", {}) or {}
    invoking = input_part.get("invoking_id", {}) or {}
    args = method.get("args", {}) or {}
    required = args.get("required", {}) if isinstance(args, dict) else args
    optional = args.get("optional", {}) if isinstance(args, dict) else {}
    output_status = normalize_status(output_part.get("status_codes"))

    compact: dict[str, Any] = {
        "i": step.get("index"),
        "kind": "method",
        "op": method.get("name"),
        "object": invoking.get("name"),
        "object_uid": aliases.simplify(invoking.get("uid"), "uid"),
        "args": {
            "required": aliases.simplify(required),
            "optional": aliases.simplify(optional),
        },
        "input_status": normalize_status(input_part.get("status_codes")),
        "output_status": output_status,
    }

    return_values = output_part.get("return_values")
    if return_values not in (None, {}, []):
        compact["returns"] = aliases.simplify(return_values)

    _add_method_specific_fields(compact, required, optional, output_part, aliases)
    compact["effect"] = infer_effect(compact)
    return _drop_empty(compact)


def _compress_data_step(
    step: dict[str, Any],
    input_part: dict[str, Any],
    output_part: dict[str, Any],
    aliases: ValueAliases,
) -> dict[str, Any]:
    op = input_part.get("command") or "unknown"
    result = output_part.get("result")
    output_args = output_part.get("args")
    if isinstance(output_args, dict) and "result" in output_args:
        result = output_args.get("result")

    compact = {
        "i": step.get("index"),
        "kind": "data",
        "op": op,
        "args": aliases.simplify(input_part.get("args", {})),
        "output_command": output_part.get("command"),
        "result": aliases.simplify(result),
    }
    compact["effect"] = infer_effect(compact)
    return _drop_empty(compact)


def _add_method_specific_fields(
    compact: dict[str, Any],
    required: Any,
    optional: Any,
    output_part: dict[str, Any],
    aliases: ValueAliases,
) -> None:
    if not isinstance(required, dict):
        return

    op = compact.get("op")
    if op == "StartSession":
        spid = str(required.get("SPID", ""))
        authority_uid = ""
        if isinstance(optional, dict):
            authority_uid = str(optional.get("HostSigningAuthority", ""))
        compact["sp"] = SPID_NAMES.get(spid, spid or None)
        compact["write"] = required.get("Write")
        compact["authority"] = symbolic_uid(authority_uid) if authority_uid else None
        compact["host_challenge"] = aliases.simplify(
            optional.get("HostChallenge") if isinstance(optional, dict) else None,
            "HostChallenge",
        )

        session_values = output_part.get("return_values", {})
        if isinstance(session_values, dict):
            required_values = session_values.get("required", {})
            compact["session_ids"] = aliases.simplify(required_values)
    elif op in {"Set", "Get"}:
        compact["columns"] = extract_columns(required, optional)
    elif op == "GenKey":
        compact["key_object"] = compact.get("object")


def infer_effect(step: dict[str, Any]) -> str | None:
    op = step.get("op")
    if step.get("kind") == "data":
        if op == "Write":
            result = normalize_status(step.get("result"))
            if result in DATA_SUCCESS:
                return f"Data Write succeeded at {step.get('args')}."
            return f"Data Write returned {step.get('result')} at {step.get('args')}."
        if op == "Read":
            return f"Data Read returned {step.get('result')} for {step.get('args')}."
        return None

    status = normalize_status(step.get("output_status"))
    if not is_success_status(status):
        return f"{op} did not apply state changes because output_status={status}."

    if op == "StartSession":
        authority = step.get("authority") or "Anybody/unauthenticated"
        return f"StartSession succeeded: sp={step.get('sp')}, write={step.get('write')}, authority={authority}."
    if op == "EndSession":
        return "EndSession succeeded; current session closed."
    if op == "Set":
        return f"Set succeeded on {step.get('object')} columns={step.get('columns')}."
    if op == "Get":
        return f"Get succeeded on {step.get('object')} columns={step.get('columns')}."
    if op == "Activate":
        return f"Activate succeeded on {step.get('object')}."
    if op == "GenKey":
        return f"GenKey succeeded on {step.get('object')}; later reads of old ciphertext should not reveal old plaintext."
    if op == "Properties":
        return "Properties negotiation succeeded."
    return None


def describe_observed_response(step: dict[str, Any]) -> str:
    if step.get("kind") == "data":
        return f"{step.get('op')} returned result={step.get('result')}"
    return f"{step.get('op')} returned output_status={step.get('output_status')}"


def extract_columns(required: Any, optional: Any) -> list[Any]:
    columns: list[Any] = []
    if isinstance(required, dict):
        cellblock = required.get("Cellblock")
        if isinstance(cellblock, list):
            for item in cellblock:
                if isinstance(item, dict):
                    columns.extend(item.values())
    if isinstance(optional, dict):
        values = optional.get("Values")
        if isinstance(values, list):
            for item in values:
                if isinstance(item, dict):
                    columns.extend(item.keys())
    return columns


def normalize_status(status: Any) -> str | None:
    if status is None:
        return None
    return re.sub(r"\s+", "_", str(status).strip()).upper()


def is_success_status(status: Any) -> bool:
    return normalize_status(status) in SUCCESS_STATUSES


def symbolic_uid(uid: Any) -> Any:
    if uid is None:
        return None
    compact = str(uid).replace(" ", "")
    if compact in SPID_NAMES:
        return f"{SPID_NAMES[compact]}({compact})"
    if compact in AUTHORITY_NAMES:
        return f"{AUTHORITY_NAMES[compact]}({compact})"
    return compact


def _looks_like_secret_or_blob(value: str) -> bool:
    compact = value.replace(" ", "")
    if len(compact) < 25:
        return False
    return bool(re.fullmatch(r"[0-9A-Fa-f]+", compact) or re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact))


def _dedupe_keep_order(items: list[str]) -> list[str]:
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            result.append(item)
            seen.add(item)
    return result


def _drop_empty(data: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in data.items() if v not in (None, {}, [])}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1:
        print("usage: python -m src.preprocess <testcase.json>", file=sys.stderr)
        return 2
    path = Path(argv[0])
    with path.open(encoding="utf-8") as f:
        steps = json.load(f)
    print(render_case_summary(steps))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
