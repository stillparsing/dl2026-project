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
    state_analysis = build_state_analysis(compressed)
    return {
        "task": "Judge only the final target response. Earlier steps are context for protocol state.",
        "target_family": classify_target(target, compressed),
        "final_target": target,
        "target_judgment_focus": build_target_judgment_focus(target, state_analysis),
        "state_before_target": state_analysis["state_before_target"],
        "state_update_trace": state_analysis["state_update_trace"],
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


def build_state_analysis(compressed_steps: list[dict[str, Any]]) -> dict[str, Any]:
    """Infer a compact deterministic state ledger from prior successful steps.

    This is intentionally conservative. It does not try to fully implement TCG
    Opal; it extracts the state variables that repeatedly appear in the public
    trajectories so the LLM does not have to rediscover them from raw JSON.
    """
    state: dict[str, Any] = {
        "active_session": {"exists": False},
        "session_history": [],
        "sp_lifecycle": {
            "AdminSP": "available",
            "LockingSP": "unknown_or_inactive_until_activated",
        },
        "authorities": {},
        "table_observations": [],
        "locking": {
            "ranges_observed": [],
            "ranges_modified": [],
            "mbr_control": {},
        },
        "crypto": {
            "genkey_events": [],
            "genkey_after_data_write": False,
        },
        "data_path": {
            "writes": [],
            "reads": [],
        },
        "communication": {
            "properties_negotiated": False,
        },
        "state_rules_applied": [
            "Process prior steps in order.",
            "Only successful prior method responses update protocol state.",
            "Failed prior method responses are observations but do not apply state changes.",
            "EndSession success clears active_session.",
            "The final target step is not applied to this state; it is judged against this state.",
        ],
    }
    trace: list[dict[str, Any]] = []

    for step in compressed_steps[:-1]:
        if not isinstance(step, dict):
            trace.append({"step": None, "event": "omitted_context_steps", "update": step})
            continue

        op = step.get("op")
        success = step_succeeded(step)
        if not success:
            trace.append(
                {
                    "step": step.get("i"),
                    "event": f"{op} failed_or_rejected",
                    "update": "no state change",
                    "observed": observed_status(step),
                }
            )
            continue

        update = apply_successful_state_update(state, step)
        if update:
            trace.append({"step": step.get("i"), "event": op, "update": update})

    state["derived_flags"] = derive_state_flags(state)
    return {
        "state_before_target": _drop_empty_recursive(state),
        "state_update_trace": trace[-60:],
    }


def step_succeeded(step: dict[str, Any]) -> bool:
    if step.get("kind") == "data":
        if step.get("op") == "Write":
            return normalize_status(step.get("result")) in DATA_SUCCESS
        if step.get("op") == "Read":
            return step.get("result") not in (None, "", "FAIL")
        return False
    return is_success_status(step.get("output_status"))


def observed_status(step: dict[str, Any]) -> Any:
    if step.get("kind") == "data":
        return step.get("result")
    return step.get("output_status")


def apply_successful_state_update(state: dict[str, Any], step: dict[str, Any]) -> str | None:
    op = step.get("op")
    obj = step.get("object")

    if op == "Properties":
        state["communication"]["properties_negotiated"] = True
        return "communication.properties_negotiated=true"

    if op == "StartSession":
        authority = step.get("authority") or "Anybody/unauthenticated"
        session = {
            "exists": True,
            "sp": step.get("sp"),
            "write": bool(step.get("write")),
            "authority": authority,
            "authenticated": bool(step.get("authority")),
            "host_challenge_shape": step.get("host_challenge_shape"),
            "session_ids_present": bool(step.get("session_ids")),
        }
        state["active_session"] = session
        state["session_history"].append({k: v for k, v in session.items() if k != "exists"})
        ensure_authority(state, authority)["sessions_started"] = ensure_authority(state, authority).get("sessions_started", 0) + 1
        return f"active_session={session.get('sp')} authority={authority} write={session.get('write')}"

    if op == "EndSession":
        state["active_session"] = {"exists": False}
        return "active_session cleared"

    if op == "Activate":
        if obj == "SP":
            state["sp_lifecycle"]["LockingSP"] = "activated"
            return "sp_lifecycle.LockingSP=activated"
        return f"{obj} activated"

    if op == "Get":
        observation = {
            "object": obj,
            "columns": step.get("columns"),
            "active_session": state.get("active_session"),
        }
        state["table_observations"].append(observation)
        if obj == "Locking":
            state["locking"]["ranges_observed"].append({"columns": step.get("columns"), "returns": step.get("returns")})
        elif obj == "MBRControl":
            state["locking"]["mbr_control"]["observed"] = step.get("returns")
        return f"observed {obj} columns={step.get('columns')}"

    if op == "Set":
        columns = step.get("columns")
        if obj == "Authority":
            authority = step.get("object_uid") or "unknown_authority"
            auth_state = ensure_authority(state, str(authority))
            auth_state["modified"] = True
            if "5" in [str(col) for col in columns or []]:
                auth_state["enabled_column_set"] = True
            return f"authority {authority} modified columns={columns}"
        if obj == "C_PIN":
            target_authority = infer_pin_owner(step, state)
            auth_state = ensure_authority(state, target_authority)
            auth_state["pin_changed"] = True
            return f"{target_authority} PIN changed"
        if obj == "Locking":
            state["locking"]["ranges_modified"].append({"columns": columns, "values": step.get("args", {}).get("optional")})
            return f"locking range modified columns={columns}"
        if obj == "MBRControl":
            state["locking"]["mbr_control"]["modified"] = {"columns": columns, "values": step.get("args", {}).get("optional")}
            return f"MBRControl modified columns={columns}"
        return f"Set applied to {obj} columns={columns}"

    if op == "GenKey":
        event = {
            "object": step.get("object"),
            "after_data_write": bool(state["data_path"]["writes"]),
        }
        state["crypto"]["genkey_events"].append(event)
        if event["after_data_write"]:
            state["crypto"]["genkey_after_data_write"] = True
        return f"GenKey on {step.get('object')}; after_data_write={event['after_data_write']}"

    if op == "Write":
        write_event = {"args": step.get("args"), "result": step.get("result")}
        state["data_path"]["writes"].append(write_event)
        return f"data write succeeded at {step.get('args')}"

    if op == "Read":
        read_event = {"args": step.get("args"), "result": step.get("result")}
        state["data_path"]["reads"].append(read_event)
        return f"data read observed result={step.get('result')}"

    return step.get("effect")


def ensure_authority(state: dict[str, Any], authority: str) -> dict[str, Any]:
    authorities = state.setdefault("authorities", {})
    if authority not in authorities:
        authorities[authority] = {}
    return authorities[authority]


def infer_pin_owner(step: dict[str, Any], state: dict[str, Any] | None = None) -> str:
    uid = str(step.get("object_uid", ""))
    for authority in AUTHORITY_NAMES.values():
        if authority in uid:
            return authority
    state = state or {}
    active_session = state.get("active_session", {}) or {}
    authorities = state.get("authorities", {}) or {}
    if active_session.get("sp") == "LockingSP" and "Admin1" in str(active_session.get("authority")):
        for authority, auth_state in authorities.items():
            if "User1" in str(authority) and auth_state.get("enabled_column_set"):
                return str(authority)
    return "C_PIN_owner"


def derive_state_flags(state: dict[str, Any]) -> dict[str, Any]:
    active_session = state.get("active_session", {})
    return {
        "has_active_session": bool(active_session.get("exists")),
        "active_authority": active_session.get("authority"),
        "active_sp": active_session.get("sp"),
        "locking_sp_activated": state.get("sp_lifecycle", {}).get("LockingSP") == "activated",
        "has_data_write": bool(state.get("data_path", {}).get("writes")),
        "genkey_after_data_write": bool(state.get("crypto", {}).get("genkey_after_data_write")),
    }


def build_target_judgment_focus(target: dict[str, Any], state_analysis: dict[str, Any]) -> dict[str, Any]:
    state = state_analysis["state_before_target"]
    focus: dict[str, Any] = {
        "judge_this_only": target,
        "state_to_use": state.get("derived_flags", {}),
        "pass_fail_test": "Answer pass only if the observed final response is consistent with state_before_target and relevant specs.",
    }
    expected_response_hint = build_expected_response_hint(target, state)
    if expected_response_hint:
        focus["expected_response_hint"] = expected_response_hint
    cues = build_target_cues(target, state)
    if cues:
        focus["preprocessor_cues"] = cues
    return focus


def build_expected_response_hint(target: dict[str, Any], state: dict[str, Any]) -> dict[str, Any] | None:
    """Return a compact target-local hint for clear expected accept/reject cases."""
    op = target.get("op")
    status = normalize_status(target.get("output_status"))
    active_session = state.get("active_session", {}) or {}
    flags = state.get("derived_flags", {}) or {}

    if op in {"Get", "Set", "GenKey"} and not active_session.get("exists"):
        return {
            "expected_behavior": "reject",
            "confidence": "high",
            "reason": f"{op} requires an active session, but state_before_target has no active_session.",
            "matching_observed_response": "pass if final response is NOT_AUTHORIZED with no useful return values; fail if final response is SUCCESS.",
        }

    if op == "StartSession":
        target_sp = target.get("sp")
        shape = target.get("host_challenge_shape", {}) or {}
        if target_sp == "LockingSP" and not flags.get("locking_sp_activated"):
            return {
                "expected_behavior": "reject",
                "confidence": "high",
                "reason": "Final StartSession requests LockingSP before LockingSP activation.",
                "matching_observed_response": "pass if final response is NOT_AUTHORIZED or INVALID_PARAMETER with no session IDs; fail if final response is SUCCESS.",
            }
        if shape.get("present") and shape.get("contains_non_alnum"):
            return {
                "expected_behavior": "reject",
                "confidence": "medium",
                "reason": "Final HostChallenge contains non-alphanumeric separator characters, unlike normal challenge tokens.",
                "matching_observed_response": "pass if final response rejects the session with no session IDs; fail if final response is SUCCESS.",
            }

    if op == "Properties":
        request_shape = target.get("properties_request_shape", {}) or {}
        if request_shape.get("malformed"):
            return {
                "expected_behavior": "reject",
                "confidence": "high",
                "reason": f"Malformed Properties request: {request_shape.get('reason')}.",
                "matching_observed_response": "pass if final response is INVALID_PARAMETER with no properties returned; fail if final response is SUCCESS.",
            }
        if status and not is_success_status(status):
            return {
                "expected_behavior": "accept",
                "confidence": "medium",
                "reason": "Properties request shape looks normal in the compressed testcase.",
                "matching_observed_response": "fail if a normal valid Properties negotiation is rejected.",
            }

    return None


def build_target_cues(target: dict[str, Any], state: dict[str, Any]) -> list[str]:
    cues: list[str] = []
    op = target.get("op")
    status = normalize_status(target.get("output_status"))
    has_returns = bool(target.get("returns") or target.get("session_ids"))
    active_session = state.get("active_session", {})

    if op == "Properties":
        if is_success_status(status) and has_returns:
            cues.append("Properties SUCCESS with returned Properties/HostProperties is a normal pass pattern.")
        elif status:
            request_shape = target.get("properties_request_shape", {}) or {}
            if request_shape.get("malformed"):
                cues.append(f"Properties request is malformed: {request_shape.get('reason')}; rejection is expected.")
            cues.append(
                f"Properties returned {status}; pass if the final request is malformed/unsupported, "
                "fail if it is a normal valid Properties negotiation."
            )
    elif op == "StartSession":
        challenge_shape = target.get("host_challenge_shape", {})
        if is_success_status(status) and target.get("session_ids"):
            cues.append("StartSession SUCCESS with HostSessionID/SPSessionID present is a pass pattern unless authentication input is malformed.")
        if challenge_shape.get("present") and not challenge_shape.get("looks_hex"):
            cues.append("HostChallenge does not look hex; SUCCESS may be suspicious.")
        if challenge_shape.get("contains_non_alnum"):
            cues.append("HostChallenge contains non-alphanumeric separator characters; rejection may be expected.")
        if challenge_shape.get("hex_chars") is not None and challenge_shape.get("hex_chars") < 32:
            cues.append("HostChallenge is very short; SUCCESS may be suspicious.")
        if status and not is_success_status(status):
            cues.append(
                f"StartSession returned {status}; pass if the requested SP/authentication should be rejected "
                "in state_before_target, fail if the session should normally succeed."
            )
    elif op in {"Get", "Set", "Activate", "GenKey"}:
        if not active_session.get("exists"):
            if is_success_status(status):
                cues.append(f"{op} target has no active session before target; SUCCESS is suspicious.")
            else:
                cues.append(f"{op} target has no active session before target; an error response may be a correct rejection.")
        elif is_success_status(status):
            cues.append(f"{op} target has active session {active_session.get('sp')} authority={active_session.get('authority')}; SUCCESS may be normal if ACL allows it.")
        elif status:
            cues.append(
                f"{op} returned {status} despite active session {active_session.get('sp')} "
                f"authority={active_session.get('authority')}; decide whether ACL/arguments require rejection."
            )
    elif op == "Read":
        if state.get("crypto", {}).get("genkey_after_data_write"):
            cues.append("A GenKey occurred after data write; Random Data is the expected safe read pattern, old/plain data is suspicious.")
    return cues


def prejudge_obvious_case(steps: list[dict[str, Any]]) -> str | None:
    """Return a deterministic verdict for high-confidence visible patterns.

    The LLM remains the fallback for ambiguous ACL/spec cases. These rules cover
    straightforward protocol responses where the compressed state ledger already
    contains enough information to avoid asking a small model to infer basics.
    """
    summary = build_case_summary(steps)
    target = summary.get("final_target", {}) or {}
    state = summary.get("state_before_target", {}) or {}
    flags = state.get("derived_flags", {}) or {}
    active_session = state.get("active_session", {}) or {}

    op = target.get("op")
    status = normalize_status(target.get("output_status"))

    if op == "Properties":
        has_property_returns = bool(target.get("returns"))
        request_shape = target.get("properties_request_shape", {}) or {}
        if is_success_status(status) and has_property_returns:
            return "pass"
        if status == "INVALID_PARAMETER" and request_shape.get("malformed") and not has_property_returns:
            return "pass"
        if status in {"INVALID_PARAMETER", "NOT_AUTHORIZED", "FAIL", "INVALID_COMMAND"} and not request_shape.get("malformed"):
            return "fail"

    if op == "Read" and flags.get("genkey_after_data_write"):
        result = str(target.get("result", "")).strip().lower()
        if result == "random data":
            return "pass"
        if result in {"8e", "original plaintext", "known old data", "0000000000000000"}:
            return "fail"

    if op == "StartSession":
        shape = target.get("host_challenge_shape", {}) or {}
        session_ids = target.get("session_ids", {}) or {}
        target_sp = target.get("sp")
        target_authority = str(target.get("authority") or "")
        authorities = state.get("authorities", {}) or {}
        if is_success_status(status):
            if target_sp == "LockingSP" and not flags.get("locking_sp_activated"):
                return "fail"
            user1_pin_changed = any(
                "User1" in str(authority) and auth_state.get("pin_changed")
                for authority, auth_state in authorities.items()
            )
            if "User1" in target_authority and not user1_pin_changed:
                return "fail"
            if shape.get("present") and not shape.get("looks_hex"):
                return "fail"
            if shape.get("present") and shape.get("hex_chars") not in (None, 64):
                return "fail"
            if session_ids:
                return "pass"
        elif status in {"NOT_AUTHORIZED", "INVALID_PARAMETER"} and not session_ids:
            if target_sp == "LockingSP" and not flags.get("locking_sp_activated"):
                return "pass"
            if shape.get("contains_non_alnum"):
                return "pass"

    if op in {"Get", "Set", "GenKey"}:
        if is_success_status(status):
            if not active_session.get("exists"):
                return "fail"
            return "pass"
        if status == "NOT_AUTHORIZED" and not active_session.get("exists"):
            return "pass"

    return None


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
    op = compact.get("op")
    if op == "Properties":
        compact["properties_request_shape"] = describe_properties_request_shape(required)
        return

    if not isinstance(required, dict):
        return

    if op == "StartSession":
        spid = str(required.get("SPID", ""))
        authority_uid = ""
        host_challenge = None
        if isinstance(optional, dict):
            authority_uid = str(optional.get("HostSigningAuthority", ""))
            host_challenge = optional.get("HostChallenge")
        compact["sp"] = SPID_NAMES.get(spid, spid or None)
        compact["write"] = required.get("Write")
        compact["authority"] = symbolic_uid(authority_uid) if authority_uid else None
        compact["host_challenge"] = aliases.simplify(
            host_challenge,
            "HostChallenge",
        )
        compact["host_challenge_shape"] = describe_value_shape(host_challenge)

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


def describe_value_shape(value: Any) -> dict[str, Any]:
    if value in (None, ""):
        return {"present": False}
    text = str(value).replace(" ", "")
    return {
        "present": True,
        "chars": len(text),
        "hex_chars": len(text) if re.fullmatch(r"[0-9A-Fa-f]+", text) else None,
        "looks_hex": bool(re.fullmatch(r"[0-9A-Fa-f]+", text)),
        "contains_non_alnum": bool(re.search(r"[^0-9A-Za-z]", text)),
    }


def describe_properties_request_shape(required: Any) -> dict[str, Any]:
    if not isinstance(required, list) or not required:
        return {"malformed": True, "reason": "required args are not a non-empty HostProperties list"}

    host_properties = None
    for item in required:
        if isinstance(item, dict) and isinstance(item.get("HostProperties"), dict):
            host_properties = item["HostProperties"]
            break

    if host_properties is None:
        return {"malformed": True, "reason": "missing HostProperties"}

    expected_keys = {"MaxComPacketSize", "MaxPacketSize", "MaxIndTokenSize"}
    missing = sorted(key for key in expected_keys if key not in host_properties)
    if missing:
        return {"malformed": True, "reason": f"missing HostProperties keys: {', '.join(missing)}"}

    for key in expected_keys:
        value = host_properties.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[0-9A-Fa-f]+", value):
            return {"malformed": True, "reason": f"{key} is not a hex string"}

    return {"malformed": False, "reason": "HostProperties shape looks normal"}


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


def _drop_empty_recursive(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: cleaned
            for key, item in value.items()
            if (cleaned := _drop_empty_recursive(item)) not in (None, {}, [])
        }
    if isinstance(value, list):
        return [
            cleaned
            for item in value
            if (cleaned := _drop_empty_recursive(item)) not in (None, {}, [])
        ]
    return value


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
