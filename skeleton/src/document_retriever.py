import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.preprocess import build_case_summary, is_success_status, normalize_status


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
DOCUMENTS_DIR = ARTIFACTS_DIR / "documents"


KEYWORD_EXPANSIONS = {
    "Properties": "properties max packet size maxcompacketsize maxpacket maxindtoken",
    "StartSession": "startsession session spid hostsigningauthority authentication authority write sessiontimeout",
    "EndSession": "endsession session close",
    "Set": "set method cellblock values columns table access control acl ace",
    "Get": "get method cellblock columns table access control acl ace",
    "Activate": "activate manufactured inactive lifecycle adminsp locking sp",
    "GenKey": "genkey media encryption key lockingrange range data removal erase cryptographic",
    "Read": "read data locking range readlock readlocked readlockenabled lba",
    "Write": "write data locking range writelock writelocked writelockenabled lba",
}

MUST_INCLUDE_DOCS = {
    "Properties": ["core/5.2.2.1", "core/5.2.2.2", "opal/4.1.1.1"],
    "StartSession": ["core/5.2.3.1", "core/5.3.4.1.5", "core/5.3.4.1.10", "opal/4.1.1.2"],
    "Activate": ["opal/5.1.1", "opal/5.1.1.2", "core/4.3"],
    "GenKey": ["core/5.3.3.16", "core/5.7.2.4", "opal/4.3.5.5"],
    "Read": ["core/5.7.3.2", "opal/4.3.7"],
    "Write": ["core/5.7.3.2", "opal/4.3.7"],
}

OBJECT_DOCS = {
    "C_PIN": ["core/5.3.2.12", "opal/4.2.1.8", "opal/4.3.1.9"],
    "Authority": ["core/5.3.2.10", "core/5.3.4.1.2", "opal/4.2.1.7", "opal/4.3.1.8"],
    "Locking": ["core/5.7.2.2", "core/5.7.3.1", "opal/4.3.5.2"],
    "LockingInfo": ["core/5.7.2.1", "opal/4.3.5.1"],
    "MBRControl": ["core/5.7.2.5", "core/5.7.3.6", "opal/4.3.5.3"],
    "SP": ["core/3.4.3", "core/4.3", "opal/5.1.1"],
    "K_AES_256": ["core/5.7.2.4", "opal/4.3.5.5"],
    "K_AES_128": ["core/5.7.2.3", "opal/4.3.5.5"],
}


@dataclass(frozen=True)
class Document:
    path: Path
    doc_id: str
    title: str
    text: str
    tokens: tuple[str, ...]
    counts: Counter


class DocumentRetriever:
    def __init__(self, documents_dir: Path = DOCUMENTS_DIR):
        self.documents_dir = documents_dir
        self.documents = self._load_documents()
        self.idf = self._build_idf(self.documents)

    def retrieve(self, summary: dict[str, Any], top_k: int = 7, max_chars: int = 5200) -> str:
        if not self.documents:
            return "No reference documents were found."

        query = build_retrieval_query(summary)
        query_tokens = _tokens(query)
        if not query_tokens:
            return "No useful retrieval query could be built."

        by_id = {doc.doc_id: doc for doc in self.documents}
        must_docs = [by_id[doc_id] for doc_id in must_include_doc_ids(summary) if doc_id in by_id]
        selected_ids = {doc.doc_id for doc in must_docs}

        scores = []
        for doc in self.documents:
            if doc.doc_id in selected_ids:
                continue
            score = self._score(doc, query_tokens)
            if score > 0:
                scores.append((score, doc))

        scores.sort(key=lambda item: item[0], reverse=True)
        selected = must_docs + [doc for _, doc in scores[:top_k]]
        if not selected:
            return "No directly matching reference snippets were found."

        snippets = []
        budget = max_chars
        per_doc_limit = max(450, max_chars // max(1, len(selected)))
        for doc in selected:
            if budget <= 0:
                break
            prefix = "MUST_INCLUDE" if doc.doc_id in selected_ids else "RETRIEVED"
            block = format_doc_snippet(doc, query_tokens, min(per_doc_limit, budget), prefix)
            snippets.append(block)
            budget -= len(block)

        return "\n\n---\n\n".join(snippets)

    def _score(self, doc: Document, query_tokens: list[str]) -> float:
        score = 0.0
        for token in query_tokens:
            tf = doc.counts.get(token, 0)
            if tf:
                score += (1.0 + math.log(tf)) * self.idf.get(token, 1.0)

        joined_title = f"{doc.doc_id} {doc.title}".lower()
        for token in set(query_tokens):
            if token in joined_title:
                score += 2.5
        return score

    def _load_documents(self) -> list[Document]:
        if not self.documents_dir.exists():
            return []

        titles = self._load_titles()
        docs = []
        for path in sorted(self.documents_dir.glob("*/*.txt")):
            if ".ipynb_checkpoints" in path.parts:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore").strip()
            if not text:
                continue
            rel = path.relative_to(self.documents_dir).as_posix()
            doc_id = rel.removesuffix(".txt")
            title = titles.get(doc_id) or _first_line(text) or doc_id
            toks = tuple(_tokens(f"{doc_id} {title}\n{text}"))
            docs.append(Document(path, doc_id, title, text, toks, Counter(toks)))
        return docs

    def _load_titles(self) -> dict[str, str]:
        titles: dict[str, str] = {}
        for section_path in self.documents_dir.glob("*/section_title.json"):
            prefix = section_path.parent.name
            try:
                data = json.loads(section_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(data, dict):
                for key, value in data.items():
                    titles[f"{prefix}/{key}"] = str(value)
        return titles

    @staticmethod
    def _build_idf(documents: list[Document]) -> dict[str, float]:
        doc_count = len(documents)
        dfs = Counter()
        for doc in documents:
            dfs.update(set(doc.tokens))
        return {
            token: math.log((1 + doc_count) / (1 + df)) + 1.0
            for token, df in dfs.items()
        }


_RETRIEVER: DocumentRetriever | None = None


def retrieve_relevant_specs(steps: list[dict[str, Any]], top_k: int = 7, max_chars: int = 5200) -> str:
    global _RETRIEVER
    if _RETRIEVER is None:
        _RETRIEVER = DocumentRetriever()
    summary = build_case_summary(steps)
    return _RETRIEVER.retrieve(summary, top_k=top_k, max_chars=max_chars)


def must_include_doc_ids(summary: dict[str, Any]) -> list[str]:
    target = summary.get("final_target", {}) or {}
    op = target.get("op")
    obj = target.get("object")
    doc_ids: list[str] = []
    doc_ids.extend(MUST_INCLUDE_DOCS.get(str(op), []))
    if op in {"Get", "Set"}:
        doc_ids.extend(["core/5.3.3.6" if op == "Get" else "core/5.3.3.7", "core/5.3.4.2"])
    if obj:
        doc_ids.extend(OBJECT_DOCS.get(str(obj), []))
    if target.get("key_object"):
        doc_ids.extend(OBJECT_DOCS.get(str(target.get("key_object")), []))

    state = summary.get("state_before_target", {}) or {}
    flags = state.get("derived_flags", {}) or {}
    if flags.get("genkey_after_data_write"):
        doc_ids.extend(["core/5.3.3.16", "core/5.7.3.2", "opal/4.3.7"])
    if flags.get("locking_sp_activated"):
        doc_ids.extend(["opal/5.1.1", "opal/4.3"])
    return _dedupe_keep_order(doc_ids)


def build_retrieval_query(summary: dict[str, Any]) -> str:
    target = summary.get("final_target", {}) or {}
    context = summary.get("context_timeline", []) or []
    state_hints = summary.get("state_hints", []) or []
    state_before_target = summary.get("state_before_target", {}) or {}
    state_update_trace = summary.get("state_update_trace", []) or []
    target_focus = summary.get("target_judgment_focus", {}) or {}

    parts: list[str] = [
        str(summary.get("target_family", "")),
        str(target.get("op", "")),
        str(target.get("object", "")),
        str(target.get("object_uid", "")),
        str(target.get("output_status", "")),
        str(target.get("result", "")),
    ]

    op = target.get("op")
    if op in KEYWORD_EXPANSIONS:
        parts.append(KEYWORD_EXPANSIONS[op])

    parts.extend(_extract_column_terms(target))
    parts.extend(str(hint) for hint in state_hints)
    parts.append(json.dumps(state_before_target, ensure_ascii=False, sort_keys=True))
    parts.append(json.dumps(state_update_trace[-20:], ensure_ascii=False, sort_keys=True))
    parts.append(json.dumps(target_focus, ensure_ascii=False, sort_keys=True))

    recent_ops = []
    successful_ops = []
    failed_ops = []
    for step in context:
        if not isinstance(step, dict):
            continue
        step_op = step.get("op")
        if step_op:
            recent_ops.append(str(step_op))
        status = normalize_status(step.get("output_status") or step.get("result"))
        if is_success_status(status):
            successful_ops.append(str(step_op))
        elif status:
            failed_ops.append(f"{step_op} {status}")
        parts.extend(_extract_column_terms(step))
        for key in ("object", "sp", "authority", "key_object"):
            if step.get(key):
                parts.append(str(step[key]))

    parts.append("recent operations " + " ".join(recent_ops[-12:]))
    parts.append("successful operations " + " ".join(successful_ops[-10:]))
    parts.append("failed operations " + " ".join(failed_ops[-10:]))

    if any(op_name == "GenKey" for op_name in recent_ops):
        parts.append(KEYWORD_EXPANSIONS["GenKey"])
    if any(op_name in {"Read", "Write"} for op_name in recent_ops + [str(op)]):
        parts.append("locking range read write data band range start length access")
    if any(op_name == "StartSession" for op_name in recent_ops + [str(op)]):
        parts.append(KEYWORD_EXPANSIONS["StartSession"])

    return "\n".join(part for part in parts if part and part != "None")


def format_doc_snippet(doc: Document, query_tokens: list[str], limit: int, prefix: str) -> str:
    excerpt = _best_excerpt(doc.text, query_tokens, limit)
    return f"[{prefix} {doc.doc_id}] {doc.title}\n{excerpt.strip()}"


def _extract_column_terms(step: dict[str, Any]) -> list[str]:
    terms: list[str] = []
    columns = step.get("columns")
    if isinstance(columns, list):
        terms.extend(str(col) for col in columns)
    args = step.get("args")
    if isinstance(args, dict):
        terms.extend(_walk_interesting_keys(args))
    return terms


def _walk_interesting_keys(value: Any) -> list[str]:
    terms: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            if _looks_interesting_key(key_text):
                terms.append(key_text)
            terms.extend(_walk_interesting_keys(item))
    elif isinstance(value, list):
        for item in value:
            terms.extend(_walk_interesting_keys(item))
    return terms


def _looks_interesting_key(key: str) -> bool:
    lowered = key.lower()
    return any(
        marker in lowered
        for marker in (
            "lock",
            "range",
            "authority",
            "password",
            "enabled",
            "start",
            "length",
            "spid",
            "host",
            "max",
        )
    )


def _tokens(text: str) -> list[str]:
    raw = re.findall(r"[A-Za-z0-9_]+", text.lower())
    tokens: list[str] = []
    for item in raw:
        tokens.append(item)
        tokens.extend(part for part in re.split(r"[_]+", item) if len(part) > 2)
    return [token for token in tokens if len(token) > 1]


def _best_excerpt(text: str, query_tokens: list[str], limit: int) -> str:
    lines = [line.rstrip() for line in text.splitlines()]
    if len(text) <= limit:
        return text

    query_set = set(query_tokens)
    scored = []
    for idx, line in enumerate(lines):
        line_tokens = set(_tokens(line))
        overlap = len(query_set & line_tokens)
        if overlap:
            scored.append((overlap, idx))

    if not scored:
        return text[:limit].rstrip()

    _, center = max(scored, key=lambda item: item[0])
    start = max(0, center - 8)
    end = min(len(lines), center + 14)
    excerpt = "\n".join(lines[start:end]).strip()

    while len(excerpt) < limit and (start > 0 or end < len(lines)):
        if start > 0:
            start -= 1
        if end < len(lines):
            end += 1
        excerpt = "\n".join(lines[start:end]).strip()

    if len(excerpt) > limit:
        excerpt = excerpt[:limit].rsplit("\n", 1)[0]
    return excerpt


def _first_line(text: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def _dedupe_keep_order(items: list[str]) -> list[str]:
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            result.append(item)
            seen.add(item)
    return result
