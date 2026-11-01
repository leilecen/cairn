from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_STORE = PROJECT_ROOT / "metrics" / "costs.jsonl"

CONTEXT_KEYS = ("project", "target", "session", "agent", "lane", "work_item", "reasoning_effort")
TOKEN_KEYS = ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens", "total_tokens")
COST_KEYS = ("cost", "cost_usd", "total_cost", "total_cost_usd")
BODY_KEYS = {
    "prompt",
    "prompts",
    "response",
    "responses",
    "completion",
    "content",
    "text",
    "html",
    "body",
    "request",
    "requests",
    "response_body",
    "request_body",
    "messages",
    "transcript",
    "tool_input",
    "tool_response",
    "headers",
    "cookie",
    "authorization",
}


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _first_present(mapping: dict[str, Any], keys: tuple[str, ...] | list[str]) -> Any:
    for key in keys:
        if key in mapping and mapping[key] not in (None, ""):
            return mapping[key]
    return None


def _safe_string(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, (str, int, float)):
        text = str(value)
        if len(text) <= 200 and "\n" not in text and "\r" not in text:
            return text
    return None


def _iter_dicts(value: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            found.append(item)
            for key, child in item.items():
                if str(key).lower() not in BODY_KEYS:
                    stack.append(child)
        elif isinstance(item, list):
            stack.extend(item)
    return found


def _usage_dicts(payload: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = []
    for item in _iter_dicts(payload):
        if any(key in item for key in TOKEN_KEYS + COST_KEYS) or "usage" in item:
            candidates.append(item)
    return candidates


def _extract_tokens(payload: dict[str, Any]) -> dict[str, int | None]:
    merged: dict[str, int | None] = {key: None for key in TOKEN_KEYS}
    aliases = {
        "input_tokens": ("input_tokens", "input", "prompt_tokens"),
        "output_tokens": ("output_tokens", "output", "completion_tokens"),
        "cache_creation_input_tokens": ("cache_creation_input_tokens", "cache_creation_tokens"),
        "cache_read_input_tokens": ("cache_read_input_tokens", "cache_read_tokens", "cached_tokens"),
        "total_tokens": ("total_tokens", "total"),
    }
    for candidate in _usage_dicts(payload):
        usage: dict[str, Any] = candidate["usage"] if isinstance(candidate.get("usage"), dict) else candidate
        for field, names in aliases.items():
            value = _first_present(usage, names)
            if merged[field] is None:
                merged[field] = _as_int(value)
    if merged["total_tokens"] is None:
        parts = [
            merged["input_tokens"],
            merged["output_tokens"],
            merged["cache_creation_input_tokens"],
            merged["cache_read_input_tokens"],
        ]
        if any(part is not None for part in parts):
            merged["total_tokens"] = sum(part or 0 for part in parts)
    return merged


def _extract_cost(payload: dict[str, Any]) -> float | None:
    for candidate in _usage_dicts(payload):
        usage: dict[str, Any] = candidate["usage"] if isinstance(candidate.get("usage"), dict) else candidate
        value = _first_present(usage, COST_KEYS)
        cost = _as_float(value)
        if cost is not None:
            return cost
    return None


def _extract_context(payload: dict[str, Any]) -> dict[str, str | None]:
    context: dict[str, str | None] = {
        "project": _safe_string(_first_present(payload, ("project", "project_name", "cwd"))) or PROJECT_ROOT.name,
        "target": _safe_string(_first_present(payload, ("target", "target_name"))),
        "session": _safe_string(_first_present(payload, ("session", "session_id", "conversation_id"))),
        "agent": _safe_string(_first_present(payload, ("agent", "agent_id", "subagent_name"))) or "main",
        "lane": _safe_string(_first_present(payload, ("lane", "work_lane"))) or "main",
        "work_item": _safe_string(_first_present(payload, ("work_item", "work_item_id"))),
        "reasoning_effort": _safe_string(_first_present(payload, ("reasoning_effort", "reasoningEffort", "effort"))),
    }
    return context


def _extract_model(payload: dict[str, Any]) -> str | None:
    for item in _iter_dicts(payload):
        model = _safe_string(_first_present(item, ("model", "model_name")))
        if model:
            return model
    return None


def _transcript_path(payload: dict[str, Any]) -> Path | None:
    value = _safe_string(_first_present(payload, ("transcript_path", "transcriptPath")))
    if not value:
        return None
    path = Path(value)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path if path.exists() and path.is_file() else None


def _read_last_usage_from_transcript(path: Path) -> dict[str, Any] | None:
    last: dict[str, Any] | None = None
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if _usage_dicts(payload):
                last = payload
    return last


def normalize_event(hook_payload: dict[str, Any], *, source: str = "hook") -> dict[str, Any]:
    transcript_payload = None
    path = _transcript_path(hook_payload)
    if path:
        transcript_payload = _read_last_usage_from_transcript(path)

    usage_source = transcript_payload or hook_payload
    context = _extract_context(hook_payload)
    if transcript_payload:
        context = {key: context.get(key) or _extract_context(transcript_payload).get(key) for key in CONTEXT_KEYS}

    event = {
        "schema": "claude_usage.v1",
        "recorded_at": _now_iso(),
        "event_name": _safe_string(_first_present(hook_payload, ("hook_event_name", "event", "event_name"))) or source,
        "source": source,
        **context,
        "model": _extract_model(usage_source) or "unknown",
        **_extract_tokens(usage_source),
        "cost_usd": _extract_cost(usage_source),
    }
    return event


def append_event(event: dict[str, Any], store: Path = DEFAULT_STORE) -> None:
    store.parent.mkdir(parents=True, exist_ok=True)
    # Claude Code may emit a SubagentStop whose transcript usage is the same
    # parent Stop turn. Avoid counting that exact adjacent mirror twice.
    if event.get("event_name") == "SubagentStop" and store.exists():
        try:
            previous = json.loads(store.read_text(encoding="utf-8").splitlines()[-1])
        except (OSError, IndexError, json.JSONDecodeError):
            previous = None
        if isinstance(previous, dict) and previous.get("event_name") == "Stop":
            fields = ("session", "model", *TOKEN_KEYS)
            if all(previous.get(field) == event.get(field) for field in fields):
                return
    with store.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")


def record_from_stdin(store: Path = DEFAULT_STORE) -> dict[str, Any] | None:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    event = normalize_event(payload)
    append_event(event, store)
    return event


def record_event_from_stdin(store: Path = DEFAULT_STORE, *, source: str = "explicit") -> dict[str, Any] | None:
    """Append an explicit compact provider-neutral usage event from stdin.

    The normalizer only emits its fixed allowlist, so prompt/response bodies,
    HTML/JS/Burp material, headers, Cookie, and Authorization fields are never
    copied into metrics/costs.jsonl even if callers accidentally include them.
    """
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    event = normalize_event(payload, source=source)
    append_event(event, store)
    return event


def _load_events(store: Path) -> list[dict[str, Any]]:
    if not store.exists():
        return []
    events = []
    with store.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict) and payload.get("schema") == "claude_usage.v1":
                events.append(payload)
    return events


def _event_date(event: dict[str, Any]) -> str:
    value = str(event.get("recorded_at") or "")
    return value[:10] if len(value) >= 10 else "unknown"


def summarize(events: list[dict[str, Any]], *, date: str | None = None, target: str | None = None) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str, str, str, str], dict[str, Any]] = {}
    for event in events:
        event_date = _event_date(event)
        if date and event_date != date:
            continue
        if target and event.get("target") != target:
            continue
        key = (
            event_date,
            str(event.get("target") or "unknown"),
            str(event.get("lane") or "unknown"),
            str(event.get("agent") or "unknown"),
            str(event.get("model") or "unknown"),
            str(event.get("reasoning_effort") or "unknown"),
        )
        row = groups.setdefault(
            key,
            {
                "date": key[0],
                "target": key[1],
                "lane": key[2],
                "agent": key[3],
                "model": key[4],
                "reasoning_effort": key[5],
                "events": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": 0,
                "total_tokens": 0,
                "cost_usd": 0.0,
                "_unknown_cost": False,
            },
        )
        row["events"] += 1
        for field in TOKEN_KEYS:
            row[field] += event.get(field) or 0
        if event.get("cost_usd") is None:
            row["_unknown_cost"] = True
        else:
            row["cost_usd"] += event["cost_usd"]

    output = []
    for row in groups.values():
        row = dict(row)
        if row.pop("_unknown_cost"):
            row["cost_usd"] = None
        output.append(row)
    return sorted(output, key=lambda item: (item["date"], item["target"], item["lane"], item["agent"], item["model"]))


def _print_table(rows: list[dict[str, Any]]) -> None:
    if not rows:
        print("No Claude usage records found.")
        return
    fields = ["date", "target", "lane", "agent", "model", "reasoning_effort", "events", *TOKEN_KEYS, "cost_usd"]
    widths = {
        field: max(
            len(field),
            *(len(str(row.get(field) if row.get(field) is not None else "unknown")) for row in rows),
        )
        for field in fields
    }
    print("  ".join(field.ljust(widths[field]) for field in fields))
    print("  ".join("-" * widths[field] for field in fields))
    for row in rows:
        print("  ".join(str(row.get(field) if row.get(field) is not None else "unknown").ljust(widths[field]) for field in fields))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Record and query Claude Code usage metadata without storing prompts/responses.")
    sub = parser.add_subparsers(dest="command", required=True)
    record = sub.add_parser(
        "record-hook",
        help="Read Claude Code hook JSON from stdin and append a sanitized usage record.",
    )
    record.add_argument("--store", type=Path, default=DEFAULT_STORE)
    record_event = sub.add_parser(
        "record-event",
        help="Read compact provider-neutral usage JSON from stdin and append a sanitized record.",
    )
    record_event.add_argument("--store", type=Path, default=DEFAULT_STORE)
    record_codex = sub.add_parser(
        "record-codex",
        help="Alias for record-event with source=codex_explicit.",
    )
    record_codex.add_argument("--store", type=Path, default=DEFAULT_STORE)
    query = sub.add_parser("summary", help="Summarize usage by date/target/lane/agent/model.")
    query.add_argument("--store", type=Path, default=DEFAULT_STORE)
    query.add_argument("--date")
    query.add_argument("--target")
    query.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.command == "record-hook":
        record_from_stdin(args.store)
        return 0
    if args.command == "record-event":
        record_event_from_stdin(args.store, source="explicit")
        return 0
    if args.command == "record-codex":
        record_event_from_stdin(args.store, source="codex_explicit")
        return 0
    rows = summarize(_load_events(args.store), date=args.date, target=args.target)
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
    else:
        _print_table(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
