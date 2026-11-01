"""Cost audit: aggregate token usage from metrics/costs.jsonl and claude-sessions.jsonl.

Usage:
    uv run python TOOLS/db/cost_audit.py

Reads only metrics/ JSONL; never writes. Compact output only.
"""

import json
import os
from collections import defaultdict
from datetime import datetime

BASE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "metrics")


def load_jsonl(path):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return rows


def agg(rows, keyfn):
    out = defaultdict(
        lambda: {
            "events": 0,
            "total_tokens": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_read": 0,
            "cache_creation": 0,
        }
    )
    for r in rows:
        k = keyfn(r)
        if k is None:
            continue
        o = out[k]
        o["events"] += 1
        o["total_tokens"] += r.get("total_tokens") or 0
        o["input_tokens"] += r.get("input_tokens") or 0
        o["output_tokens"] += r.get("output_tokens") or 0
        o["cache_read"] += r.get("cache_read_input_tokens") or 0
        o["cache_creation"] += r.get("cache_creation_input_tokens") or 0
    return out


def show(title, d, top=10):
    print(f"\n===== {title} =====")
    for k, v in sorted(d.items(), key=lambda kv: -kv[1]["total_tokens"])[:top]:
        print(
            f"{str(k):<40} total={v['total_tokens']:>12,}  in={v['input_tokens']:>10,}  "
            f"out={v['output_tokens']:>8,}  cache_read={v['cache_read']:>12,}  "
            f"cache_new={v['cache_creation']:>10,}  ev={v['events']}"
        )


def main():
    costs = load_jsonl(os.path.join(BASE, "costs.jsonl"))
    sessions = load_jsonl(os.path.join(BASE, "claude-sessions.jsonl"))
    print(f"costs.jsonl records: {len(costs)}")
    print(f"claude-sessions.jsonl records: {len(sessions)}")

    show("by lane", agg(costs, lambda r: r.get("lane") or "unknown"))
    show("by model", agg(costs, lambda r: r.get("model") or "unknown"))
    show("by agent", agg(costs, lambda r: r.get("agent") or "unknown"))
    show("by date", agg(costs, lambda r: r.get("recorded_at", "")[:10] or "unknown"))
    show("by event_name", agg(costs, lambda r: r.get("event_name") or "unknown"))
    show("by target", agg(costs, lambda r: r.get("target") or "unknown"))

    total = sum((r.get("total_tokens") or 0) for r in costs)
    cache_read_total = sum((r.get("cache_read_input_tokens") or 0) for r in costs)
    print(f"\nGRAND TOTAL tokens: {total:,} | cache_read: {cache_read_total:,} ({100 * cache_read_total / max(total, 1):.0f}%)")

    ev = defaultdict(int)
    for r in sessions:
        ev[r.get("event_name", "?")] += 1
    print("\n===== session event_name counts =====")
    for k, v in sorted(ev.items(), key=lambda kv: -kv[1]):
        print(f"{k:<24} {v:,}")

    by_sess = defaultdict(lambda: {"events": 0, "first": None, "last": None})
    for r in sessions:
        sid = r.get("session_id") or "?"
        s = by_sess[sid]
        s["events"] += 1
        ts = r.get("recorded_at", "")
        if ts:
            if s["first"] is None or ts < s["first"]:
                s["first"] = ts
            if s["last"] is None or ts > s["last"]:
                s["last"] = ts

    print("\n===== top sessions by event count (long-lived = cost bombs) =====")
    for sid, s in sorted(by_sess.items(), key=lambda kv: -kv[1]["events"])[:10]:
        span = ""
        if s["first"] and s["last"]:
            try:
                first = datetime.fromisoformat(s["first"])
                last = datetime.fromisoformat(s["last"])
                span = f"{(last - first).total_seconds() / 86400:.1f}d"
            except ValueError:  # 时间戳格式异常时保留空 span，不中断整份报表
                pass
        print(f"{sid:<40} ev={s['events']:>5}  span={span:>8}")

    print(f"\ntotal sessions: {len(by_sess)} | total events: {sum(s['events'] for s in by_sess.values())}")


if __name__ == "__main__":
    main()
