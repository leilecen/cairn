"""Rule-based offline/passive experiment candidate ranking."""

from __future__ import annotations

import sqlite3
from typing import Any

from db.experiments import list_experiments
from db.work_queue import create_work_item


def score_candidate(candidate: dict[str, Any], *, prior_keys: set[str] | None = None) -> dict[str, Any]:
    prior_keys = prior_keys or set()
    parts = {
        "information_gain": int(candidate.get("information_gain", 0)),
        "evidence_relevance": int(candidate.get("evidence_relevance", 0)),
        "focus_alignment": int(candidate.get("focus_alignment", 0)),
        "execution_cost": int(candidate.get("execution_cost", 0)),
        "risk_cost": int(candidate.get("risk_cost", 0)),
        "repetition_penalty": 3 if candidate.get("experiment_key") in prior_keys else int(candidate.get("repetition_penalty", 0)),
    }
    reasons = {
        k: str(candidate.get(f"{k}_reason") or ("repeat" if k == "repetition_penalty" and parts[k] else "rule default"))[:160]
        for k in parts
    }
    return {
        **candidate,
        "score": parts["information_gain"]
        + parts["evidence_relevance"]
        + parts["focus_alignment"]
        - parts["execution_cost"]
        - parts["risk_cost"]
        - parts["repetition_penalty"],
        "score_parts": parts,
        "score_reasons": reasons,
    }


def plan_experiments(conn, *, hunt_session_id: int, candidates: list[dict[str, Any]], limit: int = 2) -> list[dict[str, Any]]:
    prior = {str(x.get("experiment_key")) for x in list_experiments(conn, hunt_session_id=hunt_session_id)}
    allowed = [x for x in candidates if x.get("method_class", "offline") in {"offline", "passive"} and not x.get("operator_gate")]
    return sorted((score_candidate(x, prior_keys=prior) for x in allowed), key=lambda x: x["score"], reverse=True)[:limit]


def materialize_approved_experiments(conn, *, target_name: str, hunt_session_id: int, limit: int = 2) -> list[int]:
    """Turn explicit main-session approvals into bounded dispatcher work items."""
    columns = {row[1] for row in conn.execute("PRAGMA table_info(experiments)").fetchall()}
    order = "COALESCE(surprise_score,0) DESC," if "surprise_score" in columns else ""
    rows = conn.execute(
        f"SELECT * FROM experiments WHERE hunt_session_id=? AND status='approved' AND method_class IN ('offline','passive') AND work_item_id IS NULL ORDER BY {order} id ASC LIMIT ?",  # noqa: S608 -- ORDER BY 取自 schema 列存在性判断，值走参数绑定
        (hunt_session_id, limit),
    ).fetchall()
    created = []
    for row in rows:
        experiment_id = int(row["id"] if isinstance(row, sqlite3.Row) else row[0])
        values = (
            dict(row)
            if isinstance(row, sqlite3.Row)
            else {
                desc[0]: value
                for desc, value in zip(
                    conn.execute("SELECT * FROM experiments WHERE id=?", (experiment_id,)).description,
                    row,
                    strict=True,
                )
            }
        )
        work_id = create_work_item(
            conn,
            target_name=target_name,
            lane="cognitive_experiment",
            subtype=f"experiment:{experiment_id}",
            subject_table="experiments",
            subject_id=str(experiment_id),
            attack_thread_id=values.get("attack_thread_id"),
            title=f"Experiment {values.get('experiment_key', '')}",
            objective=values.get("question", "")[:800],
            priority=int(values.get("priority") or 80),
            model_tier="haiku",
            reasoning_tier="low",
            risk_class=values.get("risk_class") or "safe_passive",
        )
        update = "work_item_id=?,status='queued'"
        if "updated_at" in columns:
            update += ",updated_at=datetime('now','localtime')"
        conn.execute(f"UPDATE experiments SET {update} WHERE id=?", (work_id, experiment_id))  # noqa: S608 -- SET 子句按 schema 列存在性拼接，值走参数绑定
        created.append(experiment_id)
    conn.commit()
    return created
