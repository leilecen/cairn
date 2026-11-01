"""Build verification hypotheses from JS clusters."""

from __future__ import annotations

import json
import sqlite3
from urllib.parse import urlparse

RISKY_PARAMS = {
    "id": "IDOR",
    "userid": "horizontal_privilege",
    "orderid": "IDOR",
    "studentid": "IDOR",
    "orgid": "horizontal_privilege",
    "tenantid": "horizontal_privilege",
    "openid": "identity_swap",
    "unionid": "identity_swap",
}
AUTH_TOKENS = {"authorization", "biztoken", "token", "openid", "unionid"}


def _json_loads(value: str | None, fallback):
    try:
        return json.loads(value or "")
    except Exception:
        return fallback


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _next_step(item: dict) -> str:
    if any("sign" in hypothesis.lower() or "token" in hypothesis.lower() for hypothesis in item["hypotheses"]):
        return "vuln_review"
    if any("remove" in hypothesis.lower() for hypothesis in item["hypotheses"]):
        return "logic_probe"
    return "replay"


def build_attack_surface(conn: sqlite3.Connection, target_id: int | None = None, limit: int = 20) -> list[dict]:
    signal_columns = _table_columns(conn, "js_signals")
    cluster_columns = _table_columns(conn, "js_signal_clusters")
    select_parts = [
        "c.*",
        "s.params_json" if "params_json" in signal_columns else "'[]' AS params_json",
        "s.auth_hint" if "auth_hint" in signal_columns else "'' AS auth_hint",
        "s.signature_hint" if "signature_hint" in signal_columns else "'' AS signature_hint",
        "s.evidence_location" if "evidence_location" in signal_columns else "'' AS evidence_location",
        "s.evidence_snippet" if "evidence_snippet" in signal_columns else "'' AS evidence_snippet",
        "s.value_flow_json" if "value_flow_json" in signal_columns else "'{}' AS value_flow_json",
        "s.caller_chain_json" if "caller_chain_json" in signal_columns else "'[]' AS caller_chain_json",
        "s.business_hint" if "business_hint" in signal_columns else "'' AS business_hint",
    ]
    where_clause = "1=1" if "target_id" not in cluster_columns else "(? IS NULL OR c.target_id = ?)"
    params = (limit,) if "target_id" not in cluster_columns else (target_id, target_id, limit)
    query = f"""
        SELECT {", ".join(select_parts)}
        FROM js_signal_clusters c
        JOIN js_signals s ON s.id = c.representative_signal_id
        WHERE {where_clause}
        ORDER BY c.best_risk_score DESC, c.created_at ASC
        LIMIT ?
    """  # noqa: S608 - select parts/where clause are built from local schema checks.
    rows = conn.execute(query, params).fetchall()
    results = []
    for index, row in enumerate(rows, start=1):
        params = _json_loads(row["params_json"], [])
        value_flow = _json_loads(row["value_flow_json"], {})
        caller_chain = _json_loads(row["caller_chain_json"], [])
        auth_material: list[str] = []
        if row["auth_hint"]:
            auth_material.extend(token for token in AUTH_TOKENS if token in row["auth_hint"].lower())
        if row["signature_hint"]:
            auth_material.append(row["signature_hint"])
        method = (row["canonical_method"] or "GET").upper()
        parsed_path = urlparse(row["canonical_url"] or "").path
        endpoint = f"{method} {parsed_path or row['canonical_url']}"
        item_params = []
        hypotheses = []
        score = int(row["best_risk_score"] or 0)
        for param in params:
            key = str(param)
            test = RISKY_PARAMS.get(key.lower())
            source = "unknown"
            for flow_param in value_flow.get("params", []):
                if flow_param.get("name") == key:
                    source = flow_param.get("source", source)
            item_params.append({"name": key, "source": source, "test": test or "mutation"})
            if test:
                hypotheses.append(f"replace {key} with B account value")
                score += 6
        if row["auth_hint"]:
            hypotheses.append("remove Authorization or BizToken")
        if row["signature_hint"]:
            hypotheses.append(f"tamper {row['signature_hint']} and replay")
            score += 5
        preconditions = []
        if auth_material:
            preconditions.append("login_required")
            if "runtime_seen" in row.keys() and row["runtime_seen"]:
                preconditions.append("runtime_seen")
        results.append(
            {
                "id": f"ASM-{index:03d}",
                "endpoint": endpoint,
                "page_route": row["business_hint"] or "",
                "caller_chain": caller_chain,
                "auth_material": sorted(set(auth_material)),
                "params": item_params,
                "preconditions": preconditions,
                "hypotheses": hypotheses or ["review caller chain for auth bypass"],
                "risk_score": min(score, 99),
                "next_step": "",  # assigned below
                "evidence": {
                    "cluster_id": row["id"],
                    "location": row["evidence_location"],
                    "snippet": row["evidence_snippet"],
                },
            }
        )
        results[-1]["next_step"] = _next_step(results[-1])
    return results


def attack_surface_markdown(items: list[dict]) -> str:
    lines = []
    for item in items:
        lines.append(f"## {item['id']} {item['endpoint']}")
        lines.append(f"- risk_score: {item['risk_score']}")
        lines.append(f"- next_step: {item['next_step']}")
        lines.append(f"- caller_chain: {' -> '.join(item['caller_chain']) if item['caller_chain'] else 'n/a'}")
        lines.append(f"- auth_material: {', '.join(item['auth_material']) if item['auth_material'] else 'none'}")
        lines.append(f"- hypotheses: {', '.join(item['hypotheses'])}")
    return "\n".join(lines)
