"""Build bounded AI context for JS clusters."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path


def extract_bounded_snippet(file_path: str | None, evidence_location: str, *, radius: int = 6, max_chars: int = 600) -> dict:
    if not file_path or not Path(file_path).exists():
        return {"file": file_path or "", "line": 1, "code": ""}
    try:
        line_no = int((evidence_location or "line:1").split(":")[-1])
    except ValueError:
        line_no = 1
    lines = Path(file_path).read_text(encoding="utf-8", errors="ignore").splitlines()
    start = max(line_no - radius - 1, 0)
    end = min(line_no + radius, len(lines))
    snippet = "\n".join(lines[start:end])[:max_chars]
    return {"file": file_path, "line": line_no, "code": snippet}


def build_js_cluster_context(conn: sqlite3.Connection, cluster_id: str, *, max_total_chars: int = 1600) -> dict | None:
    cluster = conn.execute("SELECT * FROM js_signal_clusters WHERE id=?", (cluster_id,)).fetchone()
    if cluster is None:
        return None
    signal = conn.execute(
        """
        SELECT s.*, j.local_path
        FROM js_signals s
        LEFT JOIN js_files j ON j.id = s.js_file_id
        WHERE s.id = ?
        """,
        (cluster["representative_signal_id"],),
    ).fetchone()
    if signal is None:
        return None
    params = json.loads(signal["params_json"] or "[]")
    snippet = extract_bounded_snippet(signal["local_path"], signal["evidence_location"] or "line:1")
    snippet["code"] = snippet["code"][:max_total_chars]
    context = {
        "cluster": {
            "id": cluster["id"],
            "method": cluster["canonical_method"] or "GET",
            "path": cluster["canonical_url"] or "",
            "risk_score": cluster["best_risk_score"] or 0,
        },
        "call_chain_summary": [item for item in [signal["caller_hint"], signal["auth_hint"], signal["signature_hint"]] if item],
        "params": params,
        "snippets": [snippet],
    }
    return context


def build_cluster_cache_key(context: dict, *, extractor_version: str = "v1", prompt_version: str = "v1") -> str:
    serialized = json.dumps(
        {"context": context, "extractor_version": extractor_version, "prompt_version": prompt_version},
        ensure_ascii=False,
        sort_keys=True,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
