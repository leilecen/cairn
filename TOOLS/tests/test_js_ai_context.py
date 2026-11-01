import sqlite3
import sys
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from utils.js_ai_context import build_cluster_cache_key, build_js_cluster_context


def test_build_js_cluster_context_is_bounded(tmp_path):
    js_path = tmp_path / "sample.js"
    js_path.write_text("\n".join(f"line {i}" for i in range(1, 50)), encoding="utf-8")

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE js_files (id INTEGER PRIMARY KEY, local_path TEXT);
        CREATE TABLE js_signals (
            id TEXT PRIMARY KEY,
            js_file_id INTEGER,
            params_json TEXT,
            evidence_location TEXT,
            caller_hint TEXT,
            auth_hint TEXT,
            signature_hint TEXT
        );
        CREATE TABLE js_signal_clusters (
            id TEXT PRIMARY KEY,
            canonical_method TEXT,
            canonical_url TEXT,
            best_risk_score INTEGER,
            representative_signal_id TEXT
        );
        """
    )
    conn.execute("INSERT INTO js_files (id, local_path) VALUES (1, ?)", (str(js_path),))
    conn.execute(
        """
        INSERT INTO js_signals (id, js_file_id, params_json, evidence_location, caller_hint, auth_hint, signature_hint)
        VALUES ('sig-1', 1, '["orderId","sign"]', 'line:20', 'request.post', 'Bearer', 'timestamp')
        """
    )
    conn.execute(
        """
        INSERT INTO js_signal_clusters (id, canonical_method, canonical_url, best_risk_score, representative_signal_id)
        VALUES ('cluster-1', 'POST', '/api/order/detail', 85, 'sig-1')
        """
    )
    conn.commit()

    context = build_js_cluster_context(conn, "cluster-1", max_total_chars=200)
    cache_key = build_cluster_cache_key(context)

    assert context["cluster"]["risk_score"] == 85
    assert context["params"] == ["orderId", "sign"]
    assert len(context["snippets"][0]["code"]) <= 200
    assert cache_key
