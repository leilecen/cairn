import json
import sqlite3
import sys
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from js_attack_surface import attack_surface_markdown, build_attack_surface


def _conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE js_signal_clusters (
            id TEXT PRIMARY KEY,
            target_id INTEGER,
            canonical_method TEXT,
            canonical_url TEXT,
            best_risk_score INTEGER,
            representative_signal_id TEXT,
            runtime_seen INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE js_signals (
            id TEXT PRIMARY KEY,
            params_json TEXT,
            auth_hint TEXT,
            signature_hint TEXT,
            evidence_location TEXT,
            evidence_snippet TEXT,
            value_flow_json TEXT,
            caller_chain_json TEXT,
            business_hint TEXT
        );
        """
    )
    conn.execute(
        """
        INSERT INTO js_signals (
            id, params_json, auth_hint, signature_hint, evidence_location, evidence_snippet,
            value_flow_json, caller_chain_json, business_hint
        ) VALUES (
            'sig-1', '["orderId","userId"]', 'Authorization,BizToken', 'sign', 'app.js:line:12',
            'PostCF({ orderId, userId, sign })',
            ?, '["onLoad","getOrderDetail","PostCF"]', 'pages/order/detail'
        )
        """,
        (
            json.dumps(
                {
                    "params": [
                        {"name": "orderId", "source": "route_param"},
                        {"name": "userId", "source": "storage"},
                    ]
                }
            ),
        ),
    )
    conn.execute(
        """
        INSERT INTO js_signal_clusters (
            id, target_id, canonical_method, canonical_url, best_risk_score, representative_signal_id, runtime_seen
        ) VALUES ('clu-1', 1, 'POST', 'https://api.example.com/api/order/detail', 88, 'sig-1', 1)
        """
    )
    conn.commit()
    return conn


def test_build_attack_surface_produces_hypotheses_and_next_step():
    conn = _conn()
    items = build_attack_surface(conn, 1, 10)
    assert items[0]["endpoint"] == "POST /api/order/detail"
    assert items[0]["next_step"] in {"logic_probe", "vuln_review"}
    assert any(param["source"] == "route_param" for param in items[0]["params"])
    assert "runtime_seen" in items[0]["preconditions"]


def test_attack_surface_markdown_is_concise():
    conn = _conn()
    markdown = attack_surface_markdown(build_attack_surface(conn, 1, 10))
    assert "ASM-001" in markdown
    assert "caller_chain" in markdown
