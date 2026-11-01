import json
import sqlite3
import subprocess
import sys
from pathlib import Path

from db.blackboard_view import build_blackboard_view, format_blackboard_text

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = PROJECT_ROOT / "TOOLS" / "db" / "schema.sql"
VIEW_SCRIPT = PROJECT_ROOT / "TOOLS" / "db" / "blackboard_view.py"


def _conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    return conn


def _build_fixture(conn: sqlite3.Connection, target_name: str = "demo") -> None:
    conn.execute("INSERT INTO targets (id, target_name, domain) VALUES (1, ?, 'example.com')", (target_name,))
    conn.execute(
        """
        INSERT INTO work_items (
            id, target_name, lane, subtype, subject_table, subject_id, title, priority, status,
            claimed_by, claimed_at, lease_until, heartbeat_at, summary, created_at, updated_at
        ) VALUES
          (
            1, ?, 'logic_probe', NULL, 'hunt_queue', '1', 'Queued logic probe', 80, 'queued',
            NULL, NULL, NULL, NULL, NULL, '2026-07-14 09:00:00', '2026-07-14 09:00:00'
          ),
          (
            2, ?, 'js_reverse', 'signature_chain', 'js_signal_clusters', 'clu-1', 'Claimed js task', 90, 'claimed',
            'js-agent-1', '2026-07-14 09:01:00', '2026-07-14 09:11:00', '2026-07-14 09:03:00', NULL,
            '2026-07-14 09:01:00', '2026-07-14 09:03:00'
          ),
          (
            3, ?, 'quick_scout', NULL, 'pages', '3', 'Partial scout', 60, 'partial',
            NULL, NULL, NULL, NULL, 'found login form',
            '2026-07-14 09:02:00', '2026-07-14 09:04:00'
          ),
          (
            4, ?, 'replay', NULL, 'hunt_queue', '4', 'Blocked replay', 55, 'blocked',
            NULL, NULL, NULL, NULL, NULL,
            '2026-07-14 09:02:00', '2026-07-14 09:05:00'
          ),
          (
            5, ?, 'evidence_pack', NULL, 'findings', 'F-1', 'Done evidence', 50, 'done',
            NULL, NULL, NULL, NULL, NULL,
            '2026-07-14 09:02:00', '2026-07-14 09:06:00'
          ),
          (
            6, ?, 'entry_explore', NULL, 'pages', '6', 'Failed explore', 40, 'failed',
            NULL, NULL, NULL, NULL, NULL,
            '2026-07-14 09:02:00', '2026-07-14 09:07:00'
          ),
          (
            7, ?, 'asset_triage', NULL, 'target_assets', '7', 'Cancelled triage', 30, 'cancelled',
            NULL, NULL, NULL, NULL, NULL,
            '2026-07-14 09:02:00', '2026-07-14 09:08:00'
          )
        """,
        (target_name, target_name, target_name, target_name, target_name, target_name, target_name),
    )
    conn.execute(
        """
        INSERT INTO agent_events (
            work_item_id, agent_id, event_type, severity, payload_json, created_at
        ) VALUES
          (2, 'js-agent-1', 'heartbeat', 'info', '{"step":"scan"}', '2026-07-14 09:03:00'),
          (3, 'scout-agent-1', 'partial_result', 'info', '{"summary":"found login form"}', '2026-07-14 09:04:00'),
          (4, 'replay-agent-1', 'blocker', 'warning', '{"reason":"need auth"}', '2026-07-14 09:05:00')
        """
    )
    conn.execute(
        """
        INSERT INTO operator_inbox (
            id, target_name, related_work_item_id, kind, title, detail, status, created_at
        ) VALUES
          (1, ?, 4, 'login_required', 'Login needed', 'need auth session', 'open', '2026-07-14 09:06:00'),
          (2, ?, 5, 'screenshot_needed', 'Old item', 'already done', 'done', '2026-07-14 09:07:00')
        """,
        (target_name, target_name),
    )
    conn.execute(
        """
        INSERT INTO burp_actions (
            id, target_name, work_item_id, action_type, method, url, status, created_at
        ) VALUES
          (1, ?, 4, 'send_to_repeater', 'GET', 'https://example.com/api/user', 'queued', '2026-07-14 09:08:00'),
          (2, ?, 5, 'replay_compare', 'POST', 'https://example.com/api/order', 'sent', '2026-07-14 09:09:00')
        """,
        (target_name, target_name),
    )
    conn.commit()


def test_build_blackboard_view_returns_expected_json_shape_and_counts():
    conn = _conn()
    _build_fixture(conn)

    payload = build_blackboard_view(conn, target_name="demo")

    assert payload["target"] == "demo"
    assert payload["work_summary"]["queued"] == 1
    assert payload["work_summary"]["claimed"] == 1
    assert payload["work_summary"]["partial"] == 1
    assert payload["work_summary"]["blocked"] == 1
    assert payload["work_summary"]["done"] == 1
    assert payload["work_summary"]["failed"] == 1
    assert payload["work_summary"]["cancelled"] == 1


def test_build_blackboard_view_lists_active_agents_open_inbox_and_recent_events():
    conn = _conn()
    _build_fixture(conn)

    payload = build_blackboard_view(conn, target_name="demo")

    assert len(payload["active_agents"]) == 1
    assert payload["active_agents"][0]["agent_id"] == "js-agent-1"
    assert payload["active_agents"][0]["work_item_id"] == 2
    assert payload["active_agents"][0]["lane"] == "js_reverse"
    assert payload["operator_inbox"] == [
        {
            "id": 1,
            "kind": "login_required",
            "title": "Login needed",
            "detail": "need auth session",
            "related_work_item_id": 4,
            "created_at": "2026-07-14 09:06:00",
        }
    ]
    assert [event["event_type"] for event in payload["recent_events"]] == ["blocker", "partial_result", "heartbeat"]


def test_build_blackboard_view_recommends_operator_and_next_work():
    conn = _conn()
    _build_fixture(conn)

    payload = build_blackboard_view(conn, target_name="demo")
    actions = payload["next_recommended_actions"]

    assert any("operator_inbox #1" in action for action in actions)
    assert any("#1 logic_probe" in action for action in actions)
    assert any("burp_actions 1 queued" in action for action in actions)


def test_blackboard_view_includes_attack_threads():
    conn = _conn()
    _build_fixture(conn)
    conn.execute(
        """
        INSERT INTO attack_threads (
            target_name, asset_url, hypothesis, why_promising, priority, status
        ) VALUES
          ('demo', 'https://example.com/app', 'export IDOR', 'export endpoint has id', 90, 'candidate'),
          ('demo', 'https://example.com/admin', 'admin route leak', 'hidden JS route', 60, 'active')
        """
    )
    conn.commit()

    payload = build_blackboard_view(conn, target_name="demo")
    text = format_blackboard_text(payload)

    assert [item["hypothesis"] for item in payload["attack_threads"]] == [
        "export IDOR",
        "admin route leak",
    ]
    assert "[THREADS]" in text
    assert "#1 candidate priority=90 export IDOR" in text


def test_format_blackboard_text_contains_expected_sections_and_ids():
    conn = _conn()
    _build_fixture(conn)

    payload = build_blackboard_view(conn, target_name="demo")
    text = format_blackboard_text(payload)

    assert "[BLACKBOARD]" in text
    assert "queued=1 claimed=1 partial=1 blocked=1 done=1 failed=1 cancelled=1" in text
    assert "[ACTIVE]" in text
    assert "#2 js_reverse signature_chain claimed_by=js-agent-1" in text
    assert "[OPERATOR_INBOX]" in text
    assert "#1 login_required Login needed" in text
    assert "[NEXT]" in text


def test_blackboard_view_includes_compact_soft_target_ranking():
    conn = _conn()
    _build_fixture(conn)
    conn.execute(
        """
        INSERT INTO soft_targets (
            target_name, asset_id, asset_value, total_score, tier, rank,
            dimension_scores_json, evidence_json
        ) VALUES (
            'demo', 1, 'test-admin.example.com', 72, 'tier2_高优先级', 1,
            '{"attack_surface":{"score":8,"clues":["有登录功能"]}}',
            '[{"dimension":"attack_surface","reason":"有登录功能"}]'
        )
        """
    )
    conn.commit()

    payload = build_blackboard_view(conn, target_name="demo")
    text = format_blackboard_text(payload)

    assert payload["soft_targets"]["selection_required"] is True
    assert payload["soft_targets"]["results"][0]["reason_summary"] == ["有登录功能"]
    assert "dimension_scores_json" not in payload["soft_targets"]["results"][0]
    assert "[SOFT_TARGETS]" in text
    assert "test-admin.example.com" in text


def test_blackboard_view_includes_compact_semantic_profile_and_coverage_ledger():
    conn = _conn()
    _build_fixture(conn)
    conn.execute(
        """
        INSERT INTO attack_surface_profiles (
            id, target_name, soft_target_id, subject_table, subject_id,
            system_tags_json, business_tags_json, roles_json, flows_json,
            trust_boundaries_json, tech_stack_json, confidence, evidence_refs_json,
            summary, status, updated_at
        ) VALUES (
            1, 'demo', 9, 'soft_targets', '9',
            '["account-system","payment"]',
            '["order-refund"]',
            '["guest","user","admin"]',
            '["login","refund-review"]',
            '["browser-to-api","user-to-admin"]',
            '["nginx/1.24 evidence_refs:2"]',
            'medium',
            '["evidence_refs:1","evidence_refs:2"]',
            ?,
            'active',
            '2026-07-14 09:20:00'
        )
        """,
        ("focused target profile " + ("A" * 1000),),
    )
    conn.executemany(
        """
        INSERT INTO coverage_ledger (
            target_name, profile_id, item_key, category, status, confidence,
            evidence_refs_json, summary, blocker_reason, next_action, updated_at
        ) VALUES ('demo', 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                "refund-role-boundary",
                "trust_boundary",
                "covered",
                "medium",
                '["evidence_refs:3"]',
                "role boundary observed",
                None,
                "probe low-risk role replay",
                "2026-07-14 09:21:00",
            ),
            (
                "admin-workflow",
                "role_flow",
                "unknown",
                "unknown",
                "[]",
                "admin role exists but path not observed",
                None,
                "ask operator for role account",
                "2026-07-14 09:22:00",
            ),
            (
                "export-endpoint",
                "business_flow",
                "uncovered",
                "low",
                "[]",
                "export flow has not been tested",
                None,
                "queue safe replay after auth",
                "2026-07-14 09:23:00",
            ),
            (
                "payment-state-change",
                "business_flow",
                "blocked",
                "medium",
                '["evidence_refs:4"]',
                "state change requires human gate",
                "confirm_high_risk required",
                "wait for operator",
                "2026-07-14 09:24:00",
            ),
        ],
    )
    conn.commit()

    payload = build_blackboard_view(conn, target_name="demo")
    text = format_blackboard_text(payload)
    encoded = json.dumps(payload, ensure_ascii=False)
    profile = payload["attack_surface"]["profiles"][0]
    ledger_statuses = [item["status"] for item in payload["attack_surface"]["coverage_items"][:3]]

    assert profile["system_tags"] == ["account-system", "payment"]
    assert profile["coverage_counts"] == {"covered": 1, "unknown": 1, "uncovered": 1, "blocked": 1}
    assert ledger_statuses == ["blocked", "unknown", "uncovered"]
    assert "admin role exists but path not observed" in encoded
    assert "confirm_high_risk required" in encoded
    assert "A" * 500 not in encoded
    assert "[ATTACK_SURFACE]" in text
    assert "unknown=1 uncovered=1 blocked=1" in text


def test_blackboard_view_cli_supports_db_and_json(tmp_path):
    db_path = tmp_path / "view_demo.db"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    _build_fixture(conn)
    conn.close()

    cmd = [
        sys.executable,
        str(VIEW_SCRIPT),
        "--db",
        str(db_path),
        "--target",
        "demo",
        "--json",
    ]
    completed = subprocess.run(cmd, capture_output=True, text=True, check=True, cwd=PROJECT_ROOT)  # noqa: S603
    payload = json.loads(completed.stdout)

    assert payload["target"] == "demo"
    assert payload["work_summary"]["claimed"] == 1
    assert payload["active_agents"][0]["work_item_id"] == 2


def test_blackboard_view_compacts_main_model_payload_boundaries():
    conn = _conn()
    _build_fixture(conn)
    conn.execute(
        """
        INSERT INTO agent_events (
            work_item_id, agent_id, event_type, severity, payload_json, created_at
        ) VALUES (
            3, 'scout-agent-1', 'partial_result', 'info', ?, '2026-07-14 09:10:00'
        )
        """,
        (
            json.dumps(
                {
                    "worker_result": {
                        "status": "partial",
                        "summary": "HTTP/1.1 200 OK\r\nSet-Cookie: sid=secret\r\n\r\n<html>raw</html>",
                        "evidence_refs": ["evidence_refs:42"],
                    },
                    "raw_response": "<html>" + ("A" * 5000),
                }
            ),
        ),
    )
    conn.execute(
        "UPDATE operator_inbox SET detail=? WHERE id=1",
        ("Authorization: Bearer secretsecretsecretsecretsecret",),
    )
    conn.commit()

    payload = build_blackboard_view(conn, target_name="demo")
    encoded = json.dumps(payload, ensure_ascii=False)

    assert "payload" not in payload["recent_events"][0]
    assert payload["recent_event_summary"]["count"] == 3
    assert payload["recent_worker_results"][0]["evidence_refs"] == ["evidence_refs:42"]
    assert "sid=secret" not in encoded
    assert "secretsecret" not in encoded
    assert "A" * 1000 not in encoded
