"""Unit tests for etl_analyzer.py"""

import json
import sqlite3
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.etl_analyzer import analyze, normalize_js_findings


@pytest.fixture(autouse=True)
def isolate_etl_metrics(tmp_path, monkeypatch):
    monkeypatch.setenv("SRC_ETL_METRICS_FILE", str(tmp_path / "etl_metrics.jsonl"))


@pytest.fixture
def mock_deepseek(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API", "test-key-xxx")
    with patch("utils.etl_analyzer.OpenAI") as mock_cls:
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_response = MagicMock()
        mock_response.choices[0].message.content = '{"result": "test"}'
        mock_client.chat.completions.create.return_value = mock_response
        yield mock_client


def test_analyze_filter_burp_returns_string(mock_deepseek):
    result = analyze("filter_burp", '{"url": "/api/test"}')
    assert result == '{"result": "test"}'
    mock_deepseek.chat.completions.create.assert_called_once()


def _read_metrics(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_analyze_writes_success_metrics_with_usage(tmp_path, monkeypatch, mock_deepseek):
    metrics_file = tmp_path / "metrics.jsonl"
    monkeypatch.setenv("SRC_ETL_METRICS_FILE", str(metrics_file))
    response = mock_deepseek.chat.completions.create.return_value
    response.usage.prompt_tokens = 11
    response.usage.completion_tokens = 7
    response.usage.total_tokens = 18

    analyze("filter_burp", "中文数据", instruction="说明", caller="unit.test")

    [record] = _read_metrics(metrics_file)
    assert record["task"] == "filter_burp"
    assert record["model"] == "deepseek-chat"
    assert record["caller"] == "unit.test"
    assert record["input_chars"] == 4
    assert record["instruction_chars"] == 2
    assert record["output_chars"] == len('{"result": "test"}')
    assert record["status"] == "success"
    assert record["cache_db_present"] is False
    assert record["cache_hit"] is False
    assert record["prompt_tokens"] == 11
    assert record["completion_tokens"] == 7
    assert record["total_tokens"] == 18
    assert "中文数据" not in json.dumps(record, ensure_ascii=False)
    assert "说明" not in json.dumps(record, ensure_ascii=False)


def test_analyze_writes_cache_hit_metrics(tmp_path, monkeypatch, mock_deepseek):
    metrics_file = tmp_path / "metrics.jsonl"
    cache_db = tmp_path / "etl_cache.db"
    monkeypatch.setenv("SRC_ETL_METRICS_FILE", str(metrics_file))

    analyze("filter_burp", "raw_data", cache_db=cache_db, caller="first")
    mock_deepseek.chat.completions.create.reset_mock()
    analyze("filter_burp", "raw_data", cache_db=cache_db, caller="second")

    records = _read_metrics(metrics_file)
    assert records[-1]["status"] == "cache_hit"
    assert records[-1]["cache_db_present"] is True
    assert records[-1]["cache_hit"] is True
    assert records[-1]["caller"] == "second"
    mock_deepseek.chat.completions.create.assert_not_called()


def test_analyze_writes_error_metrics(tmp_path, monkeypatch, mock_deepseek):
    metrics_file = tmp_path / "metrics.jsonl"
    monkeypatch.setenv("SRC_ETL_METRICS_FILE", str(metrics_file))
    mock_deepseek.chat.completions.create.side_effect = ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        analyze("filter_burp", "secret-token-value", caller="error.case")

    [record] = _read_metrics(metrics_file)
    assert record["status"] == "error"
    assert record["output_chars"] == 0
    assert record["caller"] == "error.case"
    assert "secret-token-value" not in json.dumps(record)


def test_analyze_metrics_without_usage_fields(tmp_path, monkeypatch, mock_deepseek):
    metrics_file = tmp_path / "metrics.jsonl"
    monkeypatch.setenv("SRC_ETL_METRICS_FILE", str(metrics_file))
    mock_deepseek.chat.completions.create.return_value.usage = None

    analyze("filter_burp", "raw_data")

    [record] = _read_metrics(metrics_file)
    assert "prompt_tokens" not in record
    assert "completion_tokens" not in record
    assert "total_tokens" not in record


def test_analyze_uses_correct_model(mock_deepseek):
    analyze("filter_burp", "data")
    call_kwargs = mock_deepseek.chat.completions.create.call_args[1]
    assert call_kwargs["model"] == "deepseek-chat"


def test_analyze_unknown_task_raises_value_error(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API", "test-key-xxx")
    with pytest.raises(ValueError, match="Unknown task"):
        analyze("nonexistent_task", "data")


def test_analyze_missing_api_key_raises_runtime_error(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API", raising=False)
    with pytest.raises(RuntimeError, match="DEEPSEEK_API"):
        analyze("filter_burp", "data")


def test_analyze_instruction_prepended_to_data(mock_deepseek):
    analyze("filter_burp", "raw_data", instruction="extra context")
    call_kwargs = mock_deepseek.chat.completions.create.call_args[1]
    user_msg = call_kwargs["messages"][1]["content"]
    assert "extra context" in user_msg
    assert "raw_data" in user_msg


def test_analyze_no_instruction_sends_data_only(mock_deepseek):
    analyze("filter_burp", "raw_data")
    call_kwargs = mock_deepseek.chat.completions.create.call_args[1]
    user_msg = call_kwargs["messages"][1]["content"]
    assert user_msg == "raw_data"


def test_analyze_cache_stores_first_result(tmp_path, mock_deepseek):
    cache_db = tmp_path / "etl_cache.db"

    result = analyze("filter_burp", "raw_data", cache_db=cache_db)

    assert result == '{"result": "test"}'
    row = sqlite3.connect(cache_db).execute("SELECT task, result, model, hit_count FROM etl_cache").fetchone()
    assert row == ("filter_burp", '{"result": "test"}', "deepseek-chat", 0)


def test_analyze_js_prompt_requests_normalized_schema(mock_deepseek):
    analyze("analyze_js", "const api = '/api/user'")
    call_kwargs = mock_deepseek.chat.completions.create.call_args[1]
    system_msg = call_kwargs["messages"][0]["content"]
    assert "api_endpoints" in system_msg
    assert "hardcoded_secrets" in system_msg
    assert "signature_hints" in system_msg


def test_analyze_cache_hit_skips_model_call(tmp_path, mock_deepseek):
    cache_db = tmp_path / "etl_cache.db"
    first = analyze("filter_burp", "raw_data", cache_db=cache_db)
    mock_deepseek.chat.completions.create.reset_mock()

    second = analyze("filter_burp", "raw_data", cache_db=cache_db)

    assert first == second == '{"result": "test"}'
    mock_deepseek.chat.completions.create.assert_not_called()
    row = sqlite3.connect(cache_db).execute("SELECT hit_count FROM etl_cache WHERE task = 'filter_burp'").fetchone()
    assert row[0] == 1


def test_analyze_cache_miss_when_instruction_changes(tmp_path, mock_deepseek):
    cache_db = tmp_path / "etl_cache.db"
    analyze("filter_burp", "raw_data", instruction="v1", cache_db=cache_db)
    mock_deepseek.chat.completions.create.reset_mock()

    analyze("filter_burp", "raw_data", instruction="v2", cache_db=cache_db)

    mock_deepseek.chat.completions.create.assert_called_once()
    row = sqlite3.connect(cache_db).execute("SELECT COUNT(*) FROM etl_cache").fetchone()
    assert row[0] == 2


def test_analyze_bypass_cache_forces_model_call(tmp_path, mock_deepseek):
    cache_db = tmp_path / "etl_cache.db"
    analyze("filter_burp", "raw_data", cache_db=cache_db)
    mock_deepseek.chat.completions.create.reset_mock()

    analyze("filter_burp", "raw_data", cache_db=cache_db, bypass_cache=True)

    mock_deepseek.chat.completions.create.assert_called_once()
    row = sqlite3.connect(cache_db).execute("SELECT COUNT(*), hit_count FROM etl_cache WHERE task = 'filter_burp'").fetchone()
    assert row == (1, 0)


def test_normalize_js_findings_keeps_new_schema():
    data = {
        "api_endpoints": [{"path": "/api/orders", "method": "POST", "params": ["id"]}],
        "hardcoded_secrets": [{"type": "token", "name": "AUTH", "value": "abc"}],
        "internal_routes": ["/admin"],
        "auth_patterns": ["Bearer"],
        "signature_hints": ["timestamp+sign"],
    }
    normalized = normalize_js_findings(data)
    assert normalized == data


def test_normalize_js_findings_maps_legacy_schema():
    data = {
        "apis": [{"url": "/api/user", "method": "GET", "params": ["uid"]}],
        "secrets": [{"key": "API_KEY", "secret": "demo"}],
        "sensitive_params": ["token", "nonce"],
    }
    normalized = normalize_js_findings(data)
    assert normalized["api_endpoints"][0] == {"path": "/api/user", "method": "GET", "params": ["uid"]}
    assert normalized["hardcoded_secrets"][0] == {"type": "secret", "name": "API_KEY", "value": "demo"}
    assert normalized["api_endpoints"][1] == {"path": "", "method": "UNKNOWN", "params": ["token", "nonce"]}
    assert normalized["internal_routes"] == []
    assert normalized["auth_patterns"] == []
    assert normalized["signature_hints"] == []


@pytest.mark.parametrize(
    "task",
    [
        "filter_burp",
        "analyze_js",
        "filter_db",
        "extract_endpoints",
        "classify_business",
        "analyze_flow",
        "generate_variants",
        "diff_responses",
    ],
)
def test_all_tasks_have_system_prompts(task, mock_deepseek):
    result = analyze(task, "sample data")
    assert result is not None
    call_kwargs = mock_deepseek.chat.completions.create.call_args[1]
    system_msg = call_kwargs["messages"][0]["content"]
    assert len(system_msg) > 10
