from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from recon.recon_doctor import build_manifest, main


def _database(path: Path, target: str = "demo") -> None:
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE targets (target_name TEXT PRIMARY KEY)")
        conn.execute("INSERT INTO targets(target_name) VALUES (?)", (target,))


def _db_with_target(tmp_path: Path) -> Path:
    db_path = tmp_path / "doctor.db"
    _database(db_path)
    return db_path


def test_build_manifest_prefers_fofa_relay_and_redacts_environment_values(tmp_path, monkeypatch):
    db_path = tmp_path / "demo.db"
    _database(db_path)
    go_bin = tmp_path / "go-bin"
    go_bin.mkdir()
    httpx = go_bin / "httpx.exe"
    httpx.touch()
    subfinder = go_bin / "subfinder.exe"
    subfinder.touch()
    provider_config = tmp_path / "provider-config.yaml"
    provider_config.write_text("shodan:\n  - key: provider-secret\n", encoding="utf-8")

    class Completed:
        stdout = "httpx version 1.7.0 projectdiscovery.io"
        stderr = ""

    monkeypatch.setattr("recon.recon_doctor.subprocess.run", lambda *_args, **_kwargs: Completed(), raising=False)

    manifest = build_manifest(
        target="demo",
        db_path=db_path,
        environ={"FOFA_RELAY_KEY": "do-not-leak", "PATH": str(go_bin)},
        path_entries=[go_bin],
        subfinder_provider_config_path=provider_config,
    )

    assert manifest["fofa"] == {
        "status": "available",
        "provider": "fofa",
        "adapter": "relay",
        "credential_source": "FOFA_RELAY_KEY",
        "policy": "relay_only",
    }
    assert manifest["httpx"] == {"status": "ready", "path": str(httpx.resolve()), "python_cli_paths": []}
    assert manifest["subfinder"] == {"status": "ready", "path": str(subfinder.resolve()), "configured_providers": 1}
    assert "do-not-leak" not in str(manifest)
    assert "provider-secret" not in str(manifest)


def test_httpx_capability_only_accepts_projectdiscovery_binary(tmp_path, monkeypatch):
    scripts = tmp_path / "Python" / "Scripts"
    scripts.mkdir(parents=True)
    python_httpx = scripts / "httpx.exe"
    python_httpx.touch()
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    other_httpx = other_dir / "httpx.exe"
    other_httpx.touch()
    seen: list[list[str]] = []

    class Completed:
        stdout = "httpx 0.27.2"
        stderr = ""

    def fake_run(command, **_kwargs):
        seen.append(command)
        return Completed()

    monkeypatch.setattr("recon.recon_doctor.subprocess.run", fake_run, raising=False)
    manifest = build_manifest(
        target="demo",
        db_path=_db_with_target(tmp_path),
        environ={},
        path_entries=[scripts, other_dir],
        fofa_provider_config_path=tmp_path / "uncover-provider-config.yaml",
    )

    assert manifest["httpx"] == {
        "status": "tool_missing",
        "path": None,
        "python_cli_paths": [str(python_httpx.resolve())],
    }
    assert seen == [[str(python_httpx.resolve()), "-version"], [str(other_httpx.resolve()), "-version"]]


def test_build_manifest_marks_python_httpx_shadow_and_empty_subfinder_config_degraded(tmp_path):
    db_path = tmp_path / "demo.db"
    _database(db_path)
    scripts = tmp_path / "Python" / "Scripts"
    scripts.mkdir(parents=True)
    (scripts / "httpx.exe").touch()
    (scripts / "subfinder.exe").touch()
    provider_config = tmp_path / "provider-config.yaml"
    provider_config.write_text("shodan: []\nvirustotal: {}\n", encoding="utf-8")

    manifest = build_manifest(
        target="demo",
        db_path=db_path,
        environ={"PATH": str(scripts)},
        path_entries=[scripts],
        fofa_provider_config_path=tmp_path / "uncover-provider-config.yaml",
        subfinder_provider_config_path=provider_config,
    )

    assert manifest["fofa"] == {
        "status": "not_configured",
        "provider": "fofa",
        "adapter": None,
        "credential_source": None,
        "allowed_adapters": ["relay"],
        "policy": "relay_only",
    }
    assert manifest["httpx"] == {
        "status": "tool_missing",
        "path": None,
        "python_cli_paths": [str((scripts / "httpx.exe").resolve())],
    }
    assert manifest["subfinder"] == {
        "status": "degraded",
        "path": str((scripts / "subfinder.exe").resolve()),
        "configured_providers": 0,
    }


def test_build_manifest_rejects_unknown_target(tmp_path):
    db_path = tmp_path / "demo.db"
    _database(db_path)

    with pytest.raises(ValueError, match="target not found"):
        build_manifest(target="missing", db_path=db_path, environ={}, path_entries=[])


def test_build_manifest_reports_unknown_subfinder_config_format(tmp_path):
    db_path = tmp_path / "demo.db"
    _database(db_path)
    tool_dir = tmp_path / "tools"
    tool_dir.mkdir()
    (tool_dir / "subfinder.exe").touch()
    provider_config = tmp_path / "provider-config.yaml"
    provider_config.write_text("not: valid: yaml\n", encoding="utf-8")

    manifest = build_manifest(
        target="demo",
        db_path=db_path,
        environ={},
        path_entries=[tool_dir],
        fofa_provider_config_path=tmp_path / "uncover-provider-config.yaml",
        subfinder_provider_config_path=provider_config,
    )

    assert manifest["subfinder"]["status"] == "unknown_config_format"


def test_main_requires_explicit_target_and_db():
    with pytest.raises(SystemExit) as exc_info:
        main([])

    assert exc_info.value.code == 2


def test_main_outputs_json_manifest_for_existing_target(tmp_path, capsys, monkeypatch):
    db_path = tmp_path / "demo.db"
    _database(db_path)
    monkeypatch.setenv("PATH", "")
    monkeypatch.delenv("FOFA_RELAY_KEY", raising=False)

    assert main(["--target", "demo", "--db", str(db_path)]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["ok"] is True
    assert payload["target"] == "demo"
    assert payload["network"] == "not_used"
