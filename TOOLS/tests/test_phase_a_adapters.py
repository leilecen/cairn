from __future__ import annotations

import json

from recon.phase_a_adapters import (
    build_gitleaks_command,
    build_jsluice_command,
    build_retirejs_command,
    build_urlfinder_command,
    build_webcrack_command,
    build_x8_command,
    health_contract,
    parse_gitleaks_fixture,
    parse_jsluice_fixture,
    parse_retirejs_fixture,
    parse_urlfinder_fixture,
    parse_webcrack_fixture,
    parse_x8_fixture,
    plan_sourcemap_reconstruction,
)


def test_health_contract_uses_injected_binary_and_compact_blockers_only():
    assert health_contract("urlfinder", binary_path=None, expected_version="1.2") == {
        "tool": "urlfinder",
        "status": "blocked",
        "blocker": "tool_missing",
        "command": [],
    }
    bad = health_contract(
        "jsluice",
        binary_path="fake-jsluice",
        expected_version="0.9",
        runner=lambda _: {"returncode": 0, "stdout": "0.8"},
    )
    assert bad["blocker"] == "wrong_version"
    prefix_collision = health_contract(
        "x8", binary_path="fake-x8", expected_version="4.1", runner=lambda _: {"returncode": 0, "stdout": "x8 14.1"}
    )
    assert prefix_collision["blocker"] == "wrong_version"
    ready = health_contract(
        "x8",
        binary_path="fake-x8",
        expected_version="4.1",
        runner=lambda command: {"returncode": 0, "stdout": "x8 4.1", "command": command},
    )
    assert ready == {"tool": "x8", "status": "ready", "version": "4.1", "command": ["fake-x8", "--version"]}


def test_phase_a_commands_are_bounded_and_never_enable_katana():
    assert build_urlfinder_command("fake-urlfinder", "https://Example.test:443/app", depth=2) == [
        "fake-urlfinder",
        "-u",
        "https://example.test/app",
        "-m",
        "2",
    ]
    assert build_jsluice_command("fake-jsluice", "fixture.js") == ["fake-jsluice", "urls", "fixture.js"]
    assert build_x8_command("fake-x8", "https://example.test/", "headers.txt") == [
        "fake-x8",
        "-u",
        "https://example.test/",
        "-w",
        "headers.txt",
        "--headers",
        "--output-format",
        "json",
    ]


def test_offline_fixture_parsers_deduplicate_and_fail_compactly():
    assert parse_urlfinder_fixture("https://example.test/a\nhttps://example.test/a\n")["items"] == [{"url": "https://example.test/a"}]
    # Real jsluice urls output is NDJSON, one object per line.
    ndjson = (
        '{"url":"/api/user?id=1","queryParams":["id"],"method":"","type":"stringLiteral"}\n'
        '{"url":"/api/user?id=1","queryParams":["id"],"method":"GET","type":"fetch"}\n'
    )
    assert parse_jsluice_fixture(ndjson)["items"] == [{"url": "/api/user?id=1"}]
    # x8 json output: array of RunnerOutput objects with found_params[{name}].
    x8_output = '[{"method":"GET","url":"https://example.test/","status":200,"found_params":[{"name":"X-Forwarded-Host","value":null,"reason_kind":"header"}],"injection_place":"header"}]'
    assert parse_x8_fixture(x8_output)["items"] == [{"header": "X-Forwarded-Host"}]
    assert parse_urlfinder_fixture("not a URL")["blocker"] == "parse_failed"
    assert parse_jsluice_fixture("{")["blocker"] == "parse_failed"
    assert parse_x8_fixture('[{"found_params":[{"name":"Authorization: Bearer secret"}]}]')["blocker"] == "parse_failed"


def test_health_contract_tool_specific_version_flags():
    # URLFinder has no --version flag; its -h banner carries "Update: 2026.6.16".
    ready = health_contract(
        "urlfinder",
        binary_path="fake-urlfinder",
        expected_version="2026.6.16",
        version_flag="-h",
        runner=lambda command: {"returncode": 0, "stdout": "Update: 2026.6.16", "command": command},
    )
    assert ready == {
        "tool": "urlfinder",
        "status": "ready",
        "version": "2026.6.16",
        "command": ["fake-urlfinder", "-h"],
    }
    # jsluice prints no numeric version: empty expected_version + --help only
    # requires exit 0 and non-empty output; capability proven by fixture parsing.
    jsluice_ok = health_contract(
        "jsluice",
        binary_path="fake-jsluice",
        expected_version="",
        version_flag="--help",
        runner=lambda command: {
            "returncode": 0,
            "stdout": "jsluice - Extract URLs, paths, and secrets from JavaScript files",
            "command": command,
        },
    )
    assert jsluice_ok == {"tool": "jsluice", "status": "ready", "version": None, "command": ["fake-jsluice", "--help"]}
    jsluice_bad = health_contract(
        "jsluice",
        binary_path="fake-jsluice",
        expected_version="",
        version_flag="--help",
        runner=lambda _: {"returncode": 1, "stderr": "segfault"},
    )
    assert jsluice_bad["blocker"] == "health_check_failed"


def test_health_contract_js_restoration_tools():
    # gitleaks uses the `version` subcommand, not --version.
    gitleaks_ok = health_contract(
        "gitleaks",
        binary_path="fake-gitleaks",
        expected_version="8.21.2",
        version_flag="version",
        runner=lambda command: {"returncode": 0, "stdout": "gitleaks version v8.21.2", "command": command},
    )
    assert gitleaks_ok == {
        "tool": "gitleaks",
        "status": "ready",
        "version": "8.21.2",
        "command": ["fake-gitleaks", "version"],
    }
    webcrack_ok = health_contract(
        "webcrack",
        binary_path="fake-webcrack",
        expected_version="1.0.0",
        runner=lambda command: {"returncode": 0, "stdout": "1.0.0", "command": command},
    )
    assert webcrack_ok == {
        "tool": "webcrack",
        "status": "ready",
        "version": "1.0.0",
        "command": ["fake-webcrack", "--version"],
    }
    retire_ok = health_contract(
        "retirejs",
        binary_path="fake-retire",
        expected_version="4.6.2",
        runner=lambda command: {"returncode": 0, "stdout": "4.6.2", "command": command},
    )
    assert retire_ok == {
        "tool": "retirejs",
        "status": "ready",
        "version": "4.6.2",
        "command": ["fake-retire", "--version"],
    }


def test_js_restoration_commands_are_bounded():
    assert build_webcrack_command("fake-webcrack", "bundle.js", "tmp/js_reverse/case") == [
        "fake-webcrack",
        "bundle.js",
        "-o",
        "tmp/js_reverse/case",
    ]
    assert build_retirejs_command("fake-retire", "tmp/js_reverse/case") == [
        "fake-retire",
        "--path",
        "tmp/js_reverse/case",
        "--outputformat",
        "json",
    ]
    assert build_gitleaks_command("fake-gitleaks", "tmp/js_reverse/case", "tmp/js_reverse/case/gitleaks.json") == [
        "fake-gitleaks",
        "detect",
        "--source",
        "tmp/js_reverse/case",
        "--no-git",
        "--report-format",
        "json",
        "--report-path",
        "tmp/js_reverse/case/gitleaks.json",
    ]
    assert build_gitleaks_command("fake-gitleaks", "tmp/js_reverse/case") == [
        "fake-gitleaks",
        "detect",
        "--source",
        "tmp/js_reverse/case",
        "--no-git",
    ]


def test_js_restoration_fixture_parsers():
    webcrack_out = json.dumps(
        {
            "output_dir": "tmp/js_reverse/case",
            "files": [{"path": "app.js", "bytes": 1200}, {"path": "chunk-1.js", "bytes": 300}],
        }
    )
    assert parse_webcrack_fixture(webcrack_out)["items"] == [
        {"file": "app.js", "bytes": 1200},
        {"file": "chunk-1.js", "bytes": 300},
    ]
    assert parse_webcrack_fixture('{"files": [{"path": "../escape.js", "bytes": 1}]}')["blocker"] == "parse_failed"
    assert parse_webcrack_fixture("{}")["blocker"] == "parse_failed"


def test_empty_scans_are_observed_not_blocked():
    """真实回归（2026-10-10）：retire 扫了但没命中返回 {"data": []}，
    gitleaks 无命中返回 []——都必须是 observed empty，不是 blocker。
    旧实现用 `data.get("data") or data.get("results")` 取值，空列表是假值，
    于是「扫完没发现问题」被误判成 parse_failed。"""
    retire_empty = '{"version":"5.4.3","start":"2026-10-10T08:11:42.496Z","data":[],"messages":[],"errors":[],"time":0.039}'
    assert parse_retirejs_fixture(retire_empty) == {"tool": "retirejs", "status": "observed", "items": []}
    assert parse_gitleaks_fixture("[]") == {"tool": "gitleaks", "status": "observed", "items": []}

    retire_out = json.dumps(
        {
            "results": [
                {
                    "component": "jquery",
                    "version": "1.7.1",
                    "detection": "filecontent",
                    "vulnerabilities": [
                        {
                            "info": ["jQuery before 1.9.0 has XSS"],
                            "severity": "high",
                            "below": "1.9.0",
                            "identifiers": {"cve": ["CVE-2011-4969"]},
                        }
                    ],
                }
            ]
        }
    )
    assert parse_retirejs_fixture(retire_out)["items"] == [
        {"component": "jquery", "version": "1.7.1", "severity": "high", "cve": "CVE-2011-4969"}
    ]
    # Real retire 5.4.3 shape: top-level data[] with {file, results[]} and
    # identifiers.CVE (uppercase); observed 2026-08-14 on a jquery-1.7.1 fixture.
    real_retire = json.dumps(
        {
            "version": "5.4.3",
            "start": "2026-08-14T02:40:27.052Z",
            "data": [
                {
                    "file": "E:/SRC/tmp/retire-dir/jquery-1.7.1.min.js",
                    "results": [
                        {
                            "version": "1.7.1",
                            "component": "jquery",
                            "npmname": "jquery",
                            "detection": "filename",
                            "vulnerabilities": [
                                {
                                    "info": ["jQuery before 1.9.0 has XSS"],
                                    "below": "1.9.0b1",
                                    "severity": "medium",
                                    "identifiers": {
                                        "summary": "Selector interpreted as HTML",
                                        "CVE": ["CVE-2012-6708"],
                                    },
                                    "cwe": ["CWE-64", "CWE-79"],
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    )
    assert parse_retirejs_fixture(real_retire)["items"] == [
        {"component": "jquery", "version": "1.7.1", "severity": "medium", "cve": "CVE-2012-6708"}
    ]
    assert parse_retirejs_fixture('{"data": []}')["items"] == []
    assert parse_retirejs_fixture('{"results": []}')["items"] == []
    assert parse_retirejs_fixture("not json")["blocker"] == "parse_failed"

    gitleaks_out = json.dumps(
        [
            {
                "RuleID": "aws-access-token",
                "Description": "AWS Access Token",
                "StartLine": 10,
                "EndLine": 10,
                "Match": "AKIAIOSFODNN7EXAMPLE",
                "Secret": "AKIAIOSFODNN7EXAMPLE",
                "File": "src/app.js",
                "Commit": "abc123def4567890",
                "Fingerprint": "f",
                "Date": "2026-01-01",
                "Link": "",
            }
        ]
    )
    parsed = parse_gitleaks_fixture(gitleaks_out)
    assert parsed["items"] == [{"rule": "aws-access-token", "file": "src/app.js", "line": 10, "commit": "abc123def456"}]
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(parsed)  # secret never leaks
    assert parse_gitleaks_fixture("[]")["items"] == []
    assert parse_gitleaks_fixture("{}")["blocker"] == "parse_failed"


def test_sourcemap_reconstruction_plan_is_bounded():
    entries = [
        {"source": "webpack:///./src/app.ts", "content": "export const api = '/api/v1/user';"},
        {"source": "/static/js/main.abc.js", "content": "console.log('hi');"},
        {"source": "webpack:///./src/empty.ts", "content": ""},
        {"source": "../escape.js", "content": "evil"},
    ]
    planned = plan_sourcemap_reconstruction(entries, "tmp/js_reverse/case")
    paths = [item["file"] for item in planned]
    assert "src/app.ts" in paths
    assert "static/js/main.abc.js" in paths
    assert not any(".." in p or "escape" in p for p in paths)
    assert all(item["bytes"] > 0 for item in planned)
    assert plan_sourcemap_reconstruction([], "tmp/js_reverse/case") == []
