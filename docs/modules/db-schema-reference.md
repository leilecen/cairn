# DB 结构参考（59 表）

> **何时读这份**：查表、加表、写 SQL 之前。
> **派生自 `TOOLS/db/schema.sql` + `migrations/`**（DDL 唯一真源），本文件只是人类可读说明；**冲突一律以 DDL 为准**。
> 不要手改本文件，也不要逐表 `db_query.py -t` 试错。
> 注意：仓库根目录的 `TOOLS/schema.sql` 曾是**陈旧副本**（55 表，止于 migration 038），已于 2026-10-17 删除；DDL 真源只有这里指出的 `TOOLS/db/schema.sql` + `migrations/`。
> 落库脚本的写法真源是 [`probe-and-store-toolkit.md`](probe-and-store-toolkit.md)；命令口径统一 `.venv/Scripts/python.exe`（本机无全局 `uv`）。

约定：

- 库文件：`dbs/{slug}.db`，slug = `safe_db_stem(target)`；兼容历史 `{slug}_{YYYY-MM-DD}.db` 与中文名文件。
- 目标必须显式传入 `--target` 或 `--file`，禁止环境变量推断。
- `PK` = 主键，`NOT NULL` = 必填，`=x` = 列默认值，`∈{a|b}` = CHECK 枚举（**只接受列出的值**）。
- TEXT 主键需自造 id（如 `sp-xxx`），无自增兜底。
- 写库先看目标表 required 列；枚举列写错会被 CHECK 拒绝。

## 快速入口

```bash
# 执行位置：仓库根目录
.venv/Scripts/python.exe TOOLS/db/db_query.py --list                      # 列出所有目标库
.venv/Scripts/python.exe TOOLS/db/db_query.py --schema                    # 全量表结构
.venv/Scripts/python.exe TOOLS/db/db_query.py --target "目标名" --schema <表>   # 单表结构
.venv/Scripts/python.exe TOOLS/db/db_query.py --target "目标名" "<SQL>"          # 查询
.venv/Scripts/python.exe TOOLS/db/db_query.py --target "目标名" "<SQL>" --write --params '[...]'  # 写库
```

### 写落库脚本时：用 `TOOLS/lib/store_kit.py`

手写裸 `sqlite3` 落库脚本会踩列名静默丢弃、枚举 CHECK 回滚、复合唯一约束冲突、NOT NULL 报错等坑，`StoreKit` 逐条挡住并提供落库后自检。契约、判据与示例代码见 [`probe-and-store-toolkit.md`](probe-and-store-toolkit.md) §1（该文件是这一主题的真源，本文件不重复）。

```bash
# 已有库的一次性只读自检：退出码 0 = 无问题，1 = 有空关键字段
.venv/Scripts/python.exe TOOLS/lib/store_kit.py "<target|db 路径>" [--counts]
```

## 高频落库表（最常写错的几列）

- `target_assets` — 必填（无默认值）：`target_name`, `asset_value`
  - `asset_type` ∈ {domain, subdomain, ip, url, cidr, other}
  - `source` ∈ {manual, fofa, zoomeye, other}
  - `status` ∈ {new, validated, queued, scanned, excluded}
- `endpoint_observations` — 必填（无默认值）：`target_name`, `canonical_url`, `source`
- `findings` — 必填（无默认值）：无
- `suspicious_points` — 必填（无默认值）：无
- `work_items` — 必填（无默认值）：`target_name`, `lane`, `subject_table`, `subject_id`
  - `status` ∈ {queued, claimed, partial, blocked, done, failed, cancelled}
  - `model_tier` ∈ {haiku, sonnet, opus}
  - `reasoning_tier` ∈ {low, medium, high}
  - `upgrade_policy` ∈ {never, ask_main, auto_if_high_risk_signal}
  - `auth_requirement` ∈ {none, optional, required, multi_account_required, role_required, unknown}
  - `risk_class` ∈ {safe_passive, safe_replay, sensitive_read, state_changing, high_risk}
  - `blocker_class` ∈ {auth_barrier, network, scope, evidence, critical_found, refuted, parked, other}
- `coverage_ledger` — 必填（无默认值）：`target_name`, `item_key`, `category`
  - `status` ∈ {covered, unknown, uncovered, blocked}
  - `confidence` ∈ {low, medium, high, unknown}

## 全部表

### 核心与元数据

**`targets`** (9 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `domain` TEXT · `ip` TEXT · `tech_stack` TEXT · `requires_auth` INTEGER =0 · `auth_status` TEXT ='not_logged_in' · `discovered_at` TEXT =(datetime('now', 'localtime')) · `notes` TEXT

**`schema_version`** (3 cols)

`version` INTEGER PK · `applied_at` TEXT =(datetime('now', 'localtime')) · `description` TEXT

**`scan_state`** (17 cols)

`id` INTEGER PK · `target_id` INTEGER · `seed_url` TEXT · `phase` TEXT ='init' · `started_at` TEXT · `spider_ended_at` TEXT · `reviewed_at` TEXT · `max_depth` INTEGER =3 · `max_pages` INTEGER =200 · `total_pages` INTEGER =0 · `total_js` INTEGER =0 · `total_apis` INTEGER =0 · `total_forms` INTEGER =0 · `total_suspicious` INTEGER =0 · `total_findings` INTEGER =0 · `call_count` INTEGER =0 · `cdp_url` TEXT =NULL

**`plugins`** (11 cols)

`id` INTEGER PK · `name` TEXT NOT NULL · `type` TEXT NOT NULL ∈{nuclei_template|python_script|tool_binary|config} · `trigger_stack` TEXT · `covers_vuln_types` TEXT · `file_path` TEXT · `install_cmd` TEXT · `source` TEXT ='mapping' ∈{mapping|ai_generated} · `active` INTEGER =1 · `created_at` TEXT =(datetime('now','localtime')) · `last_used_at` TEXT

### 资产面

**`target_assets`** (33 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `asset_type` TEXT ='domain' ∈{domain|subdomain|ip|url|cidr|other} · `asset_value` TEXT NOT NULL · `port` INTEGER · `protocol` TEXT ='https' · `source` TEXT ='manual' ∈{manual|fofa|zoomeye|other} · `tech_stack` TEXT · `requires_auth` INTEGER =0 · `status` TEXT ='new' ∈{new|validated|queued|scanned|excluded} · `priority` INTEGER =0 · `notes` TEXT · `created_at` TEXT =(datetime('now','localtime')) · `validated_at` TEXT · `live_status` TEXT ='unknown' · `last_status_code` INTEGER · `last_title` TEXT · `resolved_ip` TEXT · `last_tech_stack` TEXT · `last_verified_at` TEXT · `last_verify_status` TEXT · `auth_required` INTEGER =0 · `auth_entry_found` INTEGER =0 · `login_urls` TEXT ='[]' · `register_urls` TEXT ='[]' · `auth_blocker` TEXT ='unknown' · `scope_status` TEXT ='needs_review' · `scope_reason` TEXT · `source_query` TEXT · `source_snapshot` TEXT · `scope_class` TEXT ='unknown' · `authorization_state` TEXT ='unknown' · `relation_to_target` TEXT

**`asset_relationships`** (10 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `asset_id` INTEGER NOT NULL · `related_host` TEXT NOT NULL · `relation_type` TEXT NOT NULL · `scope_class` TEXT NOT NULL ='unknown' · `authorization_state` TEXT NOT NULL ='unknown' · `evidence_refs_json` TEXT NOT NULL ='[]' · `notes` TEXT · `observed_at` TEXT =(datetime('now','localtime'))

**`asset_auth_entries`** (10 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `asset_id` INTEGER · `url` TEXT NOT NULL · `entry_type` TEXT NOT NULL ∈{login|register} · `source` TEXT NOT NULL · `confidence` TEXT ='medium' · `status` TEXT ='observed' · `notes` TEXT · `discovered_at` TEXT =(datetime('now','localtime'))

**`network_observations`** (16 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `asset_id` INTEGER · `host` TEXT NOT NULL · `ip` TEXT · `port` INTEGER · `protocol` TEXT · `service` TEXT · `tls_json` TEXT NOT NULL ='{}' · `http_json` TEXT NOT NULL ='{}' · `waf_signal` TEXT · `load_balancer_signal` TEXT · `status` TEXT NOT NULL ='observed' · `source` TEXT NOT NULL · `evidence_refs_json` TEXT NOT NULL ='[]' · `observed_at` TEXT =(datetime('now','localtime'))

**`technology_observations`** (11 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `asset_id` INTEGER · `host` TEXT NOT NULL · `technology` TEXT NOT NULL · `category` TEXT NOT NULL ='framework' · `version` TEXT · `confidence` TEXT NOT NULL ='unknown' · `source` TEXT NOT NULL · `evidence_refs_json` TEXT NOT NULL ='[]' · `observed_at` TEXT =(datetime('now','localtime'))

**`cdn_observations`** (9 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `asset_id` INTEGER · `hostname` TEXT NOT NULL · `classification` TEXT NOT NULL · `provider` TEXT NOT NULL ='' · `reasons_json` TEXT NOT NULL ='[]' · `evidence_refs_json` TEXT NOT NULL ='[]' · `observed_at` TEXT =(datetime('now','localtime'))

**`origin_candidates`** (12 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `asset_id` INTEGER · `hostname` TEXT NOT NULL · `candidate_ip` TEXT NOT NULL · `source` TEXT NOT NULL · `confidence` TEXT NOT NULL ='unknown' · `score` INTEGER NOT NULL =0 · `verification_status` TEXT NOT NULL ='unknown' · `evidence_refs_json` TEXT NOT NULL ='[]' · `notes` TEXT · `observed_at` TEXT =(datetime('now','localtime'))

**`endpoint_observations`** (38 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `asset_id` INTEGER · `page_id` INTEGER · `js_file_id` INTEGER · `js_signal_id` TEXT · `source_table` TEXT · `source_id` TEXT · `canonical_url` TEXT NOT NULL · `host` TEXT · `path` TEXT · `method` TEXT NOT NULL ='GET' · `source` TEXT NOT NULL · `auth_state` TEXT NOT NULL ='unknown' · `response_class` TEXT · `status_code` INTEGER · `content_type` TEXT · `waf_state` TEXT · `business_hint` TEXT · `parameter_names_json` TEXT NOT NULL ='[]' · `evidence_refs_json` TEXT NOT NULL ='[]' · `confidence` TEXT NOT NULL ='unknown' · `test_status` TEXT NOT NULL ='not_tested' · `first_seen_at` TEXT =(datetime('now','localtime')) · `last_seen_at` TEXT =(datetime('now','localtime')) · `observed_count` INTEGER NOT NULL =1 · `raw_endpoint` TEXT · `resolved_url` TEXT · `base_url` TEXT · `source_page_url` TEXT · `source_js_url` TEXT · `origin_host` TEXT · `route_kind` TEXT · `service_hint` TEXT · `resolution_status` TEXT ='unresolved' · `scope_class` TEXT ='unknown' · `redirect_location` TEXT · `response_fingerprint` TEXT

**`entry_observations`** (13 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `asset_id` INTEGER · `url` TEXT NOT NULL · `entry_type` TEXT NOT NULL · `source` TEXT NOT NULL · `status` TEXT NOT NULL ='unknown' · `status_code` INTEGER · `confidence` TEXT NOT NULL ='unknown' · `response_class` TEXT · `evidence_refs_json` TEXT NOT NULL ='[]' · `notes` TEXT · `observed_at` TEXT =(datetime('now','localtime'))

**`pages`** (16 cols)

`id` INTEGER PK · `url` TEXT · `depth` INTEGER =0 · `status` TEXT ='queued' · `title` TEXT · `links_found` INTEGER =0 · `forms_json` TEXT · `js_files_json` TEXT · `api_calls_json` TEXT · `suspicious_params_json` TEXT · `crawled_at` TEXT · `source` TEXT =NULL · `canonical_url` TEXT · `endpoint_fingerprint` TEXT · `signal_value` TEXT · `signal_reason` TEXT

**`page_asset_links`** (6 cols)

`page_id` INTEGER PK NOT NULL · `asset_id` INTEGER PK NOT NULL · `relation` TEXT NOT NULL ='same_host' · `confidence` TEXT NOT NULL ='medium' · `evidence_ref` TEXT · `created_at` TEXT =(datetime('now','localtime'))

**`attack_surface_profiles`** (17 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `soft_target_id` INTEGER · `subject_table` TEXT NOT NULL ='soft_targets' · `subject_id` TEXT NOT NULL · `system_tags_json` TEXT NOT NULL ='[]' · `business_tags_json` TEXT NOT NULL ='[]' · `roles_json` TEXT NOT NULL ='[]' · `flows_json` TEXT NOT NULL ='[]' · `trust_boundaries_json` TEXT NOT NULL ='[]' · `tech_stack_json` TEXT NOT NULL ='[]' · `confidence` TEXT ='unknown' ∈{low|medium|high|unknown} · `evidence_refs_json` TEXT NOT NULL ='[]' · `summary` TEXT · `status` TEXT NOT NULL ='draft' ∈{draft|active|stale|blocked} · `created_at` TEXT =(datetime('now','localtime')) · `updated_at` TEXT =(datetime('now','localtime'))

### JS 情报

**`js_files`** (18 cols)

`id` INTEGER PK · `url` TEXT · `page_url` TEXT · `analyzed` INTEGER =0 · `discovered_apis_json` TEXT · `hardcoded_secrets_json` TEXT · `internal_routes_json` TEXT · `debug_switches_json` TEXT · `analyzed_at` TEXT · `content_hash` TEXT · `local_path` TEXT · `size_bytes` INTEGER · `source_kind` TEXT ='web_script' · `source_map_url` TEXT · `source_map_status` TEXT · `extraction_status` TEXT ='pending' · `extraction_version` TEXT · `signal_count` INTEGER =0

**`js_signals`** (29 cols)

`id` TEXT PK · `target_id` INTEGER · `js_file_id` INTEGER · `source_kind` TEXT NOT NULL · `signal_type` TEXT NOT NULL · `protocol` TEXT ='http' · `method` TEXT · `url` TEXT · `path` TEXT · `host` TEXT · `params_json` TEXT · `headers_json` TEXT · `evidence_snippet` TEXT · `evidence_location` TEXT · `caller_hint` TEXT · `page_route` TEXT · `auth_hint` TEXT · `signature_hint` TEXT · `business_hint` TEXT · `value_flow_json` TEXT · `caller_chain_json` TEXT · `runtime_seen` INTEGER =0 · `runtime_evidence_json` TEXT · `confidence` INTEGER =50 · `risk_score` INTEGER =0 · `status` TEXT ='new' · `promoted_sp_id` TEXT · `created_at` TEXT =(datetime('now','localtime')) · `updated_at` TEXT =(datetime('now','localtime'))

**`js_signal_clusters`** (19 cols)

`id` TEXT PK · `target_id` INTEGER · `fingerprint` TEXT NOT NULL · `canonical_method` TEXT · `canonical_url` TEXT · `signal_types_json` TEXT · `source_count` INTEGER =1 · `best_confidence` INTEGER =0 · `best_risk_score` INTEGER =0 · `representative_signal_id` TEXT · `status` TEXT ='new' · `runtime_seen` INTEGER =0 · `runtime_count` INTEGER =0 · `attack_surface_json` TEXT · `ai_summary_json` TEXT · `ai_char_count` INTEGER =0 · `ai_cache_key` TEXT · `created_at` TEXT =(datetime('now','localtime')) · `updated_at` TEXT =(datetime('now','localtime'))

**`js_asset_links`** (6 cols)

`js_file_id` INTEGER PK NOT NULL · `asset_id` INTEGER PK NOT NULL · `relation` TEXT NOT NULL ='same_host' · `confidence` TEXT NOT NULL ='medium' · `evidence_ref` TEXT · `created_at` TEXT =(datetime('now','localtime'))

**`runtime_requests`** (16 cols)

`id` TEXT PK · `target_id` INTEGER · `source` TEXT NOT NULL · `method` TEXT · `url` TEXT NOT NULL · `host` TEXT · `path` TEXT · `headers_json` TEXT · `body_keys_json` TEXT · `page_route` TEXT · `request_time` TEXT · `matched_signal_id` TEXT · `matched_cluster_id` TEXT · `redaction_applied` INTEGER =1 · `raw_reference` TEXT · `created_at` TEXT =(datetime('now','localtime'))

### 侦察来源与运行

**`recon_sources`** (8 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `source_kind` TEXT NOT NULL · `query` TEXT · `result_json` TEXT NOT NULL ='{}' · `status` TEXT NOT NULL ='observed' · `error` TEXT · `observed_at` TEXT =(datetime('now','localtime'))

**`recon_runs`** (12 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `source` TEXT NOT NULL · `input_fingerprint` TEXT NOT NULL · `status` TEXT NOT NULL ='queued' · `attempt` INTEGER NOT NULL =0 · `cursor_json` TEXT NOT NULL ='{}' · `budget_json` TEXT NOT NULL ='{}' · `summary_json` TEXT NOT NULL ='{}' · `last_success_at` TEXT · `next_retry_at` TEXT · `updated_at` TEXT NOT NULL =(datetime('now','localtime'))

**`preauth_probe_runs`** (12 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `asset_id` INTEGER · `endpoint_group` TEXT · `max_requests` INTEGER NOT NULL =30 · `request_count` INTEGER NOT NULL =0 · `min_interval_seconds` REAL NOT NULL =2 · `status` TEXT NOT NULL ='running' · `stop_reason` TEXT · `evidence_refs_json` TEXT NOT NULL ='[]' · `started_at` TEXT =(datetime('now','localtime')) · `finished_at` TEXT

**`egress_log`** (16 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `run_id` TEXT NOT NULL ='' · `ts` TEXT NOT NULL =(datetime('now','localtime')) · `epoch` REAL NOT NULL =0 · `identity` TEXT NOT NULL ='' · `mode` TEXT NOT NULL ='burp' · `host` TEXT NOT NULL ='' · `method` TEXT NOT NULL ='GET' · `url_path` TEXT NOT NULL ='' · `status_code` INTEGER NOT NULL =0 · `elapsed_ms` INTEGER NOT NULL =0 · `planned_gap_ms` INTEGER NOT NULL =0 · `decision` TEXT NOT NULL ='sent' ∈{sent|blocked|skipped|error} · `stop_reason` TEXT NOT NULL ='' · `note` TEXT NOT NULL =''

> `egress_log` 刻意**不记录** query / body / cookie，只记出口形态要素（身份、模式、host、path、计划间隔、实际耗时、熔断结论）。用途与口径见 [`egress-traffic-shaping.md`](egress-traffic-shaping.md)，DDL 见 `migrations/042_egress_log.sql`。

### 系统与焦点

**`target_systems`** (11 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `system_key` TEXT NOT NULL · `display_name` TEXT NOT NULL · `canonical_url` TEXT NOT NULL · `description` TEXT NOT NULL ='' · `scope_class` TEXT NOT NULL ='unknown' ∈{owned|authorized_vendor|intel_only|unknown} · `lifecycle_state` TEXT NOT NULL ='discovered' ∈{discovered|mapping|ready|testing|human_blocked|parked|completed|excluded} · `created_by` TEXT NOT NULL ='operator' · `created_at` TEXT =(datetime('now','localtime')) · `updated_at` TEXT =(datetime('now','localtime'))

**`system_asset_links`** (9 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `system_id` INTEGER NOT NULL · `asset_id` INTEGER NOT NULL · `relationship` TEXT NOT NULL · `confidence` TEXT NOT NULL ='unknown' · `evidence_refs_json` TEXT NOT NULL ='[]' · `created_at` TEXT =(datetime('now','localtime')) · `updated_at` TEXT =(datetime('now','localtime'))

**`system_type_observations`** (10 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `asset_id` INTEGER NOT NULL · `classifier` TEXT NOT NULL ='declarative_system_types' · `rule_context` TEXT NOT NULL ='system_signatures:v1' · `label` TEXT NOT NULL · `rule_id` TEXT · `reasons_json` TEXT NOT NULL ='[]' · `evidence_refs_json` TEXT NOT NULL ='[]' · `observed_at` TEXT NOT NULL =(datetime('now','localtime'))

**`system_soft_targets`** (19 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `system_id` INTEGER NOT NULL · `eligibility_status` TEXT NOT NULL ='needs_review' ∈{eligible|scope_blocked|authz_blocked|needs_review} · `eligibility_reason` TEXT · `login_access` TEXT NOT NULL ='none' ∈{can_register|default_creds|test_account|operator_required|none} · `business_richness_score` INTEGER NOT NULL =0 · `focus_value_score` INTEGER NOT NULL =0 · `total_score` INTEGER NOT NULL =0 · `tier` TEXT NOT NULL ='unranked' · `rank` INTEGER · `status` TEXT NOT NULL ='ranked' ∈{ranked|focused|parked|completed|excluded} · `focused_at` TEXT · `timebox_minutes` INTEGER NOT NULL =120 · `timebox_until` TEXT · `dimension_scores_json` TEXT NOT NULL ='{}' · `evidence_json` TEXT NOT NULL ='[]' · `created_at` TEXT =(datetime('now','localtime')) · `updated_at` TEXT =(datetime('now','localtime'))

**`soft_targets`** (21 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `asset_id` INTEGER · `asset_type` TEXT ='domain' · `asset_value` TEXT NOT NULL · `port` INTEGER · `protocol` TEXT ='https' · `total_score` INTEGER NOT NULL =0 · `raw_score` INTEGER NOT NULL =0 · `penalty` INTEGER NOT NULL =0 · `tier` TEXT NOT NULL · `rank` INTEGER · `status` TEXT NOT NULL ='ranked' ∈{ranked|available|focused|failed|parked|completed|excluded} · `dimension_scores_json` TEXT NOT NULL ='{}' · `evidence_json` TEXT NOT NULL ='[]' · `failure_reason` TEXT · `failure_evidence_json` TEXT · `focused_at` TEXT · `completed_at` TEXT · `created_at` TEXT =(datetime('now','localtime')) · `updated_at` TEXT =(datetime('now','localtime'))

**`soft_target_events`** (10 cols)

`id` INTEGER PK · `soft_target_id` INTEGER · `target_name` TEXT NOT NULL · `asset_value` TEXT NOT NULL · `from_status` TEXT · `to_status` TEXT NOT NULL ∈{ranked|available|focused|failed|parked|completed|excluded} · `reason` TEXT · `evidence_json` TEXT · `actor` TEXT ='soft_target_scorer' · `created_at` TEXT =(datetime('now','localtime'))

**`attack_threads`** (26 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `asset_url` TEXT · `hypothesis` TEXT NOT NULL · `why_promising` TEXT · `current_evidence` TEXT · `next_probe` TEXT · `confidence` TEXT ='low' ∈{low|medium|high} · `priority` INTEGER =50 · `status` TEXT ='active' ∈{proposed|active|candidate|parked|killed} · `kill_condition` TEXT · `owner` TEXT · `sprint_id` TEXT · `hunt_session_id` INTEGER · `hypothesis_kind` TEXT ='falsifiable' · `expected_observation` TEXT ='' · `refuting_observation` TEXT ='' · `alternative_explanations_json` TEXT NOT NULL ='[]' · `information_gain` INTEGER NOT NULL =0 · `stop_conditions_json` TEXT NOT NULL ='[]' · `pivot_options_json` TEXT NOT NULL ='[]' · `evaluation_status` TEXT NOT NULL ='untested' ∈{untested|supported|refuted|inconclusive|blocked} · `last_evaluated_at` TEXT · `created_at` TEXT =(datetime('now','localtime')) · `updated_at` TEXT =(datetime('now','localtime')) · `last_partial_at` TEXT

**`attack_thread_events`** (7 cols)

`id` INTEGER PK · `attack_thread_id` INTEGER · `actor` TEXT NOT NULL · `event_type` TEXT NOT NULL ∈{created|partial|pivot|parked|killed|candidate|operator_decision} · `severity` TEXT ='info' ∈{debug|info|notice|warning|critical} · `payload_json` TEXT NOT NULL · `created_at` TEXT =(datetime('now','localtime'))

### 情报与认知闭环

**`suspicious_points`** (22 cols)

`id` TEXT PK NOT NULL · `page_url` TEXT · `url` TEXT · `param` TEXT · `method` TEXT ='GET' · `test_type` TEXT · `evidence` TEXT · `source` TEXT · `reasoning` TEXT · `risk` TEXT ='Medium' · `test_status` TEXT ='untested' · `burp_request_id` INTEGER · `created_at` TEXT =(datetime('now', 'localtime')) · `notes` TEXT · `endpoint_fingerprint` TEXT · `response_summary` TEXT · `risk_score` INTEGER =0 · `canonical_url` TEXT · `auth_surface_type` TEXT · `signal_value` TEXT · `signal_reason` TEXT · `noise_reason` TEXT

**`inspirations`** (21 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `stage` TEXT NOT NULL ='gleam' ∈{gleam|clue} · `content` TEXT NOT NULL · `trigger` TEXT · `source` TEXT NOT NULL ='human' ∈{agent|human|harvest} · `agent_id` TEXT · `session_id` TEXT · `confidence` TEXT NOT NULL ='low' ∈{low|medium|high} · `status` TEXT NOT NULL ='open' ∈{open|queued|verified|refuted|harvested|discarded} · `refined_from_id` INTEGER · `blocked_on_kind` TEXT · `blocked_on_id` INTEGER · `promoted_sp_id` INTEGER · `promoted_wi_id` INTEGER · `harvest_id` TEXT · `harvest_note` TEXT · `notes` TEXT · `asset_id` INTEGER · `created_at` TEXT =(datetime('now','localtime')) · `updated_at` TEXT =(datetime('now','localtime'))

**`pattern_guesses`** (16 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `seed_evidence_json` TEXT NOT NULL · `pattern` TEXT NOT NULL · `pattern_type` TEXT NOT NULL ∈{url_replace|route_guess|prefix|subdomain_guess|bucket_guess} · `derived_candidates_json` TEXT NOT NULL · `verify_action` TEXT · `verify_bound` INTEGER =100 · `gate_required` INTEGER =0 · `gate_status` TEXT ='none' ∈{none|auto_allowed|gated|approved|rejected} · `status` TEXT ='generated' ∈{generated|verified|confirmed|refuted|parked} · `result_summary` TEXT · `attack_thread_id` INTEGER · `work_item_ids_json` TEXT · `created_at` TEXT =(datetime('now','localtime')) · `updated_at` TEXT =(datetime('now','localtime'))

**`experience_entries`** (12 cols)

`id` INTEGER PK · `target_name` TEXT · `category` TEXT NOT NULL · `title` TEXT NOT NULL · `body` TEXT NOT NULL · `trigger_signal` TEXT · `source_inspiration_id` INTEGER · `effectiveness` TEXT NOT NULL ='untested' ∈{untested|validated|mixed|invalid} · `reuse_count` INTEGER NOT NULL =0 · `notes` TEXT · `created_at` TEXT =(datetime('now','localtime')) · `updated_at` TEXT =(datetime('now','localtime'))

**`experiments`** (25 cols)

`id` INTEGER PK · `hunt_session_id` INTEGER NOT NULL · `attack_thread_id` INTEGER NOT NULL · `work_item_id` INTEGER · `experiment_key` TEXT NOT NULL · `question` TEXT NOT NULL · `method_class` TEXT NOT NULL ∈{offline|passive|active_low|operator_gated} · `expected_observation` TEXT NOT NULL · `control_description` TEXT NOT NULL · `budget_json` TEXT NOT NULL ='{}' · `stop_conditions_json` TEXT NOT NULL ='[]' · `risk_class` TEXT NOT NULL ='safe_passive' · `status` TEXT NOT NULL ='proposed' ∈{proposed|approved|queued|running|observed|blocked|cancelled} · `outcome` TEXT NOT NULL ='not_run' ∈{supports|refutes|inconclusive|blocked|not_run} · `observation_summary` TEXT ='' · `alternative_explanation` TEXT ='' · `evidence_refs_json` TEXT NOT NULL ='[]' · `confidence_before` TEXT ='unknown' · `confidence_after` TEXT ='unknown' · `unknown_items_before_json` TEXT NOT NULL ='[]' · `unknown_items_after_json` TEXT NOT NULL ='[]' · `surprise_score` INTEGER NOT NULL =0 · `created_at` TEXT =(datetime('now','localtime')) · `updated_at` TEXT =(datetime('now','localtime')) · `finished_at` TEXT

**`decision_events`** (14 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `hunt_session_id` INTEGER · `attack_thread_id` INTEGER · `experiment_id` INTEGER · `actor` TEXT NOT NULL · `decision_type` TEXT NOT NULL ∈{focus|dispatch|continue|park|pivot|escalate|stop} · `compact_snapshot_json` TEXT NOT NULL ='{}' · `candidate_actions_json` TEXT NOT NULL ='[]' · `chosen_action` TEXT NOT NULL · `rationale` TEXT NOT NULL · `expected_change` TEXT NOT NULL ='' · `actual_change` TEXT NOT NULL ='' · `created_at` TEXT =(datetime('now','localtime'))

**`coverage_ledger`** (14 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `profile_id` INTEGER · `work_item_id` INTEGER · `item_key` TEXT NOT NULL · `category` TEXT NOT NULL · `status` TEXT NOT NULL ='unknown' ∈{covered|unknown|uncovered|blocked} · `confidence` TEXT ='unknown' ∈{low|medium|high|unknown} · `evidence_refs_json` TEXT NOT NULL ='[]' · `summary` TEXT · `blocker_reason` TEXT · `next_action` TEXT · `created_at` TEXT =(datetime('now','localtime')) · `updated_at` TEXT =(datetime('now','localtime'))

**`evidence_refs`** (9 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `source_table` TEXT NOT NULL · `source_id` TEXT NOT NULL · `evidence_type` TEXT NOT NULL ∈{request|response|diff|screenshot|js_signal|hypothesis|semantic_profile|coverage_ledger|repeater_tab|operator_note} · `title` TEXT · `summary` TEXT · `ref_json` TEXT · `created_at` TEXT =(datetime('now','localtime'))

**`endpoint_evidence_links`** (4 cols)

`endpoint_id` INTEGER PK NOT NULL · `evidence_ref_id` INTEGER PK NOT NULL · `relation` TEXT NOT NULL ='observed' · `created_at` TEXT =(datetime('now','localtime'))

**`hunt_queue`** (25 cols)

`id` INTEGER PK · `target_id` INTEGER · `method` TEXT NOT NULL · `url` TEXT NOT NULL · `query_string` TEXT · `body` TEXT · `content_type` TEXT · `burp_history_id` INTEGER · `endpoint_type` TEXT · `business_intent` TEXT · `risk_hint` TEXT ='Medium' · `status` TEXT ='queued' ∈{queued|in_progress|tested|confirmed|error} · `tested_types_json` TEXT ='[]' · `finding_ids` TEXT ='' · `created_at` TEXT =(datetime('now','localtime')) · `tested_at` TEXT · `notes` TEXT · `source` TEXT ='auto' ∈{auto|manual_replay|auth_explore} · `flow_id` TEXT · `endpoint_fingerprint` TEXT · `canonical_url` TEXT · `signal_value` TEXT · `signal_reason` TEXT · `risk_score` INTEGER =0 · `noise_reason` TEXT

**`hunt_sessions`** (18 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `soft_target_id` INTEGER · `focus_subject_table` TEXT NOT NULL · `focus_subject_id` TEXT NOT NULL · `goal` TEXT NOT NULL · `success_criteria_json` TEXT NOT NULL ='[]' · `stop_conditions_json` TEXT NOT NULL ='[]' · `status` TEXT NOT NULL ='proposed' ∈{proposed|active|paused|completed|abandoned} · `selected_by` TEXT NOT NULL · `system_id` INTEGER · `recon_readiness_snapshot_json` TEXT NOT NULL ='{}' · `operator_acknowledged_at` TEXT · `started_at` TEXT · `ended_at` TEXT · `summary` TEXT · `created_at` TEXT =(datetime('now','localtime')) · `updated_at` TEXT =(datetime('now','localtime'))

### 漏洞成果

**`findings`** (20 cols)

`id` TEXT PK · `sp_id` TEXT · `target_id` INTEGER · `type` TEXT · `url` TEXT · `param` TEXT · `method` TEXT · `payload` TEXT · `evidence` TEXT · `risk` TEXT · `cvss` TEXT · `remediation` TEXT · `confirmed_at` TEXT · `burp_request_id` INTEGER · `review_status` TEXT =NULL · `review_notes` TEXT · `reported_platforms` TEXT ='' · `report_file` TEXT · `audit_status` TEXT ='pending' · `audit_notes` TEXT =NULL

### 认证与会话

**`auth_sessions`** (14 cols)

`id` INTEGER PK · `token_type` TEXT · `token_name` TEXT · `token_value` TEXT · `domain` TEXT · `path` TEXT ='/' · `is_active` INTEGER =1 · `created_at` TEXT =(datetime('now', 'localtime')) · `role` TEXT ='primary' · `expires_at` TEXT · `last_checked_at` TEXT · `cookie_source` TEXT ='manual' · `username` TEXT =NULL · `password` TEXT =NULL

**`auth_credentials`** (6 cols)

`id` INTEGER PK · `account_label` TEXT · `username` TEXT · `password` TEXT · `login_url` TEXT · `created_at` TEXT =(datetime('now', 'localtime'))

**`auth_storage_tokens`** (12 cols)

`id` INTEGER PK · `role` TEXT ='primary' · `storage_type` TEXT NOT NULL · `origin` TEXT NOT NULL · `token_name` TEXT NOT NULL · `token_value` TEXT NOT NULL · `token_kind` TEXT ='storage' · `is_active` INTEGER =1 · `first_seen_at` TEXT =(datetime('now','localtime')) · `last_seen_at` TEXT =(datetime('now','localtime')) · `expires_at` TEXT · `source` TEXT ='cdp_capture'

**`auth_flow_steps`** (8 cols)

`id` INTEGER PK · `step_index` INTEGER · `action_type` TEXT · `url` TEXT · `selector_uid` TEXT · `value` TEXT · `wait_ms` INTEGER · `description` TEXT

**`browser_actions`** (10 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `work_item_id` INTEGER · `action_type` TEXT NOT NULL ∈{open_url|capture_screenshot|manual_login|inspect_page} · `url` TEXT · `selector` TEXT · `note` TEXT · `status` TEXT ='queued' ∈{queued|done|failed|skipped} · `created_at` TEXT =(datetime('now','localtime')) · `completed_at` TEXT

### 业务状态机

**`business_flows`** (17 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `asset_id` INTEGER · `system_id` INTEGER · `flow_key` TEXT NOT NULL · `name` TEXT NOT NULL · `category` TEXT · `entry_url` TEXT · `derivation` TEXT ='manual' · `completeness` TEXT ='skeleton' · `prerequisites_json` TEXT NOT NULL ='[]' · `description` TEXT · `status` TEXT NOT NULL ='draft' · `confidence` TEXT NOT NULL ='unknown' · `evidence_refs_json` TEXT NOT NULL ='[]' · `created_at` TEXT =(datetime('now','localtime')) · `updated_at` TEXT =(datetime('now','localtime'))

**`business_flow_steps`** (16 cols)

`id` INTEGER PK · `flow_id` INTEGER NOT NULL · `step_order` INTEGER NOT NULL · `step_key` TEXT NOT NULL · `name` TEXT NOT NULL · `endpoint_id` INTEGER · `url` TEXT · `method` TEXT · `action_hint` TEXT · `business_state` TEXT · `preconditions_json` TEXT NOT NULL ='[]' · `test_plan_json` TEXT NOT NULL ='[]' · `mapping_status` TEXT NOT NULL ='logical' · `evidence_refs_json` TEXT NOT NULL ='[]' · `created_at` TEXT =(datetime('now','localtime')) · `updated_at` TEXT =(datetime('now','localtime'))

**`business_flow_progress`** (11 cols)

`id` INTEGER PK · `flow_id` INTEGER NOT NULL · `step_id` INTEGER NOT NULL · `current_state` TEXT · `step_status` TEXT NOT NULL ='not_reached' · `blocked_reason` TEXT · `coverage_ledger_id` INTEGER · `suspicious_point_id` TEXT · `finding_id` TEXT · `evidence_refs_json` TEXT NOT NULL ='[]' · `updated_at` TEXT =(datetime('now','localtime'))

**`business_flow_templates`** (4 cols)

`id` INTEGER PK · `category` TEXT NOT NULL · `attack_surface_hints_json` TEXT NOT NULL ='[]' · `test_notes` TEXT

### 工作队列与协作

**`work_items`** (34 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `lane` TEXT NOT NULL · `subtype` TEXT · `subject_table` TEXT NOT NULL · `subject_id` TEXT NOT NULL · `attack_thread_id` INTEGER · `title` TEXT · `objective` TEXT · `priority` INTEGER =50 · `status` TEXT ='queued' ∈{queued|claimed|partial|blocked|done|failed|cancelled} · `claimed_by` TEXT · `claimed_at` TEXT · `lease_until` TEXT · `heartbeat_at` TEXT · `timebox_minutes` INTEGER =10 · `heartbeat_minutes` INTEGER =5 · `attempt_count` INTEGER =0 · `max_attempts` INTEGER =3 · `model_tier` TEXT ='sonnet' ∈{haiku|sonnet|opus} · `reasoning_tier` TEXT ='low' ∈{low|medium|high} · `upgrade_policy` TEXT ='ask_main' ∈{never|ask_main|auto_if_high_risk_signal} · `auth_requirement` TEXT ='unknown' ∈{none|optional|required|multi_account_required|role_required|unknown} · `risk_class` TEXT ='safe_passive' ∈{safe_passive|safe_replay|sensitive_read|state_changing|high_risk} · `summary` TEXT · `next_action` TEXT · `blocker_reason` TEXT · `last_error` TEXT · `created_at` TEXT =(datetime('now','localtime')) · `updated_at` TEXT =(datetime('now','localtime')) · `dispatch_state` TEXT ='active' · `system_id` INTEGER · `park_reason` TEXT · `blocker_class` TEXT ∈{auth_barrier|network|scope|evidence|critical_found|refuted|parked|other}

**`operator_inbox`** (22 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `related_work_item_id` INTEGER · `kind` TEXT NOT NULL ∈{choose_asset|login_required|secondary_account_required|role_account_required|screenshot_needed|confirm_scope|confirm_high_risk|manual_review|report_decision|evidence_capture|focus_switch|registration_required|burp_action_required|scope_cluster_confirm|blocked_decision} · `title` TEXT NOT NULL · `detail` TEXT · `suggested_action` TEXT · `url` TEXT · `burp_action_id` INTEGER · `evidence_ref_id` INTEGER · `system_id` INTEGER · `action_key` TEXT · `action_label` TEXT · `why_needed` TEXT · `steps_json` TEXT NOT NULL ='[]' · `expected_observation` TEXT · `report_back_format` TEXT · `blocking` INTEGER NOT NULL =1 · `status` TEXT ='open' ∈{open|accepted|skipped|done|cancelled} · `created_at` TEXT =(datetime('now','localtime')) · `resolved_at` TEXT · `expires_at` TEXT

**`agent_events`** (7 cols)

`id` INTEGER PK · `work_item_id` INTEGER · `agent_id` TEXT NOT NULL · `event_type` TEXT NOT NULL ∈{heartbeat|partial_result|hypothesis|replay_result|evidence|blocker|needs_operator|upgrade_request|done|failed} · `severity` TEXT ='info' ∈{debug|info|notice|warning|critical} · `payload_json` TEXT NOT NULL · `created_at` TEXT =(datetime('now','localtime'))

**`burp_actions`** (16 cols)

`id` INTEGER PK · `target_name` TEXT NOT NULL · `work_item_id` INTEGER · `action_type` TEXT NOT NULL ∈{send_to_repeater|replay_compare|active_scan|collaborator_check} · `method` TEXT · `url` TEXT · `headers_json` TEXT · `body` TEXT · `note` TEXT · `risk_class` TEXT ='safe_replay' ∈{safe_passive|safe_replay|sensitive_read|state_changing|high_risk} · `repeater_tab_name` TEXT · `burp_request_ref` TEXT · `status` TEXT ='queued' ∈{queued|sent|failed|skipped} · `error` TEXT · `created_at` TEXT =(datetime('now','localtime')) · `sent_at` TEXT

### ETL 缓存

**`etl_cache`** (8 cols)

`id` INTEGER PK · `task` TEXT NOT NULL · `instruction_hash` TEXT NOT NULL · `data_hash` TEXT NOT NULL · `result` TEXT NOT NULL · `model` TEXT NOT NULL · `created_at` TEXT =(datetime('now', 'localtime')) · `hit_count` INTEGER =0

