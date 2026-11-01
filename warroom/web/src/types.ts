// 后端 API 数据契约（来自 warroom/server.py 实测）
export interface Target {
  db: string
  target: string
}

/** 主视图 id（活动栏；资产视图已并入队列二级目录，不在此列） */
export type ViewId = 'overview' | 'queue' | 'findings' | 'timeline' | 'blockers' | 'insightwall'

/** 顶部 VSCode 式标签页 */
export type Tab =
  | { id: string; kind: 'view'; view: ViewId; title: string }
  | { id: string; kind: 'asset'; host: string; title: string }
  | { id: string; kind: 'finding'; findingId: string; title: string }

export interface WorkSummary {
  queued: number; claimed: number; partial: number
  blocked: number; done: number; failed: number; cancelled: number
}

export interface SoftTargetItem {
  id: number; rank: number; asset_id: number; asset: string
  port: number | null; protocol: string; status: string; score: number
  tier: string; estimated_test_cost: string; evidence_count: number
  live_status: string; auth_required: boolean; auth_entry_found: boolean
}

export interface SoftTargets {
  target?: string; count?: number
  results: SoftTargetItem[]
  selection_required?: boolean
  empty?: boolean
  message?: string
}

export interface WorkerResult {
  work_item_id: number | string
  agent_id: string
  lane: string
  status: string
  conclusion: string
  summary: string
  evidence_refs: string[]
  confidence: string
  blocker: string
  block_reason: string
  next_action: string
  risk_level: string | null
  upgrade_request: string | null
  created_at: string
  id?: number
  event_type?: string
}

export interface AgentEvent {
  work_item_id: number | string
  agent_id: string
  event_type: string
  severity: string
  lane: string
  subtype: string
  created_at: string
  wi_status?: string
  payload_json?: string
  id?: number
}

export interface NextAction {
  work_item_id: number | string
  lane: string
  title: string
  priority: number
}

export interface ViewData {
  overview: {
    work_summary: WorkSummary
    soft_targets: SoftTargets
    operator_inbox: any[]
    worker_results: WorkerResult[]
    attack_surface: any
    next_actions: any[]
  }
  state: any
  chain: any
  timeline: {
    recent_events: AgentEvent[]
    recent_worker_results: WorkerResult[]
    next_actions: NextAction[]
    cognitive_next: any[]
  }
  recon: any
}

export interface QueueItem {
  id: number | string; lane: string; subtype: string; title: string
  raw_title: string; hint: string; status: string; url: string; priority: number | null
  claimed_by: string | null; summary: string; next_action: string; blocker_reason: string
  subject_table: string; subject_id: number | null; asset_host: string
}

export interface AssetItem {
  id: number; asset_value: string; asset_type: string; port: number | null
  protocol: string; live_status: string; scope_status: string
  tech_stack: string | null; resolved_ip: string | null
  source: string; auth_required: number; login_urls: string
  endpoint_count?: number
  // 详情页字段（后端 _asset_detail 已补，2026-08-15）
  notes: string | null
  last_title: string | null
  last_status_code: number | null
  last_tech_stack: string | null
  last_verified_at: string | null
  last_verify_status: string | null
  scope_reason: string | null
  auth_blocker: string | null
  relation_to_target: string | null
  authorization_state: string | null
  register_urls: string | null
  requires_auth: number | null
  status: string | null
  priority: number | null
}

export interface Endpoint {
  canonical_url: string; host: string; path: string; method: string
  source: string; status_code: number | null; content_type: string | null
  business_hint: string | null; route_kind: string | null
  service_hint: string | null; auth_state: string | null
  waf_state: string | null; test_status: string | null
}

export interface AssetQueueItem {
  id: number | string; lane: string; subtype: string; title: string; hint: string
  status: string; priority: number | null
  asset_host?: string
  url?: string
}

export interface SuspiciousPoint {
  id: string
  test_type: string; risk: string; url: string; status: string
  reasoning?: string
}

export interface AssetDetail {
  asset: AssetItem | null
  endpoints: Endpoint[]
  queue: AssetQueueItem[]
  findings: FindingItem[]
  inspirations?: InsightItem[]
  note?: string
}

export type StageState = 'none' | 'queued' | 'doing' | 'done' | 'blocked'
export type DiscloseGroup = 'blocked' | 'progress' | 'penetrated' | 'queued' | 'untouched'

export interface DisclosureAsset {
  id: number; asset_value: string; asset_type: string; port: number | null
  protocol: string; live_status: string; scope_status: string
  tech_stack: string | null; resolved_ip: string | null
  stages: Record<string, StageState>
  stage_labels: string[]
  deepest_stage: string | null
  deepest_index: number
  stuck_stage: string | null
  group: DiscloseGroup
  findings: { type: string; risk: string; url: string }[]
  suspicious_points: SuspiciousPoint[]
  endpoint_count: number
}

export interface DisclosureData {
  assets: DisclosureAsset[]
  stages: { key: string; label: string }[]
}

export interface FindingItem {
  id: string; type: string; url: string; param: string; method: string
  risk: string; review_status: string; confirmed_at: string
  report_file: string | null; audit_status: string
  // 详情字段（后端 _findings 已补，2026-08-15）
  cvss: string | null; remediation: string | null
  review_notes: string | null; audit_notes: string | null
  payload: string | null
  reported_platforms: string | null
  evidence: string | null
  sp_id: string | null
}

export interface BlockersData {
  blocked_items: { id: number | string; lane: string; title: string; blocker_reason: string; blocker_class: string; class_zh: string; reason_zh: string; status: string; updated_at: string }[]
  operator_inbox: any[]
  coverage_blocked: any[]
  progress: { agent: string; event: string; status: string; conclusion: string; time: string }[]
  counts: { blocked: number; inbox: number; coverage: number }
}

export interface InsightItem {
  id: number; stage: string; content: string; trigger: string; status: string; confidence: string
  created_at?: string
  score?: number
}
export interface InsightBlock {
  kind: string; id: number | null; title: string; summary: string; reason: string
  asset_host: string; url: string; inspirations: InsightItem[]
}
export interface InsightWallData {
  blocks: InsightBlock[]; counts: { total: number }
}

/** 因果链全览(/api/insight-chains):同 target 全览链视图(灵光→线索→堵点上下文) */
export interface InsightChainItem {
  inspiration_id: number; stage: string; content: string; trigger: string
  status: string; confidence: string
  refined_from: string | null
  blocker: InsightBlockerContext | null
}
export interface InsightChainsData {
  chains: InsightChainItem[]
  stats: { total: number; open: number; gleam: number; clue: number }
}

/** 详情:单条灵感完整前因后果(/api/insight-detail) */
export interface InsightRefinedFrom {
  id: number; stage: string; content: string; trigger: string; confidence: string; status: string
}
export interface InsightBlockerContext {
  kind: string; id: number | null; title: string; detail: string
  host: string; url: string
}
export interface InsightUpstream {
  refined_from: InsightRefinedFrom | null
  blocker: InsightBlockerContext | null
}
export interface InsightResult {
  kind: string; id: number | null; title: string; detail: string
  risk?: string; host?: string; url?: string; lane?: string; status?: string
}
export interface InsightDownstream {
  promoted_sp: InsightResult | null
  promoted_wi: InsightResult | null
}
export interface InsightHarvest {
  harvest_id?: string; harvest_note?: string
}
export interface InsightDetailData {
  found: boolean
  error?: string
  inspiration: InsightItem & {
    source?: string; blocked_on_kind: string | null; blocked_on_id: number | null
    promoted_sp_id: number | null; promoted_wi_id: number | null
    refined_from_id: number | null; created_at: string; updated_at?: string
    harvest_id?: string; harvest_note?: string; notes?: string
  } | null
  upstream: InsightUpstream | null
  downstream: InsightDownstream | null
  harvest: InsightHarvest | null
}
