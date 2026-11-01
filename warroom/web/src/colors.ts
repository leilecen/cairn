// 状态 → 语义色映射。所有颜色引用 CSS 设计 token（见 index.css @theme），
// 不再散落硬编码彩虹色。低饱和 VSCode Dark+ 调性。
const tok = (name: string) => `var(--color-${name})`

// 漏洞风险级（key 大小写不敏感，DB 中混用 critical/Critical/Medium）
const RISK_MAP: Record<string, string> = {
  Critical: tok('danger'),
  High: tok('warn'),
  Medium: tok('warn'),
  Low: tok('ok'),
  Info: tok('info'),
}
export function riskColor(risk: string | null | undefined): string {
  if (!risk) return tok('info')
  const k = risk.charAt(0).toUpperCase() + risk.slice(1).toLowerCase()
  return RISK_MAP[k] || tok('info')
}

// 队列工作项状态
export const statusColor: Record<string, string> = {
  queued: tok('ink-dim'),
  claimed: tok('info'),
  partial: tok('violet'),
  blocked: tok('danger'),
  done: tok('ok'),
  failed: tok('danger'),
  cancelled: tok('ink-dim'),
}

// 披露阶段状态色
export const stageColor: Record<string, string> = {
  none: tok('edge-2'),
  queued: tok('ink-dim'),
  doing: tok('info'),
  done: tok('ok'),
  blocked: tok('danger'),
}

// 资产披露分组色
export const groupColor: Record<string, string> = {
  blocked: tok('danger'),
  progress: tok('info'),
  penetrated: tok('ok'),
  queued: tok('warn'),
  untouched: tok('ink-dim'),
}

export const groupLabel: Record<string, string> = {
  blocked: '卡住',
  progress: '进行中',
  penetrated: '已打穿',
  queued: '已排队',
  untouched: '未开始',
}

// 资产存活状态
export const liveColor: Record<string, string> = {
  alive: tok('ok'),
  live: tok('ok'),
  dead: tok('ink-dim'),
  down: tok('ink-dim'),
  unknown: tok('ink-dim'),
  '': tok('ink-dim'),
}
