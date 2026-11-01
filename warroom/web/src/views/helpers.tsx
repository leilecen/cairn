import type { ReactNode } from 'react'
import { useApp } from '../store'
import { resolveUrl } from '../url'

/** 当前聚焦资产 host（主攻资产，用于相对路径 URL 拼接） */
export function useFocus() {
  const { focusAsset } = useApp()
  return focusAsset
}

/* ============================================================
 * 轻组件层 —— 统一视觉语言（DeepSeek 深色 + 反 AI 味）
 * 原则：克制、方形标签、tint 色、无大面积纯色
 * ============================================================ */

/** 面板卡片：无标题时只作容器 */
export function Card({ title, children, className = '' }: { title?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`bg-surface-2 border border-edge rounded-lg px-3.5 py-3 mb-3 ${className}`}>
      {title != null && (
        <header className="mb-2.5 text-[11px] font-bold text-ink-dim tracking-[0.08em] uppercase">{title}</header>
      )}
      {children}
    </section>
  )
}

/** 标签（chip）：克制方形、细边框、tint 文字色，无彩色底。anthem 为品牌强调。 */
export function Pill({ color, children, title, anthem }: { color: string; children: ReactNode; title?: string; anthem?: boolean }) {
  return (
    <span
      title={title}
      className={`inline-flex items-center border px-1.5 py-px text-[11px] leading-4 whitespace-nowrap rounded-[4px] ${
        anthem ? 'border-accent/40 text-accent-soft' : ''
      }`}
      style={anthem ? undefined : { color, borderColor: `color-mix(in srgb, ${color} 45%, transparent)`, background: 'transparent' }}
    >
      {children}
    </span>
  )
}

/** 外链：相对路径按主攻资产 host 拼接；不可解析时显示为灰字 */
export function Link({ url, focusHost, text }: { url: string; focusHost: string | null; text?: string }) {
  const href = resolveUrl(url, focusHost)
  if (!href) return <span className="dim mono break-all">{text || url || '—'}</span>
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="text-accent-soft hover:underline break-all no-underline"
      onClick={e => { e.preventDefault(); window.open(href, '_blank', 'noopener') }}
    >
      {text || url}
    </a>
  )
}

/** 空态占位 */
export function Empty({ msg }: { msg: string }) {
  return <div className="dim text-center py-6 text-xs">{msg}</div>
}

/** 行项目：hover 高亮、底部细线分隔（列表通用） */
export function Row({ children, onClick, title }: { children: ReactNode; onClick?: () => void; title?: string }) {
  return (
    <div
      title={title}
      onClick={onClick}
      className={`flex items-center gap-2.5 px-2 py-1.5 border-b border-edge text-xs ${
        onClick ? 'cursor-pointer hover:bg-surface-4/50' : ''
      }`}
    >
      {children}
    </div>
  )
}

/** 统一表格容器 */
export function Table({ head, children }: { head: string[]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-xs">
        <thead>
          <tr className="text-left text-ink-dim border-b border-edge-2">
            {head.map(h => (
              <th key={h} className="px-2 py-1.5 font-semibold whitespace-nowrap">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  )
}

export function Td({ children, className = '' }: { children?: ReactNode; className?: string }) {
  return <td className={`px-2 py-1.5 align-top border-b border-edge ${className}`}>{children}</td>
}

/** 小按钮 */
export function Btn({ children, onClick, disabled, title }: { children: ReactNode; onClick?: () => void; disabled?: boolean; title?: string }) {
  return (
    <button
      title={title}
      onClick={onClick}
      disabled={disabled}
      className="bg-surface-3 text-ink border border-edge-2 rounded-md px-2.5 py-[3px] text-xs cursor-pointer hover:bg-surface-4 disabled:opacity-40 disabled:cursor-default whitespace-nowrap"
    >
      {children}
    </button>
  )
}

/** evidence/notes 等 JSON 字符串 → 结构化可读展示（键值对 / 数组列表，不再贴原始 JSON） */
export function JsonBlock({ json, className = '' }: { json: string; className?: string }) {
  let parsed: unknown
  try { parsed = JSON.parse(json) } catch { /* 非 JSON 原样显示 */ }
  if (typeof parsed === 'string' || parsed === null || parsed === undefined) {
    return <div className={`text-xs whitespace-pre-wrap leading-5 ${className}`}>{json}</div>
  }
  return <JsonNode data={parsed} depth={0} className={className} />
}

/** 字段中文映射（evidence 常见键） */
const EVIDENCE_KEYS_ZH: Record<string, string> = {
  confidence: '置信度', evidence_refs: '证据引用', next_action: '下一步',
  raw_evidence_policy: '证据策略', schema: '结构', source_sp_id: '来源疑点',
  source_work_item_id: '来源任务', summary: '摘要', impact: '影响面',
  affected: '影响资产', credentials: '凭据', status: '状态', leak: '泄露内容',
  deploy_time: '部署时间', errcode: '错误码', evidence: '证据', method: '方法',
  url: 'URL', test_type: '测试类型', risk: '风险', result: '结果', detail: '详情',
  version: '版本', count: '数量', items: '条目', flags: '标志',
}

function JsonNode({ data, depth, className = '' }: { data: unknown; depth: number; className?: string }) {
  if (Array.isArray(data)) {
    return (
      <div className={className}>
        {data.length === 0 && <span className="dim text-xs">（空）</span>}
        {data.map((item, i) => (
          <div key={i} className={depth > 0 ? 'ml-2 border-l border-edge pl-2 mb-1' : 'mb-1'}>
            {typeof item === 'object' && item !== null ? (
              <JsonNode data={item} depth={depth + 1} />
            ) : (
              <span className="text-xs leading-5 break-all">{String(item)}</span>
            )}
          </div>
        ))}
      </div>
    )
  }
  if (typeof data === 'object' && data !== null) {
    const entries = Object.entries(data as Record<string, unknown>)
    return (
      <div className={className}>
        {entries.map(([k, v]) => {
          const label = EVIDENCE_KEYS_ZH[k] || k
          if (typeof v === 'object' && v !== null) {
            return (
              <div key={k} className="mb-1.5">
                <div className="text-[11px] font-semibold text-ink-dim mb-0.5">{label}</div>
                <JsonNode data={v} depth={depth + 1} />
              </div>
            )
          }
          return (
            <div key={k} className="flex items-baseline gap-2 py-0.5">
              <span className="text-[11px] text-ink-dim shrink-0 w-24 truncate">{label}</span>
              <span className="text-xs break-all leading-5">{String(v)}</span>
            </div>
          )
        })}
      </div>
    )
  }
  return <span className="text-xs break-all">{String(data)}</span>
}
