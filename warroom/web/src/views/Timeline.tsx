import { useQuery } from '@tanstack/react-query'
import { useApp } from '../store'
import { fetchView } from '../api'
import { Card, Empty, Pill } from './helpers'
import { statusColor } from '../colors'
import type { AgentEvent, WorkerResult } from '../types'

// lane → 中文（与 server.py DISCLOSURE_STAGES 对齐 + 其他 lane）
const LANE_ZH: Record<string, string> = {
  source_intel: '情报收集', origin_verify: '归属验证', quick_scout: '快速侦察',
  network_profile: '端口/服务面', entry_probe: '入口探测', js_reverse: 'JS 逆向',
  preauth_probe: '未授权探测', logic_probe: '逻辑漏洞', vuln_review: '漏洞复核',
  evidence_pack: '证据打包', report_audit: '报告审核',
  asset_triage: '资产分诊', entry_explore: '入口探索', operator_task: '操作员任务',
  replay: '重放', semantic_profile: '画像', postexp: '后渗透',
}
export const laneZh = (lane: string) => LANE_ZH[lane] || lane

// 事件类型 → 中文
const EVENT_ZH: Record<string, string> = {
  done: '完成', heartbeat: '心跳', partial: '部分完成', blocked: '阻塞',
  claimed: '认领', queued: '排队', created: '创建', failed: '失败', cancelled: '取消',
}
const eventZh = (e: string) => EVENT_ZH[e] || e

export function TimedLine() {
  const { target } = useApp()
  const { data } = useQuery({ queryKey: ['view', target], queryFn: () => fetchView(target), enabled: !!target })
  const tl = data?.timeline

  if (!data) return <Empty msg="加载中…" />

  const events: any[] = tl?.recent_events ?? []
  const workers: any[] = tl?.recent_worker_results ?? []
  const next: any[] = tl?.next_actions ?? []

  return (
    <div>
      {/* 事件流：时间轴样式，一行一个结构化事件（含资产 + 任务标题） */}
      <Card title={`最近事件（${events.length}）`}>
        {!events.length && <Empty msg="无" />}
        <div className="relative pl-4">
          {events.slice(0, 30).map((e, i) => (
            <div key={i} className="relative pb-2.5 border-l border-edge pl-3 last:border-transparent">
              <span
                className="absolute -left-[3.5px] top-1.5 w-1.5 h-1.5 rounded-full"
                style={{ background: e.event_type === 'done' ? 'var(--color-ok)' : e.event_type === 'blocked' ? 'var(--color-danger)' : e.event_type === 'heartbeat' ? 'var(--color-ink-dim)' : 'var(--color-info)' }}
              />
              <div className="flex items-center gap-1.5 text-xs flex-wrap">
                <span className="dim mono shrink-0">{e.created_at}</span>
                <Pill color="var(--color-info)">{laneZh(e.lane || '')}</Pill>
                <span className="font-semibold" style={{ color: statusColor[e.event_type] || 'var(--color-ink)' }}>
                  {eventZh(e.event_type)}
                </span>
                {/* 资产 + 任务标题（说清"对谁做了什么"） */}
                {e.asset_host && <span className="text-violet shrink-0 font-semibold">{e.asset_host}</span>}
                {e.wi_title && <span className="dim truncate max-w-[300px]">{e.wi_title}</span>}
                {e.agent_id && <span className="dim mono shrink-0">{e.agent_id}</span>}
              </div>
            </div>
          ))}
        </div>
      </Card>

      {/* worker 结果：两行结构（状态行 + 结论行），结论可展开 */}
      <Card title={`最近 worker 结果（${workers.length}）`}>
        {!workers.length && <Empty msg="无" />}
        {workers.slice(0, 20).map((w, i) => (
          <details key={i} className="group border-b border-edge last:border-b-0 py-2">
            <summary className="flex items-center gap-2 text-xs cursor-pointer list-none select-none">
              <Pill color={statusColor[w.status] || 'var(--color-ok)'}>{w.status}</Pill>
              <Pill color="var(--color-info)">{laneZh(w.lane || '')}</Pill>
              {w.asset_host && <span className="text-violet font-semibold shrink-0">{w.asset_host}</span>}
              <span className="font-semibold shrink-0">{w.agent_id}</span>
              {w.work_item_id != null && <span className="dim shrink-0"># {w.work_item_id}</span>}
              {w.confidence && w.confidence !== 'unknown' && <span className="dim shrink-0">置信 {w.confidence}</span>}
              <span className="dim mono ml-auto shrink-0">{w.created_at}</span>
              <i className="codicon codicon-chevron-down text-ink-dim group-open:rotate-180 transition-transform" />
            </summary>
            <div className="mt-2 pl-1">
              {w.wi_title && <div className="text-[11px] text-ink-dim mb-1">任务：{w.wi_title}</div>}
              <div className="text-xs whitespace-pre-wrap break-words text-ink leading-5">{w.conclusion || '（无结论）'}</div>
              {w.next_action && (
                <div className="mt-1.5 text-xs text-ink-dim">
                  <span className="text-info">下一步：</span>{w.next_action}
                </div>
              )}
              {w.block_reason && (
                <div className="mt-1.5 text-xs text-danger">
                  <span>阻塞原因：</span>{w.block_reason}
                </div>
              )}
            </div>
          </details>
        ))}
      </Card>

      {/* 下一步（高优先级排队项） */}
      <Card title={`下一步（${next.length}）`}>
        {!next.length && <Empty msg="无" />}
        <ol className="list-none m-0 p-0">
          {next.map((a, i) => (
            <li key={a.work_item_id ?? i} className="flex items-baseline gap-2 py-1.5 border-b border-edge last:border-b-0 text-xs">
              <span className="dim mono shrink-0 w-5 text-right">{i + 1}.</span>
              <Pill color="var(--color-violet)">{laneZh(a.lane || '')}</Pill>
              <span className="break-words flex-1">{a.title}</span>
              {a.priority != null && <span className="dim shrink-0">pri {a.priority}</span>}
            </li>
          ))}
        </ol>
      </Card>
    </div>
  )
}
