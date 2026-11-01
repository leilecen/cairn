import { useQuery } from '@tanstack/react-query'
import { useApp } from '../store'
import { fetchBlockers } from '../api'
import { Empty, Pill, Row } from './helpers'

export function Blockers({ quiet }: { quiet?: boolean }) {
  const { target } = useApp()
  const { data, error } = useQuery({
    queryKey: ['blockers', target],
    queryFn: () => fetchBlockers(target),
    enabled: !!target,
    refetchInterval: 15000,
  })

  if (error) return <Empty msg={'堵点数据不可用: ' + String((error as Error).message)} />
  if (!data) return <Empty msg="加载中…" />

  return (
    <div>
      <div className="text-xs font-bold text-ink-bright mb-1.5">
        阻点/进展
        <span className="dim ml-2 font-normal">
          block {data.counts.blocked} · inbox {data.counts.inbox} · cov {data.counts.coverage}
        </span>
      </div>

      {/* 进展 */}
      <div className="mb-2.5">
        <div className="dim text-[11px] mb-1">进展</div>
        {!data.progress.length && <Empty msg="无" />}
        {data.progress.slice(0, quiet ? 5 : 12).map((p, i) => (
          <Row key={i}>
            <span
              className="shrink-0 w-12"
              style={{ color: p.status === 'done' ? 'var(--color-ok)' : p.status === 'blocked' ? 'var(--color-danger)' : 'var(--color-violet)' }}
            >
              {p.status}
            </span>
            <span className="truncate">{p.conclusion || p.agent}</span>
          </Row>
        ))}
      </div>

      {/* 堵点（中文摘要） */}
      <div className="mb-2.5">
        <div className="dim text-[11px] mb-1">堵点 {data.counts.blocked}</div>
        {!data.blocked_items.length && <Empty msg="无堵点" />}
        {data.blocked_items.slice(0, quiet ? 6 : 15).map((b, i) => (
          <Row key={i}>
            <Pill color="var(--color-danger)">{b.class_zh || b.lane}</Pill>
            <span className="truncate">{b.title}</span>
            {(b.reason_zh || b.blocker_reason) && (
              <div className="text-danger text-[11px] mt-0.5 w-full truncate" title={b.reason_zh || b.blocker_reason}>
                {b.reason_zh || b.blocker_reason}
              </div>
            )}
          </Row>
        ))}
      </div>

      {/* 操作员待办 */}
      <div className="mb-2.5">
        <div className="dim text-[11px] mb-1">操作员待办 {data.counts.inbox}</div>
        {!data.operator_inbox.length && <Empty msg="无" />}
        {data.operator_inbox.slice(0, quiet ? 5 : 10).map((x, i) => (
          <Row key={i}>
            <Pill color="var(--color-warn)">{x.kind}</Pill>
            <span className="truncate">{x.title || x.detail}</span>
          </Row>
        ))}
      </div>

      {/* 覆盖率堵点 */}
      <div>
        <div className="dim text-[11px] mb-1">覆盖率未覆盖 {data.counts.coverage}</div>
        {!data.coverage_blocked.length && <Empty msg="无" />}
        {data.coverage_blocked.slice(0, quiet ? 5 : 10).map((c, i) => (
          <Row key={i}>
            <span className="mono dim text-[11px] truncate">{c.category}/{c.item_key}</span>
            <span className="text-violet shrink-0 ml-auto">{c.status}</span>
          </Row>
        ))}
      </div>
    </div>
  )
}
