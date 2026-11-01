import { useQuery } from '@tanstack/react-query'
import { useApp } from '../store'
import { fetchView, fetchQueue } from '../api'
import { Card, Pill, Empty, Row } from './helpers'
import { statusColor } from '../colors'

const KPI_KEYS = ['queued', 'claimed', 'partial', 'blocked', 'done', 'failed'] as const

export function Overview() {
  const { target, setActiveView, openAssetDetail } = useApp()
  const { data } = useQuery({ queryKey: ['view', target], queryFn: () => fetchView(target), enabled: !!target })
  const queue = useQuery({ queryKey: ['queue', target], queryFn: () => fetchQueue(target), enabled: !!target })

  if (!data) return <Empty msg="加载中…" />
  const o = data.overview
  const ws = o.work_summary
  const st = o.soft_targets

  // 高优先级待测资产：队列里 priority 最高的前 6 项
  const topQueue = [...(queue.data?.items ?? [])].sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0)).slice(0, 6)

  return (
    <div>
      {/* KPI 条（点击跳队列） */}
      <Card title="工作队列 KPI">
        <div className="flex gap-2.5 flex-wrap">
          {KPI_KEYS.map(k => (
            <button
              key={k}
              onClick={() => setActiveView('queue')}
              title={`点击查看队列（${k}）`}
              className="bg-surface-3 rounded-md px-3.5 py-2 min-w-[86px] text-left cursor-pointer hover:bg-surface-4 border border-transparent hover:border-edge-2 transition-colors"
            >
              <div className="dim text-[11px] leading-4">{k}</div>
              <div className="text-[22px] font-extrabold leading-7" style={{ color: statusColor[k] }}>{ws?.[k] ?? 0}</div>
            </button>
          ))}
        </div>
      </Card>

      {/* 主攻候选（点击在队列标签内打开资产详情） */}
      <Card title="主攻候选（soft_targets 排序）· 点击资产打开详情">
        {(!st || !st.results?.length) && <Empty msg="暂无排序目标" />}
        {st?.results?.map(r => (
          <Row key={r.id} onClick={() => openAssetDetail(r.asset)} title={`打开 ${r.asset} 详情`}>
            <Pill color={r.status === 'focused' ? 'var(--color-ok)' : 'var(--color-info)'}>{r.status || 'ranked'}</Pill>
            <span className="font-semibold truncate text-violet hover:underline">{r.asset}</span>
            <span className="dim mono shrink-0">{r.protocol}{r.port ? ':' + r.port : ''}</span>
            <Pill color="var(--color-violet)">{r.tier || '—'}</Pill>
            <span className="dim shrink-0 ml-auto">rank {r.rank} · 证据 {r.evidence_count}</span>
          </Row>
        ))}
      </Card>

      {/* 高优先级待测队列（点击打开对应资产详情） */}
      <Card title="高优先级待测队列 · 点击资产打开详情">
        {!topQueue.length && <Empty msg="无待测项" />}
        {topQueue.map(it => (
          <Row key={it.id} onClick={() => it.asset_host && openAssetDetail(it.asset_host)} title={it.asset_host ? `打开 ${it.asset_host} 详情` : undefined}>
            <span className="shrink-0 w-14" style={{ color: statusColor[it.status] || 'var(--color-ink-dim)' }}>{it.status}</span>
            <span className="font-semibold truncate text-violet hover:underline">{it.title}</span>
            <span className="dim truncate ml-auto">{it.asset_host}{it.hint ? ' · ' + it.hint : ''}</span>
          </Row>
        ))}
      </Card>

      {/* 操作员待办（堵点详情在右侧 sidebar 常驻） */}
      <Card title="操作员待办">
        {(!o.operator_inbox?.length) && <Empty msg="无待办" />}
        {o.operator_inbox?.slice(0, 8).map((x, i) => (
          <Row key={i}>
            <Pill color="var(--color-warn)">{x.kind || 'inbox'}</Pill>
            <span className="truncate">{x.title || x.detail || '—'}</span>
          </Row>
        ))}
      </Card>
    </div>
  )
}
