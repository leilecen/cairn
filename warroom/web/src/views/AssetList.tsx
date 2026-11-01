import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useApp } from '../store'
import { fetchDisclosure } from '../api'
import { Card, Empty, Pill, Row } from './helpers'
import { stageColor, groupColor, groupLabel } from '../colors'
import type { DisclosureAsset } from '../types'

const GROUP_ORDER = ['blocked', 'progress', 'penetrated', 'queued', 'untouched'] as const

/** 资产列表（队列二级目录）：5 组披露分组 + 搜索过滤，点击资产在队列标签内展开详情 */
export function AssetList() {
  const { target, openAssetDetail } = useApp()
  const [q, setQ] = useState('')

  const disc = useQuery({
    queryKey: ['disclosure', target],
    queryFn: () => fetchDisclosure(target),
    enabled: !!target,
    refetchInterval: 15000,
  })

  const assets = disc.data?.assets ?? []

  const grouped = useMemo(() => {
    const kw = q.trim().toLowerCase()
    const g: Record<string, DisclosureAsset[]> = {}
    for (const grp of GROUP_ORDER) g[grp] = []
    for (const a of assets) {
      if (kw && !a.asset_value.toLowerCase().includes(kw)) continue
      ;(g[a.group] ??= []).push(a)
    }
    return g
  }, [assets, q])

  if (!disc.data) return <Empty msg="加载中…" />

  return (
    <div>
      {/* 分组汇总条 + 搜索 */}
      <div className="flex gap-2.5 mb-3.5 flex-wrap items-center">
        {GROUP_ORDER.map(grp => (
          <div
            key={grp}
            className="bg-surface-2 border border-edge rounded-md px-3.5 py-2 border-l-[3px]"
            style={{ borderLeftColor: groupColor[grp] }}
          >
            <div className="text-[11px] text-ink-dim leading-4">{groupLabel[grp]}</div>
            <div className="text-lg font-bold leading-6" style={{ color: groupColor[grp] }}>{grouped[grp].length}</div>
          </div>
        ))}
        <input
          value={q}
          onChange={e => setQ(e.target.value)}
          placeholder="过滤资产…"
          className="ml-auto bg-surface-3 text-ink border border-edge-2 rounded px-2 py-[3px] text-xs w-44 focus:outline-1 focus:outline-accent"
          aria-label="过滤资产"
        />
      </div>

      {/* 分组列表 */}
      {GROUP_ORDER.map(grp => {
        const list = grouped[grp]
        if (!list.length) return null
        return (
          <Card key={grp}>
            <div className="mb-2 text-xs font-bold" style={{ color: groupColor[grp] }}>
              {groupLabel[grp]}（{list.length}）
            </div>
            {list.map(a => (
              <AssetRow key={a.id} a={a} onClick={() => openAssetDetail(a.asset_value)} />
            ))}
          </Card>
        )
      })}
    </div>
  )
}

function AssetRow({ a, onClick }: { a: DisclosureAsset; onClick: () => void }) {
  return (
    <Row onClick={onClick} title="打开资产详情">
      {/* 阶段迷你链（11 段状态色点） */}
      <div className="flex gap-0.5 w-[132px] shrink-0">
        {a.stage_labels.map((lbl, i) => {
          const key = Object.keys(a.stages)[i] || ''
          const st = a.stages[key] || 'none'
          return <div key={i} title={`${lbl}: ${st}`} className="w-2.5 h-2.5 rounded-[2px] shrink-0" style={{ background: stageColor[st] }} />
        })}
      </div>
      <span className="font-semibold flex-1 min-w-0 truncate">{a.asset_value}</span>
      {a.port && <span className="dim mono shrink-0">:{a.port}</span>}
      <span className="dim shrink-0 hidden md:inline">端点 {a.endpoint_count}</span>
      {a.findings?.length > 0 && <Pill color="var(--color-danger)">{a.findings.length} 漏洞</Pill>}
      {a.suspicious_points?.length > 0 && <Pill color="var(--color-warn)">{a.suspicious_points.length} 疑点</Pill>}
      {a.stuck_stage && <Pill color="var(--color-danger)">卡:{a.stuck_stage}</Pill>}
    </Row>
  )
}
