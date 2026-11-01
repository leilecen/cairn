import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useApp } from '../store'
import { fetchFindings } from '../api'
import { Empty, Pill, Row, Card } from './helpers'
import { riskColor } from '../colors'
import type { FindingItem } from '../types'

function hostOf(url: string): string {
  try { return new URL(url).hostname } catch { return url.split('/')[0] || url }
}

/** 漏洞视图（漏洞组 root）：按资产分组列表；详情在组内二级标签 */
export function Findings() {
  const { target, openFindingDetail } = useApp()
  const [q, setQ] = useState('')
  const { data } = useQuery({ queryKey: ['findings', target], queryFn: () => fetchFindings(target), enabled: !!target })

  // 按资产（url host）分组
  const groups = useMemo(() => {
    const g = new Map<string, FindingItem[]>()
    for (const f of data?.findings ?? []) {
      const h = hostOf(f.url) || '未知资产'
      if (!g.has(h)) g.set(h, [])
      g.get(h)!.push(f)
    }
    return [...g.entries()].sort((a, b) => b[1].length - a[1].length)
  }, [data])

  const filtered = useMemo(() => {
    const kw = q.trim().toLowerCase()
    if (!kw) return groups
    return groups
      .map(([h, fs]) => [h, fs.filter(f => f.type.toLowerCase().includes(kw) || f.url.toLowerCase().includes(kw))] as const)
      .filter(([, fs]) => fs.length > 0)
  }, [groups, q])

  if (!data) return <Empty msg="加载中…" />
  if (!data.findings?.length) return <Empty msg="暂无漏洞成果" />

  const total = data.findings.length

  return (
    <div>
      {/* 汇总 + 搜索 */}
      <div className="flex items-center gap-2.5 mb-3.5">
        <div className="bg-surface-2 border border-edge rounded-lg px-3.5 py-2">
          <div className="text-[11px] text-ink-dim leading-4">漏洞总数</div>
          <div className="text-lg font-bold leading-6" style={{ color: 'var(--color-danger)' }}>{total}</div>
        </div>
        <div className="bg-surface-2 border border-edge rounded-lg px-3.5 py-2">
          <div className="text-[11px] text-ink-dim leading-4">涉及资产</div>
          <div className="text-lg font-bold leading-6" style={{ color: 'var(--color-info)' }}>{groups.length}</div>
        </div>
        <input
          value={q}
          onChange={e => setQ(e.target.value)}
          placeholder="过滤漏洞类型/URL…"
          className="ml-auto bg-surface-3 text-ink border border-edge-2 rounded-lg px-2.5 py-1.5 text-xs w-48 focus:outline-2 focus:outline-accent"
          aria-label="过滤漏洞"
        />
      </div>

      {/* 按资产分组 */}
      {filtered.map(([host, fs]) => (
        <Card key={host} title={`${host}（${fs.length}）`}>
          {fs.map(f => (
            <Row key={f.id || f.url} onClick={() => f.url && openFindingDetail(f.id || f.url, f.type || host)} title="打开漏洞详情">
              <Pill color={riskColor(f.risk)}>{f.risk}</Pill>
              <span className="font-semibold truncate w-44 shrink-0">{f.type}</span>
              <span className="dim mono flex-1 min-w-0 truncate">{f.url}</span>
              <span className="dim shrink-0 hidden md:inline">{f.review_status}</span>
            </Row>
          ))}
        </Card>
      ))}
    </div>
  )
}
