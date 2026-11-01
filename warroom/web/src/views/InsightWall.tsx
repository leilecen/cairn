import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useApp } from '../store'
import { fetchInsightChains, fetchInsightDetail, fetchInsightWall } from '../api'
import type { InsightBlock, InsightChainItem, InsightChainsData, InsightDetailData, InsightWallData } from '../types'
import { Card, Empty, Link, Pill } from './helpers'

const KIND_LABEL: Record<string, string> = {
  inspiration: '灵感/线索',
  suspicious_point: '未验证疑点',
  coverage_ledger: '未覆盖账本',
  work_item: '卡住攻面',
  business_flow_step: '业务流中间态',
  operator_inbox: '待操作员',
}

const STAGE_LABEL: Record<string, string> = {
  gleam: '灵光 (gleam)',
  clue: '线索 (clue)',
}

/** 单条灵感条目:显示父堵点 kind 小标签 + 状态/置信度;点击展开详情链。 */
function InsightRow({
  ins, parentKind, onOpen, open,
}: {
  ins: InsightBlock['inspirations'][number]
  parentKind: string
  onOpen: () => void
  open: boolean
}) {
  return (
    <>
      <div
        onClick={onOpen}
        title={ins.content}
        className="flex items-start gap-2 px-2 py-1.5 cursor-pointer hover:bg-surface-4/50 border-b border-edge text-xs"
      >
        <i className={`codicon ${open ? 'codicon-chevron-down' : 'codicon-chevron-right'} text-accent-soft shrink-0 mt-0.5`} />
        <span className="break-all leading-4 flex-1 min-w-0">
          <span className="text-ink">{ins.content}</span>
          <span className="dim shrink-0 ml-2">({ins.trigger || '—'})</span>
        </span>
        <Pill color="#e0af68" title="来源堵点">{KIND_LABEL[parentKind] || parentKind}</Pill>
        <Pill color={ins.confidence === 'high' ? '#4ec9b0' : ins.confidence === 'medium' ? '#d2a8ff' : '#9cdcfe'} title="置信度">
          {ins.confidence}
        </Pill>
        {typeof ins.score === 'number' && <Pill color="#6a9955" title="优先推荐得分">{ins.score.toFixed(2)}</Pill>}
      </div>
      {open && <InsightWallDetail id={ins.id} />}
    </>
  )
}

/** 详情展开区:拉取 /api/insight-detail,呈现完整前因后果链。 */
function InsightWallDetail({ id }: { id: number }) {
  const { target } = useApp()
  const { data, isLoading } = useQuery<InsightDetailData>({
    queryKey: ['insight-detail', target, id],
    queryFn: () => fetchInsightDetail(target, id),
    enabled: !!target,
  })

  if (isLoading) return <div className="dim text-[11px] px-5 py-2">加载前因后果…</div>
  if (!data || !data.found || !data.inspiration) return <div className="dim text-[11px] px-5 py-2">详情加载失败</div>

  const { inspiration: insp, upstream, downstream, harvest } = data
  const blocker = upstream?.blocker
  const refined = upstream?.refined_from
  const sp = downstream?.promoted_sp
  const wi = downstream?.promoted_wi

  return (
    <div className="ml-4 border-l border-edge pl-3 pr-2 py-2 space-y-2 bg-surface-3/30">
      {/* 灵感本体 */}
      <div className="text-[11px] leading-4">
        <span className="font-semibold text-ink-dim">{STAGE_LABEL[insp.stage] || insp.stage}</span>
        <span className="dim ml-2">status {insp.status}</span>
        <span className="dim ml-2">created {insp.created_at || '—'}</span>
        <div className="mt-1 text-ink leading-4 break-all">{insp.content}</div>
        {insp.trigger && <div className="dim mt-0.5">触发: {insp.trigger}</div>}
      </div>

      <ChainSection title="前因 · 挂靠堵点">
        {blocker ? (
          <>
            <Pill color="#4ec9b0">{KIND_LABEL[blocker.kind] || blocker.kind}</Pill>
            <div className="mt-1 text-ink text-[11px] break-all">{blocker.title || blocker.id || '—'}</div>
            {blocker.detail && <div className="dim text-[11px] mt-0.5 break-all">原因: {blocker.detail}</div>}
            {blocker.url && (
              <div className="mt-0.5">
                <Link url={blocker.url} focusHost={null} text={blocker.host || blocker.url} />
              </div>
            )}
          </>
        ) : (
          <span className="dim">无挂靠堵点(游离灵感)</span>
        )}
      </ChainSection>

      <ChainSection title="前因 · 源头灵光">
        {refined ? (
          <div className="text-[11px]">
            <div className="text-ink break-all">{refined.content}</div>
            {refined.trigger && <div className="dim mt-0.5">触发: {refined.trigger}</div>}
          </div>
        ) : (
          <span className="dim">无细化来源</span>
        )}
      </ChainSection>

      <ChainSection title="后果 · 验证成果">
        {!sp && !wi ? (
          <span className="dim">尚无验证成果</span>
        ) : (
          <div className="space-y-1">
            {sp && (
              <div className="text-[11px]">
                <Pill color="#4ec9b0">疑点 {sp.id}</Pill>
                {sp.risk && <Pill color="#f14c4c" >risk {sp.risk}</Pill>}
                <div className="mt-1 text-ink break-all">{sp.title || '—'}</div>
                {sp.detail && <div className="dim mt-0.5 break-all">原因: {sp.detail}</div>}
                {sp.url && (
                  <div className="mt-0.5">
                    <Link url={sp.url} focusHost={null} text={sp.host || sp.url} />
                  </div>
                )}
              </div>
            )}
            {wi && (
              <div className="text-[11px]">
                <Pill color="#d7ba7d">任务 {wi.id}</Pill>
                {wi.lane && <Pill color="#9cdcfe">{wi.lane}</Pill>}
                {wi.status && <Pill color="#c586c0">status {wi.status}</Pill>}
                <div className="mt-1 text-ink break-all">{wi.title || '—'}</div>
                {wi.detail && <div className="dim mt-0.5 break-all">原因: {wi.detail}</div>}
              </div>
            )}
          </div>
        )}
      </ChainSection>

      <ChainSection title="收割">
        {harvest ? (
          <div className="text-[11px]">
            <Pill color="#ce9178">harvest {harvest.harvest_id}</Pill>
            {harvest.harvest_note && <div className="dim mt-0.5 break-all">{harvest.harvest_note}</div>}
          </div>
        ) : (
          <span className="dim">未收割</span>
        )}
      </ChainSection>
    </div>
  )
}

function ChainSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="border border-edge rounded-md px-2 py-1.5">
      <div className="text-[10px] font-bold text-ink-dim tracking-wide mb-1">{title}</div>
      {children}
    </div>
  )
}

/** 顶部分组头:一类灵感(灵光/线索/游离)。 */
function GroupHeader({ label, count, tint }: { label: string; count: number; tint: string }) {
  return (
    <div className="flex items-center gap-2 px-1 pb-1.5 pt-1.5">
      <span className="h-2 w-2 rounded-full" style={{ background: tint }} />
      <span className="text-[11px] font-bold text-ink-dim tracking-wide">{label}</span>
      <span className="dim text-[11px] ml-auto">{count} 条</span>
    </div>
  )
}

/** 因果链全览单行:灵光→线索→堵点上下文→状态,全可见,无需点开。 */
function ChainRow({ item }: { item: InsightChainItem }) {
  return (
    <div className="px-2 py-1.5 border-b border-edge text-[11px] space-y-1">
      <div className="flex items-center gap-2">
        <Pill color={item.stage === 'gleam' ? '#4ec9b0' : '#d2a8ff'}>{item.stage === 'gleam' ? '灵光' : '线索'}</Pill>
        <span className="dim">#{item.inspiration_id}</span>
        <span className="text-ink flex-1 break-all min-w-0">{item.content}</span>
        <Pill color={item.confidence === 'high' ? '#4ec9b0' : item.confidence === 'medium' ? '#d2a8ff' : '#9cdcfe'} title="置信度">
          {item.confidence}
        </Pill>
        <Pill color={item.status === 'open' ? '#4ec9b0' : '#e0af68'}>status {item.status}</Pill>
      </div>
      <div className="pl-2 space-y-0.5">
        {item.refined_from ? (
          <div className="dim break-all"><span className="text-ink-dim">← 源头灵光: </span>{item.refined_from}</div>
        ) : null}
        {item.blocker ? (
          <div className="break-all">
            <span className="text-ink-dim">→ 堵点[{KIND_LABEL[item.blocker.kind] || item.blocker.kind}]: </span>
            <span className="text-ink">{item.blocker.title || item.blocker.id || '—'}</span>
            {item.blocker.detail && <span className="dim"> — {item.blocker.detail}</span>}
            {item.blocker.url && (
              <span className="ml-1"><Link url={item.blocker.url} focusHost={null} text={item.blocker.host || '链接'} /></span>
            )}
          </div>
        ) : (
          <div className="dim">游离灵感(未挂靠堵点)</div>
        )}
        {item.trigger && <div className="dim">触发: {item.trigger}</div>}
      </div>
    </div>
  )
}

export function InsightWall() {
  const { target } = useApp()
  const [view, setView] = useState<'wall' | 'chains'>('wall')
  const [recommended, setRecommended] = useState(false)
  const [open, setOpen] = useState<Set<number>>(new Set())

  const wallQuery = useQuery<InsightWallData>({
    queryKey: ['insight-wall', target, recommended],
    queryFn: () => fetchInsightWall(target, { recommended }),
    enabled: !!target,
  })
  const chainsQuery = useQuery<InsightChainsData>({
    queryKey: ['insight-chains', target],
    queryFn: () => fetchInsightChains(target),
    enabled: !!target,
  })

  const toggle = (id: number) => {
    setOpen(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  if (view === 'chains') {
    const chains = chainsQuery.data
    const stats = chains?.stats
    return (
      <Card title="灵感墙 · 因果链全览">
        <div className="flex items-center gap-2 mb-2">
          <ViewToggle view={view} onChange={setView} />
        </div>
        <div className="dim text-[11px] mb-2">
          同 target 全览链:每条灵感串联 源头灵光(灵光→线索)→ 挂靠堵点上下文 → 状态;全部行内可见。
          {stats && (
            <span className="ml-2">共 {stats.total} 条 · open {stats.open} · 灵光 {stats.gleam} · 线索 {stats.clue}</span>
          )}
        </div>
        {!chains?.chains?.length ? (
          <Empty msg="暂无灵感" />
        ) : (
          <div>
            {chains.chains.map(c => <ChainRow key={c.inspiration_id} item={c} />)}
          </div>
        )}
      </Card>
    )
  }

  const data = wallQuery.data

  if (!data) return <Empty msg="加载中…" />

  // 把所有灵感按自身 stage(而非父堵点 kind)分组;游离=未挂到任何堵点的灵感。
  const gleam: { ins: InsightBlock['inspirations'][number]; parentKind: string }[] = []
  const clue: { ins: InsightBlock['inspirations'][number]; parentKind: string }[] = []
  const free: { ins: InsightBlock['inspirations'][number]; parentKind: string }[] = []
  const freeIds = new Set<number>((data.blocks.find(b => b.kind === 'inspiration')?.inspirations ?? []).map(i => i.id))

  for (const b of data.blocks ?? []) {
    for (const i of b.inspirations ?? []) {
      const item = { ins: i, parentKind: b.kind }
      if (freeIds.has(i.id)) free.push(item)
      else if (i.stage === 'gleam') gleam.push(item)
      else if (i.stage === 'clue') clue.push(item)
      else free.push(item)
    }
  }

  const renderItems = (items: { ins: InsightBlock['inspirations'][number]; parentKind: string }[]) =>
    items.map(({ ins, parentKind }, j) => (
      <InsightRow
        key={j}
        ins={ins}
        parentKind={parentKind}
        open={open.has(ins.id)}
        onOpen={() => toggle(ins.id)}
      />
    ))

  return (
    <div>
      <Card title={`灵感墙 · 共 ${(gleam.length + clue.length + free.length) || 0} 条灵感`}>
        <div className="flex items-center gap-3 mb-2">
          <ViewToggle view={view} onChange={setView} />
          <label className="flex items-center gap-1 text-[11px] text-ink-dim cursor-pointer select-none">
            <input
              type="checkbox"
              checked={recommended}
              onChange={e => setRecommended(e.target.checked)}
              className="accent-[#4ec9b0]"
            />
            优先推荐
          </label>
          {recommended && <span className="dim text-[11px]">已按确定性评分降序,得分见绿色标签</span>}
        </div>
        <div className="dim text-[11px] mb-2">按灵感类型分组(灵光 / 线索 / 游离),每条灵感带父堵点标签;点开看完整前因后果。</div>
        {!data.blocks?.length && <Empty msg="暂无灵感" />}

        <div className="mb-2">
          <GroupHeader label={`灵光 ${STAGE_LABEL.gleam}`} count={gleam.length} tint="#4ec9b0" />
          {gleam.length ? renderItems(gleam) : <div className="dim px-2 py-1 text-[11px]">暂无灵光</div>}
        </div>

        <div className="mb-2">
          <GroupHeader label={`线索 ${STAGE_LABEL.clue}`} count={clue.length} tint="#d2a8ff" />
          {clue.length ? renderItems(clue) : <div className="dim px-2 py-1 text-[11px]">暂无线索</div>}
        </div>

        <div>
          <GroupHeader label="游离灵感/线索" count={free.length} tint="#e0af68" />
          {free.length ? renderItems(free) : <div className="dim px-2 py-1 text-[11px]">暂无游离灵感</div>}
        </div>
      </Card>
    </div>
  )
}

function ViewToggle({ view, onChange }: { view: 'wall' | 'chains'; onChange: (v: 'wall' | 'chains') => void }) {
  const base = 'px-2 py-0.5 text-[11px] rounded border border-edge cursor-pointer'
  const active = ' bg-[#2d3a2f] text-ink border-[#4ec9b0]/50'
  const inactive = ' text-ink-dim hover:bg-surface-4/40'
  return (
    <div className="flex items-center gap-1">
      <button className={base + (view === 'wall' ? active : inactive)} onClick={() => onChange('wall')}>堵点列表</button>
      <button className={base + (view === 'chains' ? active : inactive)} onClick={() => onChange('chains')}>因果链全览</button>
    </div>
  )
}
