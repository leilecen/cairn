import { useQuery } from '@tanstack/react-query'
import { useApp } from '../store'
import { fetchAssetDetail, fetchDisclosure, fetchFindings } from '../api'
import { Card, Empty, Pill, Row, Table, Td } from './helpers'
import { riskColor, statusColor, stageColor } from '../colors'
import type { FindingItem } from '../types'

/** 资产详情（队列组二级标签）：头部 + 资产介绍 + 披露链 + 最近探测 + 范围授权 + 端点 + 队列 + 发现 */
export function AssetDetail({ host }: { host: string }) {
  const { target, openSpDetail, openFindingDetail, openAssetDetail } = useApp()
  const detail = useQuery({
    queryKey: ['assetDetail', target, host],
    queryFn: () => fetchAssetDetail(target, host),
    enabled: !!target && !!host,
    refetchInterval: 15000,
  })
  const disc = useQuery({
    queryKey: ['disclosure', target],
    queryFn: () => fetchDisclosure(target),
    enabled: !!target,
  })
  const allFindings = useQuery({
    queryKey: ['findings', target],
    queryFn: () => fetchFindings(target),
    enabled: !!target,
  })

  if (!detail.data) return <Empty msg="加载中…" />
  const a = detail.data.asset
  if (!a) return <Empty msg={`未找到资产 ${host} 详情`} />
  const eps = detail.data.endpoints ?? []
  const q = detail.data.queue ?? []
  const insp = detail.data.inspirations ?? []
  const discAsset = disc.data?.assets.find(x => x.asset_value === host)
  const fs: FindingItem[] = discAsset?.findings?.length
    ? (allFindings.data?.findings ?? []).filter(f => f.url.includes(host))
    : detail.data.findings ?? []
  const sps = discAsset?.suspicious_points ?? []

  const notes = a.notes as string | null | undefined

  return (
    <div>
      {/* 资产头部 */}
      <Card>
        <div className="flex items-baseline gap-2.5 flex-wrap">
          <span className="text-base font-bold text-ink-bright">{a.asset_value}</span>
          <Pill color={a.live_status === 'live' ? 'var(--color-ok)' : 'var(--color-ink-dim)'}>{a.live_status || 'unknown'}</Pill>
          <Pill color={a.scope_status === 'in_scope' ? 'var(--color-ok)' : 'var(--color-warn)'}>{a.scope_status}</Pill>
          <span className="dim">{a.asset_type}</span>
          {a.resolved_ip && <span className="dim mono">→ {a.resolved_ip}</span>}
          {a.priority != null && <span className="dim">pri {a.priority}</span>}
        </div>
        <div className="mt-2 flex gap-4 flex-wrap text-xs">
          <span><span className="dim">端口 </span><span className="mono">{a.port ?? '—'}</span></span>
          <span><span className="dim">协议 </span><span className="mono">{a.protocol ?? '—'}</span></span>
          <span><span className="dim">来源 </span>{a.source ?? '—'}</span>
          <span><span className="dim">需认证 </span>{a.auth_required ? '是' : '否'}</span>
          {a.relation_to_target && <span><span className="dim">关系 </span>{a.relation_to_target}</span>}
        </div>
        {a.tech_stack && (
          <div className="mt-2 text-xs">
            <span className="dim">指纹 </span><span className="text-violet">{a.tech_stack}</span>
          </div>
        )}
        {a.login_urls && a.login_urls !== '[]' && (
          <div className="mt-2 text-xs">
            <span className="dim">登录入口 </span>
            {(() => { try { return (JSON.parse(a.login_urls) as string[]).join('  ') } catch { return a.login_urls } })()}
          </div>
        )}
      </Card>

      {/* 资产介绍（notes）：按分隔符分段展示，避免糊成一团 */}
      {notes && (
        <Card title="资产介绍 / 备注">
          <NotesList text={notes} />
        </Card>
      )}

      {/* 披露进度链 */}
      {discAsset && (
        <Card title="渐进式披露进度">
          <div className="flex flex-wrap gap-1">
            {discAsset.stage_labels.map((lbl, i) => {
              const key = Object.keys(discAsset.stages)[i] || ''
              const st = discAsset.stages[key] || 'none'
              return (
                <div
                  key={i}
                  title={`${lbl}: ${st}`}
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-xs"
                  style={{
                    borderColor: stageColor[st],
                    background: stageColor[st] + '12',
                    color: stageColor[st],
                  }}
                >
                  <span className="w-2 h-2 rounded-[2px] inline-block" style={{ background: stageColor[st] }} />
                  {lbl}
                </div>
              )
            })}
          </div>
          {discAsset.stuck_stage && (
            <div className="mt-2 text-xs text-danger">当前卡在：<b>{discAsset.stuck_stage}</b></div>
          )}
          {discAsset.deepest_stage && (
            <div className="mt-1 text-xs text-ink-dim">最深推进到：{discAsset.deepest_stage}</div>
          )}
        </Card>
      )}

      {/* 最近探测 */}
      {(a.last_status_code != null || a.last_title || a.last_tech_stack || a.last_verified_at) && (
        <Card title="最近探测">
          <div className="flex gap-4 flex-wrap text-xs">
            {a.last_status_code != null && (
              <span><span className="dim">状态码 </span><span className="mono" style={{ color: a.last_status_code < 400 ? 'var(--color-ok)' : 'var(--color-warn)' }}>{a.last_status_code}</span></span>
            )}
            {a.last_title && <span><span className="dim">页面标题 </span><span className="mono">{a.last_title}</span></span>}
            {a.last_tech_stack && <span><span className="dim">指纹 </span><span className="text-violet">{a.last_tech_stack}</span></span>}
            {a.last_verified_at && <span><span className="dim">验证时间 </span><span className="mono">{a.last_verified_at}</span></span>}
            {a.last_verify_status && <span><span className="dim">验证状态 </span>{a.last_verify_status}</span>}
          </div>
        </Card>
      )}

      {/* 范围 / 授权 */}
      {(a.scope_reason || a.auth_blocker || a.authorization_state) && (
        <Card title="范围 / 授权">
          <div className="flex flex-col gap-1.5 text-xs">
            {a.authorization_state && <div><span className="dim">授权状态 </span>{a.authorization_state}</div>}
            {a.scope_reason && <div><span className="dim">范围原因 </span>{a.scope_reason}</div>}
            {a.auth_blocker && a.auth_blocker !== 'unknown' && (
              <div><span className="dim">认证阻塞 </span><span className="text-warn">{a.auth_blocker}</span></div>
            )}
          </div>
        </Card>
      )}

      {/* 资产灵感（显示在 已探测目录/端点 之上） */}
      <Card title={`资产灵感（${insp.length}）`}>
        {!insp.length && <Empty msg="暂无该资产的灵感/线索（可用 insight_capture --asset 显式挂靠，或从堵点追溯）" />}
        {insp.map((it, i) => (
          <Row key={i}>
            <Pill color={it.stage === 'gleam' ? 'var(--color-violet)' : 'var(--color-info)'}>
              {it.stage === 'gleam' ? '灵光' : '线索'}
            </Pill>
            <span className="truncate">{it.content}</span>
            {it.trigger && <span className="dim truncate ml-auto max-w-[35%]" title={it.trigger}>{it.trigger}</span>}
            <span className="dim shrink-0">{confidenceLabel(it.confidence)}</span>
            <span className="shrink-0" style={{ color: statusColor[it.status] || 'var(--color-ink-dim)' }}>{it.status}</span>
          </Row>
        ))}
      </Card>

      {/* 已探测目录/端点（限高 + 无限滚动，不再截断） */}
      <Card title={`已探测目录/端点（${eps.length}）`}>
        {!eps.length && <Empty msg="暂无探测记录（该资产尚未做入口/JS 探测）" />}
        {eps.length > 0 && (
          <div className="overflow-y-auto max-h-72 rounded-lg border border-edge">
            <Table head={['方法', '路径', '业务提示', '鉴权']}>
              {eps.map((e, i) => (
                <tr key={i}>
                  <Td className="whitespace-nowrap">
                    <span className="mono" style={{ color: e.method === 'GET' ? 'var(--color-info)' : 'var(--color-warn)' }}>{e.method}</span>
                  </Td>
                  <Td className="max-w-[360px]"><span className="mono break-all">{e.path}</span></Td>
                  <Td className="dim">{e.business_hint || '—'}</Td>
                  <Td className="whitespace-nowrap">
                    {e.auth_state && <Pill color={e.auth_state === 'auth' ? 'var(--color-warn)' : 'var(--color-ok)'}>{e.auth_state}</Pill>}
                  </Td>
                </tr>
              ))}
            </Table>
          </div>
        )}
      </Card>

      {/* 相关队列（行可点击：有 url 开网页，否则跳资产详情） */}
      <Card title={`相关队列（${q.length}）`}>
        {!q.length && <Empty msg="无" />}
        {q.map((qi, i) => (
          <Row
            key={i}
            onClick={() => {
              if (qi.url) { window.open(qi.url, '_blank', 'noopener'); return }
              if (qi.asset_host && qi.asset_host !== host) openAssetDetail(qi.asset_host)
            }}
            title={qi.url ? `打开 ${qi.url}` : qi.asset_host && qi.asset_host !== host ? `打开 ${qi.asset_host} 详情` : undefined}
          >
            <span className="shrink-0" style={{ color: statusColor[qi.status] || 'var(--color-ink-dim)' }}>{qi.status}</span>
            <span className="dim shrink-0">{qi.lane}</span>
            <span className="truncate">{qi.title}</span>
            {qi.url && <span className="text-accent-soft mono shrink-0 max-w-[200px] truncate">{qi.url}</span>}
            {qi.hint && <span className="dim truncate ml-auto">· {qi.hint}</span>}
          </Row>
        ))}
      </Card>

      {/* 发现：疑点（可点开详情）+ 漏洞（可点开详情） */}
      <Card title={`发现（疑点 ${sps.length} · 漏洞 ${fs.length}）`}>
        {!sps.length && !fs.length && <Empty msg="无" />}
        {fs.map(f => (
          <Row key={f.id || f.url} onClick={f.url ? () => openFindingDetail(f.id || f.url, f.type) : undefined} title={f.url ? '打开漏洞详情' : undefined}>
            <Pill color={riskColor(f.risk)}>{f.risk}</Pill>
            <span className="truncate font-semibold">{f.type}</span>
            <span className="dim mono truncate ml-auto">{f.url}</span>
          </Row>
        ))}
        {sps.map((sp, i) => (
          <Row
            key={'s' + i}
            onClick={() => sp.id && openSpDetail(sp.id, sp.test_type || '疑点')}
            title={sp.id ? '打开疑点详情' : undefined}
          >
            <Pill color="var(--color-warn)">疑点</Pill>
            <span className="truncate font-semibold">{sp.test_type}</span>
            {sp.reasoning && <span className="dim truncate ml-auto max-w-[40%]">{sp.reasoning}</span>}
            <span className="dim shrink-0">{sp.risk}</span>
          </Row>
        ))}
      </Card>
    </div>
  )
}

/** 资产介绍分段渲染：| 分主段 → 段内 [来源] 标记 + ; 子句，避免糊成一团 */
export function NotesList({ text }: { text: string }) {
  const segs = text
    .split(/[|\n]/)
    .map(s => s.trim())
    .filter(Boolean)

  if (segs.length <= 1) {
    // 单段：内部再按分号拆
    const parts = segs[0]?.split(/[;；]/).map(s => s.trim()).filter(Boolean) ?? [text]
    if (parts.length <= 1) return <div className="text-xs whitespace-pre-wrap leading-5">{text}</div>
    return (
      <ul className="list-none m-0 p-0 flex flex-col gap-1">
        {parts.map((p, i) => <NoteItem key={i} seg={p} />)}
      </ul>
    )
  }

  return (
    <ul className="list-none m-0 p-0 flex flex-col gap-2">
      {segs.map((s, i) => <NoteItem key={i} seg={s} />)}
    </ul>
  )
}

/** 置信度中文标签 */
function confidenceLabel(c: string | null | undefined): string {
  const map: Record<string, string> = { low: '低', medium: '中', high: '高', unknown: '未知' }
  return map[c || ''] || c || ''
}

/** 单条 note：识别开头 [来源-日期] 标记 + 子句拆行 */
function NoteItem({ seg }: { seg: string }) {
  // 识别开头 [xxx] 标记（如 [wi173-2026-08-13]、[main-2026-08-13]、[2026-08-13股权穿透]）
  const m = seg.match(/^\[([^\]]+)\](.*)$/)
  const badge = m ? m[1] : ''
  const rest = (m ? m[2] : seg).trim()

  // 剩余部分按分号拆子句
  const clauses = rest.split(/[;；]/).map(s => s.trim()).filter(Boolean)

  return (
    <li className="text-xs leading-5 border-l-2 border-accent/40 pl-2.5">
      {badge && (
        <span className="inline-block text-[10px] px-1.5 py-px rounded bg-surface-4 text-ink-dim mr-1.5 align-middle">{badge}</span>
      )}
      {clauses.length <= 1 ? (
        <span className="break-words">{rest}</span>
      ) : (
        <span className="flex flex-col gap-0.5">
          {clauses.map((c, i) => (
            <span key={i} className="break-words">{i === 0 ? c : <span className="text-ink-dim">· {c}</span>}</span>
          ))}
        </span>
      )}
    </li>
  )
}
