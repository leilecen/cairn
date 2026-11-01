import { useQuery } from '@tanstack/react-query'
import { useApp } from '../store'
import { fetchSpDetail } from '../api'
import { Card, Empty, Pill, Link, useFocus, JsonBlock } from './helpers'
import { riskColor } from '../colors'

/** 疑点详情（组内二级标签）：suspicious_points 全字段 */
export function SpDetail({ id }: { id: string }) {
  const { target } = useApp()
  const focusHost = useFocus()
  const { data } = useQuery({
    queryKey: ['sp', target, id],
    queryFn: () => fetchSpDetail(target, id),
    enabled: !!target && !!id,
    refetchInterval: 15000,
  })

  if (!data) return <Empty msg="加载中…" />
  const sp = data.sp
  if (!sp) return <Empty msg={`未找到疑点 ${id}`} />

  return (
    <div>
      {/* 头部 */}
      <Card>
        <div className="flex items-center gap-2.5 flex-wrap">
          <Pill color={riskColor(sp.risk)}>{sp.risk || '—'}</Pill>
          <Pill color="var(--color-warn)">{sp.test_type}</Pill>
          <span className="text-base font-bold text-ink-bright">{sp.endpoint_fingerprint || sp.url || id}</span>
          <Pill color={sp.test_status === 'confirmed' ? 'var(--color-ok)' : sp.test_status === 'untested' ? 'var(--color-warn)' : 'var(--color-ink-dim)'}>
            {sp.test_status}
          </Pill>
          {sp.auth_surface_type && <span className="dim">{sp.auth_surface_type}</span>}
        </div>
        <div className="mt-2 flex gap-4 flex-wrap text-xs">
          {sp.method && <span><span className="dim">方法 </span><span className="mono">{sp.method}</span></span>}
          {sp.param && <span><span className="dim">参数 </span><span className="mono">{sp.param}</span></span>}
          {sp.risk_score != null && <span><span className="dim">风险分 </span><span className="mono">{sp.risk_score}</span></span>}
          {sp.source && <span><span className="dim">来源 </span>{sp.source}</span>}
          {sp.created_at && <span><span className="dim">时间 </span><span className="mono">{sp.created_at}</span></span>}
        </div>
        {sp.url && (
          <div className="mt-2 text-xs">
            <span className="dim">URL </span><Link url={sp.url} focusHost={focusHost} />
          </div>
        )}
        {sp.page_url && sp.page_url !== sp.url && (
          <div className="mt-1 text-xs">
            <span className="dim">页面 </span><Link url={sp.page_url} focusHost={focusHost} />
          </div>
        )}
      </Card>

      {/* 推理依据 */}
      {sp.reasoning && (
        <Card title="推理依据">
          <div className="text-xs whitespace-pre-wrap leading-5">{sp.reasoning}</div>
        </Card>
      )}

      {/* 信号 */}
      {(sp.signal_value || sp.signal_reason) && (
        <Card title="信号">
          <div className="flex flex-col gap-1.5 text-xs">
            {sp.signal_value && <div><span className="dim">信号值 </span><span className="mono text-warn">{sp.signal_value}</span></div>}
            {sp.signal_reason && <div><span className="dim">信号理由 </span>{sp.signal_reason}</div>}
          </div>
        </Card>
      )}

      {/* 响应摘要 */}
      {sp.response_summary && (
        <Card title="响应摘要">
          <div className="text-xs whitespace-pre-wrap leading-5">{sp.response_summary}</div>
        </Card>
      )}

      {/* 证据（JSON → 结构化展示） */}
      {sp.evidence && (
        <Card title="证据">
          <div className="bg-surface-3 rounded-lg p-2.5">
            <JsonBlock json={sp.evidence} />
          </div>
        </Card>
      )}

      {/* 备注 */}
      {sp.notes && (
        <Card title="备注">
          <div className="text-xs whitespace-pre-wrap leading-5">{sp.notes}</div>
        </Card>
      )}

      {/* 噪声标记 */}
      {sp.noise_reason && (
        <Card title="噪声标记">
          <div className="text-xs text-ink-dim">{sp.noise_reason}</div>
        </Card>
      )}

      {/* 关联漏洞 */}
      {sp.findings?.length > 0 && (
        <Card title={`关联漏洞（${sp.findings.length}）`}>
          {sp.findings.map((f: any, i: number) => (
            <div key={i} className="text-xs py-1 border-b border-edge last:border-b-0">
              <Pill color={riskColor(f.risk)}>{f.risk}</Pill> <span className="font-semibold">{f.type}</span>
              <span className="dim mono ml-2">{f.url}</span>
            </div>
          ))}
        </Card>
      )}
    </div>
  )
}
