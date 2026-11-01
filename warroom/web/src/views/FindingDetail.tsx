import { useQuery } from '@tanstack/react-query'
import { useApp } from '../store'
import { fetchFindings } from '../api'
import { Card, Empty, Pill, Link, useFocus, JsonBlock } from './helpers'
import { riskColor } from '../colors'

/** 漏洞详情（tab 内容）：完整字段展示 */
export function FindingDetail({ findingId }: { findingId: string }) {
  const { target } = useApp()
  const focusHost = useFocus()
  const { data } = useQuery({ queryKey: ['findings', target], queryFn: () => fetchFindings(target), enabled: !!target })

  if (!data) return <Empty msg="加载中…" />
  const f = data.findings.find(x => x.id === findingId || x.url === findingId)
  if (!f) return <Empty msg={`未找到漏洞 ${findingId}`} />

  return (
    <div>
      {/* 头部 */}
      <Card>
        <div className="flex items-center gap-2.5 flex-wrap">
          <Pill color={riskColor(f.risk)}>{f.risk || '—'}</Pill>
          {f.cvss && <Pill color="var(--color-warn)">CVSS {f.cvss}</Pill>}
          <span className="text-base font-bold text-ink-bright">{f.type}</span>
          <Pill color={f.review_status === 'confirmed' ? 'var(--color-ok)' : f.review_status === 'refuted' ? 'var(--color-danger)' : 'var(--color-warn)'}>
            {f.review_status}
          </Pill>
          {f.audit_status && <span className="dim">{f.audit_status}</span>}
        </div>
        <div className="mt-2 flex gap-4 flex-wrap text-xs">
          <span><span className="dim">方法 </span><span className="mono">{f.method || '—'}</span></span>
          <span><span className="dim">参数 </span><span className="mono">{f.param || '—'}</span></span>
          <span><span className="dim">确认时间 </span><span className="mono">{f.confirmed_at || '—'}</span></span>
          <span><span className="dim">ID </span><span className="mono">{f.id || '—'}</span></span>
        </div>
        <div className="mt-2 text-xs">
          <span className="dim">URL </span>
          <Link url={f.url} focusHost={focusHost} />
        </div>
      </Card>

      {/* 载荷 */}
      {f.payload && (
        <Card title="Payload">
          <pre className="mono text-xs text-warn whitespace-pre-wrap break-all bg-surface-3 rounded-lg p-2.5 m-0">{f.payload}</pre>
        </Card>
      )}

      {/* 利用/发现过程（evidence JSON → 结构化展示） */}
      {f.evidence && (
        <Card title="利用 / 发现过程（evidence）">
          <div className="bg-surface-3 rounded-lg p-2.5">
            <JsonBlock json={f.evidence} />
          </div>
        </Card>
      )}

      {/* 关联疑点 */}
      {f.sp_id && (
        <Card title="关联疑点">
          <div className="text-xs mono">{f.sp_id}</div>
        </Card>
      )}

      {/* 复核/审计备注 */}
      {(f.review_notes || f.audit_notes) && (
        <Card title="备注">
          {f.review_notes && (
            <div className="mb-2">
              <div className="dim text-[11px] mb-1">复核结论</div>
              <div className="text-xs whitespace-pre-wrap">{f.review_notes}</div>
            </div>
          )}
          {f.audit_notes && (
            <div>
              <div className="dim text-[11px] mb-1">审计备注</div>
              <div className="text-xs whitespace-pre-wrap">{f.audit_notes}</div>
            </div>
          )}
        </Card>
      )}

      {/* 修复建议 */}
      {f.remediation && (
        <Card title="修复建议">
          <div className="text-xs whitespace-pre-wrap">{f.remediation}</div>
        </Card>
      )}

      {/* 已申报平台 */}
      {f.reported_platforms && f.reported_platforms !== '[]' && (
        <Card title="已申报平台">
          <div className="text-xs mono whitespace-pre-wrap">{f.reported_platforms}</div>
        </Card>
      )}

      {/* 报告文件 */}
      {f.report_file && (
        <Card title="报告文件">
          <div className="text-xs mono">{f.report_file}</div>
        </Card>
      )}
    </div>
  )
}
