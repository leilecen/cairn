import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useApp, VIEW_TITLES, type SubTab } from './store'
import { fetchTargets } from './api'
import '@vscode/codicons/dist/codicon.css'
import { Overview } from './views/Overview'
import { Queue } from './views/Queue'
import { AssetDetail } from './views/AssetDetail'
import { SpDetail } from './views/SpDetail'
import { Findings } from './views/Findings'
import { FindingDetail } from './views/FindingDetail'
import { TimedLine } from './views/Timeline'
import { Blockers } from './views/Blockers'
import { InsightWall } from './views/InsightWall'
import type { ViewId } from './types'

// 主视图标签（组）。堵点已在右侧 sidebar 常驻，不入标签。
const VIEWS: { id: ViewId; label: string; icon: string }[] = [
  { id: 'overview', label: '态势', icon: 'codicon-pulse' },
  { id: 'queue', label: '队列', icon: 'codicon-list-unordered' },
  { id: 'findings', label: '漏洞', icon: 'codicon-bug' },
  { id: 'timeline', label: '时间线', icon: 'codicon-history' },
  { id: 'insightwall', label: '灵感墙', icon: 'codicon-lightbulb' },
]

const SUB_ICON: Record<SubTab['kind'], string> = {
  asset: 'codicon-server-environment',
  sp: 'codicon-lightbulb',
  finding: 'codicon-bug',
}

export default function App() {
  const { target, setTarget, activeView, setActiveView, queueGroup, findingsGroup, closeSubTab, activateSubTab } = useApp()
  const [now, setNow] = useState(new Date())

  const targets = useQuery({ queryKey: ['targets'], queryFn: fetchTargets })

  useEffect(() => {
    if (!target && targets.data?.targets?.length) setTarget(targets.data.targets[0].target)
  }, [targets.data, target])

  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(t)
  }, [])

  // 当前组的二级标签（浏览器式分组）
  const curGroup = activeView === 'findings' ? findingsGroup : (activeView === 'queue' ? queueGroup : null)
  const curGroupName: 'queue' | 'findings' = activeView === 'findings' ? 'findings' : 'queue'

  return (
    <div className="flex flex-col h-full">
      {/* 顶栏：左目标切换，右刷新；无标题文字 */}
      <header className="flex items-center gap-2 px-3 py-1.5 bg-surface-2 border-b border-edge">
        <select
          value={target}
          onChange={e => setTarget(e.target.value)}
          className="max-w-[280px]"
          aria-label="切换目标"
        >
          {targets.data?.targets?.map(t => (
            <option key={t.db} value={t.target}>{t.target}</option>
          ))}
        </select>
        <div className="ml-auto flex items-center gap-2">
          <span className="dim mono text-[11px]">上次刷新 {now.toLocaleTimeString('zh-CN', { hour12: false })}</span>
          <button
            onClick={() => window.location.reload()}
            className="flex items-center gap-1 bg-surface-3 text-ink border border-edge-2 rounded-lg px-2.5 py-1.5 text-xs cursor-pointer hover:bg-surface-4"
          >
            <i className="codicon codicon-refresh" /> 刷新
          </button>
        </div>
      </header>

      {/* 组标签栏（主视图） */}
      <div className="flex items-stretch bg-surface-2 border-b border-edge shrink-0" style={{ height: 32 }} role="tablist" aria-label="主视图">
        {VIEWS.map(v => {
          const on = activeView === v.id
          const groupHasSub = v.id === 'queue' ? queueGroup.tabs.length > 0 : v.id === 'findings' ? findingsGroup.tabs.length > 0 : false
          return (
            <button
              key={v.id}
              role="tab"
              aria-selected={on}
              onClick={() => setActiveView(v.id)}
              className={`flex items-center gap-1.5 px-3 text-xs border-r border-edge cursor-pointer select-none whitespace-nowrap ${
                on ? 'bg-surface text-ink-bright border-t-2 border-t-accent' : 'bg-surface-2 text-ink-dim hover:bg-surface-3 hover:text-ink border-t-2 border-t-transparent'
              }`}
            >
              <i className={`codicon ${v.icon} text-[13px] ${on ? 'text-accent-soft' : ''}`} />
              {v.label}
              {groupHasSub && (
                <span className="text-[10px] rounded-full bg-surface-4 px-1.5 leading-4 text-ink-dim">{v.id === 'queue' ? queueGroup.tabs.length : findingsGroup.tabs.length}</span>
              )}
            </button>
          )
        })}
      </div>

      {/* 组内二级标签（浏览器式分组，仅 queue/findings 有） */}
      {curGroup && curGroup.tabs.length > 0 && (
        <div className="flex items-stretch bg-surface-3/60 border-b border-edge shrink-0 overflow-x-auto" style={{ height: 28 }}>
          <SubTabItem
            active={curGroup.active === 'root'}
            icon="codicon-list-unordered"
            title={activeView === 'findings' ? '漏洞列表' : '队列列表'}
            onClick={() => activateSubTab(curGroupName, 'root')}
          />
          {curGroup.tabs.map(t => (
            <SubTabItem
              key={t.kind + ':' + t.key}
              active={curGroup.active === t.key}
              icon={SUB_ICON[t.kind]}
              title={t.title}
              onClick={() => activateSubTab(curGroupName, t.key)}
              onClose={() => closeSubTab(curGroupName, t.key)}
            />
          ))}
        </div>
      )}

      {/* 主体：编辑器 + 右侧堵点 sidebar */}
      <div className="flex flex-1 min-h-0">
        <div className="flex-1 overflow-auto p-3.5">
          {activeView === 'overview' && <Overview />}
          {activeView === 'queue' && <QueueTabContent />}
          {activeView === 'findings' && <FindingsTabContent />}
          {activeView === 'timeline' && <TimedLine />}
          {activeView === 'insightwall' && <InsightWall />}
        </div>

        {/* 右侧常驻堵点/进展 */}
        <aside className="w-80 bg-surface-2 border-l border-edge overflow-auto p-3 shrink-0 hidden xl:block">
          <Blockers quiet />
        </aside>
      </div>
    </div>
  )
}

function SubTabItem({ active, icon, title, onClick, onClose }: { active: boolean; icon: string; title: string; onClick: () => void; onClose?: () => void }) {
  return (
    <div
      role="tab"
      aria-selected={active}
      onClick={onClick}
      className={`group flex items-center gap-1.5 px-2.5 text-[11px] border-r border-edge cursor-pointer select-none whitespace-nowrap ${
        active ? 'bg-surface-2 text-ink-bright' : 'text-ink-dim hover:bg-surface-3 hover:text-ink'
      }`}
      title={title}
    >
      <i className={`codicon ${icon} text-[11px] ${active ? 'text-accent-soft' : ''}`} />
      <span className="max-w-[140px] truncate">{title}</span>
      {onClose && (
        <button
          onClick={e => { e.stopPropagation(); onClose() }}
          className={`flex items-center justify-center w-3.5 h-3.5 rounded-sm cursor-pointer border-none bg-transparent ${
            active ? 'text-ink-dim hover:bg-surface-4 hover:text-ink-bright' : 'text-transparent hover:bg-surface-4 hover:text-ink group-hover:text-ink-dim'
          }`}
          title="关闭"
          aria-label="关闭标签"
        >
          <i className="codicon codicon-close text-[10px]" />
        </button>
      )}
    </div>
  )
}

/** 队列组内容：root=队列列表，子标签=资产/疑点/漏洞详情 */
function QueueTabContent() {
  const { queueGroup } = useApp()
  if (queueGroup.active === 'root') return <Queue />
  const tab = queueGroup.tabs.find(t => t.key === queueGroup.active)
  if (!tab) return <Queue />
  if (tab.kind === 'asset') return <AssetDetail host={tab.key} />
  if (tab.kind === 'sp') return <SpDetail id={tab.key} />
  if (tab.kind === 'finding') return <FindingDetail findingId={tab.key} />
  return <Queue />
}

/** 漏洞组内容：root=漏洞列表，子标签=漏洞详情 */
function FindingsTabContent() {
  const { findingsGroup } = useApp()
  if (findingsGroup.active === 'root') return <Findings />
  const tab = findingsGroup.tabs.find(t => t.key === findingsGroup.active)
  if (!tab) return <Findings />
  if (tab.kind === 'finding') return <FindingDetail findingId={tab.key} />
  return <Findings />
}
