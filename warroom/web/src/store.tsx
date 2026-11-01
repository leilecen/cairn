import { createContext, useContext, useState, useCallback, useEffect, type ReactNode } from 'react'
import type { ViewId } from './types'

/** 组内二级标签：资产详情 / 疑点详情 / 漏洞详情（浏览器式标签分组） */
export interface SubTab {
  kind: 'asset' | 'sp' | 'finding'
  key: string
  title: string
}

interface GroupState {
  tabs: SubTab[]
  active: string   // 'root' 或 tab key
}

interface AppState {
  target: string
  setTarget: (t: string) => void
  focusAsset: string | null
  setFocusAsset: (a: string | null) => void

  // 主视图标签（组）
  activeView: ViewId
  setActiveView: (v: ViewId) => void

  // 组内二级标签（浏览器式分组）：queue 组 / findings 组
  queueGroup: GroupState
  findingsGroup: GroupState
  openAssetDetail: (host: string) => void
  openSpDetail: (id: string, title: string) => void
  openFindingDetail: (id: string, title: string) => void
  closeSubTab: (group: 'queue' | 'findings', key: string) => void
  activateSubTab: (group: 'queue' | 'findings', key: string) => void
  backToRoot: (group: 'queue' | 'findings') => void
}

const Ctx = createContext<AppState | null>(null)

export const VIEW_TITLES: Record<ViewId, string> = {
  overview: '态势',
  queue: '队列',
  findings: '漏洞',
  timeline: '时间线',
  blockers: '堵点',
  insightwall: '灵感墙',
}

// localStorage 持久化：目标 + 标签分组（关闭作战室/刷新/重开不丢，2026-08-15）
// key 含 target → 切换目标各自恢复自己的标签页
const TARGET_KEY = 'warroom:target'
const VIEW_KEY = 'warroom:view'

function loadTarget(): string {
  try { return localStorage.getItem(TARGET_KEY) || '' } catch { return '' }
}

function groupKey(target: string, group: string): string {
  return `warroom:group:${target}:${group}`
}

function loadGroup(target: string, group: 'queue' | 'findings'): GroupState {
  try {
    const raw = localStorage.getItem(groupKey(target, group))
    if (raw) {
      const p = JSON.parse(raw)
      if (p && Array.isArray(p.tabs) && typeof p.active === 'string') {
        return { tabs: p.tabs, active: p.active }
      }
    }
  } catch { /* ignore */ }
  return { tabs: [], active: 'root' }
}

function loadView(): ViewId {
  try {
    const v = localStorage.getItem(VIEW_KEY)
    if (v === 'overview' || v === 'queue' || v === 'findings' || v === 'timeline' || v === 'insightwall') return v
  } catch { /* ignore */ }
  return 'overview'
}

const emptyGroup = (): GroupState => ({ tabs: [], active: 'root' })

export function AppProvider({ children }: { children: ReactNode }) {
  // 初始值：target 已知时直接恢复其标签页
  const [target, setTargetState] = useState<string>(loadTarget)
  const [focusAsset, setFocusAsset] = useState<string | null>(null)
  const [activeView, setActiveViewState] = useState<ViewId>(loadView)
  const [queueGroup, setQueueGroup] = useState<GroupState>(() => loadGroup(loadTarget(), 'queue'))
  const [findingsGroup, setFindingsGroup] = useState<GroupState>(() => loadGroup(loadTarget(), 'findings'))

  // 目标切换：加载该目标的标签页 + 视图（并持久化）
  const setTarget = useCallback((t: string) => {
    setTargetState(t)
    try { localStorage.setItem(TARGET_KEY, t) } catch { /* ignore */ }
    setQueueGroup(loadGroup(t, 'queue'))
    setFindingsGroup(loadGroup(t, 'findings'))
    setActiveViewState(loadView())
  }, [])

  const setActiveView = useCallback((v: ViewId) => {
    setActiveViewState(v)
    try { localStorage.setItem(VIEW_KEY, v) } catch { /* ignore */ }
  }, [])

  // 标签页变化 → 持久化（按 target 分 key）
  useEffect(() => {
    if (!target) return
    try {
      localStorage.setItem(groupKey(target, 'queue'), JSON.stringify(queueGroup))
      localStorage.setItem(groupKey(target, 'findings'), JSON.stringify(findingsGroup))
    } catch { /* ignore */ }
  }, [target, queueGroup, findingsGroup])

  // 在指定组 upsert 一个二级标签并激活（同 kind+key 去重）
  const upsertSubTab = useCallback((
    group: 'queue' | 'findings',
    tab: SubTab,
    jumpToView?: ViewId,
  ) => {
    const setter = group === 'queue' ? setQueueGroup : setFindingsGroup
    setter(prev => {
      const exists = prev.tabs.some(t => t.kind === tab.kind && t.key === tab.key)
      return {
        tabs: exists ? prev.tabs : [...prev.tabs, tab],
        active: tab.key,
      }
    })
    if (jumpToView) setActiveView(jumpToView)
  }, [setActiveView])

  // 队列资产详情：开在 queue 组
  const openAssetDetail = useCallback((host: string) => {
    upsertSubTab('queue', { kind: 'asset', key: host, title: host }, 'queue')
  }, [upsertSubTab])

  // 疑点详情：开在 queue 组（资产详情里的疑点）
  const openSpDetail = useCallback((id: string, title: string) => {
    upsertSubTab('queue', { kind: 'sp', key: id, title: title || '疑点' })
  }, [upsertSubTab])

  // 漏洞详情：开在漏洞组（从漏洞列表）或队列组（从资产详情发现）
  const openFindingDetail = useCallback((id: string, title: string) => {
    const group = activeView === 'findings' ? 'findings' : 'queue'
    upsertSubTab(group, { kind: 'finding', key: id, title: title || '漏洞' })
    if (group === 'findings') setActiveView('findings')
  }, [activeView, upsertSubTab, setActiveView])

  const closeSubTab = useCallback((group: 'queue' | 'findings', key: string) => {
    const setter = group === 'queue' ? setQueueGroup : setFindingsGroup
    setter(prev => {
      const idx = prev.tabs.findIndex(t => t.key === key)
      if (idx < 0) return prev
      const tabs = prev.tabs.filter(t => t.key !== key)
      let active = prev.active
      if (active === key) {
        active = tabs[Math.min(idx, tabs.length - 1)]?.key ?? 'root'
      }
      return { tabs, active }
    })
  }, [])

  const activateSubTab = useCallback((group: 'queue' | 'findings', key: string) => {
    const setter = group === 'queue' ? setQueueGroup : setFindingsGroup
    setter(prev => ({ ...prev, active: key }))
  }, [])

  const backToRoot = useCallback((group: 'queue' | 'findings') => {
    const setter = group === 'queue' ? setQueueGroup : setFindingsGroup
    setter(prev => ({ ...prev, active: 'root' }))
  }, [])

  return (
    <Ctx.Provider
      value={{
        target, setTarget, focusAsset, setFocusAsset,
        activeView, setActiveView,
        queueGroup, findingsGroup,
        openAssetDetail, openSpDetail, openFindingDetail,
        closeSubTab, activateSubTab, backToRoot,
      }}
    >
      {children}
    </Ctx.Provider>
  )
}

export function useApp() {
  const v = useContext(Ctx)
  if (!v) throw new Error('useApp must be inside AppProvider')
  return v
}
