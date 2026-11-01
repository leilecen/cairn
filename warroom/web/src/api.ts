import type {
  Target, ViewData, QueueItem, AssetItem, FindingItem, BlockersData, AssetDetail, DisclosureData, InsightWallData, InsightDetailData, InsightChainsData,
} from './types'

const BASE = '/api'

async function get<T>(path: string): Promise<T> {
  const res = await fetch(path)
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
  return res.json() as Promise<T>
}

export const fetchTargets = () => get<{ targets: Target[] }>(`${BASE}/targets`)
export const fetchView = (target: string) => get<ViewData>(`${BASE}/view?target=${encodeURIComponent(target)}`)
export const fetchQueue = (target: string) => get<{ items: QueueItem[] }>(`${BASE}/queue?target=${encodeURIComponent(target)}`)
export const fetchAssets = (target: string) => get<{ assets: AssetItem[]; counts: any }>(`${BASE}/assets?target=${encodeURIComponent(target)}`)
export const fetchFindings = (target: string) => get<{ findings: FindingItem[] }>(`${BASE}/findings?target=${encodeURIComponent(target)}`)
export const fetchBlockers = (target: string) => get<BlockersData>(`${BASE}/blockers?target=${encodeURIComponent(target)}`)
export const fetchAssetDetail = (target: string, host: string) => get<AssetDetail>(`${BASE}/asset?target=${encodeURIComponent(target)}&host=${encodeURIComponent(host)}`)
export const fetchDisclosure = (target: string) => get<DisclosureData>(`${BASE}/disclosure?target=${encodeURIComponent(target)}`)
export const fetchSpDetail = (target: string, id: string) => get<{ sp: any }>(`${BASE}/sp?target=${encodeURIComponent(target)}&id=${encodeURIComponent(id)}`)
export const fetchInsightWall = (target: string, opts?: { recommended?: boolean }) => {
  const params: string[] = [`target=${encodeURIComponent(target)}`]
  if (opts?.recommended) params.push('recommended=1')
  return get<InsightWallData>(`${BASE}/insight-wall?${params.join('&')}`)
}
export const fetchInsightDetail = (target: string, id: number | string) => get<InsightDetailData>(`${BASE}/insight-detail?target=${encodeURIComponent(target)}&id=${encodeURIComponent(String(id))}`)
export const fetchInsightChains = (target: string) => get<InsightChainsData>(`${BASE}/insight-chains?target=${encodeURIComponent(target)}`)
