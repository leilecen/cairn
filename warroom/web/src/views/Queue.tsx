import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useApp } from '../store'
import { fetchQueue } from '../api'
import { Empty, useFocus, Btn } from './helpers'
import { statusColor } from '../colors'
import { resolveUrl } from '../url'
import { AssetList } from './AssetList'

type QueueSub = 'queue' | 'assets'

/** 队列视图（队列组 root）：待测队列 / 资产分组列表；详情在组内二级标签 */
export function Queue() {
  const { openAssetDetail } = useApp()
  const [sub, setSub] = useState<QueueSub>('queue')

  return (
    <div>
      <SubTabs sub={sub} onSwitch={setSub} />
      <div className="mt-3">
        {sub === 'queue' ? (
          <QueueList onOpenAsset={openAssetDetail} />
        ) : (
          <AssetList />
        )}
      </div>
    </div>
  )
}

function SubTabs({ sub, onSwitch }: { sub: QueueSub; onSwitch: (s: QueueSub) => void }) {
  const items: { id: QueueSub; label: string }[] = [
    { id: 'queue', label: '待测队列' },
    { id: 'assets', label: '资产（披露分组）' },
  ]
  return (
    <div className="flex items-end gap-0.5">
      {items.map(it => (
        <button
          key={it.id}
          onClick={() => onSwitch(it.id)}
          className={`px-3.5 py-1.5 text-xs rounded-t-md border border-b-0 cursor-pointer ${
            sub === it.id
              ? 'bg-surface-2 text-ink-bright border-edge'
              : 'bg-transparent text-ink-dim border-transparent hover:text-ink'
          }`}
        >
          {it.label}
        </button>
      ))}
    </div>
  )
}

function QueueList({ onOpenAsset }: { onOpenAsset: (host: string) => void }) {
  const { target } = useApp()
  const focusHost = useFocus()
  const { data } = useQuery({
    queryKey: ['queue', target],
    queryFn: () => fetchQueue(target),
    enabled: !!target,
    refetchInterval: 15000,
  })

  if (!data) return <Empty msg="加载中…" />
  if (!data.items?.length) return <Empty msg="待测队列为空" />

  return (
    <div>
      {data.items.map(it => {
        const href = resolveUrl(it.url, focusHost)
        return (
          <div
            key={it.id}
            className="flex items-center gap-2.5 px-2 py-2 border-b border-edge text-xs hover:bg-surface-4/50"
          >
            {/* 状态 */}
            <span
              className="w-16 shrink-0 whitespace-nowrap"
              style={{ color: statusColor[it.status] || 'var(--color-ink-dim)' }}
            >
              {it.status}
            </span>

            {/* 资产名（打开资产详情） */}
            {it.asset_host ? (
              <button
                onClick={() => onOpenAsset(it.asset_host)}
                title="打开该资产详情"
                className="w-36 shrink-0 text-left text-violet hover:underline truncate bg-transparent border-none p-0 text-xs cursor-pointer"
              >
                {it.asset_host}
              </button>
            ) : (
              <span className="dim w-36 shrink-0 truncate">—</span>
            )}

            {/* 中文说明 */}
            <span className="flex-1 min-w-0 truncate">{it.title}</span>

            {/* 指纹/端口 */}
            {it.hint && (
              <span className="dim shrink-0 max-w-[200px] truncate hidden lg:inline">{it.hint}</span>
            )}

            {/* 蓝色 URL（打开对应网页） */}
            {href ? (
              <a
                href={href}
                target="_blank"
                rel="noopener noreferrer"
                onClick={e => { e.preventDefault(); window.open(href, '_blank', 'noopener') }}
                className="text-accent-soft no-underline hover:underline shrink-0 max-w-[280px] truncate"
              >
                {it.url}
              </a>
            ) : (
              <span className="dim mono shrink-0 truncate max-w-[200px]">{it.url || '—'}</span>
            )}

            {/* 优先级 */}
            {it.priority != null && (
              <span className="dim shrink-0 w-8 text-right">{it.priority}</span>
            )}

            {/* 末尾按钮：打开资产详情 */}
            <Btn onClick={() => it.asset_host && onOpenAsset(it.asset_host)} disabled={!it.asset_host} title="查看资产详情">
              详情
            </Btn>
          </div>
        )
      })}
    </div>
  )
}
