/**
 * warroom-dashboard — Client 半（浏览器/桌面壳里的 GUI 侧）
 *
 * 把 SRC 作战室看板以「右侧可调宽抽屉」融入 DSH GUI（web 与 desktop 共用同一份 bundle）：
 *  - 注册 shell.overlay：可拖拽入口按钮 + 抽屉面板（iframe 内嵌作战室后端）
 *  - 打开前先「协议级探活」（no-cors fetch /api/targets，绕开 CORS 误报），最多重试 ~16s，
 *    避免后端刚被 host 半拉起时抽屉里只有浏览器错误页
 *  - 候选地址：localStorage warroom.url 覆盖 → Dev Tunnel 端口映射 → 当前 host 的 8787/8788/8789
 *  - 桌面端适配：抽屉可拖左边缘调宽、可重载 iframe、可「在浏览器打开」、入口按钮可拖拽 + 双击变图标态；
 *    宽度/位置/展开状态/紧凑态都持久化到 localStorage（按 origin 隔离，desktop 与 web 各记各的）
 *  - 快捷键：Esc 关闭；Ctrl/Cmd+Alt+W 开关
 *
 * 构建：esbuild src/client.tsx -> lib/client.js（window.__ModuleLoader__ 格式）
 */
import { useCallback, useEffect, useRef, useState, type ComponentType } from 'react'

/** 候选端口：与 host 半的 DEFAULT_PORTS 保持一致。 */
const PORTS = [8787, 8788, 8789]
/** Dev Tunnels 主机名形如 bww3c3lf-3080.asse.devtunnels.ms（端口段 = 被转发的本地端口）。 */
const DEV_TUNNEL_RE = /^([a-z0-9-]+)-(\d+)\.([a-z0-9.-]+)\.devtunnels\.ms$/i
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/
const HOSTNAME_RE = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i

const STORE = {
  url: 'warroom.url',
  open: 'warroom.open',
  width: 'warroom.width',
  btnRight: 'warroom.btn.right',
  btnBottom: 'warroom.btn.bottom',
  compact: 'warroom.btn.compact',
}

function readStore(key: string): string | null {
  try { return localStorage.getItem(key) } catch { return null }
}
function writeStore(key: string, value: string): void {
  try { localStorage.setItem(key, value) } catch { /* 无 localStorage 时静默降级 */ }
}
function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms))
}

/** 作战室后端候选地址（按访问场景）。 */
function warroomCandidates(): string[] {
  const override = readStore(STORE.url)
  if (override) return [override]
  const host = window.location.hostname || '127.0.0.1'
  const tunnel = host.match(DEV_TUNNEL_RE)
  if (tunnel) return PORTS.map((p) => `https://${tunnel[1]}-${p}.${tunnel[3]}.devtunnels.ms/`)
  // 非网络主机名（自定义协议壳 / 空 host）回落到本机，否则沿用当前 host（手机走局域网 IP 的场景）
  const target = host === 'localhost' || IPV4_RE.test(host) || (HOSTNAME_RE.test(host) && host.includes('.')) || IPV4_RE.test(host)
    ? host
    : '127.0.0.1'
  return PORTS.map((p) => `http://${target}:${p}/`)
}

/**
 * 协议级探活：no-cors 模式只看「请求是否发得出去」，不读响应，因此不会像默认 cors 模式那样
 * 被 CORS 拦截误判成「后端没起」。任何 HTTP 状态都算可达，网络错误/超时才算不可达。
 */
async function reachable(base: string, timeoutMs = 900): Promise<boolean> {
  try {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeoutMs)
    await fetch(`${base}api/targets`, {
      mode: 'no-cors',
      cache: 'no-store',
      credentials: 'omit',
      signal: controller.signal,
    })
    clearTimeout(timer)
    return true
  } catch {
    return false
  }
}

function clampWidth(px: number): number {
  const max = Math.max(420, window.innerWidth - 80)
  return Math.min(Math.max(420, px), max)
}

const btnStyle: Record<string, string | number> = {
  pointerEvents: 'auto',
  display: 'flex',
  alignItems: 'center',
  gap: 6,
  padding: '8px 14px',
  borderRadius: 8,
  border: '1px solid rgba(255,255,255,.14)',
  background: 'rgba(30,30,30,.92)',
  color: '#4ec9b0',
  fontSize: 13,
  fontWeight: 600,
  cursor: 'grab',
  boxShadow: '0 4px 16px rgba(0,0,0,.45)',
  userSelect: 'none',
}

/** overlay 条目组件：可拖拽入口按钮 + 可调宽右侧抽屉 */
const WarroomOverlay: ComponentType<any> = () => {
  const [open, setOpen] = useState(false)
  const [phase, setPhase] = useState<'idle' | 'probing' | 'ready' | 'error'>('idle')
  const [baseUrl, setBaseUrl] = useState('')
  const [detail, setDetail] = useState('')
  const [reloadKey, setReloadKey] = useState(0)
  const [width, setWidth] = useState(() => clampWidth(Number(readStore(STORE.width)) || Math.min(1100, window.innerWidth * 0.88)))
  const [compact, setCompact] = useState(() => readStore(STORE.compact) === '1')
  const [btnPos, setBtnPos] = useState(() => ({
    right: Number(readStore(STORE.btnRight)) || 18,
    bottom: Number(readStore(STORE.btnBottom)) || 18,
  }))
  const btnRef = useRef<HTMLButtonElement | null>(null)
  const dragRef = useRef<{ x: number; y: number; right: number; bottom: number; moved: boolean } | null>(null)
  const resizingRef = useRef(false)

  /** 逐个候选地址探活，失败后重试若干轮（host 半拉后端约需数秒）。 */
  const connect = useCallback(async () => {
    setPhase('probing')
    setDetail('')
    const urls = warroomCandidates()
    for (let round = 0; round < 6; round++) {
      for (const url of urls) {
        if (await reachable(url)) {
          setBaseUrl(url)
          setPhase('ready')
          return
        }
      }
      await sleep(600)
    }
    setPhase('error')
    setDetail(`已尝试 ${urls.join(' / ')}。若后端换了端口或走隧道，可在控制台执行 localStorage.setItem('warroom.url','http://127.0.0.1:8787/') 后重开。`)
  }, [])

  const openPanel = useCallback(() => {
    setOpen(true)
    writeStore(STORE.open, '1')
    void connect()
  }, [connect])

  const closePanel = useCallback(() => {
    setOpen(false)
    writeStore(STORE.open, '0')
  }, [])

  // 载入时恢复上次的展开状态（桌面端常驻使用：关掉页面再回来还在）
  useEffect(() => {
    if (readStore(STORE.open) === '1') {
      setOpen(true)
      void connect()
    }
  }, [connect])

  // 快捷键：Esc 关闭；Ctrl/Cmd+Alt+W 开关
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') closePanel()
      if ((e.ctrlKey || e.metaKey) && e.altKey && (e.key === 'w' || e.key === 'W')) {
        e.preventDefault()
        setOpen((prev) => {
          if (prev) {
            writeStore(STORE.open, '0')
            return false
          }
          writeStore(STORE.open, '1')
          void connect()
          return true
        })
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [closePanel, connect])

  // 已就绪后每 20s 复检：后端挂了就把 iframe 换成可重试的提示，而不是留一页旧数据
  useEffect(() => {
    if (phase !== 'ready' || !baseUrl) return
    const timer = window.setInterval(() => {
      void reachable(baseUrl, 1200).then((ok) => {
        if (!ok) {
          setPhase('error')
          setDetail('后端连接中断，请确认 warroom 后端进程是否还在运行。')
        }
      })
    }, 20000)
    return () => window.clearInterval(timer)
  }, [phase, baseUrl])

  // ── 入口按钮拖拽（简单 pointer 手势；双击切换紧凑态） ──
  const onBtnPointerDown = (e: React.PointerEvent<HTMLButtonElement>) => {
    if (e.button !== 0) return
    dragRef.current = { x: e.clientX, y: e.clientY, right: btnPos.right, bottom: btnPos.bottom, moved: false }
    btnRef.current?.setPointerCapture(e.pointerId)
  }
  const onBtnPointerMove = (e: React.PointerEvent<HTMLButtonElement>) => {
    const d = dragRef.current
    if (!d) return
    const dx = e.clientX - d.x
    const dy = e.clientY - d.y
    if (Math.abs(dx) > 3 || Math.abs(dy) > 3) d.moved = true
    setBtnPos({
      right: Math.min(Math.max(6, d.right - dx), window.innerWidth - 60),
      bottom: Math.min(Math.max(6, d.bottom - dy), window.innerHeight - 40),
    })
  }
  const onBtnPointerUp = (e: React.PointerEvent<HTMLButtonElement>) => {
    const d = dragRef.current
    dragRef.current = null
    try { btnRef.current?.releasePointerCapture(e.pointerId) } catch { /* noop */ }
    if (d?.moved) {
      writeStore(STORE.btnRight, String(btnPos.right))
      writeStore(STORE.btnBottom, String(btnPos.bottom))
    } else {
      openPanel()
    }
  }

  // ── 抽屉左边缘拖拽调宽 ──
  const onResizeDown = (e: React.PointerEvent<HTMLDivElement>) => {
    resizingRef.current = true
    ;(e.target as HTMLElement).setPointerCapture(e.pointerId)
  }
  const onResizeMove = (e: React.PointerEvent<HTMLDivElement>) => {
    if (!resizingRef.current) return
    setWidth(clampWidth(window.innerWidth - e.clientX))
  }
  const onResizeUp = (e: React.PointerEvent<HTMLDivElement>) => {
    resizingRef.current = false
    try { (e.target as HTMLElement).releasePointerCapture(e.pointerId) } catch { /* noop */ }
    writeStore(STORE.width, String(width))
  }

  const iconBtn: Record<string, string | number> = {
    pointerEvents: 'auto',
    background: 'transparent',
    border: '1px solid #333338',
    color: '#d4d4d4',
    borderRadius: 4,
    padding: '3px 10px',
    fontSize: 12,
    cursor: 'pointer',
  }

  return (
    <div
      data-warroom-dashboard
      style={{
        position: 'fixed',
        inset: 0,
        pointerEvents: 'none',
        zIndex: 9999,
        fontFamily: '"Segoe UI", "Microsoft YaHei", system-ui, sans-serif',
      }}
    >
      {!open && (
        <button
          ref={btnRef}
          onClick={(e) => e.preventDefault()}
          onPointerDown={onBtnPointerDown}
          onPointerMove={onBtnPointerMove}
          onPointerUp={onBtnPointerUp}
          onDoubleClick={(e) => {
            e.preventDefault()
            const next = !compact
            setCompact(next)
            writeStore(STORE.compact, next ? '1' : '0')
          }}
          title="点击打开作战室（拖拽移动，双击切紧凑态，Ctrl/Cmd+Alt+W 开关）"
          style={{ position: 'fixed', right: btnPos.right, bottom: btnPos.bottom, ...btnStyle }}
        >
          <span aria-hidden>⬡</span>
          {!compact && <span>作战室</span>}
          {phase === 'error' && !compact && <span style={{ color: '#e06c75', fontSize: 11 }}>· 未连接</span>}
        </button>
      )}

      {open && (
        <>
          <div
            onClick={closePanel}
            style={{ position: 'fixed', inset: 0, pointerEvents: 'auto', background: 'rgba(0,0,0,.45)' }}
          />
          <div
            style={{
              position: 'fixed',
              top: 0,
              right: 0,
              bottom: 0,
              width,
              pointerEvents: 'auto',
              display: 'flex',
              flexDirection: 'column',
              background: '#0a0a0a',
              boxShadow: '-8px 0 32px rgba(0,0,0,.5)',
              borderLeft: '1px solid #26262a',
            }}
          >
            {/* 左边缘拖拽调宽 */}
            <div
              onPointerDown={onResizeDown}
              onPointerMove={onResizeMove}
              onPointerUp={onResizeUp}
              title="拖拽调整宽度"
              style={{
                position: 'absolute',
                left: -3,
                top: 0,
                bottom: 0,
                width: 6,
                cursor: 'col-resize',
                zIndex: 2,
              }}
            />

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '6px 12px',
                background: '#111214',
                borderBottom: '1px solid #26262a',
                flex: 'none',
              }}
            >
              <span style={{ color: '#4ec9b0', fontWeight: 700, fontSize: 13 }}>⬡ SRC 作战室</span>
              <span style={{ color: '#8b8b93', fontSize: 11 }}>
                {baseUrl || '未连接'} · 只读看板
              </span>
              <div style={{ flex: 1 }} />
              {phase === 'ready' && (
                <>
                  <button onClick={() => setReloadKey((k) => k + 1)} title="重新加载看板" style={iconBtn}>
                    ⟳ 重载
                  </button>
                  <button
                    onClick={() => window.open(baseUrl, '_blank', 'noopener,noreferrer')}
                    title="在浏览器中打开（便于手机/外屏对照）"
                    style={iconBtn}
                  >
                    ↗ 浏览器
                  </button>
                </>
              )}
              <button onClick={closePanel} title="关闭 (Esc)" style={iconBtn}>
                ✕ 关闭
              </button>
            </div>

            <div style={{ flex: 1, position: 'relative', overflow: 'hidden' }}>
              {phase === 'ready' ? (
                <iframe
                  key={`${baseUrl}#${reloadKey}`}
                  src={baseUrl}
                  title="SRC 作战室看板"
                  style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', border: 'none', background: '#0a0a0a' }}
                />
              ) : (
                <div
                  style={{
                    position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
                    alignItems: 'center', justifyContent: 'center', gap: 12,
                    background: '#0a0a0a', color: phase === 'error' ? '#e06c75' : '#4ec9b0',
                    fontSize: 13, padding: 24, textAlign: 'center',
                  }}
                >
                  <div style={{ fontWeight: 700 }}>
                    {phase === 'probing' ? '⬡ 正在连接作战室后端…' : phase === 'error' ? '✕ 作战室后端未就绪' : '⬡ 准备打开作战室'}
                  </div>
                  {phase === 'probing' && (
                    <div style={{ color: '#8b8b93', fontSize: 12 }}>
                      host 半已自动拉起后端（8787/8788/8789），通常数秒内可达
                    </div>
                  )}
                  {detail && (
                    <div style={{ color: '#8b8b93', fontSize: 12, maxWidth: 460, wordBreak: 'break-all' }}>{detail}</div>
                  )}
                  <button
                    onClick={() => void connect()}
                    style={{
                      background: '#22262a', color: '#d4d4d4', border: '1px solid #3a3f44',
                      borderRadius: 6, padding: '6px 16px', fontSize: 12, cursor: 'pointer',
                    }}
                  >
                    重试
                  </button>
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  )
}

export function apply(ctx: any): void {
  // 防重挂载：HMR 重载或同一页面重复加载插件时只保留一份 overlay。
  const flag = '__warroomDashboardMounted'
  if ((window as any)[flag]) return
  ;(window as any)[flag] = true

  // 'shell.overlay' 由 ui-layout 把 AppFrame 注册进 'root' 时才声明；用 slots.inject 挂到其声明生命周期上。
  ctx.slots.inject('shell.overlay', () =>
    ctx.slots.register(
      {
        name: 'shell.overlay',
        id: 'warroom-dashboard',
      },
      WarroomOverlay,
    ),
  )
}

/** Required services (cordis fiber inject — loader passes module exports as object plugin). */
export const inject = ['slots']
