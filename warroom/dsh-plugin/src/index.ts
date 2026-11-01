/**
 * warroom-dashboard — Host 半（运行在 dsh 的 Node 进程里，web / desktop 两个 profile 通用）
 *
 * 职责：确保 SRC 作战室后端（warroom/server.py）在 dsh 启动时已就绪。
 *  1. 按候选端口逐个探测「这是不是我们的后端」——HTTP GET /api/targets 并校验 JSON，
 *     而不是只看 TCP 能连（8787 被别的服务占用时，旧实现会误判为「已在运行」→ 抽屉里看到别人的页面）。
 *  2. 未就绪 → 以 detached 后台进程拉起，stdout/stderr 落 <projectRoot>/tmp/warroom/backend-<port>.log。
 *  3. 解释器按 仓库 .venv → uv → py/python 顺序解析（本机 shell 无全局 uv，优先用 .venv/Scripts/python.exe）。
 *     旧实现只 spawn('uv', …)，PATH 里没有 uv 时静默失败、抽屉里只剩浏览器错误页。
 *
 * 配置来源（字段级，前者优先；用于跨机器/换目录）：
 *  1) 环境变量 WARROOM_PROJECT_ROOT / WARROOM_PORTS / WARROOM_PORT / WARROOM_HOST /
 *     WARROOM_PYTHON / WARROOM_AUTOSTART，以及旧名 SRC_PROJECT_ROOT
 *  2) $DSH_HOME/warroom.json（默认 ~/.dsh/warroom.json）
 *     {"projectRoot":"D:/path/to/cairn","port":8787,"host":"0.0.0.0","python":"…python.exe","autoStart":true}
 *  3) 内置默认：候选端口 [8787,8788,8789]；bind host 0.0.0.0（沿用旧行为，手机/Dev Tunnel 可达；
 *     只想本机访问就在 warroom.json 里写 "host": "127.0.0.1"）
 *
 * 生命周期：子进程 detached + unref，独立常驻，不随 dsh 退出；端口探测保证多实例（web + desktop）幂等复用。
 * 构建：esbuild src/index.ts -> lib/index.js（ESM，导出 apply / ensureBackend）
 */
import { spawn } from 'node:child_process'
import { existsSync, mkdirSync, openSync, readFileSync } from 'node:fs'
import { get as httpGet } from 'node:http'
import { createConnection } from 'node:net'
import { homedir } from 'node:os'
import { dirname, join, resolve } from 'node:path'

const DEFAULT_PORTS = [8787, 8788, 8789]
const READY_TIMEOUT_MS = 25000
/** 后端入口相对项目根的路径（同时是「项目根识别标记」）。 */
const SERVER_REL = join('warroom', 'server.py')

export interface WarroomConfig {
  projectRoot?: string
  ports: number[]
  host: string
  python?: string
  autoStart: boolean
}

export interface EnsureResult {
  status: 'ready' | 'starting' | 'error'
  port?: number
  message: string
}

interface Interpreter {
  command: string
  args: string[]
  label: string
}

// ─────────────────────────── 配置 ───────────────────────────

function readJsonFile(file: string): Record<string, unknown> | undefined {
  try {
    const parsed = JSON.parse(readFileSync(file, 'utf8').replace(/^\uFEFF/, ''))
    return parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : undefined
  } catch {
    return undefined
  }
}

function envNumber(env: NodeJS.ProcessEnv, name: string): number | undefined {
  const raw = env[name]
  if (!raw) return undefined
  const n = Number(raw)
  return Number.isInteger(n) && n > 0 && n < 65536 ? n : undefined
}

function envFlag(env: NodeJS.ProcessEnv, name: string, fallback: boolean): boolean {
  const raw = env[name]
  if (raw === undefined || raw.trim() === '') return fallback
  return !/^(0|false|no|off)$/i.test(raw.trim())
}

function normalizePorts(...sources: Array<number[] | undefined>): number[] {
  const out: number[] = []
  for (const list of sources) {
    for (const n of list ?? []) {
      const port = Number(n)
      if (Number.isInteger(port) && port > 0 && port < 65536 && !out.includes(port)) out.push(port)
    }
  }
  return out.length > 0 ? out : DEFAULT_PORTS.slice()
}

/** 合并 env + $DSH_HOME/warroom.json + 默认值，字段级覆盖。 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): WarroomConfig {
  const home = env.DSH_HOME || join(homedir(), '.dsh')
  const file = readJsonFile(join(home, 'warroom.json')) ?? {}

  const envPorts = (env.WARROOM_PORTS || '')
    .split(',')
    .map((s) => Number(s.trim()))
    .filter((n) => Number.isInteger(n) && n > 0 && n < 65536)
  const filePorts = Array.isArray(file.ports) ? (file.ports as number[]) : undefined
  const singlePort = envNumber(env, 'WARROOM_PORT') ?? (typeof file.port === 'number' ? file.port : undefined)

  const ports = normalizePorts(
    envPorts.length > 0 ? envPorts : undefined,
    filePorts,
    singlePort !== undefined ? [singlePort, ...DEFAULT_PORTS] : undefined,
  )

  const rootRaw =
    env.WARROOM_PROJECT_ROOT ||
    env.SRC_PROJECT_ROOT ||
    (typeof file.projectRoot === 'string' ? file.projectRoot : '')

  return {
    projectRoot: rootRaw || undefined,
    ports,
    host: env.WARROOM_HOST || (typeof file.host === 'string' && file.host ? file.host : '0.0.0.0'),
    python: env.WARROOM_PYTHON || (typeof file.python === 'string' && file.python ? file.python : undefined),
    autoStart: envFlag(env, 'WARROOM_AUTOSTART', file.autoStart !== false),
  }
}

// ─────────────────────────── 探测 ───────────────────────────

/** 探测 127.0.0.1:port 是否有 TCP 监听（判断端口是否被别的服务占用）。 */
export function probePort(port: number, timeoutMs = 600): Promise<boolean> {
  return new Promise((done) => {
    let settled = false
    const finish = (ok: boolean) => {
      if (settled) return
      settled = true
      try { sock.destroy() } catch { /* noop */ }
      done(ok)
    }
    const sock = createConnection({ port, host: '127.0.0.1' })
    sock.setTimeout(timeoutMs)
    sock.once('connect', () => finish(true))
    sock.once('error', () => finish(false))
    sock.once('timeout', () => finish(false))
  })
}

/**
 * 判断 127.0.0.1:port 上跑的是不是作战室后端：GET /api/targets 必须返回 200 且 JSON 里有 targets 数组。
 * 只看 TCP 会误判（任何服务都能占 8787），所以这里做一次协议级校验。
 */
export function probeWarroom(port: number, timeoutMs = 1500): Promise<boolean> {
  return new Promise((done) => {
    let settled = false
    const finish = (ok: boolean) => {
      if (settled) return
      settled = true
      try { req.destroy() } catch { /* noop */ }
      done(ok)
    }
    const req = httpGet(
      { host: '127.0.0.1', port, path: '/api/targets', timeout: timeoutMs, headers: { accept: 'application/json' } },
      (res) => {
        if (res.statusCode !== 200) { res.resume(); finish(false); return }
        let body = ''
        res.setEncoding('utf8')
        res.on('data', (chunk) => {
          body += chunk
          if (body.length > 65536) finish(false)
        })
        res.on('end', () => {
          try {
            const parsed = JSON.parse(body) as { targets?: unknown }
            finish(Array.isArray(parsed?.targets))
          } catch { finish(false) }
        })
      },
    )
    req.on('timeout', () => finish(false))
    req.on('error', () => finish(false))
  })
}

/** 等待后端协议级就绪（带总超时）。 */
async function waitWarroom(port: number, timeoutMs: number): Promise<boolean> {
  const start = Date.now()
  for (;;) {
    if (await probeWarroom(port, 800)) return true
    if (Date.now() - start > timeoutMs) return false
    await new Promise((r) => setTimeout(r, 500))
  }
}

// ─────────────────────────── 项目根 / 解释器 ───────────────────────────

/** 定位 SRC 项目根：返回含 warroom/server.py 的目录。 */
export function locateRoot(config: WarroomConfig = loadConfig()): string | null {
  const candidates: string[] = []
  if (config.projectRoot) candidates.push(config.projectRoot)
  let dir = process.cwd()
  for (let i = 0; i < 6; i++) {
    candidates.push(dir)
    const parent = dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  // 本机已知路径兜底（跨 profile 启动时 cwd 常常不是项目根）
  candidates.push('D:/path/to/cairn')

  for (const cand of candidates) {
    if (!cand) continue
    const base = resolve(cand)
    if (existsSync(join(base, SERVER_REL))) return base
  }
  return null
}

/** 在 PATH 里找一个可执行文件（不依赖 which/where 子进程）。 */
export function findOnPath(names: string[]): string | undefined {
  const sep = process.platform === 'win32' ? ';' : ':'
  const dirs = (process.env.PATH || '').split(sep).filter(Boolean)
  const exts = process.platform === 'win32'
    ? (process.env.PATHEXT || '.COM;.EXE;.BAT;.CMD').split(';').filter(Boolean)
    : ['']
  for (const dir of dirs) {
    for (const name of names) {
      const plain = join(dir, name)
      if (existsSync(plain)) return plain
      if (process.platform === 'win32' && !/\.[a-z]+$/i.test(name)) {
        for (const ext of exts) {
          const withExt = join(dir, name + ext.toLowerCase())
          if (existsSync(withExt)) return withExt
          const upper = join(dir, name + ext.toUpperCase())
          if (existsSync(upper)) return upper
        }
      }
    }
  }
  return undefined
}

/**
 * 解析 Python 解释器，顺序：显式配置 → 仓库 venv → PATH 上的 uv → PATH 上的 python/py。
 * venv 优先的原因见 AGENTS.md：本机 shell 没有全局 uv，仓库 venv 才是稳定入口。
 */
export function resolveInterpreter(root: string, config: WarroomConfig = loadConfig()): Interpreter | null {
  if (config.python && existsSync(config.python)) {
    return { command: config.python, args: [], label: `python(${config.python})` }
  }
  const venv = process.platform === 'win32'
    ? join(root, '.venv', 'Scripts', 'python.exe')
    : join(root, '.venv', 'bin', 'python')
  if (existsSync(venv)) return { command: venv, args: [], label: `venv(${venv})` }

  const uv = findOnPath(['uv']) ??
    [join(process.env.LOCALAPPDATA || '', 'hermes', 'bin', 'uv.exe'), join(homedir(), '.local', 'bin', 'uv.exe')]
      .find((p) => p && existsSync(p))
  if (uv) return { command: uv, args: ['run', 'python'], label: `uv(${uv})` }

  const fallback = findOnPath(process.platform === 'win32' ? ['python', 'py'] : ['python3', 'python'])
  if (fallback) {
    return {
      command: fallback,
      args: /[\\/]py(\.exe)?$/i.test(fallback) ? ['-3'] : [],
      label: `python(${fallback})`,
    }
  }
  return null
}

// ─────────────────────────── 拉起后端 ───────────────────────────

/** 选一个「TCP 空闲」的候选端口，跳过被别的服务占用的端口。 */
async function pickPort(ports: number[]): Promise<number | undefined> {
  for (const port of ports) {
    if (!(await probePort(port, 400))) return port
  }
  return undefined
}

/** detached 拉起后端，stdout/stderr 追加写日志文件；返回日志路径。 */
function startBackend(root: string, port: number, host: string, interp: Interpreter): string {
  const logDir = join(root, 'tmp', 'warroom')
  mkdirSync(logDir, { recursive: true })
  const logPath = join(logDir, `backend-${port}.log`)
  const out = openSync(logPath, 'a')
  const err = openSync(logPath, 'a')

  const child = spawn(
    interp.command,
    [...interp.args, SERVER_REL, '--port', String(port), '--host', host],
    { cwd: root, stdio: ['ignore', out, err], detached: true, windowsHide: true, shell: false },
  )
  child.on('error', (e: Error) => {
    console.error('[warroom-dashboard] spawn backend failed:', e?.message ?? e)
  })
  child.unref()
  return logPath
}

/**
 * 幂等确保后端就绪。
 * @returns ready=已有实例复用 / starting=本次拉起成功 / error=需要人工处理（含可读原因）
 */
export async function ensureBackend(config: WarroomConfig = loadConfig()): Promise<EnsureResult> {
  for (const port of config.ports) {
    if (await probeWarroom(port)) {
      return { status: 'ready', port, message: `warroom 后端已在运行(${port})，复用现有实例` }
    }
  }

  if (!config.autoStart) {
    return { status: 'error', message: '未检测到 warroom 后端，且 WARROOM_AUTOSTART / autoStart 已关闭' }
  }

  const root = locateRoot(config)
  if (!root) {
    return {
      status: 'error',
      message: '未找到 SRC 项目根(warroom/server.py)；设 WARROOM_PROJECT_ROOT 或 ~/.dsh/warroom.json 的 projectRoot',
    }
  }

  const port = await pickPort(config.ports)
  if (port === undefined) {
    return { status: 'error', message: `候选端口全部被占用(${config.ports.join(', ')})` }
  }

  const interp = resolveInterpreter(root, config)
  if (!interp) {
    return { status: 'error', message: `未找到可用 Python 解释器；确认 ${join(root, '.venv')} 或 PATH 上的 uv/python` }
  }

  const logPath = startBackend(root, port, config.host, interp)
  const ok = await waitWarroom(port, READY_TIMEOUT_MS)
  return ok
    ? { status: 'starting', port, message: `已拉起后端(${interp.label} → 127.0.0.1:${port}, bind ${config.host})，日志 ${logPath}` }
    : { status: 'error', port, message: `后端拉起后超时未就绪(${READY_TIMEOUT_MS}ms)，见日志 ${logPath}` }
}

/** host 半入口：cordis loader 加载本插件时调用；异步副作用不阻塞插件加载。 */
export function apply(_ctx?: unknown): void {
  ensureBackend()
    .then((r) => {
      const line = `[warroom-dashboard] backend ensure: ${r.status} — ${r.message}`
      if (r.status === 'error') console.error(line)
      else console.log(line)
    })
    .catch((e: unknown) => {
      console.error('[warroom-dashboard] backend ensure failed:', (e as Error)?.message ?? e)
    })
}
