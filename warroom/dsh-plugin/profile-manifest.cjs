#!/usr/bin/env node
/**
 * profile-manifest.cjs — dsh profile 清单/补丁的小工具（给 install.ps1 用，也可单独跑）
 *
 * 做三件事，全部幂等，写前先备份 (.bak-<时间戳>)：
 *  1. dependencies 里加/删 `warroom-dashboard`（默认 spec: file:./vendor/warroom-dashboard）
 *  2. dsh.profile.bundles 里加/删该组合包（组合包机制：由包内 cordis.patch.yml 提供 loader 行）
 *  3. profile 自己的 cordis.patch.yml 里加/删 `- insert:` 行（web profile 目前用的老机制）
 *
 * 用法:
 *   node profile-manifest.cjs add    --profile-dir <dir> --package <name> [--spec <spec>] [--bundle] [--patch-row]
 *   node profile-manifest.cjs remove --profile-dir <dir> --package <name> [--bundle] [--patch-row]
 *   node profile-manifest.cjs status --profile-dir <dir> --package <name>
 */
const fs = require('node:fs')
const path = require('node:path')

function parseArgs(argv) {
  const [command, ...rest] = argv
  const opts = { command }
  for (let i = 0; i < rest.length; i++) {
    const token = rest[i]
    if (!token.startsWith('--')) throw new Error(`unexpected argument: ${token}`)
    const key = token.slice(2)
    if (key === 'bundle' || key === 'patch-row' || key === 'help') { opts[key] = true; continue }
    const value = rest[++i]
    if (value === undefined) throw new Error(`missing value for --${key}`)
    opts[key] = value
  }
  return opts
}

function readText(file) {
  return fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, '')
}

function readJson(file) {
  return JSON.parse(readText(file))
}

function backup(file) {
  const stamp = new Date().toISOString().replace(/[-:TZ.]/g, '').slice(0, 14)
  const target = `${file}.bak-${stamp}`
  fs.copyFileSync(file, target)
  return target
}

function writeJson(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8')
}

/** 找到 profile 的 cordis.patch.yml 中该 id 的 insert 行（只支持基础的 `- id:` + `name:` 两行形式）。 */
function findPatchRow(lines, pkg) {
  const idLine = new RegExp(`^(\\s*)-\\s*id:\\s*['"]?${pkg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}['"]?\\s*$`)
  for (let i = 0; i < lines.length; i++) {
    const match = lines[i].match(idLine)
    if (!match) continue
    const indent = match[1].length
    let end = i + 1
    while (end < lines.length && /^\s+[\w-]+:/.test(lines[end]) && (lines[end].match(/^\s*/)[0].length > indent)) end++
    const block = lines.slice(i, end)
    const complex = block.some((line, idx) => idx > 0 && /^\s+(config|disabled|inject)\s*:/.test(line))
    return { start: i, end, block, complex }
  }
  return undefined
}

function main() {
  const opts = parseArgs(process.argv.slice(2))
  if (!opts.command || opts.help) {
    console.log(fs.readFileSync(__filename, 'utf8').split('*/')[0].split('/**')[1])
    return
  }
  const profileDir = path.resolve(opts['profile-dir'] ?? '.')
  const pkg = opts.package
  const spec = opts.spec ?? 'file:./vendor/warroom-dashboard'
  if (!pkg) throw new Error('--package is required')

  const manifestPath = path.join(profileDir, 'package.json')
  const patchPath = path.join(profileDir, 'cordis.patch.yml')
  const manifest = readJson(manifestPath)
  manifest.dependencies ??= {}
  manifest.dsh ??= {}
  manifest.dsh.profile ??= {}
  manifest.dsh.profile.bundles ??= []

  const report = []

  if (opts.command === 'status') {
    report.push(`dependency: ${manifest.dependencies[pkg] ?? '(none)'}`)
    report.push(`in dsh.profile.bundles: ${manifest.dsh.profile.bundles.includes(pkg)}`)
    if (fs.existsSync(patchPath)) {
      const lines = readText(patchPath).split(/\r?\n/)
      const row = findPatchRow(lines, pkg)
      report.push(`patch row in cordis.patch.yml: ${row ? `line ${row.start + 1}` : '(none)'}`)
    } else {
      report.push('patch row in cordis.patch.yml: (no cordis.patch.yml)')
    }
    console.log(report.join('\n'))
    return
  }

  if (opts.command === 'add') {
    let touched = false

    if (manifest.dependencies[pkg] !== spec) {
      report.push(`dependency ${pkg}: ${manifest.dependencies[pkg] ?? '(none)'} → ${spec}`)
      manifest.dependencies[pkg] = spec
      touched = true
    } else {
      report.push(`dependency ${pkg}: 已是 ${spec}`)
    }

    if (opts.bundle) {
      if (!manifest.dsh.profile.bundles.includes(pkg)) {
        manifest.dsh.profile.bundles.push(pkg)
        report.push(`dsh.profile.bundles += ${pkg}（顺序: ${manifest.dsh.profile.bundles.join(' → ')}）`)
        touched = true
      } else {
        report.push(`dsh.profile.bundles: 已包含 ${pkg}`)
      }
    }

    if (touched) {
      const bak = backup(manifestPath)
      writeJson(manifestPath, manifest)
      report.push(`package.json 已写入（备份 ${path.basename(bak)}）`)
    }

    if (opts['patch-row']) {
      if (!fs.existsSync(patchPath)) {
        report.push(`cordis.patch.yml 不存在，跳过手写 insert 行（如果走组合包机制不需要它）`)
      } else {
        const raw = readText(patchPath)
        const lines = raw.split(/\r?\n/)
        if (findPatchRow(lines, pkg)) {
          report.push(`cordis.patch.yml: 已有 ${pkg} 的 insert 行，跳过`)
        } else {
          const suffix = raw.endsWith('\n') ? '' : '\n'
          const block = `${suffix}\n# ── SRC 作战室看板（${pkg}，由 install.ps1 写入）──\n- insert:\n    - id: ${pkg}\n      name: '${pkg}'\n`
          const bak = backup(patchPath)
          fs.writeFileSync(patchPath, raw + block, 'utf8')
          report.push(`cordis.patch.yml += insert(${pkg})（备份 ${path.basename(bak)}）`)
        }
      }
    }
  }

  if (opts.command === 'remove') {
    let touched = false

    if (manifest.dependencies[pkg] !== undefined) {
      delete manifest.dependencies[pkg]
      report.push(`dependency ${pkg}: 已移除`)
      touched = true
    }
    if (opts.bundle) {
      const before = manifest.dsh.profile.bundles.length
      manifest.dsh.profile.bundles = manifest.dsh.profile.bundles.filter((name) => name !== pkg)
      if (manifest.dsh.profile.bundles.length !== before) {
        report.push(`dsh.profile.bundles -= ${pkg}`)
        touched = true
      }
    }
    if (touched) {
      const bak = backup(manifestPath)
      writeJson(manifestPath, manifest)
      report.push(`package.json 已写入（备份 ${path.basename(bak)}）`)
    }

    if (opts['patch-row'] && fs.existsSync(patchPath)) {
      const raw = readText(patchPath)
      const lines = raw.split(/\r?\n/)
      const row = findPatchRow(lines, pkg)
      if (!row) {
        report.push(`cordis.patch.yml: 没有 ${pkg} 的 insert 行，跳过`)
      } else if (row.complex) {
        report.push(`cordis.patch.yml: ${pkg} 的行带 config/disabled/inject，未自动删除，请手工处理 (line ${row.start + 1})`)
      } else {
        const bak = backup(patchPath)
        lines.splice(row.start, row.end - row.start)
        fs.writeFileSync(patchPath, lines.join('\n'), 'utf8')
        report.push(`cordis.patch.yml -= insert(${pkg})（备份 ${path.basename(bak)}）`)
      }
    }
  }

  console.log(report.join('\n'))
}

try {
  main()
} catch (error) {
  console.error(`profile-manifest: ${error.message}`)
  process.exit(1)
}
