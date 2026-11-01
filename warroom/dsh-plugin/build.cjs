// 构建 warroom-dashboard 插件 bundle
//  - client 半:lib/client.js —— window.__ModuleLoader__.load({id, factory}) 格式（GUI 侧 overlay）
//  - host 半:lib/index.js —— 纯 ESM，导出 apply()/ensureBackend()（dsh Node 进程侧，拉起 warroom 后端）
// esbuild 从 warroom/web/node_modules 解析（vite 自带），缺失时回落到仓库根 node_modules。
// node 内置模块在 host 半里 external。
const path = require('path')
const fs = require('fs')

const rootDir = __dirname
const webRoot = path.resolve(rootDir, '..', 'web')

/** esbuild 解析：优先 warroom/web 自己的依赖，其次仓库根（避免因为没跑过 npm install 就构建不了）。 */
function resolveEsbuild() {
  const candidates = [
    path.join(webRoot, 'node_modules', 'esbuild'),
    path.resolve(rootDir, '..', '..', 'node_modules', 'esbuild'),
  ]
  for (const candidate of candidates) {
    try { return require(candidate) } catch { /* 试下一个 */ }
  }
  throw new Error(`esbuild not found; run: cd ${webRoot} && npm install  (or npm install at repo root)`)
}

const esbuild = resolveEsbuild()

const banner = `window.__ModuleLoader__.load({
\tid: "warroom-dashboard",
\tfactory: (require) => {
\t\tvar module = { exports: {} };
\t\tvar exports = module.exports;
\t\tObject.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
`

const footer = `\t\treturn module.exports;
\t}
});
`

function report(file) {
  const bytes = fs.statSync(file).size
  console.log(`  ${path.relative(rootDir, file)}  ${(bytes / 1024).toFixed(1)} KiB`)
}

async function main() {
  // ── client 半（GUI overlay，ModuleLoader 格式）──
  await esbuild.build({
    entryPoints: [path.join(rootDir, 'src', 'client.tsx')],
    outfile: path.join(rootDir, 'lib', 'client.js'),
    bundle: true,
    format: 'cjs',
    platform: 'browser',
    jsx: 'automatic',
    loader: { '.tsx': 'tsx', '.ts': 'ts' },
    // 运行时由 ModuleLoader 注入，不打包
    external: [
      'react',
      'react/jsx-runtime',
      '@deepseek-ai/dsh-client-runtime',
      '@deepseek-ai/dsh-client-ui-layout',
      '@deepseek-ai/dsh-client-locale',
      '@deepseek-ai/dsh-client-ui-slots',
      '@deepseek-ai/cordis',
    ],
    banner: { js: banner },
    footer: { js: footer },
    logLevel: 'info',
  })

  // ── host 半（ESM，Node 侧拉起后端）──
  await esbuild.build({
    entryPoints: [path.join(rootDir, 'src', 'index.ts')],
    outfile: path.join(rootDir, 'lib', 'index.js'),
    bundle: true,
    format: 'esm',
    platform: 'node',
    target: 'node18',
    loader: { '.ts': 'ts' },
    // node 内置模块不打包（由运行时提供）
    external: [
      'node:net', 'node:child_process', 'node:fs', 'node:http',
      'node:os', 'node:path', 'node:url',
    ],
    logLevel: 'info',
  })

  console.log('[warroom-dashboard] built:')
  report(path.join(rootDir, 'lib', 'client.js'))
  report(path.join(rootDir, 'lib', 'index.js'))
}

main().catch((e) => { console.error(e); process.exit(1) })
