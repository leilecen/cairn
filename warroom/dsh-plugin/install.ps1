# warroom-dashboard 安装脚本（dsh profile: desktop / web）
#
# 用法:
#   pwsh -File install.ps1                                   # 安装到 desktop profile（默认）
#   pwsh -File install.ps1 -Profile web                      # 安装到 web profile
#   pwsh -File install.ps1 -Action status                    # 看当前安装状态
#   pwsh -File install.ps1 -Action uninstall                 # 卸载（含清单与 patch 行回退）
#   pwsh -File install.ps1 -NoBuild                          # 跳过 esbuild 构建，只用现有 lib
#
# 两套等价机制（同一 profile 只用其中一套，避免同 id 重复注册）:
#   desktop: 组合包机制 —— package.json 依赖 file:./vendor/warroom-dashboard
#            + dsh.profile.bundles 加入 warroom-dashboard + 包内 cordis.patch.yml 提供 loader 行。
#            dsh 启动时按 dsh.bundle.patch 应用这一层；插件管理器里也能看到/开关这个组合包。
#   web:     profile patch 机制 —— profile 自己的 cordis.patch.yml 里插一条 insert 行（保持历史行为不变）。
#
# 生效: desktop / web 的 dsh 都带 dsh-hmr，manifest 变更可能即时重载；没出现按钮时刷新页面，
#       再不行重启 dsh（desktop = DeepSeek Harness.exe；web = dsh web）。
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
param(
  [ValidateSet('desktop', 'web')][string]$Profile = 'desktop',
  [ValidateSet('install', 'uninstall', 'status')][string]$Action = 'install',
  [switch]$NoBuild,
  [string]$DshHome = '',
  [string]$ProjectRoot = ''
)

$ErrorActionPreference = 'Stop'

$pluginDir = $PSScriptRoot
$repoRoot = Split-Path -Parent (Split-Path -Parent $pluginDir)
if (-not $DshHome) { $DshHome = if ($env:DSH_HOME) { $env:DSH_HOME } else { Join-Path $env:USERPROFILE '.dsh' } }
$profileDir = Join-Path $DshHome (Join-Path 'profiles' $Profile)
$packageName = 'warroom-dashboard'
$spec = 'file:./vendor/warroom-dashboard'
$vendorDir = Join-Path $profileDir "vendor\$packageName"
$moduleDir = Join-Path $profileDir "node_modules\$packageName"

if (-not (Test-Path (Join-Path $profileDir 'package.json'))) {
  throw "profile 不存在或未初始化: $profileDir"
}

function Invoke-Manifest([string[]]$Extra) {
  # profile-manifest.cjs 的动词是 add/remove/status；本脚本的动作名是 install/uninstall/status
  $verb = switch ($Action) { 'install' { 'add' } 'uninstall' { 'remove' } default { 'status' } }
  $manifestArgs = @((Join-Path $pluginDir 'profile-manifest.cjs'), $verb, '--profile-dir', $profileDir, '--package', $packageName, '--spec', $spec) + $Extra
  & node @manifestArgs
  if ($LASTEXITCODE -ne 0) { throw "profile-manifest.cjs 失败（exit $LASTEXITCODE）" }
}

Write-Host "[warroom] profile = $Profile" -ForegroundColor Cyan
Write-Host "[warroom] profile dir = $profileDir"

if ($Action -eq 'status') {
  Invoke-Manifest @()
  foreach ($p in @($vendorDir, $moduleDir)) {
    Write-Host ("[warroom] {0}: {1}" -f $p, (Test-Path $p))
  }
  exit 0
}

if ($Action -eq 'uninstall') {
  $extra = if ($Profile -eq 'desktop') { @('--bundle') } else { @('--patch-row') }
  Invoke-Manifest $extra
  foreach ($p in @($vendorDir, $moduleDir)) {
    if (Test-Path $p) { Remove-Item -Recurse -Force $p; Write-Host "[warroom] 已删除 $p" }
  }
  Write-Host '[warroom] 卸载完成。刷新页面（或重启 dsh）后按钮消失。' -ForegroundColor Yellow
  exit 0
}

# ── 构建 ──
if (-not $NoBuild) {
  Write-Host '[warroom] 构建插件 bundle (esbuild)...'
  & node (Join-Path $pluginDir 'build.cjs')
  if ($LASTEXITCODE -ne 0) { throw '构建失败' }
}
foreach ($f in @('lib\index.js', 'lib\client.js', 'package.json', 'cordis.patch.yml')) {
  $src = Join-Path $pluginDir $f
  if (-not (Test-Path $src)) { throw "缺少构建产物/清单文件: $src（先跑不带 -NoBuild 的安装）" }
}

# ── 拷贝: 仓库 → profile/vendor → profile/node_modules ──
# 两个坑:
#  1) pnpm 的 file: 依赖常用硬链接，直接 Copy-Item -Force 会报「无法用自身覆盖项」→ 先删目标再拷。
#  2) node_modules/<pkg> 可能是指向 vendor 的 junction → 那种情况不能再自拷贝。
$payloadFiles = @('package.json', 'cordis.patch.yml', 'README.md')
$payloadDirs = @('lib')

function Reset-Payload([string]$dir) {
  foreach ($f in $payloadFiles) {
    $target = Join-Path $dir $f
    if (Test-Path $target) { Remove-Item $target -Force -ErrorAction SilentlyContinue }
  }
  foreach ($d in $payloadDirs) {
    $target = Join-Path $dir $d
    if (Test-Path $target) { Remove-Item $target -Recurse -Force -ErrorAction SilentlyContinue }
  }
}

New-Item -ItemType Directory -Force -Path $vendorDir | Out-Null
Reset-Payload $vendorDir
foreach ($f in $payloadFiles) {
  $src = Join-Path $pluginDir $f
  if (Test-Path $src) { Copy-Item $src -Destination (Join-Path $vendorDir $f) -Force }
}
New-Item -ItemType Directory -Force -Path (Join-Path $vendorDir 'lib') | Out-Null
Copy-Item (Join-Path $pluginDir 'lib\*.js') -Destination (Join-Path $vendorDir 'lib') -Force

# node_modules 那份是 loader 真正解析的目录；vendor 那份是 pnpm file: 依赖的源。
$moduleItem = Get-Item $moduleDir -Force -ErrorAction SilentlyContinue
$moduleIsLink = $moduleItem -and (($moduleItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
if ($moduleIsLink) {
  Write-Host "[warroom] $moduleDir 是指向 vendor 的链接，payload 已写入 vendor（两者同步生效）"
} else {
  New-Item -ItemType Directory -Force -Path $moduleDir | Out-Null
  Reset-Payload $moduleDir
  Copy-Item (Join-Path $vendorDir '*') -Destination $moduleDir -Recurse -Force
  Write-Host "[warroom] 已同步 $vendorDir 与 $moduleDir"
}

# ── 清单: 依赖 + (组合包 | patch 行) ──
if ($Profile -eq 'desktop') {
  Invoke-Manifest @('--bundle')
} else {
  Invoke-Manifest @('--patch-row')
}

# ── 校验（在 profile 目录里解析，等价于 loader 的解析路径）──
Push-Location $profileDir
try {
  $resolveCheck = & node -e "try{console.log(require.resolve('$packageName/package.json'))}catch(e){console.log('RESOLVE_FAILED')}" 2>&1
} finally {
  Pop-Location
}
$resolveText = ($resolveCheck | Out-String).Trim()
Write-Host "[warroom] 依赖解析: $resolveText"
if ($resolveText -notmatch 'package\.json') {
  Write-Host '[warroom] 警告: loader 解析不到该包，检查 node_modules/warroom-dashboard 是否存在' -ForegroundColor Yellow
}

# 打印最终清单状态（依赖 / 组合包 / patch 行）
Invoke-Manifest @()

Write-Host '[warroom] 安装完成。' -ForegroundColor Green
Write-Host '[warroom] 生效方式: 刷新 dsh 页面；若无「⬡ 作战室」按钮则重启 dsh（desktop = DeepSeek Harness.exe，web = dsh web）。'
Write-Host '[warroom] 回退: pwsh -File install.ps1 -Profile <profile> -Action uninstall'
if ($ProjectRoot) {
  Write-Host "[warroom] 自定义项目根请写 $DshHome\warroom.json : {`"projectRoot`": `"$ProjectRoot`"}"
}
