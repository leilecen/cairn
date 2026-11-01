# warroom-dashboard 回退脚本（旧版是「git checkout 到重构前 + 重建」，已不适用）
#
# 现在回退 = 卸载插件，可选先用本次安装留下的清单备份把 profile 还原到安装前状态。
#
# 用法:
#   pwsh -File rollback.ps1                        # 从 desktop profile 卸载
#   pwsh -File rollback.ps1 -Profile web           # 从 web profile 卸载
#   pwsh -File rollback.ps1 -RestoreManifest       # 先用最新的 package.json.bak-* / cordis.patch.yml.bak-* 还原，再卸载
param(
  [ValidateSet('desktop', 'web')][string]$Profile = 'desktop',
  [switch]$RestoreManifest,
  [string]$DshHome = ''
)

$ErrorActionPreference = 'Stop'
$pluginDir = $PSScriptRoot
if (-not $DshHome) { $DshHome = if ($env:DSH_HOME) { $env:DSH_HOME } else { Join-Path $env:USERPROFILE '.dsh' } }
$profileDir = Join-Path $DshHome (Join-Path 'profiles' $Profile)

if ($RestoreManifest) {
  foreach ($name in @('package.json', 'cordis.patch.yml')) {
    $backup = Get-ChildItem -Path $profileDir -Filter "$name.bak-*" -ErrorAction SilentlyContinue |
      Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($backup) {
      Copy-Item $backup.FullName -Destination (Join-Path $profileDir $name) -Force
      Write-Host "[rollback] 已用 $($backup.Name) 还原 $name"
    } else {
      Write-Host "[rollback] 没有 $name 的备份，跳过"
    }
  }
}

& pwsh -NoProfile -File (Join-Path $pluginDir 'install.ps1') -Profile $Profile -Action uninstall -NoBuild
Write-Host '[rollback] 完成。刷新页面（或重启 dsh）后「⬡ 作战室」按钮消失。' -ForegroundColor Yellow
