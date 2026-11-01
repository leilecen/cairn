# SRC 作战室 一键启动
# 用法: powershell -ExecutionPolicy Bypass -File warroom/start.ps1
# 效果: 启动后端(8787, 托管 /api + 前端 dist) -> 打开浏览器 -> 脚本保持运行
# 停止: 关闭本窗口 / Ctrl+C
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "[warroom] 检查前端构建产物..."
if (-not (Test-Path "$root\warroom\web\dist\index.html")) {
    Write-Host "[warroom] dist 不存在, 执行 npm run build ..."
    Push-Location "$root\warroom\web"
    npm run build
    if ($LASTEXITCODE -ne 0) { Write-Host "[warroom] 构建失败" -ForegroundColor Red; exit 1 }
    Pop-Location
}

$port = 8787
$existing = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "[warroom] 端口 $port 已被占用, 直接打开浏览器 (已有实例在运行)"
} else {
    Write-Host "[warroom] 启动后端 http://127.0.0.1:$port ..."
    Start-Process -FilePath "uv" -ArgumentList "run", "python", "warroom/server.py", "--port", "$port" -WorkingDirectory $root -WindowStyle Hidden
    Start-Sleep -Seconds 2
}

Start-Process "http://127.0.0.1:$port/"
Write-Host "[warroom] 已打开浏览器 http://127.0.0.1:$port/"
Write-Host "[warroom] 提示: 后端由独立进程运行; 需要停止时: Get-NetTCPConnection -LocalPort 8787 | Stop-Process"
