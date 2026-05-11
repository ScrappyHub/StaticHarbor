param([Parameter(Mandatory=$true)][string]$RepoRoot)

$ErrorActionPreference="Stop"
Set-StrictMode -Version Latest

function Die([string]$m){ throw $m }

$RepoRoot=(Resolve-Path -LiteralPath $RepoRoot).Path
$PSExe=Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
$ListenRunner=Join-Path $RepoRoot "scripts\_RUN_static_harbor_listen_smoke_v1.ps1"
$HttpRunner=Join-Path $RepoRoot "scripts\_RUN_static_harbor_http_listen_smoke_v1.ps1"

$listenOut=& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $ListenRunner -RepoRoot $RepoRoot 2>&1
$listenCode=$LASTEXITCODE
$listenOut | Out-Host
if($listenCode -ne 0){ Die ("LISTEN_SMOKE_FAIL: exit=" + $listenCode) }
if(($listenOut -join "`n") -notmatch "STATIC_HARBOR_LISTEN_SMOKE_OK"){ Die "LISTEN_SMOKE_TOKEN_MISSING" }

$httpOut=& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $HttpRunner -RepoRoot $RepoRoot 2>&1
$httpCode=$LASTEXITCODE
$httpOut | Out-Host
if($httpCode -ne 0){ Die ("HTTP_SMOKE_FAIL: exit=" + $httpCode) }
if(($httpOut -join "`n") -notmatch "STATIC_HARBOR_HTTP_LISTEN_SMOKE_OK"){ Die "HTTP_SMOKE_TOKEN_MISSING" }

Write-Host "STATIC_HARBOR_TIER0_FULL_GREEN_OK" -ForegroundColor Green
