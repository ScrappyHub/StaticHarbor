param([Parameter(Mandatory=$true)][string]$RepoRoot)

$ErrorActionPreference="Stop"
Set-StrictMode -Version Latest

function Die([string]$m){ throw $m }

function Find-Python {
  foreach($c in @("python","python3","py")){
    $cmd = Get-Command $c -ErrorAction SilentlyContinue
    if($cmd){ return $cmd.Source }
  }
  return $null
}

function Get-FreeTcpPort {
  $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse("127.0.0.1"),0)
  $l.Start()
  try { return $l.LocalEndpoint.Port } finally { $l.Stop() }
}

$RepoRoot = (Resolve-Path $RepoRoot).Path
$Engine   = Join-Path $RepoRoot "static_harbor_engine.py"

if(-not (Test-Path $Engine)){ Die "ENGINE_MISSING" }

$py = Find-Python
if(-not $py){ Die "PYTHON_NOT_FOUND" }

$proof = Join-Path $RepoRoot "proofs\debug"
New-Item -ItemType Directory -Force -Path $proof | Out-Null

$port = Get-FreeTcpPort

$out = Join-Path $proof "engine_stdout.log"
$err = Join-Path $proof "engine_stderr.log"

Write-Host ("DEBUG_BIND_PORT: " + $port) -ForegroundColor Cyan

$proc = Start-Process -FilePath $py -ArgumentList @(
  $Engine,"listen",
  "--bind","127.0.0.1",
  "--tcp",$port,
  "--echo",
  "--echo-mode","static",
  "--log","dummy.jsonl"
) `
-RedirectStandardOutput $out `
-RedirectStandardError  $err `
-PassThru `
-WindowStyle Hidden

Start-Sleep -Milliseconds 800

$bound = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue

if(-not $bound){

  Write-Host "=== ENGINE STDOUT ===" -ForegroundColor Yellow
  if(Test-Path $out){ Get-Content $out | Out-Host }

  Write-Host "=== ENGINE STDERR ===" -ForegroundColor Red
  if(Test-Path $err){ Get-Content $err | Out-Host }

  try { $proc.Kill() } catch {}

  Die "ENGINE_BIND_FAILED"
}

Write-Host "ENGINE_BIND_OK" -ForegroundColor Green

try { $proc.Kill() } catch {}
