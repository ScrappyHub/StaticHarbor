param([Parameter(Mandatory=$true)][string]$RepoRoot)

$ErrorActionPreference="Stop"
Set-StrictMode -Version Latest

function Die([string]$m){ throw $m }

function EnsureDir([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){ Die "EnsureDir: empty" }
  if(-not (Test-Path -LiteralPath $p -PathType Container)){
    New-Item -ItemType Directory -Force -Path $p | Out-Null
  }
}

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
  try { return [int]$l.LocalEndpoint.Port } finally { $l.Stop() }
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$Engine   = Join-Path $RepoRoot "static_harbor_engine.py"
if(-not (Test-Path -LiteralPath $Engine -PathType Leaf)){ Die ("ENGINE_MISSING: " + $Engine) }

$py = Find-Python
if(-not $py){ Die "PYTHON_NOT_FOUND" }

$proofDir = Join-Path $RepoRoot "proofs\receipts"
EnsureDir $proofDir

$httpLog     = Join-Path $proofDir "http_listen_events.jsonl"
$httpReceipt = $httpLog + ".receipts.jsonl"
$httpStdOut  = Join-Path $proofDir "http_listen_stdout.log"
$httpStdErr  = Join-Path $proofDir "http_listen_stderr.log"

foreach($p in @($httpLog,$httpReceipt,$httpStdOut,$httpStdErr)){
  if(Test-Path -LiteralPath $p -PathType Leaf){ Remove-Item -LiteralPath $p -Force }
}

$port = Get-FreeTcpPort
Write-Host ("HTTP_SMOKE_START: 127.0.0.1:" + $port) -ForegroundColor Cyan

$proc = Start-Process -FilePath $py -ArgumentList @(
  $Engine, "http-listen",
  "--bind","127.0.0.1",
  "--tcp",[string]$port,
  "--echo-mode","static",
  "--log",$httpLog,
  "--once"
) -RedirectStandardOutput $httpStdOut -RedirectStandardError $httpStdErr -PassThru -WindowStyle Hidden

Start-Sleep -Milliseconds 500

$bound = Get-NetTCPConnection -State Listen -LocalAddress 127.0.0.1 -LocalPort $port -ErrorAction SilentlyContinue
if(-not $bound){
  Write-Host "=== HTTP STDOUT ===" -ForegroundColor Yellow
  if(Test-Path -LiteralPath $httpStdOut -PathType Leaf){ Get-Content -LiteralPath $httpStdOut | Out-Host }
  Write-Host "=== HTTP STDERR ===" -ForegroundColor Red
  if(Test-Path -LiteralPath $httpStdErr -PathType Leaf){ Get-Content -LiteralPath $httpStdErr | Out-Host }
  if($proc.HasExited){ Write-Host ("HTTP_EXIT_CODE: " + $proc.ExitCode) -ForegroundColor Red }
  try { if(-not $proc.HasExited){ $proc.Kill() } } catch {}
  Die "HTTP_LISTENER_DID_NOT_BIND"
}

$curl = Get-Command curl.exe -ErrorAction SilentlyContinue
if(-not $curl){ Die "CURL_EXE_MISSING" }

Write-Host ("CURL: http://127.0.0.1:" + $port + "/") -ForegroundColor Cyan
$body = & $curl.Source @("--noproxy","*","--http1.1","-sS",("http://127.0.0.1:" + $port + "/"))
if($LASTEXITCODE -ne 0){ Die ("CURL_FAIL: exit=" + $LASTEXITCODE) }
$body | Out-Host

try { $null = $proc.WaitForExit(5000) } catch {}
if(-not $proc.HasExited){
  try { $proc.Kill() } catch {}
  Die "HTTP_ONCE_DID_NOT_EXIT"
}
if($proc.ExitCode -ne 0){
  Write-Host "=== HTTP STDOUT ===" -ForegroundColor Yellow
  if(Test-Path -LiteralPath $httpStdOut -PathType Leaf){ Get-Content -LiteralPath $httpStdOut | Out-Host }
  Write-Host "=== HTTP STDERR ===" -ForegroundColor Red
  if(Test-Path -LiteralPath $httpStdErr -PathType Leaf){ Get-Content -LiteralPath $httpStdErr | Out-Host }
  Die ("HTTP_PROCESS_FAIL: exit=" + $proc.ExitCode)
}

if(-not (Test-Path -LiteralPath $httpLog -PathType Leaf)){ Die ("HTTP_LOG_MISSING: " + $httpLog) }
if(-not (Test-Path -LiteralPath $httpReceipt -PathType Leaf)){ Die ("HTTP_RECEIPT_LOG_MISSING: " + $httpReceipt) }

Write-Host "STATIC_HARBOR_HTTP_LISTEN_SMOKE_OK" -ForegroundColor Green
