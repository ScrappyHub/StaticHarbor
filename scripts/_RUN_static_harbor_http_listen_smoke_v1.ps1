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

function Find-Python(){
  foreach($c in @("python","python3","py")){
    $cmd = Get-Command $c -ErrorAction SilentlyContinue
    if($cmd){ return $cmd.Source }
  }
  return $null
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$Engine   = Join-Path $RepoRoot "static_harbor_engine.py"
if(-not (Test-Path -LiteralPath $Engine -PathType Leaf)){ Die ("ENGINE_MISSING: " + $Engine) }

$py = Find-Python
if(-not $py){ Die "PYTHON_NOT_FOUND" }

$logDir = Join-Path $RepoRoot "proofs\receipts"
EnsureDir $logDir
$log = Join-Path $logDir "http_listen_events.jsonl"
if(Test-Path -LiteralPath $log -PathType Leaf){ Remove-Item -LiteralPath $log -Force }

$port = 18081

Write-Host ("HTTP_SMOKE_START: 127.0.0.1:" + $port) -ForegroundColor Cyan

$proc = Start-Process -FilePath $py -ArgumentList @(
  $Engine, "http-listen",
  "--bind","127.0.0.1",
  "--tcp",[string]$port,
  "--echo-mode","static",
  "--log",$log,
  "--once"
) -PassThru -WindowStyle Hidden

Start-Sleep -Milliseconds 250

$curl = Get-Command curl.exe -ErrorAction SilentlyContinue
if(-not $curl){ try { $proc.Kill() } catch {}; Die "CURL_EXE_MISSING" }

Write-Host ("CURL: http://127.0.0.1:" + $port + "/") -ForegroundColor Cyan

# Use -sS to avoid progress meter on stderr; print body to stdout
$curlOut  = & $curl.Source @("--noproxy","*","--http1.1","-sS","--output","-",("http://127.0.0.1:" + $port + "/")) 2>&1
$curlCode = $LASTEXITCODE

$curlOut | Out-Host

if($curlCode -ne 0){
  try { $proc.Kill() } catch {}
  Die ("CURL_FAIL: exit=" + $curlCode)
}

try { $null = $proc.WaitForExit(5000) } catch {}
if(-not $proc.HasExited){
  try { $proc.Kill() } catch {}
  Die "HTTP_SMOKE_FAIL: server did not exit (once-mode)"
}

if($proc.ExitCode -ne 0){
  Die ("HTTP_SMOKE_FAIL: server exit=" + $proc.ExitCode)
}

if(-not (Test-Path -LiteralPath $log -PathType Leaf)){
  Die ("HTTP_SMOKE_FAIL: log missing -> " + $log)
}

$line = Get-Content -LiteralPath $log -TotalCount 1 -ErrorAction Stop
if([string]::IsNullOrWhiteSpace($line)){ Die "HTTP_SMOKE_FAIL: empty log" }

if($line -notmatch '"schema"\s*:\s*"static_harbor\.http_listen_event\.v1"'){
  Die ("HTTP_SMOKE_FAIL: schema mismatch in log line: " + $line)
}

Write-Host ("HTTP_SMOKE_OK: body received + log OK -> " + $log) -ForegroundColor Green
