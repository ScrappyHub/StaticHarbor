param([Parameter(Mandatory=$true)][string]$RepoRoot)

$ErrorActionPreference="Stop"
Set-StrictMode -Version Latest

function Die([string]$m){ throw $m }
function EnsureDir([string]$Path){ if(-not (Test-Path -LiteralPath $Path -PathType Container)){ New-Item -ItemType Directory -Force -Path $Path | Out-Null } }
function SafeRemoveFile([string]$Path){ try{ if(Test-Path -LiteralPath $Path -PathType Leaf){ Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue } }catch{} }
function Find-Python { foreach($c in @("python","python3","py")){ $cmd=Get-Command $c -ErrorAction SilentlyContinue; if($cmd){ return $cmd.Source } }; return $null }
function Get-FreeTcpPort {
  $l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse("127.0.0.1"),0)
  $l.Start()
  try{ return [int]$l.LocalEndpoint.Port } finally{ $l.Stop() }
}

$RepoRoot=(Resolve-Path -LiteralPath $RepoRoot).Path
$Engine=Join-Path $RepoRoot "static_harbor_engine.py"
$py=Find-Python
if(-not $py){ Die "PYTHON_NOT_FOUND" }

$proofDir=Join-Path $RepoRoot "proofs\receipts"
EnsureDir $proofDir

$log=Join-Path $proofDir "http_listen_events.jsonl"
$receipt=$log + ".receipts.jsonl"
$stdout=Join-Path $proofDir "http_listen_stdout.log"
$stderr=Join-Path $proofDir "http_listen_stderr.log"
foreach($p in @($log,$receipt,$stdout,$stderr)){ SafeRemoveFile $p }

$port=Get-FreeTcpPort
Write-Host ("HTTP_SMOKE_START: 127.0.0.1:" + $port) -ForegroundColor Cyan

$proc=Start-Process -FilePath $py -ArgumentList @(
  $Engine,"http-listen",
  "--bind","127.0.0.1",
  "--tcp",[string]$port,
  "--echo-mode","static",
  "--log",$log,
  "--once"
) -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden

Start-Sleep -Milliseconds 500

$curl=Get-Command curl.exe -ErrorAction SilentlyContinue
if(-not $curl){ Die "CURL_EXE_MISSING" }

Write-Host ("CURL: http://127.0.0.1:" + $port + "/") -ForegroundColor Cyan
$curlOut=& $curl.Source @("-sS","--fail","--noproxy","*","--http1.1",("http://127.0.0.1:" + $port + "/")) 2>&1
$curlCode=$LASTEXITCODE
$curlOut | Out-Host

[void]$proc.WaitForExit(5000)
$proc.Refresh()
if(-not $proc.HasExited){
  try{ $proc.Kill() }catch{}
  [void]$proc.WaitForExit(2000)
  $proc.Refresh()
}

Write-Host "=== HTTP STDOUT ===" -ForegroundColor Yellow
if(Test-Path -LiteralPath $stdout){ Get-Content -LiteralPath $stdout | Out-Host }
Write-Host "=== HTTP STDERR ===" -ForegroundColor Yellow
if(Test-Path -LiteralPath $stderr){ Get-Content -LiteralPath $stderr | Out-Host }

if($curlCode -ne 0){ Die ("HTTP_CURL_FAIL: exit=" + $curlCode) }
if($curlOut -notmatch "STATIC_HARBOR_HTTP_V1"){ Die "HTTP_BODY_TOKEN_MISSING" }
if(-not (Test-Path -LiteralPath $log -PathType Leaf)){ Die ("HTTP_LOG_MISSING: " + $log) }
if(-not (Test-Path -LiteralPath $receipt -PathType Leaf)){ Die ("HTTP_RECEIPT_LOG_MISSING: " + $receipt) }

$line=Get-Content -LiteralPath $log -TotalCount 1
if($line -notmatch '"schema":\s*"static_harbor\.http_listen_event\.v1"'){ Die ("HTTP_LOG_SCHEMA_MISMATCH: " + $line) }

Write-Host "STATIC_HARBOR_HTTP_LISTEN_SMOKE_OK" -ForegroundColor Green
