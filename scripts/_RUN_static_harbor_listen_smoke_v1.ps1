param([Parameter(Mandatory=$true)][string]$RepoRoot)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Die([string]$Message) { throw $Message }

function EnsureDir([string]$Path) {
  if([string]::IsNullOrWhiteSpace($Path)) { Die "ENSUREDIR_EMPTY" }
  if(-not (Test-Path -LiteralPath $Path -PathType Container)) {
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
  }
}

function SafeRemoveFile([string]$Path) {
  try {
    if(Test-Path -LiteralPath $Path -PathType Leaf) {
      Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    }
  } catch {}
}

function Find-Python {
  foreach($c in @("python","python3","py")) {
    $cmd = Get-Command $c -ErrorAction SilentlyContinue
    if($cmd) { return $cmd.Source }
  }
  return $null
}

function Get-FreeTcpPort {
  $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse("127.0.0.1"),0)
  $l.Start()
  try { return [int]$l.LocalEndpoint.Port } finally { $l.Stop() }
}

function Get-FreeUdpPort {
  $u = New-Object System.Net.Sockets.UdpClient(0)
  try { return [int]$u.Client.LocalEndPoint.Port } finally { $u.Close() }
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$Engine = Join-Path $RepoRoot "static_harbor_engine.py"
if(-not (Test-Path -LiteralPath $Engine -PathType Leaf)) { Die ("ENGINE_MISSING: " + $Engine) }

$py = Find-Python
if(-not $py) { Die "PYTHON_NOT_FOUND" }

$proofDir = Join-Path $RepoRoot "proofs\receipts"
EnsureDir $proofDir

$tcpLog = Join-Path $proofDir "listen_tcp_events.jsonl"
$udpLog = Join-Path $proofDir "listen_udp_events.jsonl"
$tcpReceipt = $tcpLog + ".receipts.jsonl"
$udpReceipt = $udpLog + ".receipts.jsonl"

$tcpStdOut = Join-Path $proofDir "listen_tcp_stdout.log"
$tcpStdErr = Join-Path $proofDir "listen_tcp_stderr.log"
$udpStdOut = Join-Path $proofDir "listen_udp_stdout.log"
$udpStdErr = Join-Path $proofDir "listen_udp_stderr.log"

foreach($p in @($tcpLog,$udpLog,$tcpReceipt,$udpReceipt,$tcpStdOut,$tcpStdErr,$udpStdOut,$udpStdErr)) {
  SafeRemoveFile $p
}

$tcpPort = Get-FreeTcpPort
$udpPort = Get-FreeUdpPort

Write-Host ("LISTEN_SMOKE_START_TCP: 127.0.0.1:" + $tcpPort) -ForegroundColor Cyan

$tcpProc = Start-Process -FilePath $py -ArgumentList @(
  $Engine, "listen",
  "--bind","127.0.0.1",
  "--tcp",[string]$tcpPort,
  "--echo",
  "--echo-mode","static",
  "--log",$tcpLog
) -RedirectStandardOutput $tcpStdOut -RedirectStandardError $tcpStdErr -PassThru -WindowStyle Hidden

Start-Sleep -Milliseconds 500

$bound = Get-NetTCPConnection -State Listen -LocalAddress 127.0.0.1 -LocalPort $tcpPort -ErrorAction SilentlyContinue
if(-not $bound) {
  Write-Host "=== TCP STDOUT ===" -ForegroundColor Yellow
  if(Test-Path -LiteralPath $tcpStdOut){ Get-Content -LiteralPath $tcpStdOut | Out-Host }
  Write-Host "=== TCP STDERR ===" -ForegroundColor Red
  if(Test-Path -LiteralPath $tcpStdErr){ Get-Content -LiteralPath $tcpStdErr | Out-Host }
  try { if(-not $tcpProc.HasExited){ $tcpProc.Kill() } } catch {}
  Die "TCP_LISTENER_DID_NOT_BIND"
}

$tcpClient = [System.Net.Sockets.TcpClient]::new("127.0.0.1",$tcpPort)
try {
  $tcpStream = $tcpClient.GetStream()
  $bytes = [System.Text.Encoding]::ASCII.GetBytes("hello`n")
  $tcpStream.Write($bytes,0,$bytes.Length)
  Start-Sleep -Milliseconds 50
  $buf = New-Object byte[] 1024
  $n = $tcpStream.Read($buf,0,$buf.Length)
  $body = [System.Text.Encoding]::ASCII.GetString($buf,0,$n)
  if($body -notmatch "STATIC_HARBOR_ECHO_V1") { Die ("TCP_ECHO_BAD: " + $body) }
}
finally {
  try { $tcpStream.Dispose() } catch {}
  try { $tcpClient.Close() } catch {}
}

Start-Sleep -Milliseconds 250

if(-not (Test-Path -LiteralPath $tcpLog -PathType Leaf)) { Die ("TCP_LOG_MISSING: " + $tcpLog) }
if(-not (Test-Path -LiteralPath $tcpReceipt -PathType Leaf)) { Die ("TCP_RECEIPT_LOG_MISSING: " + $tcpReceipt) }

Write-Host "LISTEN_SMOKE_TCP_OK" -ForegroundColor Green
try { if(-not $tcpProc.HasExited){ $tcpProc.Kill() } } catch {}

Write-Host ("LISTEN_SMOKE_START_UDP: 127.0.0.1:" + $udpPort) -ForegroundColor Cyan

$udpProc = Start-Process -FilePath $py -ArgumentList @(
  $Engine, "listen",
  "--bind","127.0.0.1",
  "--udp",[string]$udpPort,
  "--echo",
  "--echo-mode","static",
  "--log",$udpLog
) -RedirectStandardOutput $udpStdOut -RedirectStandardError $udpStdErr -PassThru -WindowStyle Hidden

Start-Sleep -Milliseconds 700

$udpSock = New-Object System.Net.Sockets.Socket(
  [System.Net.Sockets.AddressFamily]::InterNetwork,
  [System.Net.Sockets.SocketType]::Dgram,
  [System.Net.Sockets.ProtocolType]::Udp
)

try {
  $udpSock.ReceiveTimeout = 3000
  $serverEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse("127.0.0.1"),$udpPort)
  $payload = [System.Text.Encoding]::ASCII.GetBytes("hello`n")
  [void]$udpSock.SendTo($payload,$serverEp)

  $buf = New-Object byte[] 1024
  $remoteEp = [System.Net.EndPoint](New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any,0))
  $n = $udpSock.ReceiveFrom($buf,[ref]$remoteEp)
  $body = [System.Text.Encoding]::ASCII.GetString($buf,0,$n)

  if($body -notmatch "STATIC_HARBOR_ECHO_V1") { Die ("UDP_ECHO_BAD: " + $body) }
}
catch {
  Write-Host "=== UDP STDOUT ===" -ForegroundColor Yellow
  if(Test-Path -LiteralPath $udpStdOut){ Get-Content -LiteralPath $udpStdOut | Out-Host }
  Write-Host "=== UDP STDERR ===" -ForegroundColor Red
  if(Test-Path -LiteralPath $udpStdErr){ Get-Content -LiteralPath $udpStdErr | Out-Host }
  try { if(-not $udpProc.HasExited){ $udpProc.Kill() } } catch {}
  Die ("UDP_RECEIVE_FAIL: " + $_.Exception.Message)
}
finally {
  $udpSock.Close()
}

Start-Sleep -Milliseconds 250

if(-not (Test-Path -LiteralPath $udpLog -PathType Leaf)) { Die ("UDP_LOG_MISSING: " + $udpLog) }
if(-not (Test-Path -LiteralPath $udpReceipt -PathType Leaf)) { Die ("UDP_RECEIPT_LOG_MISSING: " + $udpReceipt) }

Write-Host "LISTEN_SMOKE_UDP_OK" -ForegroundColor Green
try { if(-not $udpProc.HasExited){ $udpProc.Kill() } } catch {}

Write-Host "STATIC_HARBOR_LISTEN_SMOKE_OK" -ForegroundColor Green
