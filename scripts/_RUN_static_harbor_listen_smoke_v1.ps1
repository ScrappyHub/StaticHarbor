param(
  [Parameter(Mandatory = $true)][string]$RepoRoot
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Die([string]$m) { throw $m }

function EnsureDir([string]$p) {
  if ([string]::IsNullOrWhiteSpace($p)) { Die "EnsureDir: empty" }
  if (-not (Test-Path -LiteralPath $p -PathType Container)) {
    New-Item -ItemType Directory -Force -Path $p | Out-Null
  }
}

function Write-Utf8NoBomLf([string]$Path, [string]$Text) {
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path -LiteralPath $dir -PathType Container)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
  }
  $lf = ($Text -replace "`r`n", "`n") -replace "`r", "`n"
  if (-not $lf.EndsWith("`n")) { $lf += "`n" }
  $enc = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($Path, $lf, $enc)
}

function Read-Utf8NoBom([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    Die ("MISSING_FILE: " + $Path)
  }
  $enc = New-Object System.Text.UTF8Encoding($false)
  return [System.IO.File]::ReadAllText($Path, $enc)
}

function Find-Python {
  foreach ($c in @("python", "python3", "py")) {
    $cmd = Get-Command $c -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
  }
  return $null
}

function Wait-PortOpen([string]$TargetHost, [int]$Port, [int]$TimeoutMs) {
  $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
  while ([DateTime]::UtcNow -lt $deadline) {
    try {
      $client = [System.Net.Sockets.TcpClient]::new()
      try {
        $iar = $client.BeginConnect($TargetHost, $Port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne(150)) {
          $client.EndConnect($iar)
          return $true
        }
      } finally {
        try { $client.Close() } catch {}
      }
    } catch {}
    Start-Sleep -Milliseconds 50
  }
  return $false
}

function Stop-ProcSafe($Proc) {
  if ($null -eq $Proc) { return }
  try {
    if (-not $Proc.HasExited) {
      Stop-Process -Id $Proc.Id -Force -ErrorAction SilentlyContinue
      try { $null = $Proc.WaitForExit(2000) } catch {}
    }
  } catch {}
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$Engine   = Join-Path $RepoRoot "static_harbor_engine.py"
if (-not (Test-Path -LiteralPath $Engine -PathType Leaf)) { Die ("ENGINE_MISSING: " + $Engine) }

$py = Find-Python
if (-not $py) { Die "PYTHON_NOT_FOUND" }

$receiptDir = Join-Path $RepoRoot "proofs\receipts"
EnsureDir $receiptDir

$tcpLog = Join-Path $receiptDir "listen_tcp_events.jsonl"
$udpLog = Join-Path $receiptDir "listen_udp_events.jsonl"

if (Test-Path -LiteralPath $tcpLog -PathType Leaf) { Remove-Item -LiteralPath $tcpLog -Force }
if (Test-Path -LiteralPath $udpLog -PathType Leaf) { Remove-Item -LiteralPath $udpLog -Force }

$tcpPort = 18082
$udpPort = 18083

Write-Host ("LISTEN_SMOKE_START_TCP: 127.0.0.1:" + $tcpPort) -ForegroundColor Cyan

$tcpProc = Start-Process -FilePath $py -ArgumentList @(
  $Engine, "listen",
  "--bind", "127.0.0.1",
  "--tcp", [string]$tcpPort,
  "--echo",
  "--echo-mode", "static",
  "--log", $tcpLog
) -PassThru -WindowStyle Hidden

if (-not (Wait-PortOpen -TargetHost "127.0.0.1" -Port $tcpPort -TimeoutMs 3000)) {
  Stop-ProcSafe $tcpProc
  Die "TCP_LISTENER_DID_NOT_BIND"
}

$tcpClient = $null
$tcpStream = $null
try {
  $tcpClient = [System.Net.Sockets.TcpClient]::new("127.0.0.1", $tcpPort)
  $tcpStream = $tcpClient.GetStream()
  $payload = [System.Text.Encoding]::ASCII.GetBytes("hello`n")
  $tcpStream.Write($payload, 0, $payload.Length)
  Start-Sleep -Milliseconds 50
  $buf = New-Object byte[] 1024
  $n = $tcpStream.Read($buf, 0, $buf.Length)
  $resp = [System.Text.Encoding]::ASCII.GetString($buf, 0, $n)
  if ($resp -ne "STATIC_HARBOR_ECHO_V1`n") {
    Die ("TCP_ECHO_MISMATCH: " + $resp)
  }
  Write-Host "LISTEN_SMOKE_TCP_OK" -ForegroundColor Green
} finally {
  try { if ($null -ne $tcpStream) { $tcpStream.Dispose() } } catch {}
  try { if ($null -ne $tcpClient) { $tcpClient.Close() } } catch {}
  Stop-ProcSafe $tcpProc
}

if (-not (Test-Path -LiteralPath $tcpLog -PathType Leaf)) {
  Die ("TCP_LOG_MISSING: " + $tcpLog)
}

$tcpLine = Get-Content -LiteralPath $tcpLog -TotalCount 1 -ErrorAction Stop
if ([string]::IsNullOrWhiteSpace($tcpLine)) { Die "TCP_LOG_EMPTY" }
if ($tcpLine -notmatch '"schema"\s*:\s*"static_harbor\.listen_event\.v1"') { Die ("TCP_LOG_SCHEMA_BAD: " + $tcpLine) }
if ($tcpLine -notmatch '"proto"\s*:\s*"tcp"') { Die ("TCP_LOG_PROTO_BAD: " + $tcpLine) }

Write-Host ("LISTEN_SMOKE_START_UDP: 127.0.0.1:" + $udpPort) -ForegroundColor Cyan

$udpProc = Start-Process -FilePath $py -ArgumentList @(
  $Engine, "listen",
  "--bind", "127.0.0.1",
  "--udp", [string]$udpPort,
  "--echo",
  "--echo-mode", "static",
  "--log", $udpLog
) -PassThru -WindowStyle Hidden

Start-Sleep -Milliseconds 300

$udpClient = $null
try {
  $udpClient = New-Object System.Net.Sockets.UdpClient
  $udpClient.Client.ReceiveTimeout = 3000
  $bytes = [System.Text.Encoding]::ASCII.GetBytes("hello`n")
  [void]$udpClient.Send($bytes, $bytes.Length, "127.0.0.1", $udpPort)
  $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
  $respBytes = $udpClient.Receive([ref]$remote)
  $resp = [System.Text.Encoding]::ASCII.GetString($respBytes)
  if ($resp -ne "STATIC_HARBOR_ECHO_V1`n") {
    Die ("UDP_ECHO_MISMATCH: " + $resp)
  }
  Write-Host "LISTEN_SMOKE_UDP_OK" -ForegroundColor Green
} finally {
  try { if ($null -ne $udpClient) { $udpClient.Close() } } catch {}
  Stop-ProcSafe $udpProc
}

if (-not (Test-Path -LiteralPath $udpLog -PathType Leaf)) {
  Die ("UDP_LOG_MISSING: " + $udpLog)
}

$udpLine = Get-Content -LiteralPath $udpLog -TotalCount 1 -ErrorAction Stop
if ([string]::IsNullOrWhiteSpace($udpLine)) { Die "UDP_LOG_EMPTY" }
if ($udpLine -notmatch '"schema"\s*:\s*"static_harbor\.listen_event\.v1"') { Die ("UDP_LOG_SCHEMA_BAD: " + $udpLine) }
if ($udpLine -notmatch '"proto"\s*:\s*"udp"') { Die ("UDP_LOG_PROTO_BAD: " + $udpLine) }

Write-Host ("LISTEN_SMOKE_OK: tcp_log=" + $tcpLog) -ForegroundColor Green
Write-Host ("LISTEN_SMOKE_OK: udp_log=" + $udpLog) -ForegroundColor Green
