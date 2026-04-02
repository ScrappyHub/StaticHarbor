param(
  [Parameter(Mandatory = $true)][string]$RepoRoot
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Die([string]$Message) {
  throw $Message
}

function Ensure-Dir([string]$Path) {
  if ([string]::IsNullOrWhiteSpace($Path)) { Die "ENSURE_DIR_EMPTY" }
  if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
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

function Parse-GateFile([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    Die ("PARSE_GATE_MISSING: " + $Path)
  }
  $tokens = $null
  $errors = $null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
  if ($errors -and $errors.Count -gt 0) {
    $msg = ($errors | ForEach-Object { $_.Message }) -join "; "
    Die ("PARSE_GATE_ERROR: " + $msg + " (file: " + $Path + ")")
  }
}

function Find-Python {
  foreach ($candidate in @("python", "python3", "py")) {
    $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
  }
  return $null
}

function Find-PowerShellExe {
  $ps51 = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
  if (Test-Path -LiteralPath $ps51 -PathType Leaf) { return $ps51 }
  $pwsh = Get-Command pwsh.exe -ErrorAction SilentlyContinue
  if ($pwsh) { return $pwsh.Source }
  $powershell = Get-Command powershell.exe -ErrorAction SilentlyContinue
  if ($powershell) { return $powershell.Source }
  return $null
}

function Require-File([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    Die ("REQUIRED_FILE_MISSING: " + $Path)
  }
}

function New-RunId {
  return [DateTime]::UtcNow.ToString("yyyyMMdd_HHmmss_fff")
}

function Run-ChildPsFile {
  param(
    [Parameter(Mandatory = $true)][string]$PowerShellExe,
    [Parameter(Mandatory = $true)][string]$FilePath,
    [Parameter(Mandatory = $true)][string[]]$ArgumentList,
    [Parameter(Mandatory = $true)][string]$StdOutPath,
    [Parameter(Mandatory = $true)][string]$StdErrPath
  )

  & $PowerShellExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $FilePath @ArgumentList 1> $StdOutPath 2> $StdErrPath
  return $LASTEXITCODE
}

function Run-ChildPy {
  param(
    [Parameter(Mandatory = $true)][string]$PythonExe,
    [Parameter(Mandatory = $true)][string[]]$ArgumentList,
    [Parameter(Mandatory = $true)][string]$StdOutPath,
    [Parameter(Mandatory = $true)][string]$StdErrPath
  )

  & $PythonExe @ArgumentList 1> $StdOutPath 2> $StdErrPath
  return $LASTEXITCODE
}

function Require-FileContains([string]$Path, [string]$Pattern, [string]$Token) {
  Require-File $Path
  $txt = Read-Utf8NoBom $Path
  if ($txt -notmatch $Pattern) {
    Die ($Token + ": " + $Path)
  }
}

function Copy-IfExists([string]$SourcePath, [string]$DestPath) {
  if (Test-Path -LiteralPath $SourcePath -PathType Leaf) {
    $dir = Split-Path -Parent $DestPath
    if ($dir) { Ensure-Dir $dir }
    Copy-Item -LiteralPath $SourcePath -Destination $DestPath -Force
  }
}

function Write-JsonFile([string]$Path, [object]$Object) {
  $json = $Object | ConvertTo-Json -Depth 10
  Write-Utf8NoBomLf -Path $Path -Text $json
}

function Write-Sha256SumsLast([string]$RootDir, [string]$OutputPath) {
  $files = Get-ChildItem -LiteralPath $RootDir -Recurse -File | Where-Object {
    $_.FullName -ne $OutputPath
  } | Sort-Object FullName

  $lines = New-Object System.Collections.Generic.List[string]
  foreach ($f in $files) {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $f.FullName).Hash.ToLowerInvariant()
    $rel = $f.FullName.Substring($RootDir.Length).TrimStart('\')
    $rel = $rel -replace '\\', '/'
    [void]$lines.Add($hash + " *" + $rel)
  }

  Write-Utf8NoBomLf -Path $OutputPath -Text (($lines.ToArray()) -join "`n")
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

$PowerShellExe = Find-PowerShellExe
if (-not $PowerShellExe) { Die "POWERSHELL_EXE_NOT_FOUND" }

$PythonExe = Find-Python
if (-not $PythonExe) { Die "PYTHON_NOT_FOUND" }

$EnginePath = Join-Path $RepoRoot "static_harbor_engine.py"
$ListenRunnerPath = Join-Path $RepoRoot "scripts\_RUN_static_harbor_listen_smoke_v1.ps1"
$HttpRunnerPath = Join-Path $RepoRoot "scripts\_RUN_static_harbor_http_listen_smoke_v1.ps1"
$ListenSchemaPath = Join-Path $RepoRoot "schemas\static_harbor.listen_event.v1.json"
$HttpSchemaPath = Join-Path $RepoRoot "schemas\static_harbor.http_listen_event.v1.json"

Require-File $EnginePath
Require-File $ListenRunnerPath
Require-File $HttpRunnerPath
Require-File $ListenSchemaPath
Require-File $HttpSchemaPath

Parse-GateFile $PSCommandPath
Parse-GateFile $ListenRunnerPath
Parse-GateFile $HttpRunnerPath

$RunId = New-RunId
$RunRoot = Join-Path $RepoRoot ("proofs\receipts\static_harbor_tier0_full_green\" + $RunId)
Ensure-Dir $RunRoot

$AckDir = Join-Path $HOME ".static_harbor"
Ensure-Dir $AckDir
$AckPath = Join-Path $AckDir "ethics_ack.json"

$ackObject = [ordered]@{
  schema     = "static_harbor.ethics_ack.v1"
  ok         = $true
  goal       = "tier0 full green local scan smoke"
  targets    = "127.0.0.1 authorized loopback only"
  permission = $true
  scope      = $true
}
Write-JsonFile -Path $AckPath -Object $ackObject

$ListenStdOut = Join-Path $RunRoot "listen_smoke_stdout.log"
$ListenStdErr = Join-Path $RunRoot "listen_smoke_stderr.log"
$listenExit = Run-ChildPsFile `
  -PowerShellExe $PowerShellExe `
  -FilePath $ListenRunnerPath `
  -ArgumentList @("-RepoRoot", $RepoRoot) `
  -StdOutPath $ListenStdOut `
  -StdErrPath $ListenStdErr

if ($null -eq $listenExit) { Die "LISTEN_SMOKE_FAIL: exit=null" }
if ([int]$listenExit -ne 0) { Die ("LISTEN_SMOKE_FAIL: exit=" + $listenExit) }

Require-FileContains -Path $ListenStdOut -Pattern 'LISTEN_SMOKE_TCP_OK' -Token 'LISTEN_SMOKE_TCP_TOKEN_MISSING'
Require-FileContains -Path $ListenStdOut -Pattern 'LISTEN_SMOKE_UDP_OK' -Token 'LISTEN_SMOKE_UDP_TOKEN_MISSING'

$TcpLogSrc = Join-Path $RepoRoot "proofs\receipts\listen_tcp_events.jsonl"
$UdpLogSrc = Join-Path $RepoRoot "proofs\receipts\listen_udp_events.jsonl"
Require-FileContains -Path $TcpLogSrc -Pattern '"schema"\s*:\s*"static_harbor\.listen_event\.v1"' -Token 'LISTEN_TCP_SCHEMA_MISSING'
Require-FileContains -Path $UdpLogSrc -Pattern '"schema"\s*:\s*"static_harbor\.listen_event\.v1"' -Token 'LISTEN_UDP_SCHEMA_MISSING'
Require-FileContains -Path $TcpLogSrc -Pattern '"proto"\s*:\s*"tcp"' -Token 'LISTEN_TCP_PROTO_MISSING'
Require-FileContains -Path $UdpLogSrc -Pattern '"proto"\s*:\s*"udp"' -Token 'LISTEN_UDP_PROTO_MISSING'

Copy-IfExists -SourcePath $TcpLogSrc -DestPath (Join-Path $RunRoot "listen_tcp_events.jsonl")
Copy-IfExists -SourcePath $UdpLogSrc -DestPath (Join-Path $RunRoot "listen_udp_events.jsonl")

$HttpStdOut = Join-Path $RunRoot "http_listen_smoke_stdout.log"
$HttpStdErr = Join-Path $RunRoot "http_listen_smoke_stderr.log"
$httpExit = Run-ChildPsFile `
  -PowerShellExe $PowerShellExe `
  -FilePath $HttpRunnerPath `
  -ArgumentList @("-RepoRoot", $RepoRoot) `
  -StdOutPath $HttpStdOut `
  -StdErrPath $HttpStdErr

if ($null -eq $httpExit) { Die "HTTP_LISTEN_SMOKE_FAIL: exit=null" }
if ([int]$httpExit -ne 0) { Die ("HTTP_LISTEN_SMOKE_FAIL: exit=" + $httpExit) }

Require-FileContains -Path $HttpStdOut -Pattern 'HTTP_SMOKE_OK' -Token 'HTTP_SMOKE_TOKEN_MISSING'

$HttpLogSrc = Join-Path $RepoRoot "proofs\receipts\http_listen_events.jsonl"
Require-FileContains -Path $HttpLogSrc -Pattern '"schema"\s*:\s*"static_harbor\.http_listen_event\.v1"' -Token 'HTTP_LISTEN_SCHEMA_MISSING'
Copy-IfExists -SourcePath $HttpLogSrc -DestPath (Join-Path $RunRoot "http_listen_events.jsonl")

$ScanStdOut = Join-Path $RunRoot "scan_smoke_stdout.log"
$ScanStdErr = Join-Path $RunRoot "scan_smoke_stderr.log"

$scanExit = Run-ChildPy `
  -PythonExe $PythonExe `
  -ArgumentList @(
    $EnginePath,
    "scan",
    "--host", "127.0.0.1",
    "--ports", "22,80,443"
  ) `
  -StdOutPath $ScanStdOut `
  -StdErrPath $ScanStdErr

if ($null -eq $scanExit) { Die "SCAN_SMOKE_FAIL: exit=null" }
if ([int]$scanExit -ne 0) { Die ("SCAN_SMOKE_FAIL: exit=" + $scanExit) }

Require-FileContains -Path $ScanStdOut -Pattern '"schema"\s*:\s*"static_harbor\.scan_result\.v1"' -Token 'SCAN_SCHEMA_MISSING'
Require-FileContains -Path $ScanStdOut -Pattern '"host"\s*:\s*"127\.0\.0\.1"' -Token 'SCAN_HOST_MISSING'
Require-FileContains -Path $ScanStdOut -Pattern '"scanned"\s*:\s*3' -Token 'SCAN_COUNT_MISSING'

$summary = [ordered]@{
  schema = "static_harbor.tier0_full_green.summary.v1"
  run_id = $RunId
  repo_root = $RepoRoot
  engine = "static_harbor_engine.py"
  components = [ordered]@{
    listen_smoke = [ordered]@{
      exit_code = [int]$listenExit
      tcp_log = "listen_tcp_events.jsonl"
      udp_log = "listen_udp_events.jsonl"
    }
    http_listen_smoke = [ordered]@{
      exit_code = [int]$httpExit
      http_log = "http_listen_events.jsonl"
    }
    scan_smoke = [ordered]@{
      exit_code = [int]$scanExit
      host = "127.0.0.1"
      ports = "22,80,443"
    }
  }
}

$SummaryPath = Join-Path $RunRoot "summary.json"
Write-JsonFile -Path $SummaryPath -Object $summary

$ShaPath = Join-Path $RunRoot "sha256sums.txt"
Write-Sha256SumsLast -RootDir $RunRoot -OutputPath $ShaPath

Write-Host ("STATIC_HARBOR_TIER0_FULL_GREEN_OK: " + $RunRoot) -ForegroundColor Green
