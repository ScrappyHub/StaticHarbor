param([Parameter(Mandatory=$true)][string]$RepoRoot)

$ErrorActionPreference="Stop"
Set-StrictMode -Version Latest

function Die([string]$m){ throw $m }

function Parse-GatePs1([string]$Path){
$tok=$null;$err=$null
[void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tok,[ref]$err)
if($err -and $err.Count -gt 0){ Die ("PARSE_FAIL: " + $Path + " :: " + (($err | ForEach-Object Message) -join "; ")) }
}

$RepoRoot=(Resolve-Path -LiteralPath $RepoRoot).Path
$py=(Get-Command python -ErrorAction Stop).Source
$Engine=Join-Path $RepoRoot "static_harbor_engine.py"

if(-not (Test-Path -LiteralPath $Engine -PathType Leaf)){ Die "ENGINE_MISSING" }

$required=@(
"README.md",
"docs\STATICHARBOR_SPEC_V1.md",
"docs\WBS_V1.md",
"schemas\static_harbor.listen_event.v1.json",
"schemas\static_harbor.http_listen_event.v1.json",
"schemas\static_harbor.receipt_event.v1.json",
"scripts\_RUN_static_harbor_listen_smoke_v1.ps1",
"scripts\_RUN_static_harbor_http_listen_smoke_v1.ps1",
"scripts\_RUN_static_harbor_tier0_full_green_v1.ps1"
)

foreach($rel in $required){
$p=Join-Path $RepoRoot $rel
if(-not (Test-Path -LiteralPath $p -PathType Leaf)){ Die ("REQUIRED_FILE_MISSING: " + $rel) }
}

Get-ChildItem -LiteralPath (Join-Path $RepoRoot "scripts") -Filter "*.ps1" -File | ForEach-Object {
Parse-GatePs1 $_.FullName
}

& $py -m py_compile $Engine
if($LASTEXITCODE -ne 0){ Die "PY_COMPILE_FAIL" }

Get-ChildItem -LiteralPath (Join-Path $RepoRoot "schemas") -Filter "*.json" -File | ForEach-Object {
$null = Get-Content -Raw -LiteralPath $_.FullName | ConvertFrom-Json
}

Write-Host "STATIC_HARBOR_REPO_HYGIENE_OK" -ForegroundColor Green
