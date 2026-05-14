param([Parameter(Mandatory=$true)][string]$RepoRoot)

$ErrorActionPreference="Stop"
Set-StrictMode -Version Latest

function Die([string]$m){ throw $m }

$RepoRoot=(Resolve-Path -LiteralPath $RepoRoot).Path
$schemas=Join-Path $RepoRoot "schemas"

$required=@(
  "static_harbor.listen_event.v1.json",
  "static_harbor.http_listen_event.v1.json",
  "static_harbor.receipt_event.v1.json"
)

foreach($name in $required){
  $p=Join-Path $schemas $name
  if(-not (Test-Path -LiteralPath $p -PathType Leaf)){ Die ("SCHEMA_MISSING: " + $name) }

  try {
    $json = Get-Content -Raw -LiteralPath $p | ConvertFrom-Json
  } catch {
    Die ("SCHEMA_JSON_INVALID: " + $name + " :: " + $_.Exception.Message)
  }

  if(-not $json.'$schema'){ Die ("SCHEMA_NO_DOLLAR_SCHEMA: " + $name) }
  if(-not $json.title){ Die ("SCHEMA_NO_TITLE: " + $name) }
  if(-not $json.type){ Die ("SCHEMA_NO_TYPE: " + $name) }
}

Write-Host "STATIC_HARBOR_SCHEMA_VALIDATE_OK" -ForegroundColor Green
