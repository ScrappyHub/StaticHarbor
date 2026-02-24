[CmdletBinding(PositionalBinding=$false)]
param(
  [Parameter(Mandatory=$true)][ValidateSet("cli","gui")][string]$Mode,
  [Parameter(ValueFromRemainingArguments=$true)][string[]]$Args
)

$ErrorActionPreference="Stop"
Set-StrictMode -Version Latest
function Die([string]$m){ throw $m }
$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Engine  = Join-Path $RepoRoot "static_harbor_engine.py"
if(-not (Test-Path -LiteralPath $Engine -PathType Leaf)){ Die ("ENGINE_MISSING: " + $Engine) }

# Choose python command deterministically
$py=$null
foreach($c in @("python","python3","py")){ $cmd=Get-Command $c -ErrorAction SilentlyContinue; if($cmd){ $py=$cmd.Source; break } }
if(-not $py){ Die "PYTHON_NOT_FOUND" }

if($Mode -eq "cli"){
  & $py $Engine @($Args)
  exit $LASTEXITCODE
}

if($Mode -eq "gui"){
  & $py $Engine gui
  exit $LASTEXITCODE
}
Die ("BAD_MODE: " + $Mode)
