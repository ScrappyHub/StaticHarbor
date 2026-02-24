[CmdletBinding(PositionalBinding=$false)]
param(
  [Parameter(Mandatory=$false)][ValidateSet("cli","gui")][string]$Mode="cli",
  [Parameter(ValueFromRemainingArguments=$true)][string[]]$Args=@()
)
$ErrorActionPreference="Stop"
Set-StrictMode -Version Latest

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$run  = Join-Path $here "scripts\run.ps1"

$pwsh = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
if(-not $pwsh){ $pwsh = (Get-Command powershell -ErrorAction Stop).Source }

# pass remaining args through as literal argv tokens
& $pwsh -NoProfile -ExecutionPolicy Bypass -File $run -RepoRoot $here -Mode $Mode @Args
