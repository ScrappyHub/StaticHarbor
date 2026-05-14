param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [string]$ReceiptDir = ""
)

$ErrorActionPreference="Stop"
Set-StrictMode -Version Latest

function Die([string]$m){ throw $m }

function HasProp($obj,[string]$name){
  return $null -ne ($obj.PSObject.Properties | Where-Object { $_.Name -eq $name } | Select-Object -First 1)
}

function To-CanonJson($obj){
  if($null -eq $obj){ return "null" }
  if($obj -is [string]){ return ($obj | ConvertTo-Json -Compress) }
  if($obj -is [bool]){ if($obj){ return "true" } else { return "false" } }
  if($obj -is [int] -or $obj -is [long] -or $obj -is [double] -or $obj -is [decimal]){ return [string]$obj }

  if($obj -is [System.Collections.IEnumerable] -and -not ($obj -is [string]) -and -not ($obj.PSObject.Properties.Name -contains "schema")){
    $parts=@()
    foreach($x in $obj){ $parts += (To-CanonJson $x) }
    return "[" + ($parts -join ",") + "]"
  }

  $names=@($obj.PSObject.Properties.Name | Sort-Object)
  $pairs=@()
  foreach($n in $names){
    $k = ($n | ConvertTo-Json -Compress)
    $v = To-CanonJson ($obj.PSObject.Properties[$n].Value)
    $pairs += ($k + ":" + $v)
  }
  return "{" + ($pairs -join ",") + "}"
}

function Sha256Text([string]$s){
  $bytes=[System.Text.Encoding]::UTF8.GetBytes($s)
  $sha=[System.Security.Cryptography.SHA256]::Create()
  try { return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "") }
  finally { $sha.Dispose() }
}

$RepoRoot=(Resolve-Path -LiteralPath $RepoRoot).Path
if([string]::IsNullOrWhiteSpace($ReceiptDir)){
  $ReceiptDir = Join-Path $RepoRoot "proofs\receipts"
}

if(-not (Test-Path -LiteralPath $ReceiptDir -PathType Container)){
  Die ("RECEIPT_DIR_MISSING: " + $ReceiptDir)
}

$files=@(Get-ChildItem -LiteralPath $ReceiptDir -Filter "*.receipts.jsonl" -File -ErrorAction SilentlyContinue)
if($files.Count -lt 1){ Die "RECEIPT_FILES_MISSING" }

foreach($f in $files){
  $prev=$null
  $lineNo=0
  $lines=Get-Content -LiteralPath $f.FullName
  if($lines.Count -lt 1){ Die ("RECEIPT_FILE_EMPTY: " + $f.Name) }

  foreach($line in $lines){
    $lineNo++
    if([string]::IsNullOrWhiteSpace($line)){ Die ("RECEIPT_BLANK_LINE: " + $f.Name + ":" + $lineNo) }

    try { $obj = $line | ConvertFrom-Json }
    catch { Die ("RECEIPT_JSON_INVALID: " + $f.Name + ":" + $lineNo) }

    foreach($prop in @("schema","event_sha256","event_type","prev_receipt_sha256","receipt_sha256","ts_utc")){
      if(-not (HasProp $obj $prop)){ Die ("RECEIPT_PROP_MISSING: " + $f.Name + ":" + $lineNo + ":" + $prop) }
    }

    if($obj.schema -ne "static_harbor.receipt_event.v1"){
      Die ("RECEIPT_SCHEMA_BAD: " + $f.Name + ":" + $lineNo)
    }

    if($lineNo -eq 1){
      if($null -ne $obj.prev_receipt_sha256){
        Die ("RECEIPT_FIRST_PREV_NOT_NULL: " + $f.Name)
      }
    } else {
      if($obj.prev_receipt_sha256 -ne $prev){
        Die ("RECEIPT_CHAIN_BREAK: " + $f.Name + ":" + $lineNo)
      }
    }

    $copy = $line | ConvertFrom-Json
    $copy.PSObject.Properties.Remove("receipt_sha256")
    $canon = To-CanonJson $copy
    $calc = Sha256Text $canon

    if($calc -ne $obj.receipt_sha256){
      Die ("RECEIPT_HASH_MISMATCH: " + $f.Name + ":" + $lineNo)
    }

    $prev = $obj.receipt_sha256
  }
}

Write-Host ("STATIC_HARBOR_RECEIPT_VERIFY_OK files=" + $files.Count) -ForegroundColor Green
