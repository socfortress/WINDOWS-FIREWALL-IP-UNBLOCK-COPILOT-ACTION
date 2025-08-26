[CmdletBinding()]
param(
  [string]$TargetIP,
  [string]$Direction='Inbound',
  [int]$MaxWaitSeconds=300,
  [string]$LogPath="$env:TEMP\UnblockIP-script.log",
  [string]$ARLog='C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)
if ($Arg1 -and -not $TargetIP)   { $TargetIP = $Arg1 }
if ($Arg2 -and -not $Direction)  { $Direction = $Arg2 }
if ($Arg3 -and -not $MaxWaitSeconds) { $MaxWaitSeconds = [int]$Arg3 }

$ErrorActionPreference='Stop'
$HostName=$env:COMPUTERNAME
$LogMaxKB=100
$LogKeep=5
$runStart=Get-Date

if (-not $TargetIP) { throw "TargetIP is required (no interactive input allowed)" }
if ($TargetIP -notmatch '^(\d{1,3}\.){3}\d{1,3}$'){ throw "Invalid IPv4 address format: $TargetIP" }

function Write-Log {
  param([string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
  $ts=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line="[$ts][$Level] $Message"
  switch($Level){
    'ERROR'{Write-Host $line -ForegroundColor Red}
    'WARN' {Write-Host $line -ForegroundColor Yellow}
    default{Write-Host $line}
  }
  Add-Content -Path $LogPath -Value $line -Encoding utf8
}
function Rotate-Log {
  if(Test-Path $LogPath -PathType Leaf){
    if((Get-Item $LogPath).Length/1KB -gt $LogMaxKB){
      for($i=$LogKeep-1;$i -ge 0;$i--){
        $old="$LogPath.$i";$new="$LogPath."+($i+1)
        if(Test-Path $old){Rename-Item $old $new -Force}
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}
function NowZ { (Get-Date).ToString('yyyy-MM-dd HH:mm:sszzz') }
function Write-NDJSONLines {
  param([string[]]$JsonLines,[string]$Path=$ARLog)
  $tmp = Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
  Set-Content -Path $tmp -Value ($JsonLines -join [Environment]::NewLine) -Encoding ascii -Force
  try { Move-Item -Path $tmp -Destination $Path -Force } catch { Move-Item -Path $tmp -Destination ($Path + '.new') -Force }
}

Rotate-Log
Write-Log "=== SCRIPT START : Unblock IP ==="
Write-Log "Target IP: $TargetIP"
Write-Log "Requested Direction: $Direction"

$ts = NowZ
$lines = @()

try {
  $ipToken = ($TargetIP -replace '\.','_')
  $nameBase = "Block_$ipToken"
  $candidateNames = @($nameBase, "${nameBase}_In", "${nameBase}_Out")

  $byName = @()
  foreach ($n in $candidateNames) {
    $r = Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue
    if ($r) { $byName += $r }
  }

  $byAddr = @()
  $allRules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Action -eq 'Block' }
  foreach ($r in @($allRules)) {
    try {
      $afs = @( Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue )
      if (-not $afs) { continue }
      $addrList = @()
      foreach ($af in $afs) {
        if ($af.RemoteAddress) { $addrList += @($af.RemoteAddress) }
        if ($af.LocalAddress)  { $addrList += @($af.LocalAddress)  }
      }
      if ($addrList -contains $TargetIP) {
        $byAddr += $r
      }
    } catch { }
  }

  $matches = @()
  if ($byName) { $matches += $byName }
  if ($byAddr) { $matches += $byAddr }
  $matchMap = @{}
  foreach ($r in $matches) { if ($r -and -not $matchMap.ContainsKey($r.Name)) { $matchMap[$r.Name] = $r } }
  $matches = $matchMap.Values

  foreach ($r in @($matches)) {
    $lines += ([pscustomobject]@{
      timestamp      = $ts
      host           = $HostName
      action         = 'unblock_ip'
      copilot_action = $true
      type           = 'match'
      display_name   = $r.DisplayName
      name           = $r.Name
      direction      = "$($r.Direction)"
      profile        = "$($r.Profile)"
      enabled        = [bool]$r.Enabled
      action_effect  = "$($r.Action)"
    } | ConvertTo-Json -Compress -Depth 6)
  }
  $removedOk = 0
  $removedFail = 0
  foreach ($r in @($matches)) {
    try {
      if ($r.Name) {
        Remove-NetFirewallRule -Name $r.Name -ErrorAction Stop
      } else {
        Remove-NetFirewallRule -DisplayName $r.DisplayName -ErrorAction Stop
      }
      $removedOk++
      $lines += ([pscustomobject]@{
        timestamp      = $ts
        host           = $HostName
        action         = 'unblock_ip'
        copilot_action = $true
        type           = 'rule_removed'
        display_name   = $r.DisplayName
        name           = $r.Name
      } | ConvertTo-Json -Compress -Depth 5)
    } catch {
      $removedFail++
      $lines += ([pscustomobject]@{
        timestamp      = $ts
        host           = $HostName
        action         = 'unblock_ip'
        copilot_action = $true
        type           = 'remove_error'
        display_name   = $r.DisplayName
        name           = $r.Name
        error          = $_.Exception.Message
      } | ConvertTo-Json -Compress -Depth 5)
    }
  }

  $remaining = @()
  foreach ($n in $candidateNames) {
    $rr = Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue
    if ($rr) { $remaining += $rr }
  }
  $allRules2 = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Action -eq 'Block' }
  foreach ($r2 in @($allRules2)) {
    try {
      $afs2 = @( Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r2 -ErrorAction SilentlyContinue )
      if (-not $afs2) { continue }
      $addrList2 = @()
      foreach ($af2 in $afs2) {
        if ($af2.RemoteAddress) { $addrList2 += @($af2.RemoteAddress) }
        if ($af2.LocalAddress)  { $addrList2 += @($af2.LocalAddress)  }
      }
      if ($addrList2 -contains $TargetIP) { $remaining += $r2 }
    } catch { }
  }
  $remMap = @{}
  foreach ($r3 in $remaining) { if ($r3 -and -not $remMap.ContainsKey($r3.Name)) { $remMap[$r3.Name] = $r3 } }
  $remaining = $remMap.Values

  $lines += ([pscustomobject]@{
    timestamp      = $ts
    host           = $HostName
    action         = 'unblock_ip'
    copilot_action = $true
    type           = 'verify_overall'
    target_ip      = $TargetIP
    candidates     = $candidateNames
    matched_rules  = (@($matches) | ForEach-Object { $_.Name })
    removed_ok     = $removedOk
    remove_failed  = $removedFail
    remaining      = (@($remaining) | ForEach-Object { $_.Name })
  } | ConvertTo-Json -Compress -Depth 6)

  $status =
    if ((@($matches)).Count -eq 0) { 'not_found' }
    elseif ($removedFail -eq 0 -and (@($remaining)).Count -eq 0) { 'unblocked' }
    elseif ($removedOk -gt 0 -and (@($remaining)).Count -gt 0) { 'partial' }
    else { 'unknown' }

  $summary = [pscustomobject]@{
    timestamp      = $ts
    host           = $HostName
    action         = 'unblock_ip'
    copilot_action = $true
    type           = 'summary'
    target_ip      = $TargetIP
    direction      = $Direction
    candidate_rule = $nameBase
    matched        = (@($matches)).Count
    removed_ok     = $removedOk
    remove_failed  = $removedFail
    remaining      = (@($remaining)).Count
    status         = $status
    duration_s     = [math]::Round(((Get-Date)-$runStart).TotalSeconds,1)
  }
  $lines = @(( $summary | ConvertTo-Json -Compress -Depth 6 )) + $lines

  Write-NDJSONLines -JsonLines $lines -Path $ARLog
  Write-Log ("NDJSON written to {0} ({1} lines)" -f $ARLog,$lines.Count) 'INFO'
}
catch {
  Write-Log $_.Exception.Message 'ERROR'
  $err=[pscustomobject]@{
    timestamp      = $ts
    host           = $HostName
    action         = 'unblock_ip'
    copilot_action = $true
    type           = 'error'
    target_ip      = $TargetIP
    error          = $_.Exception.Message
  }
  Write-NDJSONLines -JsonLines @(( $err | ConvertTo-Json -Compress -Depth 5 )) -Path $ARLog
  Write-Log "Error NDJSON written" 'INFO'
}
finally {
  $dur=[int]((Get-Date)-$runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
