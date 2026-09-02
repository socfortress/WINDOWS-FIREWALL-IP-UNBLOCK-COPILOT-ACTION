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

  # Normalize requested direction
  if ($Direction -match '^Inbound$') {
      $Direction = 'Inbound'
      $LegacyDirectionSuffix = 'In'
      $DirectionValue = 1
  }
  elseif ($Direction -match '^Outbound$') {
      $Direction = 'Outbound'
      $LegacyDirectionSuffix = 'Out'
      $DirectionValue = 2
  }
  else {
      throw "Invalid Direction '$Direction'. Expected Inbound or Outbound."
  }

  # Support:
  #   Block_8_8_8_8              (old format)
  #   Block_8_8_8_8_In           (legacy format used by current Unblock script)
  #   Block_8_8_8_8_Out
  #   Block_8_8_8_8_Inbound      (current Block Action)
  #   Block_8_8_8_8_Outbound
  $candidateNames = @(
      $nameBase,
      "${nameBase}_${LegacyDirectionSuffix}",
      "${nameBase}_${Direction}"
  )

  $UseNetSecurity = [bool](Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue)

  if (-not $UseNetSecurity) {
      $FirewallPolicy = New-Object -ComObject HNetCfg.FwPolicy2
  }

  function Find-MatchingBlockRules {

      $found = @()

      if ($UseNetSecurity) {

          # Match known rule names first
          foreach ($n in $candidateNames) {

              $rules = @(Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue)

              foreach ($r in $rules) {

                  if (
                      "$($r.Action)" -eq 'Block' -and
                      "$($r.Direction)" -eq $Direction
                  ) {
                      $found += $r
                  }
              }
          }

          # Also find matching block rules by IP
          $allRules = Get-NetFirewallRule -ErrorAction SilentlyContinue |
              Where-Object {
                  $_.Action -eq 'Block' -and
                  "$($_.Direction)" -eq $Direction
              }

          foreach ($r in @($allRules)) {

              try {

                  $afs = @(
                      Get-NetFirewallAddressFilter `
                          -AssociatedNetFirewallRule $r `
                          -ErrorAction SilentlyContinue
                  )

                  if (-not $afs) {
                      continue
                  }

                  $addrList = @()

                  foreach ($af in $afs) {

                      if ($af.RemoteAddress) {
                          $addrList += @($af.RemoteAddress)
                      }

                      if ($af.LocalAddress) {
                          $addrList += @($af.LocalAddress)
                      }
                  }

                  if ($addrList -contains $TargetIP) {
                      $found += $r
                  }

              }
              catch {
              }
          }

      }
      else {

          # Windows Server 2008 R2 / systems without NetSecurity

          # Match known rule names first
          foreach ($n in $candidateNames) {

              $r = $null

              try {
                  $r = $FirewallPolicy.Rules.Item($n)
              }
              catch {
                  $r = $null
              }

              if (
                  $r -and
                  $r.Action -eq 0 -and
                  $r.Direction -eq $DirectionValue
              ) {
                  $found += $r
              }
          }

          # Also search all firewall rules by IP
          foreach ($r in $FirewallPolicy.Rules) {

              try {

                  # NET_FW_ACTION_BLOCK = 0
                  if ($r.Action -ne 0) {
                      continue
                  }

                  # 1 = Inbound / 2 = Outbound
                  if ($r.Direction -ne $DirectionValue) {
                      continue
                  }

                  $addrList = @()

                  if ($r.RemoteAddresses) {
                      $addrList += @(
                          $r.RemoteAddresses -split ',' |
                              ForEach-Object { $_.Trim() }
                      )
                  }

                  if ($r.LocalAddresses) {
                      $addrList += @(
                          $r.LocalAddresses -split ',' |
                              ForEach-Object { $_.Trim() }
                      )
                  }

                  if ($addrList -contains $TargetIP) {
                      $found += $r
                  }

              }
              catch {
              }
          }
      }

      # Deduplicate results by rule name
      $map = @{}

      foreach ($r in @($found)) {

          if ($r -and $r.Name -and -not $map.ContainsKey($r.Name)) {
              $map[$r.Name] = $r
          }
      }

      return @($map.Values)
  }


  # ----------------------------------------------------------------------
  # Find matching rules
  # ----------------------------------------------------------------------

  $matches = @(Find-MatchingBlockRules)


  # ----------------------------------------------------------------------
  # Log matches
  # ----------------------------------------------------------------------

  foreach ($r in @($matches)) {

      if ($UseNetSecurity) {

          $displayName = $r.DisplayName
          $ruleDirection = "$($r.Direction)"
          $ruleProfile = "$($r.Profile)"
          $ruleAction = "$($r.Action)"

      }
      else {

          $displayName = $r.Name

          $ruleDirection = if ($r.Direction -eq 1) {
              'Inbound'
          }
          elseif ($r.Direction -eq 2) {
              'Outbound'
          }
          else {
              "$($r.Direction)"
          }

          $ruleProfile = "$($r.Profiles)"

          $ruleAction = if ($r.Action -eq 0) {
              'Block'
          }
          elseif ($r.Action -eq 1) {
              'Allow'
          }
          else {
              "$($r.Action)"
          }
      }

      $lines += ([pscustomobject]@{
          timestamp      = $ts
          host           = $HostName
          action         = 'unblock_ip'
          copilot_action = $true
          type           = 'match'
          display_name   = $displayName
          name           = $r.Name
          direction      = $ruleDirection
          profile        = $ruleProfile
          enabled        = [bool]$r.Enabled
          action_effect  = $ruleAction
      } | ConvertTo-Json -Compress -Depth 6)
  }


  # ----------------------------------------------------------------------
  # Remove matching rules
  # ----------------------------------------------------------------------

  $removedOk = 0
  $removedFail = 0

  foreach ($r in @($matches)) {

      try {

          if ($UseNetSecurity) {

              if ($r.Name) {
                  Remove-NetFirewallRule -Name $r.Name -ErrorAction Stop
              }
              else {
                  Remove-NetFirewallRule -DisplayName $r.DisplayName -ErrorAction Stop
              }

          }
          else {

              $FirewallPolicy.Rules.Remove($r.Name)
          }

          $removedOk++

          $displayName = if ($UseNetSecurity) {
              $r.DisplayName
          }
          else {
              $r.Name
          }

          $lines += ([pscustomobject]@{
              timestamp      = $ts
              host           = $HostName
              action         = 'unblock_ip'
              copilot_action = $true
              type           = 'rule_removed'
              display_name   = $displayName
              name           = $r.Name
          } | ConvertTo-Json -Compress -Depth 5)

      }
      catch {

          $removedFail++

          $displayName = if ($UseNetSecurity) {
              $r.DisplayName
          }
          else {
              $r.Name
          }

          $lines += ([pscustomobject]@{
              timestamp      = $ts
              host           = $HostName
              action         = 'unblock_ip'
              copilot_action = $true
              type           = 'remove_error'
              display_name   = $displayName
              name           = $r.Name
              error          = $_.Exception.Message
          } | ConvertTo-Json -Compress -Depth 5)
      }
  }


  # ----------------------------------------------------------------------
  # Verify removal
  # ----------------------------------------------------------------------

  $remaining = @(Find-MatchingBlockRules)

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
