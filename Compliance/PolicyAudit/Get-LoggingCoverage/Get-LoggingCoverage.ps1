#requires -Version 7.2
<#
.SYNOPSIS
    Report local logging-stack coverage across five controls with a percent rollup.

.DESCRIPTION
    Get-LoggingCoverage audits the local machine's logging configuration across five
    control areas:

      1. PowerShell ScriptBlock Logging  — HKLM registry
      2. PowerShell Module Logging       — HKLM registry (with optional ModuleNames check)
      3. PowerShell Transcription        — HKLM registry (two rows: toggle + output dir)
      4. Sysmon                          — Windows service presence and state
      5. Windows Event Forwarding (WEF)  — Wecsvc service + wecutil subscription count

    Each control emits one or more rows with Status in { Enabled, Disabled, Missing, Unknown }.
    After all checks a summary '__OverallScore' row reports the enabled fraction as a percentage.

    This script is local-only and read-only — it never modifies any setting.

.PARAMETER OutputPath
    When supplied, all result rows (including the rollup) are exported as a UTF-8 CSV.

.EXAMPLE
    Get-LoggingCoverage
    # Emit all logging-coverage rows to the pipeline.

.EXAMPLE
    Get-LoggingCoverage -OutputPath .\logging-report.csv
    # Emit rows and also write a CSV file.

.EXAMPLE
    Get-LoggingCoverage | Where-Object { $_.Status -ne 'Enabled' }
    # Show only controls that are not fully enabled.
#>

# ---------------------------------------------------------------------------
# Private helper: Get-GLCRegistryValue
# Returns the value of a registry entry, or $null if the path or name is absent.
# ---------------------------------------------------------------------------
function Get-GLCRegistryValue {
    <#
    .SYNOPSIS
        Return a registry value, or $null if the key/value is missing.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    try {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    }
    catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
# Private helper: Get-GLCService
# Returns the first matching service object, or $null if none found.
# ---------------------------------------------------------------------------
function Get-GLCService {
    <#
    .SYNOPSIS
        Return the first service matching the name pattern, or $null if absent.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    try {
        $svc = @(Get-Service -Name $Name -ErrorAction SilentlyContinue)
        if ($svc.Count -gt 0) {
            return $svc[0]
        }
        return $null
    }
    catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
# Private helper: Invoke-GLCWecutil
# Runs 'wecutil es' and returns the raw stdout. Tests mock this helper.
# ---------------------------------------------------------------------------
function Invoke-GLCWecutil {
    <#
    .SYNOPSIS
        Run wecutil es and return stdout as a string. Returns empty string if no subscriptions.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $output = & wecutil.exe es 2>&1
    return ($output -join "`n")
}

# ---------------------------------------------------------------------------
# Public function: Get-LoggingCoverage
# ---------------------------------------------------------------------------
function Get-LoggingCoverage {
    <#
    .SYNOPSIS
        Report local logging-stack coverage across five controls with a percent rollup.

    .DESCRIPTION
        Audits PowerShell ScriptBlock logging, Module logging, Transcription, Sysmon,
        and Windows Event Forwarding. Emits one PSCustomObject row per sub-check, then
        appends an '__OverallScore' summary row.

        Read-only — does not modify any setting. Local-only by design; for fleet rollups
        invoke via Invoke-Command from an orchestration tool.

    .PARAMETER OutputPath
        When supplied, all result rows are exported as a UTF-8 CSV.

    .EXAMPLE
        Get-LoggingCoverage

    .EXAMPLE
        Get-LoggingCoverage -OutputPath .\logging-report.csv
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputPath
    )

    $rows = [System.Collections.Generic.List[object]]::new()

    # ------------------------------------------------------------------
    # Helper closure: build a result row.
    # ------------------------------------------------------------------
    $MakeRow = {
        param([string]$Control, [string]$Setting, [object]$Value, [string]$Status)
        [PSCustomObject]@{
            Control = $Control
            Setting = $Setting
            Value   = $Value
            Status  = $Status
        }
    }

    # ==================================================================
    # 1. PowerShell ScriptBlock Logging
    # ==================================================================
    $sblPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $sblVal  = Get-GLCRegistryValue -Path $sblPath -Name 'EnableScriptBlockLogging'

    $sblStatus = switch ($sblVal) {
        1       { 'Enabled' }
        0       { 'Disabled' }
        default { 'Missing' }
    }
    $sblDisplay = if ($null -eq $sblVal) { 'NotSet' } else { $sblVal }

    $rows.Add((&$MakeRow `
        -Control 'PowerShell ScriptBlock Logging' `
        -Setting 'EnableScriptBlockLogging' `
        -Value   $sblDisplay `
        -Status  $sblStatus))

    # ==================================================================
    # 2. PowerShell Module Logging
    # ==================================================================
    $mlPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    $mlVal  = Get-GLCRegistryValue -Path $mlPath -Name 'EnableModuleLogging'

    $mlStatus  = switch ($mlVal) {
        1       { 'Enabled' }
        0       { 'Disabled' }
        default { 'Missing' }
    }
    $mlDisplay = if ($null -eq $mlVal) { 'NotSet' } else { $mlVal }

    # Bonus: if enabled, check whether ModuleNames subkey is populated.
    if ($mlVal -eq 1) {
        $moduleNamesPath = Join-Path $mlPath 'ModuleNames'
        if (Test-Path -LiteralPath $moduleNamesPath) {
            $moduleNames = @(Get-Item -LiteralPath $moduleNamesPath -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty Property -ErrorAction SilentlyContinue)
            if ($moduleNames.Count -eq 0) {
                $mlDisplay = 'Configured but ModuleNames empty'
            }
        }
        else {
            $mlDisplay = 'Configured but ModuleNames empty'
        }
    }

    $rows.Add((&$MakeRow `
        -Control 'PowerShell Module Logging' `
        -Setting 'EnableModuleLogging' `
        -Value   $mlDisplay `
        -Status  $mlStatus))

    # ==================================================================
    # 3. PowerShell Transcription — two rows
    # ==================================================================
    $txPath    = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    $txVal     = Get-GLCRegistryValue -Path $txPath -Name 'EnableTranscripting'
    $txDirVal  = Get-GLCRegistryValue -Path $txPath -Name 'OutputDirectory'

    $txStatus  = switch ($txVal) {
        1       { 'Enabled' }
        0       { 'Disabled' }
        default { 'Missing' }
    }
    $txDisplay    = if ($null -eq $txVal)    { 'NotSet' } else { $txVal }
    $txDirDisplay = if ($null -eq $txDirVal) { 'NotSet' } else { $txDirVal }

    $rows.Add((&$MakeRow `
        -Control 'PowerShell Transcription' `
        -Setting 'EnableTranscripting' `
        -Value   $txDisplay `
        -Status  $txStatus))

    $rows.Add((&$MakeRow `
        -Control 'PowerShell Transcription' `
        -Setting 'OutputDirectory' `
        -Value   $txDirDisplay `
        -Status  $txStatus))   # mirrors the toggle status

    # ==================================================================
    # 4. Sysmon
    # ==================================================================
    $sysmon = Get-GLCService -Name 'Sysmon*'

    if ($null -eq $sysmon) {
        $rows.Add((&$MakeRow `
            -Control 'Sysmon' `
            -Setting 'Sysmon Service' `
            -Value   'NotInstalled' `
            -Status  'Missing'))
    }
    else {
        $svcStatus   = if ($sysmon.Status -eq 'Running') { 'Enabled' } else { 'Disabled' }
        $svcDisplay  = "$($sysmon.DisplayName): $($sysmon.Status)"
        $rows.Add((&$MakeRow `
            -Control 'Sysmon' `
            -Setting 'Sysmon Service' `
            -Value   $svcDisplay `
            -Status  $svcStatus))
    }

    # ==================================================================
    # 5. Windows Event Forwarding (WEF) — two rows
    # ==================================================================

    # 5a. Wecsvc service
    $wecsvc = Get-GLCService -Name 'Wecsvc'

    if ($null -eq $wecsvc) {
        $rows.Add((&$MakeRow `
            -Control 'Windows Event Forwarding' `
            -Setting 'Wecsvc Service' `
            -Value   'NotInstalled' `
            -Status  'Missing'))
    }
    else {
        $wecsvcStatus  = if ($wecsvc.Status -eq 'Running') { 'Enabled' } else { 'Disabled' }
        $rows.Add((&$MakeRow `
            -Control 'Windows Event Forwarding' `
            -Setting 'Wecsvc Service' `
            -Value   ([string]$wecsvc.Status) `
            -Status  $wecsvcStatus))
    }

    # 5b. WEF subscriptions via wecutil
    try {
        $wecutilOut     = Invoke-GLCWecutil
        $subLines       = @($wecutilOut -split "`n" |
                            Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $subCount       = $subLines.Count
        $subStatus      = if ($subCount -gt 0) { 'Enabled' } else { 'Disabled' }
        $subDisplay     = if ($subCount -gt 0) { "$subCount" } else { 'None' }

        $rows.Add((&$MakeRow `
            -Control 'Windows Event Forwarding' `
            -Setting 'WEF Subscriptions' `
            -Value   $subDisplay `
            -Status  $subStatus))
    }
    catch {
        Write-Warning "Invoke-GLCWecutil failed: $($_.Exception.Message)"
        $rows.Add((&$MakeRow `
            -Control 'Windows Event Forwarding' `
            -Setting 'WEF Subscriptions' `
            -Value   'Unknown' `
            -Status  'Unknown'))
    }

    # ==================================================================
    # Roll-up row
    # ==================================================================
    $totalChecks  = $rows.Count
    $enabledCount = ($rows | Where-Object { $_.Status -eq 'Enabled' }).Count
    $pct          = if ($totalChecks -gt 0) {
        [Math]::Round(($enabledCount / $totalChecks) * 100)
    }
    else { 0 }

    $rows.Add([PSCustomObject]@{
        Control = '__OverallScore'
        Setting = ''
        Value   = "$enabledCount / $totalChecks"
        Status  = "$pct%"
    })

    # ==================================================================
    # Emit to pipeline
    # ==================================================================
    $rows | ForEach-Object { Write-Output $_ }

    # ==================================================================
    # Optional CSV export
    # ==================================================================
    if ($OutputPath) {
        $rows | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Verbose "Results exported to: $OutputPath"
    }
}
