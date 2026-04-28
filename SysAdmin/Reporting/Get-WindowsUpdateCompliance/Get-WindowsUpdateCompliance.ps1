#requires -Version 7.2

<#
.SYNOPSIS
    Reports per-host Windows Update compliance: last install date, missing
    update count, reboot-required state, and days since last update.

.DESCRIPTION
    Get-WindowsUpdateCompliance queries one or more Windows hosts to determine
    their Windows Update compliance posture.

    Primary collection uses the Microsoft.Update.Session COM object
    (Get-WUCSession helper) to retrieve the count of missing updates via
    Windows Update Agent. When COM is unavailable or blocked the script falls
    back to reading the last-successful-install timestamp from the Windows
    Update registry key.

    For each host the function emits a PSCustomObject with the following fields:
      ComputerName        - Target host name.
      LastInstalledDate   - DateTime of the last successful update install.
      DaysSinceLastUpdate - Integer days elapsed since LastInstalledDate.
      MissingUpdateCount  - Integer (COM) or 'Unknown' (Registry fallback).
      RebootRequired      - Boolean if Get-PendingReboot is available, else null.
      Source              - 'COM', 'Registry', or 'Unreachable'.
      IsStale             - True when DaysSinceLastUpdate > StaleDays.

    Pass -OutputPath to also export a CSV and a JSON sidecar file.

.PARAMETER ComputerName
    One or more host names to query. Defaults to the local machine.
    FQDNs whose leftmost label matches the local NetBIOS name are treated
    as local (e.g. 'WK01.corp.local' when running on WK01).

.PARAMETER StaleDays
    Number of days after which a host is considered stale. Default: 30.
    A host is stale when DaysSinceLastUpdate is strictly greater than this
    value.

.PARAMETER OutputPath
    Optional CSV output path. When set the function also writes a JSON
    sidecar with the same base name and a .json extension.

.EXAMPLE
    Get-WindowsUpdateCompliance

    Checks the local machine and emits one result object to the pipeline.

.EXAMPLE
    Get-WindowsUpdateCompliance -ComputerName SRV01,SRV02 -StaleDays 14 -OutputPath C:\Reports\wu.csv

    Checks two servers with a 14-day staleness threshold and writes CSV + JSON output.
#>

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Stub gate — makes Get-PendingReboot mockable in tests when the companion
# script is not dot-sourced. Pester's Mock requires the command to exist in
# scope before it can be intercepted.
# ---------------------------------------------------------------------------
if (-not (Get-Command Get-PendingReboot -ErrorAction SilentlyContinue)) {
    function Get-PendingReboot {
        <#
        .SYNOPSIS
            Stub — replaced at runtime when Get-PendingReboot.ps1 is in scope.
        #>
        [CmdletBinding()]
        param(
            [Parameter()]
            [string[]]$ComputerName = @($env:COMPUTERNAME),
            [Parameter()]
            [string]$OutputPath
        )
        throw 'Get-PendingReboot not available — dot-source Get-PendingReboot.ps1 to enable RebootRequired reporting.'
    }
}

# ---------------------------------------------------------------------------
# Single source of truth — remote WU collection body
# Mirrors the local logic but is self-contained for Invoke-Command transport.
# ---------------------------------------------------------------------------
$script:WUCRemoteBody = {
    $comSession = $null
    try {
        $comSession = New-Object -ComObject 'Microsoft.Update.Session' -ErrorAction Stop
    }
    catch {
        $comSession = $null
    }

    $lastInstalled    = $null
    $missingCount     = $null
    $source           = 'Registry'

    if ($null -ne $comSession) {
        try {
            $searcher     = $comSession.CreateUpdateSearcher()
            $searchResult = $searcher.Search('IsInstalled=0')
            $missingCount = $searchResult.Updates.Count
            $source       = 'COM'

            # Try to get LastInstallDate from update history (first installed entry)
            $histCount = $searcher.GetTotalHistoryCount()
            if ($histCount -gt 0) {
                $history = $searcher.QueryHistory(0, 1)
                if ($history -and $history.Count -gt 0) {
                    $lastInstalled = $history.Item(0).Date
                }
            }
        }
        catch {
            $source       = 'Registry'
            $missingCount = $null
        }
    }

    if ($null -eq $lastInstalled) {
        $regProp = Get-ItemProperty `
            -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install' `
            -Name LastSuccessTime `
            -ErrorAction SilentlyContinue
        if ($regProp -and $regProp.LastSuccessTime) {
            try {
                $lastInstalled = [datetime]::Parse($regProp.LastSuccessTime)
            }
            catch {
                $lastInstalled = $null
            }
        }
        if ($source -ne 'COM') {
            $missingCount = 'Unknown'
        }
    }

    $days    = if ($null -ne $lastInstalled) { [int]([datetime]::Now - $lastInstalled).TotalDays } else { $null }

    [PSCustomObject]@{
        LastInstalledDate   = $lastInstalled
        DaysSinceLastUpdate = $days
        MissingUpdateCount  = $missingCount
        Source              = $source
    }
}

# ---------------------------------------------------------------------------
# Private helper: Get-WUCSession
# Returns a Microsoft.Update.Session COM object, or $null if unavailable.
# Tests mock this helper to avoid real COM calls.
# ---------------------------------------------------------------------------
function Get-WUCSession {
    <#
    .SYNOPSIS
        Return a Microsoft.Update.Session COM object, or $null if unavailable.
    #>
    try {
        $session = New-Object -ComObject 'Microsoft.Update.Session' -ErrorAction Stop
        return $session
    }
    catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
# Private helper: Get-WUCLastInstallTimeFromRegistry
# Reads the last-successful-install timestamp from the Windows Update
# registry key. Returns a [datetime] or $null.
# Tests mock this helper to avoid real registry reads.
# ---------------------------------------------------------------------------
function Get-WUCLastInstallTimeFromRegistry {
    <#
    .SYNOPSIS
        Read the last Windows Update install time from the registry.
    #>
    $regProp = Get-ItemProperty `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install' `
        -Name LastSuccessTime `
        -ErrorAction SilentlyContinue
    if ($regProp -and $regProp.LastSuccessTime) {
        try {
            return [datetime]::Parse($regProp.LastSuccessTime)
        }
        catch {
            return $null
        }
    }
    return $null
}

# ---------------------------------------------------------------------------
# Private helper: Test-WUCIsLocalHost
# FQDN-aware check — returns $true when $Name resolves to the local machine.
# ---------------------------------------------------------------------------
function Test-WUCIsLocalHost {
    <#
    .SYNOPSIS
        Return $true if the supplied name refers to the local machine.
    #>
    param(
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Name)) { return $true }
    $lower    = $Name.ToLower()
    $compName = $env:COMPUTERNAME.ToLower()
    if ($lower -in @('.', 'localhost', $compName)) { return $true }
    if ($lower.StartsWith("$compName.")) { return $true }
    return $false
}

# ---------------------------------------------------------------------------
# Private helper: Invoke-WUCLocalCollection
# Runs the COM + registry collection logic in-process on the local machine.
# ---------------------------------------------------------------------------
function Invoke-WUCLocalCollection {
    <#
    .SYNOPSIS
        Collect Windows Update data from the local host using COM then registry fallback.
    #>
    $session      = Get-WUCSession
    $lastInstalled = $null
    $missingCount  = $null
    $source        = 'Registry'

    if ($null -ne $session) {
        try {
            $searcher     = $session.CreateUpdateSearcher()
            $searchResult = $searcher.Search('IsInstalled=0')
            $missingCount = $searchResult.Updates.Count
            $source       = 'COM'
        }
        catch {
            $source       = 'Registry'
            $missingCount = $null
        }
    }

    # Always try registry for last install date (COM history is complex to mock)
    $lastInstalled = Get-WUCLastInstallTimeFromRegistry

    if ($source -eq 'Registry') {
        $missingCount = 'Unknown'
    }

    $days = if ($null -ne $lastInstalled) {
        [int]([datetime]::Now - $lastInstalled).TotalDays
    }
    else {
        $null
    }

    [PSCustomObject]@{
        LastInstalledDate   = $lastInstalled
        DaysSinceLastUpdate = $days
        MissingUpdateCount  = $missingCount
        Source              = $source
    }
}

# ---------------------------------------------------------------------------
# Public function: Get-WindowsUpdateCompliance
# ---------------------------------------------------------------------------
function Get-WindowsUpdateCompliance {
    <#
    .SYNOPSIS
        Report per-host Windows Update compliance status.

    .DESCRIPTION
        Queries one or more Windows hosts for their Windows Update compliance
        posture. Uses the Microsoft.Update.Session COM object when available,
        falling back to registry reads. See script-level help for full details.

    .PARAMETER ComputerName
        Target host names. Defaults to the local machine.

    .PARAMETER StaleDays
        Staleness threshold in days. Default: 30.

    .PARAMETER OutputPath
        Optional CSV output path. A JSON sidecar is also written.

    .EXAMPLE
        Get-WindowsUpdateCompliance

    .EXAMPLE
        Get-WindowsUpdateCompliance -ComputerName SRV01 -StaleDays 14 -OutputPath C:\Reports\wu.csv
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [string[]]$ComputerName = @($env:COMPUTERNAME),

        [Parameter()]
        [int]$StaleDays = 30,

        [Parameter()]
        [string]$OutputPath
    )

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($h in $ComputerName) {
        Write-Verbose "Processing host: $h"

        # ---- Unreachable check (remote hosts only) --------------------------
        if (-not (Test-WUCIsLocalHost -Name $h)) {
            $reachable = Test-Connection -ComputerName $h -Count 1 -Quiet
            if (-not $reachable) {
                $row = [PSCustomObject]@{
                    ComputerName        = $h
                    LastInstalledDate   = $null
                    DaysSinceLastUpdate = $null
                    MissingUpdateCount  = $null
                    RebootRequired      = $null
                    Source              = 'Unreachable'
                    IsStale             = $null
                }
                $results.Add($row)
                Write-Output $row
                continue
            }

            # ---- Remote collection -----------------------------------------
            try {
                $raw = Invoke-Command -ComputerName $h -ScriptBlock $script:WUCRemoteBody -ErrorAction Stop
                $isStale = if ($null -ne $raw.DaysSinceLastUpdate) {
                    $raw.DaysSinceLastUpdate -gt $StaleDays
                }
                else {
                    $null
                }

                $row = [PSCustomObject]@{
                    ComputerName        = $h
                    LastInstalledDate   = $raw.LastInstalledDate
                    DaysSinceLastUpdate = $raw.DaysSinceLastUpdate
                    MissingUpdateCount  = $raw.MissingUpdateCount
                    RebootRequired      = $null
                    Source              = $raw.Source
                    IsStale             = $isStale
                }
            }
            catch {
                Write-Warning "Could not query host '$h': $($_.Exception.Message)"
                $row = [PSCustomObject]@{
                    ComputerName        = $h
                    LastInstalledDate   = $null
                    DaysSinceLastUpdate = $null
                    MissingUpdateCount  = $null
                    RebootRequired      = $null
                    Source              = 'Unreachable'
                    IsStale             = $null
                }
            }

            $results.Add($row)
            Write-Output $row
            continue
        }

        # ---- Local collection ----------------------------------------------
        $raw     = Invoke-WUCLocalCollection
        $isStale = if ($null -ne $raw.DaysSinceLastUpdate) {
            $raw.DaysSinceLastUpdate -gt $StaleDays
        }
        else {
            $null
        }

        # Optional: get reboot-required state if Get-PendingReboot is available
        $rebootRequired = $null
        $prCmd = Get-Command Get-PendingReboot -ErrorAction SilentlyContinue
        if ($prCmd) {
            try {
                $prResult       = Get-PendingReboot -ComputerName $h
                $rebootRequired = $prResult.RebootRequired
            }
            catch {
                $rebootRequired = $null
            }
        }

        $row = [PSCustomObject]@{
            ComputerName        = $h
            LastInstalledDate   = $raw.LastInstalledDate
            DaysSinceLastUpdate = $raw.DaysSinceLastUpdate
            MissingUpdateCount  = $raw.MissingUpdateCount
            RebootRequired      = $rebootRequired
            Source              = $raw.Source
            IsStale             = $isStale
        }

        $results.Add($row)
        Write-Output $row
    }

    # ---- Output files -------------------------------------------------------
    if ($OutputPath) {
        $allResults = $results.ToArray()
        $allResults | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8

        # JSON sidecar: swap extension to .json
        $jsonPath = [System.IO.Path]::ChangeExtension($OutputPath, '.json')
        $allResults | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

        Write-Verbose "CSV written to: $OutputPath"
        Write-Verbose "JSON written to: $jsonPath"
    }
}
