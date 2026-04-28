#requires -Version 7.2

<#
    Get-PendingReboot.ps1

    Standalone reboot-status reporter for one or more Windows hosts.
    Checks five registry conditions and reports whether a reboot is pending,
    along with the reasons why.

    See README.md for details and examples.
#>

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Single source of truth — 5-condition reboot check body
# ---------------------------------------------------------------------------
# Returns [PSCustomObject]@{ RebootRequired; Reasons; QueriedAt }
# ComputerName and Status are added by the callers so that both the local
# helper and the remote wrapper produce identical output shapes.
$script:RebootCheckBody = {
    $reasons = [System.Collections.Generic.List[string]]::new()

    # 1. Component Based Servicing
    $cbsKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    if (Test-Path -LiteralPath $cbsKey) {
        $reasons.Add('Component Based Servicing')
    }

    # 2. Windows Update
    $wuKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    if (Test-Path -LiteralPath $wuKey) {
        $reasons.Add('Windows Update')
    }

    # 3. Pending File Rename Operations
    $smKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    try {
        $smProps = Get-ItemProperty -LiteralPath $smKey -ErrorAction Stop
        if ($smProps.PendingFileRenameOperations) {
            $reasons.Add('Pending File Rename')
        }
    }
    catch {
        # Key missing or inaccessible — not a pending reboot signal
    }

    # 4. SCCM Client reboot data
    $sccmKey = 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client\Reboot Management\RebootData'
    if (Test-Path -LiteralPath $sccmKey) {
        $reasons.Add('SCCM Client')
    }

    # 5. Computer rename pending (ActiveComputerName vs ComputerName mismatch)
    $activeKey  = 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName'
    $pendingKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName'
    try {
        $activeProps  = Get-ItemProperty -LiteralPath $activeKey  -ErrorAction Stop
        $pendingProps = Get-ItemProperty -LiteralPath $pendingKey -ErrorAction Stop
        if ($activeProps.ComputerName -ne $pendingProps.ComputerName) {
            $reasons.Add('Computer Rename')
        }
    }
    catch {
        # Keys missing or inaccessible — treat as no rename pending
    }

    [PSCustomObject]@{
        RebootRequired = ($reasons.Count -gt 0)
        Reasons        = $reasons.ToArray()
        QueriedAt      = (Get-Date)
    }
}

# ---------------------------------------------------------------------------
# Private helper — runs all 5 checks on the LOCAL machine
# ---------------------------------------------------------------------------

function Test-PRRebootCondition {
    <#
        Checks five registry conditions for a pending reboot on the local
        machine and returns a PSCustomObject with RebootRequired, Reasons,
        ComputerName, QueriedAt, and Status.

        Uses $script:RebootCheckBody as the single source of truth for the
        5-check logic.
    #>
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    $raw = & $script:RebootCheckBody
    [PSCustomObject]@{
        ComputerName   = $ComputerName
        RebootRequired = $raw.RebootRequired
        Reasons        = $raw.Reasons
        QueriedAt      = $raw.QueriedAt
        Status         = 'OK'
    }
}

# ---------------------------------------------------------------------------
# Private helper — FQDN-aware local host detection
# ---------------------------------------------------------------------------

function Test-PRIsLocalHost {
    <#
        Returns $true if the supplied name resolves to the local machine.
        Recognises '.', 'localhost', the bare NetBIOS name, and any FQDN
        whose leftmost label matches the NetBIOS name (e.g. WK01.corp.local
        when $env:COMPUTERNAME is WK01).
    #>
    param(
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Name)) { return $true }
    $lower    = $Name.ToLower()
    $compName = $env:COMPUTERNAME.ToLower()
    if ($lower -in @('.', 'localhost', $compName)) { return $true }
    if ($lower.StartsWith("$compName.")) { return $true }   # FQDN whose leftmost label matches
    return $false
}

# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Report pending-reboot status for one or more Windows hosts.

.DESCRIPTION
    Checks five registry conditions that indicate a reboot is required on
    each target host:

      1. Component Based Servicing (CBS) — key present means CBS has staged
         a change that requires a reboot to complete.
      2. Windows Update — key present means Windows Update is waiting for a
         reboot to apply patches.
      3. Pending File Rename Operations — a non-empty value in the Session
         Manager key indicates files will be renamed or deleted on next boot.
      4. SCCM Client — key present means the Configuration Manager client
         has a pending reboot request.
      5. Computer Rename — mismatch between ActiveComputerName and the
         pending ComputerName means a rename is staged for next boot.

    For remote hosts the checks run via Invoke-Command using the same
    scriptblock body as local checks (single source of truth). Hosts that
    cannot be reached are recorded with Status='Unreachable' rather than
    causing the entire run to fail.

    Results are emitted on the pipeline as PSCustomObjects. Pass -OutputPath
    to also write a JSON file.

.PARAMETER ComputerName
    One or more host names to check. Defaults to the local machine.
    Use '.' or 'localhost' to target the local machine explicitly.
    FQDNs whose leftmost label matches the local machine name are also
    treated as local (e.g. 'WK01.corp.local' when running on WK01).

.PARAMETER OutputPath
    Optional path for a JSON output file. The file is written (or
    overwritten) with UTF-8 encoding.

.EXAMPLE
    Get-PendingReboot

    Checks the local machine and emits one result object to the pipeline.

.EXAMPLE
    Get-PendingReboot -ComputerName SRV01, SRV02, SRV03 -OutputPath C:\Reports\reboot.json

    Checks three servers and writes the results to a JSON file.
#>
function Get-PendingReboot {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter()]
        [string[]]$ComputerName = @($env:COMPUTERNAME),

        [Parameter()]
        [string]$OutputPath
    )

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($h in $ComputerName) {
        # Prefer the shared SysAdmin.Common helper when it is loaded; fall back to
        # the private Test-PRIsLocalHost so the script works fully standalone.
        $isLocal = if (Get-Command Test-IsLocalHost -ErrorAction SilentlyContinue) {
            Test-IsLocalHost -Name $h
        } else {
            Test-PRIsLocalHost -Name $h
        }
        if ($isLocal) {
            # Local — call helper directly so mocks work in tests
            $r = Test-PRRebootCondition -ComputerName $h
            $results.Add($r)
        }
        else {
            # Remote — ship the shared scriptblock via Invoke-Command
            try {
                $raw = Invoke-Command -ComputerName $h -ScriptBlock $script:RebootCheckBody -ErrorAction Stop
                $results.Add([PSCustomObject]@{
                    ComputerName   = $h
                    RebootRequired = $raw.RebootRequired
                    Reasons        = $raw.Reasons
                    QueriedAt      = $raw.QueriedAt
                    Status         = 'OK'
                })
            }
            catch {
                Write-Warning "Could not reach host '$h': $($_.Exception.Message)"
                $results.Add([PSCustomObject]@{
                    ComputerName   = $h
                    RebootRequired = $false
                    Reasons        = @()
                    QueriedAt      = (Get-Date)
                    Status         = 'Unreachable'
                })
            }
        }
    }

    $allResults = $results.ToArray()

    if ($OutputPath) {
        $allResults | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputPath -Encoding UTF8
        Write-Information "JSON written to $OutputPath" -InformationAction Continue
    }

    return $allResults
}
