#requires -Version 7.2
<#
.SYNOPSIS
    Find stale AD users and computers (no logon for N days) and quarantine them.

.DESCRIPTION
    Remove-StaleADObject identifies Active Directory user and/or computer objects
    whose LastLogonDate is older than -StaleDays days and quarantines them by
    disabling the account and moving it to a designated quarantine OU.

    No objects are ever deleted. The destructive action is Disable + Move only.

    All state-changing calls are gated behind ShouldProcess so -WhatIf works
    end-to-end. Run with -WhatIf first against any live directory.

    Requires -QuarantineOU when performing real actions (not -WhatIf).

.PARAMETER Mode
    Which object type(s) to scan. 'User', 'Computer', or 'Both'. Default: 'Both'.

.PARAMETER StaleDays
    Number of days since last logon before an object is considered stale.
    Minimum 30, maximum 730. Default: 90.

.PARAMETER QuarantineOU
    Distinguished name of the OU to move stale objects into.
    Required when -WhatIf is NOT in effect.

.PARAMETER IncludeDisabled
    By default, already-disabled objects are skipped. Set this switch to
    process disabled objects too (useful if a prior run disabled but failed
    to move an account).

.PARAMETER OutputPath
    Optional path to write the result report as a UTF-8 CSV file.

.EXAMPLE
    Remove-StaleADObject -WhatIf
    # Preview stale objects. -QuarantineOU is not required in WhatIf mode.

.EXAMPLE
    Remove-StaleADObject -Mode User -StaleDays 60 -QuarantineOU 'OU=Quarantine,DC=corp,DC=local' -WhatIf
    # Preview users with no logon in 60 days.

.EXAMPLE
    Remove-StaleADObject -StaleDays 90 -QuarantineOU 'OU=Quarantine,DC=corp,DC=local' -OutputPath .\stale-report.csv
    # Disable and move stale objects, write CSV report.
#>

# ---------------------------------------------------------------------------
# Stub gate — makes AD cmdlets mockable when the module is not installed.
# Pester's Mock requires the command to exist in scope before mocking.
# ---------------------------------------------------------------------------
if (-not (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
    function Get-ADUser {
        <#
        .SYNOPSIS
            Stub — replaced at runtime by the ActiveDirectory module.
        #>
        [CmdletBinding()]
        param(
            [string]$Filter,
            [string[]]$Properties
        )
        throw 'ActiveDirectory module not loaded — install RSAT or import the module.'
    }
    function Get-ADComputer {
        <#
        .SYNOPSIS
            Stub — replaced at runtime by the ActiveDirectory module.
        #>
        [CmdletBinding()]
        param(
            [string]$Filter,
            [string[]]$Properties
        )
        throw 'ActiveDirectory module not loaded — install RSAT or import the module.'
    }
    function Disable-ADAccount {
        <#
        .SYNOPSIS
            Stub — replaced at runtime by the ActiveDirectory module.
        #>
        [CmdletBinding(SupportsShouldProcess = $true)]
        param(
            [string]$Identity
        )
        throw 'ActiveDirectory module not loaded — install RSAT or import the module.'
    }
    function Move-ADObject {
        <#
        .SYNOPSIS
            Stub — replaced at runtime by the ActiveDirectory module.
        #>
        [CmdletBinding(SupportsShouldProcess = $true)]
        param(
            [string]$Identity,
            [string]$TargetPath
        )
        throw 'ActiveDirectory module not loaded — install RSAT or import the module.'
    }
}

# ---------------------------------------------------------------------------
# Public function: Remove-StaleADObject
# ---------------------------------------------------------------------------
function Remove-StaleADObject {
    <#
    .SYNOPSIS
        Find stale AD users and computers and quarantine them by disabling
        and moving to a designated OU. Never deletes anything.

    .DESCRIPTION
        Identifies Active Directory user and/or computer objects whose
        LastLogonDate is older than -StaleDays days and quarantines them by
        disabling the account and moving it to the -QuarantineOU. No objects
        are ever deleted.

        All state-changing calls are gated behind ShouldProcess so -WhatIf
        works end-to-end without requiring -QuarantineOU.

    .PARAMETER Mode
        Which object type(s) to scan. 'User', 'Computer', or 'Both'.
        Default: 'Both'.

    .PARAMETER StaleDays
        Days since last logon before an object is stale. Range: 30-730.
        Default: 90.

    .PARAMETER QuarantineOU
        Destination OU distinguished name. Required unless -WhatIf is used.

    .PARAMETER IncludeDisabled
        Process already-disabled objects instead of skipping them.

    .PARAMETER OutputPath
        Optional path to write the result report as a CSV.

    .EXAMPLE
        Remove-StaleADObject -WhatIf

    .EXAMPLE
        Remove-StaleADObject -StaleDays 90 -QuarantineOU 'OU=Quarantine,DC=corp,DC=local' -OutputPath .\report.csv
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter()]
        [ValidateSet('User', 'Computer', 'Both')]
        [string]$Mode = 'Both',

        [Parameter()]
        [ValidateRange(30, 730)]
        [int]$StaleDays = 90,

        [Parameter()]
        [string]$QuarantineOU,

        [Parameter()]
        [switch]$IncludeDisabled,

        [Parameter()]
        [string]$OutputPath
    )

    # Validate QuarantineOU requirement when real actions will be taken.
    # WhatIfPreference is $true when -WhatIf is active.
    if (-not $WhatIfPreference -and [string]::IsNullOrWhiteSpace($QuarantineOU)) {
        throw '-QuarantineOU is required unless -WhatIf is used.'
    }

    $cutoff = (Get-Date).AddDays(-$StaleDays)
    $report = [System.Collections.Generic.List[object]]::new()

    # -------------------------------------------------------------------------
    # User pass
    # -------------------------------------------------------------------------
    if ($Mode -eq 'User' -or $Mode -eq 'Both') {
        try {
            $userCandidates = @(
                Get-ADUser -Filter * -Properties LastLogonDate, Enabled, DistinguishedName -ErrorAction Stop |
                    Where-Object { $_.LastLogonDate -lt $cutoff }
            )
        }
        catch {
            throw
        }

        foreach ($obj in $userCandidates) {
            $row = [PSCustomObject]@{
                ObjectType        = 'User'
                SamAccountName    = $obj.SamAccountName
                DistinguishedName = $obj.DistinguishedName
                LastLogonDate     = $obj.LastLogonDate
                OriginalOU        = (Split-Path $obj.DistinguishedName -Parent)
                Action            = ''
                Reason            = ''
            }

            if ($obj.Enabled -eq $false -and -not $IncludeDisabled) {
                $row.Action = 'Skipped:AlreadyDisabled'
                $report.Add($row)
                continue
            }

            $target      = "$($obj.SamAccountName) ($($obj.DistinguishedName))"
            $description = "Disable and move to '$QuarantineOU' (last logon: $($obj.LastLogonDate))"

            if ($PSCmdlet.ShouldProcess($target, $description)) {
                try {
                    Disable-ADAccount -Identity $obj.DistinguishedName -ErrorAction Stop
                    Move-ADObject    -Identity $obj.DistinguishedName -TargetPath $QuarantineOU -ErrorAction Stop
                    $row.Action = 'Disable+Move'
                }
                catch {
                    $row.Action = 'Failed'
                    $row.Reason = $_.Exception.Message
                    Write-Warning "Failed to quarantine '$($obj.SamAccountName)': $($_.Exception.Message)"
                }
            }
            else {
                $row.Action = 'WhatIf'
            }

            $report.Add($row)
        }
    }

    # -------------------------------------------------------------------------
    # Computer pass
    # -------------------------------------------------------------------------
    if ($Mode -eq 'Computer' -or $Mode -eq 'Both') {
        try {
            $computerCandidates = @(
                Get-ADComputer -Filter * -Properties LastLogonDate, Enabled, DistinguishedName -ErrorAction Stop |
                    Where-Object { $_.LastLogonDate -lt $cutoff }
            )
        }
        catch {
            throw
        }

        foreach ($obj in $computerCandidates) {
            $row = [PSCustomObject]@{
                ObjectType        = 'Computer'
                SamAccountName    = $obj.SamAccountName
                DistinguishedName = $obj.DistinguishedName
                LastLogonDate     = $obj.LastLogonDate
                OriginalOU        = (Split-Path $obj.DistinguishedName -Parent)
                Action            = ''
                Reason            = ''
            }

            if ($obj.Enabled -eq $false -and -not $IncludeDisabled) {
                $row.Action = 'Skipped:AlreadyDisabled'
                $report.Add($row)
                continue
            }

            $target      = "$($obj.SamAccountName) ($($obj.DistinguishedName))"
            $description = "Disable and move to '$QuarantineOU' (last logon: $($obj.LastLogonDate))"

            if ($PSCmdlet.ShouldProcess($target, $description)) {
                try {
                    Disable-ADAccount -Identity $obj.DistinguishedName -ErrorAction Stop
                    Move-ADObject    -Identity $obj.DistinguishedName -TargetPath $QuarantineOU -ErrorAction Stop
                    $row.Action = 'Disable+Move'
                }
                catch {
                    $row.Action = 'Failed'
                    $row.Reason = $_.Exception.Message
                    Write-Warning "Failed to quarantine '$($obj.SamAccountName)': $($_.Exception.Message)"
                }
            }
            else {
                $row.Action = 'WhatIf'
            }

            $report.Add($row)
        }
    }

    # Emit all rows to the pipeline.
    $report | ForEach-Object { Write-Output $_ }

    # Write CSV report if -OutputPath is set.
    if ($OutputPath) {
        $report | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Verbose "Report written to: $OutputPath"
    }
}
