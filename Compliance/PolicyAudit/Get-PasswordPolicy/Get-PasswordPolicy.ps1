#requires -Version 7.2
<#
.SYNOPSIS
    Report domain, local, and fine-grained password policies with optional CIS/NIST baseline comparison.

.DESCRIPTION
    Get-PasswordPolicy collects password-policy settings from three sources:

      Domain   — Active Directory default domain password policy (requires RSAT).
      Local    — Local machine policy via net accounts (no RSAT required).
      FGPP     — AD Fine-Grained Password Policies (requires RSAT; opt-in via
                 -IncludeFGPP because enumeration can be slow in large forests).

    When -BaselinePath is supplied, each row is compared against the JSON baseline
    and marked Compliant or NonCompliant. Without -BaselinePath every row is
    Status='Unknown'.

    This script is read-only: it never modifies any policy setting.

.PARAMETER IncludeDomain
    Collect the AD default domain password policy. Default: $true.
    Pass -IncludeDomain:$false to suppress.

.PARAMETER IncludeLocal
    Collect the local machine password policy via net accounts. Default: $true.
    Pass -IncludeLocal:$false to suppress.

.PARAMETER IncludeFGPP
    Collect AD Fine-Grained Password Policies. Default: $false (opt-in).

.PARAMETER BaselinePath
    Path to a JSON baseline file. When supplied, each policy row is compared
    against the baseline and Status is set to Compliant or NonCompliant.
    See samples/baseline-example.json for the expected shape.

.PARAMETER OutputPath
    When supplied, all result rows are also exported as a CSV file (UTF-8).

.EXAMPLE
    Get-PasswordPolicy
    # Collect domain + local policies; no baseline comparison.

.EXAMPLE
    Get-PasswordPolicy -BaselinePath .\samples\baseline-example.json
    # Compare against the shipped CIS-style baseline.

.EXAMPLE
    Get-PasswordPolicy -IncludeDomain:$false -IncludeLocal:$false -IncludeFGPP
    # FGPP rows only.

.EXAMPLE
    Get-PasswordPolicy -BaselinePath .\baseline.json -OutputPath .\audit.csv
    # Compare and export results to CSV.
#>

# ---------------------------------------------------------------------------
# Stub gate — makes AD cmdlets mockable when the module is not installed.
# Pester's Mock requires the command to exist in scope before mocking.
# ---------------------------------------------------------------------------
if (-not (Get-Command Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue)) {
    function Get-ADDefaultDomainPasswordPolicy {
        <#
        .SYNOPSIS
            Stub — replaced at runtime by the ActiveDirectory module.
        #>
        throw 'ActiveDirectory module not loaded — install RSAT.ActiveDirectory.'
    }
    function Get-ADFineGrainedPasswordPolicy {
        <#
        .SYNOPSIS
            Stub — replaced at runtime by the ActiveDirectory module.
        #>
        [CmdletBinding()]
        param(
            [string]$Filter
        )
        throw 'ActiveDirectory module not loaded — install RSAT.ActiveDirectory.'
    }
}

# ---------------------------------------------------------------------------
# Private helper: Get-GPPNetAccount
# Parses 'net accounts' output into a hashtable.
# ComplexityEnabled is not directly reported by net accounts; set to $null.
# ---------------------------------------------------------------------------
function Get-GPPNetAccount {
    <#
    .SYNOPSIS
        Parse net accounts output into a policy hashtable.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $raw = & cmd.exe /c net accounts 2>&1

    $result = @{
        MinLength         = 0
        MaxAge            = 0
        MinAge            = 0
        History           = 0
        LockoutThreshold  = 0
        LockoutDuration   = 0
        ComplexityEnabled = $null
    }

    foreach ($line in $raw) {
        if ($line -match 'Minimum password length\s*:\s*(\S+)') {
            $val = $Matches[1]
            $result['MinLength'] = if ($val -match '^\d+$') { [int]$val } else { 0 }
        }
        elseif ($line -match 'Maximum password age \(days\)\s*:\s*(\S+)') {
            $val = $Matches[1]
            $result['MaxAge'] = if ($val -match '^\d+$') { [int]$val } else { 0 }
        }
        elseif ($line -match 'Minimum password age \(days\)\s*:\s*(\S+)') {
            $val = $Matches[1]
            $result['MinAge'] = if ($val -match '^\d+$') { [int]$val } else { 0 }
        }
        elseif ($line -match 'Length of password history maintained\s*:\s*(\S+)') {
            $val = $Matches[1]
            $result['History'] = if ($val -match '^\d+$') { [int]$val } else { 0 }
        }
        elseif ($line -match 'Lockout threshold\s*:\s*(\S+)') {
            $val = $Matches[1]
            $result['LockoutThreshold'] = if ($val -match '^\d+$') { [int]$val } else { 0 }
        }
        elseif ($line -match 'Lockout duration \(minutes\)\s*:\s*(\S+)') {
            $val = $Matches[1]
            $result['LockoutDuration'] = if ($val -match '^\d+$') { [int]$val } else { 0 }
        }
    }

    return $result
}

# ---------------------------------------------------------------------------
# Private helper: Compare-GPPPolicyToBaseline
# Diffs one policy row against a baseline object; returns Status + Deltas.
# ---------------------------------------------------------------------------
function Compare-GPPPolicyToBaseline {
    <#
    .SYNOPSIS
        Compare a policy row to a baseline and return Status and Deltas.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Row,

        [Parameter(Mandatory)]
        [PSCustomObject]$Baseline
    )

    $deltas = [System.Collections.Generic.List[object]]::new()

    $fields = @(
        @{ RowProp = 'MinLength';              BaseKey = 'MinLength' },
        @{ RowProp = 'HistoryCount';           BaseKey = 'HistoryCount' },
        @{ RowProp = 'MaxAgeDays';             BaseKey = 'MaxAgeDays' },
        @{ RowProp = 'MinAgeDays';             BaseKey = 'MinAgeDays' },
        @{ RowProp = 'LockoutThreshold';       BaseKey = 'LockoutThreshold' },
        @{ RowProp = 'LockoutDurationMinutes'; BaseKey = 'LockoutDurationMinutes' }
    )

    foreach ($f in $fields) {
        $baseVal = $Baseline.($f.BaseKey)
        $rowVal  = $Row.($f.RowProp)
        if ($null -ne $baseVal -and $null -ne $rowVal -and $baseVal -ne $rowVal) {
            $deltas.Add([PSCustomObject]@{
                Field    = $f.BaseKey
                Expected = $baseVal
                Actual   = $rowVal
            })
        }
    }

    # Compare ComplexityEnabled separately (bool, not numeric).
    if ($null -ne $Baseline.ComplexityEnabled -and $null -ne $Row.ComplexityEnabled) {
        if ($Baseline.ComplexityEnabled -ne $Row.ComplexityEnabled) {
            $deltas.Add([PSCustomObject]@{
                Field    = 'ComplexityEnabled'
                Expected = $Baseline.ComplexityEnabled
                Actual   = $Row.ComplexityEnabled
            })
        }
    }

    $status = if ($deltas.Count -eq 0) { 'Compliant' } else { 'NonCompliant' }
    return @{ Status = $status; Deltas = $deltas.ToArray() }
}

# ---------------------------------------------------------------------------
# Public function: Get-PasswordPolicy
# ---------------------------------------------------------------------------
function Get-PasswordPolicy {
    <#
    .SYNOPSIS
        Report domain, local, and fine-grained password policies.

    .DESCRIPTION
        Collects password-policy settings from Active Directory (domain + FGPP)
        and the local machine (net accounts). Optionally compares each row against
        a JSON baseline (CIS/NIST-style) and marks rows Compliant or NonCompliant.

        Read-only — does not modify any policy setting.

    .PARAMETER IncludeDomain
        Collect the AD default domain password policy. Default: $true.
        Pass -IncludeDomain:$false to suppress.

    .PARAMETER IncludeLocal
        Collect local machine password policy via net accounts. Default: $true.
        Pass -IncludeLocal:$false to suppress.

    .PARAMETER IncludeFGPP
        Collect AD Fine-Grained Password Policies. Default: $false (opt-in).

    .PARAMETER BaselinePath
        Path to a JSON baseline file for compliance comparison.

    .PARAMETER OutputPath
        When supplied, export all result rows as a CSV (UTF-8).

    .EXAMPLE
        Get-PasswordPolicy

    .EXAMPLE
        Get-PasswordPolicy -BaselinePath .\samples\baseline-example.json -OutputPath .\audit.csv
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [bool]$IncludeDomain = $true,

        [Parameter()]
        [bool]$IncludeLocal = $true,

        [Parameter()]
        [switch]$IncludeFGPP,

        [Parameter()]
        [string]$BaselinePath,

        [Parameter()]
        [string]$OutputPath
    )

    # ------------------------------------------------------------------
    # Load baseline if requested.
    # ------------------------------------------------------------------
    $baseline = $null
    if ($BaselinePath) {
        if (-not (Test-Path -LiteralPath $BaselinePath)) {
            throw "Baseline file not found: '$BaselinePath'."
        }
        try {
            $baseline = Get-Content -LiteralPath $BaselinePath -Raw | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            throw "Failed to parse baseline JSON at '$BaselinePath': $($_.Exception.Message)"
        }
    }

    $results = [System.Collections.Generic.List[object]]::new()

    # ------------------------------------------------------------------
    # Helper: build a result row and apply baseline comparison.
    # ------------------------------------------------------------------
    function ConvertTo-GPPRow {
        param(
            [string]$Source,
            [int]$MinLength,
            $ComplexityEnabled,
            [int]$HistoryCount,
            [int]$MaxAgeDays,
            $MinAgeDays,
            [int]$LockoutThreshold,
            [int]$LockoutDurationMinutes
        )

        $row = [PSCustomObject]@{
            Source                 = $Source
            MinLength              = $MinLength
            ComplexityEnabled      = $ComplexityEnabled
            HistoryCount           = $HistoryCount
            MaxAgeDays             = $MaxAgeDays
            MinAgeDays             = $MinAgeDays
            LockoutThreshold       = $LockoutThreshold
            LockoutDurationMinutes = $LockoutDurationMinutes
            Status                 = 'Unknown'
            Deltas                 = @()
        }

        if ($null -ne $baseline) {
            $cmp        = Compare-GPPPolicyToBaseline -Row $row -Baseline $baseline
            $row.Status = $cmp.Status
            $row.Deltas = $cmp.Deltas
        }

        return $row
    }

    # ------------------------------------------------------------------
    # Domain policy.
    # ------------------------------------------------------------------
    if ($IncludeDomain) {
        $dp = Get-ADDefaultDomainPasswordPolicy
        $maxAgeDays = if ($dp.MaxPasswordAge -is [timespan]) {
            [int]$dp.MaxPasswordAge.TotalDays
        }
        else {
            [int]$dp.MaxPasswordAge
        }
        $minAgeDays = if ($dp.MinPasswordAge -is [timespan]) {
            [int]$dp.MinPasswordAge.TotalDays
        }
        else {
            if ($null -ne $dp.PSObject.Properties['MinPasswordAge']) {
                [int]$dp.MinPasswordAge
            }
            else { $null }
        }
        $lockoutDuration = if ($dp.LockoutDuration -is [timespan]) {
            [int]$dp.LockoutDuration.TotalMinutes
        }
        else {
            [int]$dp.LockoutDuration
        }

        $results.Add((ConvertTo-GPPRow `
            -Source                 'Domain' `
            -MinLength              ([int]$dp.MinPasswordLength) `
            -ComplexityEnabled      ([bool]$dp.ComplexityEnabled) `
            -HistoryCount           ([int]$dp.PasswordHistoryCount) `
            -MaxAgeDays             $maxAgeDays `
            -MinAgeDays             $minAgeDays `
            -LockoutThreshold       ([int]$dp.LockoutThreshold) `
            -LockoutDurationMinutes $lockoutDuration))
    }

    # ------------------------------------------------------------------
    # Local policy (net accounts).
    # ------------------------------------------------------------------
    if ($IncludeLocal) {
        $local = Get-GPPNetAccount
        $results.Add((ConvertTo-GPPRow `
            -Source                 'Local' `
            -MinLength              $local['MinLength'] `
            -ComplexityEnabled      $local['ComplexityEnabled'] `
            -HistoryCount           $local['History'] `
            -MaxAgeDays             $local['MaxAge'] `
            -MinAgeDays             $local['MinAge'] `
            -LockoutThreshold       $local['LockoutThreshold'] `
            -LockoutDurationMinutes $local['LockoutDuration']))
    }

    # ------------------------------------------------------------------
    # Fine-Grained Password Policies (opt-in).
    # ------------------------------------------------------------------
    if ($IncludeFGPP) {
        $fgpps = @(Get-ADFineGrainedPasswordPolicy -Filter '*')
        foreach ($fgpp in $fgpps) {
            $fMaxAge = if ($fgpp.MaxPasswordAge -is [timespan]) {
                [int]$fgpp.MaxPasswordAge.TotalDays
            }
            else { [int]$fgpp.MaxPasswordAge }

            $fMinAge = if ($fgpp.MinPasswordAge -is [timespan]) {
                [int]$fgpp.MinPasswordAge.TotalDays
            }
            else {
                if ($null -ne $fgpp.PSObject.Properties['MinPasswordAge']) {
                    [int]$fgpp.MinPasswordAge
                }
                else { $null }
            }

            $fLockout = if ($fgpp.LockoutDuration -is [timespan]) {
                [int]$fgpp.LockoutDuration.TotalMinutes
            }
            else { [int]$fgpp.LockoutDuration }

            $results.Add((ConvertTo-GPPRow `
                -Source                 "FGPP:$($fgpp.Name)" `
                -MinLength              ([int]$fgpp.MinPasswordLength) `
                -ComplexityEnabled      ([bool]$fgpp.ComplexityEnabled) `
                -HistoryCount           ([int]$fgpp.PasswordHistoryCount) `
                -MaxAgeDays             $fMaxAge `
                -MinAgeDays             $fMinAge `
                -LockoutThreshold       ([int]$fgpp.LockoutThreshold) `
                -LockoutDurationMinutes $fLockout))
        }
    }

    # ------------------------------------------------------------------
    # Emit to pipeline.
    # ------------------------------------------------------------------
    $results | ForEach-Object { Write-Output $_ }

    # ------------------------------------------------------------------
    # Optional CSV export.
    # ------------------------------------------------------------------
    if ($OutputPath) {
        $results | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Verbose "Results exported to: $OutputPath"
    }
}
