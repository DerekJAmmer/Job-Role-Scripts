#requires -Version 7.2
<#
.SYNOPSIS
    Export local user-rights assignments and optionally diff against a CIS-style JSON baseline.

.DESCRIPTION
    Get-UserRightsAssignment runs 'secedit /export' to dump the local security policy to a
    temporary INF file, parses the [Privilege Rights] section, and emits one row per privilege.

    When -BaselinePath is supplied the script compares each privilege's assigned accounts
    against the JSON baseline and marks each row Compliant, Drift, or Missing.
    Without -BaselinePath every row has Status='Unknown'.

    This script is read-only: it never calls 'secedit /import' or modifies any policy setting.

.PARAMETER BaselinePath
    Path to a JSON baseline file. When supplied, each privilege is compared against the baseline
    and Status is set to Compliant, Drift, or Missing. See samples/cis-user-rights-baseline.json
    for the expected shape.

.PARAMETER OutputPath
    When supplied, all result rows are also exported as a CSV file (UTF-8, no type information).

.EXAMPLE
    Get-UserRightsAssignment
    # Collect all user-rights assignments; no baseline comparison (Status = Unknown).

.EXAMPLE
    Get-UserRightsAssignment -BaselinePath .\samples\cis-user-rights-baseline.json
    # Compare against the shipped CIS 2.2.x baseline.

.EXAMPLE
    Get-UserRightsAssignment -BaselinePath .\samples\cis-user-rights-baseline.json -OutputPath .\rights-report.csv
    # Compare and export results to CSV.
#>

# ---------------------------------------------------------------------------
# Private helper: Invoke-GURASecedit
# Exports user-rights policy to a temp INF via secedit.exe.
# Tests mock this helper rather than secedit.exe directly.
# ---------------------------------------------------------------------------
function Invoke-GURASecedit {
    <#
    .SYNOPSIS
        Run secedit.exe /export to dump user-rights assignments to a temp INF file.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $infPath = [System.IO.Path]::GetTempFileName()
    & secedit.exe /export /cfg $infPath /areas USER_RIGHTS /quiet 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "secedit failed (exit $LASTEXITCODE): unable to export user-rights policy"
    }
    return $infPath
}

# ---------------------------------------------------------------------------
# Private helper: Get-GURAResolveSid
# Translates a SID string to a friendly NTAccount name.
# On failure, returns the raw SID string (never throws).
# ---------------------------------------------------------------------------
function Get-GURAResolveSid {
    <#
    .SYNOPSIS
        Translate a SID string to a friendly NTAccount name, or return the SID on failure.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Sid
    )

    # Strip leading '*' that secedit prefixes on SIDs.
    $cleanSid = $Sid.TrimStart('*')

    try {
        $sidObj = [System.Security.Principal.SecurityIdentifier]::new($cleanSid)
        return $sidObj.Translate([System.Security.Principal.NTAccount]).Value
    }
    catch {
        return $cleanSid
    }
}

# ---------------------------------------------------------------------------
# Private helper: ConvertTo-GURARow
# Build a single result PSCustomObject from parsed privilege fields.
# ---------------------------------------------------------------------------
function ConvertTo-GURARow {
    <#
    .SYNOPSIS
        Build a result row PSCustomObject from parsed privilege fields.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [string]$Privilege,
        [string]$AccountSids  = '',
        [string]$AccountNames = '',
        [string]$Status       = 'Unknown',
        [object]$Expected     = $null,
        [object]$Actual       = $null,
        [string]$Reason       = ''
    )

    return [PSCustomObject]@{
        Privilege    = $Privilege
        AccountSids  = $AccountSids
        AccountNames = $AccountNames
        Status       = $Status
        Expected     = $Expected
        Actual       = $Actual
        Reason       = $Reason
    }
}

# ---------------------------------------------------------------------------
# Public function: Get-UserRightsAssignment
# ---------------------------------------------------------------------------
function Get-UserRightsAssignment {
    <#
    .SYNOPSIS
        Export local user-rights assignments and optionally diff against a CIS-style JSON baseline.

    .DESCRIPTION
        Wraps 'secedit /export', parses the [Privilege Rights] section, and emits one row per
        privilege. Optionally diffs the live assignments against a CIS-style JSON baseline.

        Read-only — does not call 'secedit /import' or modify any policy setting.

    .PARAMETER BaselinePath
        Path to a JSON baseline file for compliance comparison.

    .PARAMETER OutputPath
        When supplied, export all result rows as a CSV (UTF-8).

    .EXAMPLE
        Get-UserRightsAssignment

    .EXAMPLE
        Get-UserRightsAssignment -BaselinePath .\samples\cis-user-rights-baseline.json -OutputPath .\report.csv
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$BaselinePath,

        [Parameter()]
        [string]$OutputPath
    )

    # ------------------------------------------------------------------
    # Load and validate baseline if requested.
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

    # ------------------------------------------------------------------
    # Export user-rights via secedit and parse the INF.
    # ------------------------------------------------------------------
    $infPath = Invoke-GURASecedit

    $results = [System.Collections.Generic.List[object]]::new()

    try {
        $infContent = Get-Content -LiteralPath $infPath -Raw

        # Parse the [Privilege Rights] section.
        $liveMap = @{}

        # Find the section between [Privilege Rights] and the next [section] or end.
        $sectionMatch = [regex]::Match($infContent, '(?i)\[Privilege Rights\]([\s\S]*?)(?=\[|\z)')
        if ($sectionMatch.Success) {
            $sectionBody = $sectionMatch.Groups[1].Value
            foreach ($line in ($sectionBody -split '\r?\n')) {
                $trimmed = $line.Trim()
                if ($trimmed -match '^(Se\w+)\s*=\s*(.+)$') {
                    $privilege = $Matches[1]
                    $rawValues = $Matches[2]

                    # Split on comma, trim each entry.
                    $sidEntries = $rawValues -split ',' | ForEach-Object { $_.Trim() } |
                        Where-Object { $_ -ne '' }

                    # Build semicolon-joined AccountSids string (preserve '*' prefix as-is for transparency).
                    $accountSids = $sidEntries -join ';'

                    # Resolve each SID to a friendly name (strip '*' inside Get-GURAResolveSid).
                    $accountNames = $sidEntries | ForEach-Object { Get-GURAResolveSid -Sid $_ }

                    $liveMap[$privilege] = @{
                        AccountSids  = $accountSids
                        AccountNames = $accountNames  # array
                    }
                }
            }
        }

        # ------------------------------------------------------------------
        # No baseline: emit all live rows with Status='Unknown'.
        # ------------------------------------------------------------------
        if ($null -eq $baseline) {
            foreach ($key in $liveMap.Keys) {
                $entry      = $liveMap[$key]
                $namesJoined = $entry.AccountNames -join ';'
                $results.Add((ConvertTo-GURARow -Privilege $key `
                    -AccountSids $entry.AccountSids `
                    -AccountNames $namesJoined `
                    -Status 'Unknown' `
                    -Expected $null `
                    -Actual $namesJoined))
            }
        }
        else {
            # ------------------------------------------------------------------
            # Baseline mode: build a lookup of expected accounts per privilege.
            # ------------------------------------------------------------------
            $expectedMap = @{}
            foreach ($entry in $baseline.privileges) {
                $expectedMap[$entry.Privilege] = $entry.ExpectedAccounts
            }

            # Emit rows for all baseline privileges.
            foreach ($bKey in $expectedMap.Keys) {
                $expectedAccounts = [string[]]$expectedMap[$bKey]
                $expectedJoined   = $expectedAccounts -join ';'

                if ($liveMap.ContainsKey($bKey)) {
                    $entry      = $liveMap[$bKey]
                    $actualNames = [string[]]$entry.AccountNames
                    $actualJoined = $actualNames -join ';'

                    # Case-insensitive set comparison.
                    $expectedSet = [System.Collections.Generic.HashSet[string]]::new(
                        [System.StringComparer]::OrdinalIgnoreCase)
                    foreach ($a in $expectedAccounts) { [void]$expectedSet.Add($a) }

                    $actualSet = [System.Collections.Generic.HashSet[string]]::new(
                        [System.StringComparer]::OrdinalIgnoreCase)
                    foreach ($a in $actualNames) { [void]$actualSet.Add($a) }

                    if ($expectedSet.SetEquals($actualSet)) {
                        $results.Add((ConvertTo-GURARow -Privilege $bKey `
                            -AccountSids $entry.AccountSids `
                            -AccountNames $actualJoined `
                            -Status 'Compliant' `
                            -Expected $expectedJoined `
                            -Actual $actualJoined))
                    }
                    else {
                        # Calculate added/removed relative to baseline.
                        $added   = $actualNames   | Where-Object { -not $expectedSet.Contains($_) }
                        $removed = $expectedAccounts | Where-Object { -not $actualSet.Contains($_) }

                        $reasonParts = @()
                        if ($added)   { $reasonParts += "Added: $($added -join ', ')" }
                        if ($removed) { $reasonParts += "Removed: $($removed -join ', ')" }

                        $results.Add((ConvertTo-GURARow -Privilege $bKey `
                            -AccountSids $entry.AccountSids `
                            -AccountNames $actualJoined `
                            -Status 'Drift' `
                            -Expected $expectedJoined `
                            -Actual $actualJoined `
                            -Reason ($reasonParts -join '; ')))
                    }
                }
                else {
                    # Baseline privilege absent from live data → Missing.
                    $results.Add((ConvertTo-GURARow -Privilege $bKey `
                        -AccountSids '' `
                        -AccountNames '' `
                        -Status 'Missing' `
                        -Expected $expectedJoined `
                        -Actual $null))
                }
            }

            # Emit Unknown rows for live privileges not present in the baseline.
            foreach ($key in $liveMap.Keys) {
                if (-not $expectedMap.ContainsKey($key)) {
                    $entry       = $liveMap[$key]
                    $namesJoined = $entry.AccountNames -join ';'
                    $results.Add((ConvertTo-GURARow -Privilege $key `
                        -AccountSids $entry.AccountSids `
                        -AccountNames $namesJoined `
                        -Status 'Unknown' `
                        -Expected $null `
                        -Actual $namesJoined))
                }
            }
        }
    }
    finally {
        # Always remove the temp INF file.
        if (Test-Path -LiteralPath $infPath) {
            Remove-Item -LiteralPath $infPath -Force -ErrorAction SilentlyContinue
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
