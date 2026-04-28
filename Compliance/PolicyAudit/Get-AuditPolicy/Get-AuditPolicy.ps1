#requires -Version 7.2
<#
.SYNOPSIS
    Retrieve and optionally compare Windows audit policy settings against a CIS-style JSON baseline.

.DESCRIPTION
    Get-AuditPolicy wraps 'auditpol.exe /get /category:* /r', parses the CSV output, and
    emits one row per audit subcategory. Each row contains the subcategory name, its derived
    category (via a built-in lookup), and the current Inclusion Setting.

    When -BaselinePath is supplied the script compares each row against the JSON baseline and
    marks it Compliant, Drift, or Missing. Without -BaselinePath every row has Status='Unknown'.

    This script is read-only: it never calls 'auditpol /set' or modifies any policy setting.

.PARAMETER BaselinePath
    Path to a JSON baseline file. When supplied, each subcategory is compared against the
    baseline and Status is set to Compliant, Drift, or Missing. See samples/cis-audit-baseline.json
    for the expected shape.

.PARAMETER OutputPath
    When supplied, all result rows are also exported as a CSV file (UTF-8, no type information).

.EXAMPLE
    Get-AuditPolicy
    # Collect all audit subcategories; no baseline comparison (Status = Unknown).

.EXAMPLE
    Get-AuditPolicy -BaselinePath .\samples\cis-audit-baseline.json
    # Compare against the shipped CIS 17.x baseline.

.EXAMPLE
    Get-AuditPolicy -BaselinePath .\samples\cis-audit-baseline.json -OutputPath .\audit-report.csv
    # Compare and export results to CSV.
#>

# ---------------------------------------------------------------------------
# Static subcategory-to-category lookup.
# Covers the main CIS 17.1-17.9 subcategories plus common extras.
# Unknown subcategories map to 'Other'.
# ---------------------------------------------------------------------------
$script:GAPCategoryMap = @{
    # Account Logon (17.1)
    'Credential Validation'                   = 'Account Logon'
    'Kerberos Authentication Service'         = 'Account Logon'
    'Kerberos Service Ticket Operations'      = 'Account Logon'
    'Other Account Logon Events'              = 'Account Logon'

    # Account Management (17.2)
    'Application Group Management'            = 'Account Management'
    'Computer Account Management'             = 'Account Management'
    'Distribution Group Management'           = 'Account Management'
    'Other Account Management Events'         = 'Account Management'
    'Security Group Management'               = 'Account Management'
    'User Account Management'                 = 'Account Management'

    # Detailed Tracking (17.3)
    'DPAPI Activity'                          = 'Detailed Tracking'
    'PNP Activity'                            = 'Detailed Tracking'
    'Process Creation'                        = 'Detailed Tracking'
    'Process Termination'                     = 'Detailed Tracking'
    'RPC Events'                              = 'Detailed Tracking'
    'Token Right Adjusted Events'             = 'Detailed Tracking'

    # DS Access (17.4)
    'Detailed Directory Service Replication'  = 'DS Access'
    'Directory Service Access'                = 'DS Access'
    'Directory Service Changes'               = 'DS Access'
    'Directory Service Replication'           = 'DS Access'

    # Logon/Logoff (17.5)
    'Account Lockout'                         = 'Logon/Logoff'
    'User / Device Claims'                    = 'Logon/Logoff'
    'Group Membership'                        = 'Logon/Logoff'
    'IPsec Extended Mode'                     = 'Logon/Logoff'
    'IPsec Main Mode'                         = 'Logon/Logoff'
    'IPsec Quick Mode'                        = 'Logon/Logoff'
    'Logoff'                                  = 'Logon/Logoff'
    'Logon'                                   = 'Logon/Logoff'
    'Network Policy Server'                   = 'Logon/Logoff'
    'Other Logon/Logoff Events'               = 'Logon/Logoff'
    'Special Logon'                           = 'Logon/Logoff'

    # Object Access (17.6)
    'Application Generated'                   = 'Object Access'
    'Certification Services'                  = 'Object Access'
    'Detailed File Share'                     = 'Object Access'
    'File Share'                              = 'Object Access'
    'File System'                             = 'Object Access'
    'Filtering Platform Connection'           = 'Object Access'
    'Filtering Platform Packet Drop'          = 'Object Access'
    'Handle Manipulation'                     = 'Object Access'
    'Kernel Object'                           = 'Object Access'
    'Other Object Access Events'              = 'Object Access'
    'Registry'                                = 'Object Access'
    'Removable Storage'                       = 'Object Access'
    'SAM'                                     = 'Object Access'
    'Central Policy Staging'                  = 'Object Access'

    # Policy Change (17.7)
    'Audit Policy Change'                     = 'Policy Change'
    'Authentication Policy Change'            = 'Policy Change'
    'Authorization Policy Change'             = 'Policy Change'
    'Filtering Platform Policy Change'        = 'Policy Change'
    'MPSSVC Rule-Level Policy Change'         = 'Policy Change'
    'Other Policy Change Events'              = 'Policy Change'

    # Privilege Use (17.8)
    'Non Sensitive Privilege Use'             = 'Privilege Use'
    'Other Privilege Use Events'              = 'Privilege Use'
    'Sensitive Privilege Use'                 = 'Privilege Use'

    # System (17.9)
    'IPsec Driver'                            = 'System'
    'Other System Events'                     = 'System'
    'Security State Change'                   = 'System'
    'Security System Extension'               = 'System'
    'System Integrity'                        = 'System'
}

# ---------------------------------------------------------------------------
# Private helper: Invoke-GAPAuditPol
# Runs auditpol.exe and returns raw stdout as a single string.
# Tests mock this helper rather than auditpol.exe directly.
# ---------------------------------------------------------------------------
function Invoke-GAPAuditPol {
    <#
    .SYNOPSIS
        Run auditpol.exe /get /category:* /r and return the raw CSV output.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $output = & auditpol.exe /get /category:* /r 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "auditpol failed (exit $LASTEXITCODE): $output"
    }
    return ($output -join "`n")
}

# ---------------------------------------------------------------------------
# Private helper: ConvertTo-GAPRow
# Build a single result PSCustomObject from parsed auditpol fields.
# ---------------------------------------------------------------------------
function ConvertTo-GAPRow {
    <#
    .SYNOPSIS
        Build a result row PSCustomObject from auditpol CSV fields.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [string]$Subcategory,
        [string]$Setting,
        [string]$Status     = 'Unknown',
        [object]$Expected   = $null,
        [object]$Actual     = $null
    )

    $category = if ($script:GAPCategoryMap.ContainsKey($Subcategory)) {
        $script:GAPCategoryMap[$Subcategory]
    }
    else {
        'Other'
    }

    return [PSCustomObject]@{
        Category    = $category
        Subcategory = $Subcategory
        Setting     = $Setting
        Status      = $Status
        Expected    = $Expected
        Actual      = $Actual
    }
}

# ---------------------------------------------------------------------------
# Public function: Get-AuditPolicy
# ---------------------------------------------------------------------------
function Get-AuditPolicy {
    <#
    .SYNOPSIS
        Retrieve and optionally compare Windows audit policy settings against a JSON baseline.

    .DESCRIPTION
        Wraps 'auditpol.exe /get /category:* /r', parses the CSV output, and emits one row per
        audit subcategory. Optionally diffs the live settings against a CIS-style JSON baseline.

        Read-only — does not call 'auditpol /set' or modify any policy setting.

    .PARAMETER BaselinePath
        Path to a JSON baseline file for compliance comparison.

    .PARAMETER OutputPath
        When supplied, export all result rows as a CSV (UTF-8).

    .EXAMPLE
        Get-AuditPolicy

    .EXAMPLE
        Get-AuditPolicy -BaselinePath .\samples\cis-audit-baseline.json -OutputPath .\report.csv
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
            $baseline = Get-Content -LiteralPath $BaselinePath | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            throw "Failed to parse baseline JSON at '$BaselinePath': $($_.Exception.Message)"
        }
    }

    # ------------------------------------------------------------------
    # Invoke auditpol and parse the CSV output.
    # ------------------------------------------------------------------
    $rawCsv = Invoke-GAPAuditPol

    # Build a hashtable of subcategory -> setting from the live auditpol data.
    $liveMap = @{}

    $lines = $rawCsv -split "`n"
    $headerSkipped = $false

    foreach ($line in $lines) {
        $trimmed = $line.Trim()

        # Skip the header row (first non-blank line).
        if (-not $headerSkipped) {
            if ($trimmed -match '^Machine Name') {
                $headerSkipped = $true
            }
            continue
        }

        # Skip blank lines.
        if ([string]::IsNullOrWhiteSpace($trimmed)) {
            continue
        }

        # Parse CSV row: MachineName, PolicyTarget, Subcategory, GUID, InclusionSetting, ExclusionSetting
        $fields = $trimmed -split ','
        if ($fields.Count -lt 5) {
            Write-Warning "Could not parse line: $trimmed"
            continue
        }

        $subcategory = $fields[2].Trim()
        $setting     = $fields[4].Trim()

        if ([string]::IsNullOrWhiteSpace($subcategory)) {
            Write-Warning "Could not parse line: $trimmed"
            continue
        }

        $liveMap[$subcategory] = $setting
    }

    $results = [System.Collections.Generic.List[object]]::new()

    # ------------------------------------------------------------------
    # No baseline: emit all live rows with Status='Unknown'.
    # ------------------------------------------------------------------
    if ($null -eq $baseline) {
        foreach ($key in $liveMap.Keys) {
            $results.Add((ConvertTo-GAPRow -Subcategory $key -Setting $liveMap[$key] -Status 'Unknown'))
        }
    }
    else {
        # ------------------------------------------------------------------
        # Baseline mode: build a lookup of expected settings.
        # ------------------------------------------------------------------
        $expectedMap = @{}
        foreach ($entry in $baseline.subcategories) {
            $expectedMap[$entry.Subcategory] = $entry.Expected
        }

        # Emit rows for all live subcategories.
        foreach ($key in $liveMap.Keys) {
            $actualSetting = $liveMap[$key]

            if ($expectedMap.ContainsKey($key)) {
                $expectedSetting = $expectedMap[$key]
                if ($actualSetting -eq $expectedSetting) {
                    $results.Add((ConvertTo-GAPRow -Subcategory $key -Setting $actualSetting `
                        -Status 'Compliant' -Expected $expectedSetting -Actual $actualSetting))
                }
                else {
                    $results.Add((ConvertTo-GAPRow -Subcategory $key -Setting $actualSetting `
                        -Status 'Drift' -Expected $expectedSetting -Actual $actualSetting))
                }
            }
            else {
                # Live subcategory not in baseline — emit as Unknown.
                $results.Add((ConvertTo-GAPRow -Subcategory $key -Setting $actualSetting -Status 'Unknown'))
            }
        }

        # Emit Missing rows for baseline subcategories absent from live data.
        foreach ($bKey in $expectedMap.Keys) {
            if (-not $liveMap.ContainsKey($bKey)) {
                $results.Add((ConvertTo-GAPRow -Subcategory $bKey -Setting '' `
                    -Status 'Missing' -Expected $expectedMap[$bKey] -Actual $null))
            }
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
