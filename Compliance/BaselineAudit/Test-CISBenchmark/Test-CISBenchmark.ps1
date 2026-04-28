#requires -Version 7.2
<#
.SYNOPSIS
    Audit local Windows settings against a subset of CIS Windows 10/11 benchmark controls.

.DESCRIPTION
    Test-CISBenchmark loads a JSON benchmark file containing a subset of CIS Windows 10/11
    controls and evaluates each one locally. It dispatches each control by type
    (RegistryValue, AuditPolicy, ServiceState, SecurityPolicy, Manual) and emits one row
    per control with a Status of Compliant, NonCompliant, Manual, Error, or Unknown, plus
    Expected and Actual values so you can see exactly where drift occurred.

    This script is read-only — it never calls Set-* or modifies any system setting.

    An optional HTML report is written via Write-ComplianceReport when -HtmlPath is supplied.

.PARAMETER ComputerName
    Target computer(s). Currently only the local machine ('.') is supported; passing any
    other value emits a warning and skips that target. Default: @('.').

.PARAMETER BenchmarkPath
    Path to the JSON benchmark file. Mandatory. See samples/cis-win11-subset.json for shape.

.PARAMETER OutputPath
    When supplied, all result rows are exported as a UTF-8 CSV.

.PARAMETER HtmlPath
    When supplied, an HTML report is written via Write-ComplianceReport.

.PARAMETER Section
    When supplied, only controls whose section property matches one of these values are run.

.PARAMETER IncludeManual
    By default, Manual controls are excluded. Use this switch to include them in output.

.EXAMPLE
    Test-CISBenchmark -BenchmarkPath .\samples\cis-win11-subset.json

.EXAMPLE
    Test-CISBenchmark -BenchmarkPath .\samples\cis-win11-subset.json -Section 'Account Policies' -OutputPath .\cis-report.csv

.EXAMPLE
    Test-CISBenchmark -BenchmarkPath .\samples\cis-win11-subset.json -IncludeManual -HtmlPath .\cis-report.html
#>

# ---------------------------------------------------------------------------
# Private wrapper: Invoke-TCBAuditPol
# Runs auditpol.exe and returns raw CSV output as a single string.
# Tests mock this helper rather than auditpol.exe directly.
# ---------------------------------------------------------------------------
function Invoke-TCBAuditPol {
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
# Private wrapper: Get-TCBRegValue
# Reads a registry value; returns $null if the key or value is missing.
# Never throws — callers treat $null as NonCompliant.
# ---------------------------------------------------------------------------
function Get-TCBRegValue {
    <#
    .SYNOPSIS
        Read a single registry value. Returns $null if the key or value does not exist.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )

    try {
        $props = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $props.$Name
    }
    catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
# Private wrapper: Get-TCBService
# Wraps Get-Service; returns a lightweight PSCustomObject or $null if not found.
# ---------------------------------------------------------------------------
function Get-TCBService {
    <#
    .SYNOPSIS
        Return service Name, Status, and StartType, or $null if the service does not exist.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name
    )

    try {
        $svc = Get-Service -Name $Name -ErrorAction Stop
        return [PSCustomObject]@{
            Name      = $svc.Name
            Status    = $svc.Status.ToString()
            StartType = $svc.StartType.ToString()
        }
    }
    catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
# Private wrapper: Invoke-TCBNetAccount
# Runs 'net accounts' and returns output as a single string.
# Throws on non-zero exit so the caller can surface Status=Error.
# ---------------------------------------------------------------------------
function Invoke-TCBNetAccount {
    <#
    .SYNOPSIS
        Run 'net accounts' and return raw output as a string.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $output = & net accounts 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "net accounts failed (exit $LASTEXITCODE): $output"
    }
    return ($output -join "`n")
}

# ---------------------------------------------------------------------------
# Private parser: Convert-TCBAuditPolCsv
# Parses raw auditpol /r CSV into a hashtable keyed by subcategory name.
# ---------------------------------------------------------------------------
function Convert-TCBAuditPolCsv {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([string]$RawCsv)

    $map = @{}
    if ([string]::IsNullOrWhiteSpace($RawCsv)) { return $map }

    $lines = $RawCsv -split "`n"
    $headerSkipped = $false

    foreach ($line in $lines) {
        $trimmed = $line.Trim()

        if (-not $headerSkipped) {
            if ($trimmed -match '^Machine Name') {
                $headerSkipped = $true
            }
            continue
        }

        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }

        $fields = $trimmed -split ','
        if ($fields.Count -lt 5) { continue }

        $subcategory = $fields[2].Trim()
        $setting     = $fields[4].Trim()

        if (-not [string]::IsNullOrWhiteSpace($subcategory)) {
            $map[$subcategory] = $setting
        }
    }

    return $map
}

# ---------------------------------------------------------------------------
# Private parser: Convert-TCBNetAccountsText
# Parses 'net accounts' key: value lines into a hashtable.
# ---------------------------------------------------------------------------
function Convert-TCBNetAccountsText {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([string]$RawText)

    $map = @{}
    if ([string]::IsNullOrWhiteSpace($RawText)) { return $map }

    foreach ($line in ($RawText -split "`n")) {
        $trimmed = $line.Trim()
        if ($trimmed -match '^(.+?):\s+(.+)$') {
            $key   = $Matches[1].Trim()
            $value = $Matches[2].Trim()
            $map[$key] = $value
        }
    }

    return $map
}

# ---------------------------------------------------------------------------
# Private dispatcher: Test-TCBRegistryValue
# ---------------------------------------------------------------------------
function Test-TCBRegistryValue {
    [CmdletBinding()]
    param([object]$Control)

    $exp      = $Control.expected
    $actual   = Get-TCBRegValue -Path $exp.Path -Name $exp.Name
    $expected = $exp.Value

    if ($null -eq $actual) {
        return @{
            Status   = 'NonCompliant'
            Actual   = $null
            Expected = $expected
            Reason   = 'Registry key/value not present'
        }
    }

    if ($exp.ValueType -eq 'DWord') {
        $match = ([int]$actual -eq [int]$expected)
    }
    else {
        $match = ([string]$actual -ieq [string]$expected)
    }

    if ($match) {
        return @{ Status = 'Compliant';    Actual = $actual; Expected = $expected; Reason = '' }
    }
    else {
        return @{ Status = 'NonCompliant'; Actual = $actual; Expected = $expected; Reason = "Expected '$expected'; got '$actual'" }
    }
}

# ---------------------------------------------------------------------------
# Private dispatcher: Test-TCBAuditPolicy
# Requires a pre-parsed audit hashtable passed in via -AuditMap.
# ---------------------------------------------------------------------------
function Test-TCBAuditPolicy {
    [CmdletBinding()]
    param(
        [object]   $Control,
        [hashtable]$AuditMap
    )

    $exp         = $Control.expected
    $subcategory = $exp.Subcategory
    $expected    = $exp.Setting

    if ($null -eq $AuditMap -or -not $AuditMap.ContainsKey($subcategory)) {
        return @{
            Status   = 'Error'
            Actual   = $null
            Expected = $expected
            Reason   = "Subcategory '$subcategory' not found in live audit data"
        }
    }

    $actual = $AuditMap[$subcategory]

    if ($actual -eq $expected) {
        return @{ Status = 'Compliant';    Actual = $actual; Expected = $expected; Reason = '' }
    }
    else {
        return @{ Status = 'NonCompliant'; Actual = $actual; Expected = $expected; Reason = "Expected '$expected'; got '$actual'" }
    }
}

# ---------------------------------------------------------------------------
# Private dispatcher: Test-TCBServiceState
# ---------------------------------------------------------------------------
function Test-TCBServiceState {
    [CmdletBinding()]
    param([object]$Control)

    $exp      = $Control.expected
    $svc      = Get-TCBService -Name $exp.Name

    if ($null -eq $svc) {
        return @{
            Status   = 'NonCompliant'
            Actual   = $null
            Expected = $exp.StartType
            Reason   = 'Service not found'
        }
    }

    if ($svc.StartType -ieq $exp.StartType) {
        return @{ Status = 'Compliant';    Actual = $svc.StartType; Expected = $exp.StartType; Reason = '' }
    }
    else {
        return @{
            Status   = 'NonCompliant'
            Actual   = $svc.StartType
            Expected = $exp.StartType
            Reason   = "Expected StartType '$($exp.StartType)'; got '$($svc.StartType)'"
        }
    }
}

# ---------------------------------------------------------------------------
# Private dispatcher: Test-TCBSecurityPolicy
# Requires a pre-parsed net-accounts hashtable passed in via -NetMap.
# ---------------------------------------------------------------------------
function Test-TCBSecurityPolicy {
    [CmdletBinding()]
    param(
        [object]   $Control,
        [hashtable]$NetMap
    )

    $exp      = $Control.expected
    $setting  = $exp.Setting
    $expected = $exp.Value

    if ($null -eq $NetMap -or -not $NetMap.ContainsKey($setting)) {
        return @{
            Status   = 'Error'
            Actual   = $null
            Expected = $expected
            Reason   = "Setting '$setting' not found in net accounts output"
        }
    }

    $actual = $NetMap[$setting]

    # Numeric compare when both sides parse as int; else string.
    $intExp = 0; $intAct = 0
    if ([int]::TryParse($expected, [ref]$intExp) -and [int]::TryParse($actual, [ref]$intAct)) {
        $match = ($intAct -eq $intExp)
    }
    else {
        $match = ($actual -ieq $expected)
    }

    if ($match) {
        return @{ Status = 'Compliant';    Actual = $actual; Expected = $expected; Reason = '' }
    }
    else {
        return @{ Status = 'NonCompliant'; Actual = $actual; Expected = $expected; Reason = "Expected '$expected'; got '$actual'" }
    }
}

# ---------------------------------------------------------------------------
# Public function: Test-CISBenchmark
# ---------------------------------------------------------------------------
function Test-CISBenchmark {
    <#
    .SYNOPSIS
        Audit Windows settings against a CIS benchmark JSON subset file.

    .DESCRIPTION
        Loads a JSON benchmark file and evaluates each control locally. Emits one row per
        control with Status Compliant / NonCompliant / Manual / Error / Unknown plus
        Expected and Actual delta values and a SUMMARY row at the end.

        Read-only — never calls Set-* or changes any system configuration.

    .PARAMETER ComputerName
        Target(s). Only '.' (local) is currently supported; others emit a warning.

    .PARAMETER BenchmarkPath
        Mandatory path to the JSON benchmark file.

    .PARAMETER OutputPath
        When supplied, export all rows as a UTF-8 CSV.

    .PARAMETER HtmlPath
        When supplied, write an HTML report via Write-ComplianceReport.

    .PARAMETER Section
        Filter controls to only those whose section matches one of these values.

    .PARAMETER IncludeManual
        Include Manual controls in output (excluded by default).
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]]$ComputerName = @('.'),

        [Parameter(Mandatory)]
        [string]$BenchmarkPath,

        [Parameter()]
        [string]$OutputPath,

        [Parameter()]
        [string]$HtmlPath,

        [Parameter()]
        [string[]]$Section,

        [Parameter()]
        [switch]$IncludeManual
    )

    # ------------------------------------------------------------------
    # Validate and load benchmark JSON.
    # ------------------------------------------------------------------
    if (-not (Test-Path -LiteralPath $BenchmarkPath)) {
        throw "Benchmark file not found: '$BenchmarkPath'"
    }

    $benchmark = $null
    try {
        $benchmark = Get-Content -LiteralPath $BenchmarkPath -Raw |
            ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Failed to parse benchmark JSON at '$BenchmarkPath': $($_.Exception.Message)"
    }

    # ------------------------------------------------------------------
    # Pre-fetch live data caches (one call each, failures are tolerated).
    # ------------------------------------------------------------------
    $auditMap = $null
    try {
        $rawAudit = Invoke-TCBAuditPol
        $auditMap = Convert-TCBAuditPolCsv -RawCsv $rawAudit
    }
    catch {
        Write-Warning "Could not retrieve audit policy data: $($_.Exception.Message)"
    }

    $netMap = $null
    try {
        $rawNet = Invoke-TCBNetAccount
        $netMap = Convert-TCBNetAccountsText -RawText $rawNet
    }
    catch {
        Write-Warning "Could not retrieve net accounts data: $($_.Exception.Message)"
    }

    # ------------------------------------------------------------------
    # ComputerName: warn and skip non-local targets.
    # ------------------------------------------------------------------
    $localNames = @('.', $env:COMPUTERNAME, 'localhost', '127.0.0.1')
    foreach ($cn in $ComputerName) {
        if ($cn -notin $localNames) {
            Write-Warning "Remote execution not yet implemented for $cn — skipping"
        }
    }

    # ------------------------------------------------------------------
    # Filter controls.
    # ------------------------------------------------------------------
    $controls = $benchmark.controls

    if ($Section -and $Section.Count -gt 0) {
        $controls = $controls | Where-Object { $_.section -in $Section }
    }

    if (-not $IncludeManual) {
        $controls = $controls | Where-Object { $_.type -ne 'Manual' }
    }

    # ------------------------------------------------------------------
    # Evaluate each control.
    # ------------------------------------------------------------------
    $results = [System.Collections.Generic.List[object]]::new()
    $cc = 0; $nc = 0; $mc = 0; $ec = 0; $uc = 0

    foreach ($control in $controls) {
        $detail = $null

        if ($control.type -eq 'Manual') {
            $detail = @{
                Status   = 'Manual'
                Actual   = $null
                Expected = $null
                Reason   = $control.remediation
            }
        }
        else {
            try {
                switch ($control.type) {
                    'RegistryValue'  { $detail = Test-TCBRegistryValue  -Control $control }
                    'AuditPolicy'    { $detail = Test-TCBAuditPolicy    -Control $control -AuditMap $auditMap }
                    'ServiceState'   { $detail = Test-TCBServiceState   -Control $control }
                    'SecurityPolicy' { $detail = Test-TCBSecurityPolicy -Control $control -NetMap $netMap }
                    default {
                        $detail = @{
                            Status   = 'Unknown'
                            Actual   = $null
                            Expected = $null
                            Reason   = "Unknown control type: $($control.type)"
                        }
                    }
                }
            }
            catch {
                $detail = @{
                    Status   = 'Error'
                    Actual   = $null
                    Expected = $null
                    Reason   = $_.Exception.Message
                }
            }
        }

        switch ($detail.Status) {
            'Compliant'    { $cc++ }
            'NonCompliant' { $nc++ }
            'Manual'       { $mc++ }
            'Error'        { $ec++ }
            'Unknown'      { $uc++ }
        }

        $row = [PSCustomObject]@{
            ControlId   = $control.id
            Title       = $control.title
            Section     = $control.section
            Type        = $control.type
            Status      = $detail.Status
            Expected    = $detail.Expected
            Actual      = $detail.Actual
            Reason      = $detail.Reason
            Remediation = $control.remediation
        }

        $results.Add($row)
    }

    # ------------------------------------------------------------------
    # Append SUMMARY row.
    # ------------------------------------------------------------------
    $summary = [PSCustomObject]@{
        ControlId   = 'SUMMARY'
        Title       = 'Summary'
        Section     = ''
        Type        = ''
        Status      = ''
        Expected    = $null
        Actual      = $null
        Reason      = "Compliant=$cc;NonCompliant=$nc;Manual=$mc;Error=$ec;Unknown=$uc"
        Remediation = ''
    }
    $results.Add($summary)

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

    # ------------------------------------------------------------------
    # Optional HTML report via Write-ComplianceReport.
    # ------------------------------------------------------------------
    if ($HtmlPath) {
        $moduleBase = Join-Path $PSScriptRoot '..' '..' '_SHARED' 'PowerShell' 'Compliance.Common'
        $moduleFile = Join-Path $moduleBase 'Compliance.Common.psm1'
        if (Test-Path -LiteralPath $moduleFile) {
            Import-Module $moduleFile -Force -ErrorAction SilentlyContinue
        }
        $results | Write-ComplianceReport -OutFile $HtmlPath -Title 'CIS Benchmark Audit'
    }
}
