#requires -Version 7.2
<#
.SYNOPSIS
    Audit local Windows settings against a subset of DISA STIG Windows 11 controls.

.DESCRIPTION
    Test-STIGCompliance loads a JSON STIG file containing a subset of DISA STIG Windows 11
    controls and evaluates each one locally. It dispatches each control by type
    (RegistryValue, AuditPolicy, ServiceState, SecurityPolicy, BitLockerStatus, Manual) and
    emits one row per control with a Status of NotAFinding, Open, NotApplicable, Manual, or
    Error, plus Expected and Actual values so you can see exactly where drift occurred.

    Controls may declare an optional applicabilityCheck (RegistryValue type only). If the
    check does not match, the control is emitted with Status=NotApplicable and the main test
    is skipped.

    A -FailOnSeverity parameter (comma-separated CAT values) drives a WouldFailGate flag in
    the SUMMARY row Reason field. The script itself does NOT exit 1 to support unattended use.

    This script is read-only — it never calls Set-* or modifies any system setting.

    An optional HTML report is written via Write-ComplianceReport when -HtmlPath is supplied.

.PARAMETER ComputerName
    Target computer(s). Currently only the local machine ('.') is supported; passing any
    other value emits a warning and skips that target. Default: @('.').

.PARAMETER STIGPath
    Path to the JSON STIG file. Mandatory. See samples/stig-win11-subset.json for shape.

.PARAMETER OutputPath
    When supplied, all result rows are exported as a UTF-8 CSV.

.PARAMETER HtmlPath
    When supplied, an HTML report is written via Write-ComplianceReport.

.PARAMETER Severity
    When supplied, only controls whose severity property matches one of these values are run.

.PARAMETER IncludeManual
    By default, Manual controls are excluded. Use this switch to include them in output.

.PARAMETER FailOnSeverity
    Comma-separated severity categories (e.g. 'CAT I,II'). After all checks complete, if any
    Open result matches one of these severities the SUMMARY row includes WouldFailGate=true.
    The script never calls exit 1 — the gate is informational.

.EXAMPLE
    Test-STIGCompliance -STIGPath .\samples\stig-win11-subset.json

.EXAMPLE
    Test-STIGCompliance -STIGPath .\samples\stig-win11-subset.json -Severity 'CAT I' -OutputPath .\stig-report.csv

.EXAMPLE
    Test-STIGCompliance -STIGPath .\samples\stig-win11-subset.json -IncludeManual -FailOnSeverity 'CAT I,CAT II'
#>

# ---------------------------------------------------------------------------
# Private wrapper: Invoke-TSCAuditPol
# Runs auditpol.exe and returns raw CSV output as a single string.
# Tests mock this helper rather than auditpol.exe directly.
# ---------------------------------------------------------------------------
function Invoke-TSCAuditPol {
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
# Private wrapper: Get-TSCRegValue
# Reads a registry value; returns $null if the key or value is missing.
# Never throws — callers treat $null as Open.
# ---------------------------------------------------------------------------
function Get-TSCRegValue {
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
# Private wrapper: Get-TSCService
# Wraps Get-Service; returns a lightweight PSCustomObject or $null if not found.
# ---------------------------------------------------------------------------
function Get-TSCService {
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
# Private wrapper: Invoke-TSCNetAccount
# Runs 'net accounts' and returns output as a single string.
# Throws on non-zero exit so the caller can surface Status=Error.
# ---------------------------------------------------------------------------
function Invoke-TSCNetAccount {
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
# Private wrapper: Invoke-TSCManageBde
# Runs 'manage-bde -status <MountPoint>' and returns raw output as a string.
# Throws on failure so the caller can surface Status=Error.
# ---------------------------------------------------------------------------
function Invoke-TSCManageBde {
    <#
    .SYNOPSIS
        Run 'manage-bde -status <MountPoint>' and return raw output as a string.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$MountPoint
    )

    $output = & manage-bde -status $MountPoint 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "manage-bde failed (exit $LASTEXITCODE): $output"
    }
    return ($output -join "`n")
}

# ---------------------------------------------------------------------------
# Private parser: Convert-TSCAuditPolCsv
# Parses raw auditpol /r CSV into a hashtable keyed by subcategory name.
# ---------------------------------------------------------------------------
function Convert-TSCAuditPolCsv {
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
# Private parser: Convert-TSCNetAccountsText
# Parses 'net accounts' key: value lines into a hashtable.
# ---------------------------------------------------------------------------
function Convert-TSCNetAccountsText {
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
# Private helper: Test-TSCApplicabilityCheck
# Evaluates the optional applicabilityCheck on a control.
# Returns $true if applicable (or no check defined), $false if not applicable.
# ---------------------------------------------------------------------------
function Test-TSCApplicabilityCheck {
    [CmdletBinding()]
    [OutputType([bool])]
    param([object]$Control)

    $check = $Control.applicabilityCheck
    if ($null -eq $check) { return $true }

    if ($check.type -eq 'RegistryValue') {
        $actual = Get-TSCRegValue -Path $check.Path -Name $check.Name
        if ($null -eq $actual) { return $false }

        # Numeric compare when both sides parse as int; else string.
        $intExp = 0; $intAct = 0
        if ([int]::TryParse([string]$check.Value, [ref]$intExp) -and
            [int]::TryParse([string]$actual,       [ref]$intAct)) {
            return ($intAct -eq $intExp)
        }
        return ([string]$actual -ieq [string]$check.Value)
    }

    # Unknown applicability check type — treat as applicable to avoid suppressing controls.
    return $true
}

# ---------------------------------------------------------------------------
# Private dispatcher: Test-TSCRegistryValue
# ---------------------------------------------------------------------------
function Test-TSCRegistryValue {
    [CmdletBinding()]
    param([object]$Control)

    $exp      = $Control.expected
    $actual   = Get-TSCRegValue -Path $exp.Path -Name $exp.Name
    $expected = $exp.Value

    if ($null -eq $actual) {
        return @{
            Status   = 'Open'
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
        return @{ Status = 'NotAFinding'; Actual = $actual; Expected = $expected; Reason = '' }
    }
    else {
        return @{ Status = 'Open'; Actual = $actual; Expected = $expected; Reason = "Expected '$expected'; got '$actual'" }
    }
}

# ---------------------------------------------------------------------------
# Private dispatcher: Test-TSCAuditPolicy
# Requires a pre-parsed audit hashtable passed in via -AuditMap.
# ---------------------------------------------------------------------------
function Test-TSCAuditPolicy {
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
        return @{ Status = 'NotAFinding'; Actual = $actual; Expected = $expected; Reason = '' }
    }
    else {
        return @{ Status = 'Open'; Actual = $actual; Expected = $expected; Reason = "Expected '$expected'; got '$actual'" }
    }
}

# ---------------------------------------------------------------------------
# Private dispatcher: Test-TSCServiceState
# Supports NotPresent expectation: when expected.NotPresent = true, NotAFinding
# means the service does NOT exist; Open means it does exist.
# ---------------------------------------------------------------------------
function Test-TSCServiceState {
    [CmdletBinding()]
    param([object]$Control)

    $exp = $Control.expected
    $svc = Get-TSCService -Name $exp.Name

    # "NotPresent" expectation: the service should not exist.
    if ($exp.PSObject.Properties.Name -contains 'NotPresent' -and $exp.NotPresent -eq $true) {
        if ($null -eq $svc) {
            return @{ Status = 'NotAFinding'; Actual = 'NotPresent'; Expected = 'NotPresent'; Reason = '' }
        }
        else {
            return @{
                Status   = 'Open'
                Actual   = $svc.StartType
                Expected = 'NotPresent'
                Reason   = "Service '$($exp.Name)' exists but should not be installed"
            }
        }
    }

    # Standard StartType expectation.
    if ($null -eq $svc) {
        return @{
            Status   = 'Open'
            Actual   = $null
            Expected = $exp.StartType
            Reason   = 'Service not found'
        }
    }

    if ($svc.StartType -ieq $exp.StartType) {
        return @{ Status = 'NotAFinding'; Actual = $svc.StartType; Expected = $exp.StartType; Reason = '' }
    }
    else {
        return @{
            Status   = 'Open'
            Actual   = $svc.StartType
            Expected = $exp.StartType
            Reason   = "Expected StartType '$($exp.StartType)'; got '$($svc.StartType)'"
        }
    }
}

# ---------------------------------------------------------------------------
# Private dispatcher: Test-TSCSecurityPolicy
# Requires a pre-parsed net-accounts hashtable passed in via -NetMap.
# For STIG lockout threshold the requirement is <= N, not exact match.
# The expected shape may include a Operator field ('LessThanOrEqual' | 'Equal').
# When Operator is absent, defaults to 'Equal'.
# ---------------------------------------------------------------------------
function Test-TSCSecurityPolicy {
    [CmdletBinding()]
    param(
        [object]   $Control,
        [hashtable]$NetMap
    )

    $exp      = $Control.expected
    $setting  = $exp.Setting
    $expected = $exp.Value
    $operator = if ($exp.PSObject.Properties.Name -contains 'Operator') { $exp.Operator } else { 'Equal' }

    if ($null -eq $NetMap -or -not $NetMap.ContainsKey($setting)) {
        return @{
            Status   = 'Error'
            Actual   = $null
            Expected = $expected
            Reason   = "Setting '$setting' not found in net accounts output"
        }
    }

    $actual = $NetMap[$setting]

    $intExp = 0; $intAct = 0
    $bothInt = [int]::TryParse($expected, [ref]$intExp) -and [int]::TryParse($actual, [ref]$intAct)

    $match = switch ($operator) {
        'LessThanOrEqual' {
            if ($bothInt) { $intAct -le $intExp } else { $false }
        }
        default {
            if ($bothInt) { $intAct -eq $intExp } else { $actual -ieq $expected }
        }
    }

    if ($match) {
        return @{ Status = 'NotAFinding'; Actual = $actual; Expected = $expected; Reason = '' }
    }
    else {
        return @{ Status = 'Open'; Actual = $actual; Expected = $expected; Reason = "Expected '$expected' (operator: $operator); got '$actual'" }
    }
}

# ---------------------------------------------------------------------------
# Private dispatcher: Test-TSCBitLockerStatus
# Calls Invoke-TSCManageBde and checks for required encryption strings.
# ---------------------------------------------------------------------------
function Test-TSCBitLockerStatus {
    [CmdletBinding()]
    param([object]$Control)

    $exp        = $Control.expected
    $mountPoint = $exp.MountPoint

    $raw = $null
    try {
        $raw = Invoke-TSCManageBde -MountPoint $mountPoint
    }
    catch {
        return @{
            Status   = 'Error'
            Actual   = $null
            Expected = 'Fully Encrypted; Protection On'
            Reason   = "manage-bde failed: $($_.Exception.Message)"
        }
    }

    $fullyEncrypted  = $raw -match 'Conversion Status:\s+Fully Encrypted'
    $protectionOn    = $raw -match 'Protection Status:\s+Protection On'

    $actualStr = "FullyEncrypted=$fullyEncrypted;ProtectionOn=$protectionOn"

    if ($fullyEncrypted -and $protectionOn) {
        return @{ Status = 'NotAFinding'; Actual = $actualStr; Expected = 'Fully Encrypted; Protection On'; Reason = '' }
    }
    else {
        return @{
            Status   = 'Open'
            Actual   = $actualStr
            Expected = 'Fully Encrypted; Protection On'
            Reason   = "BitLocker not fully enabled on $mountPoint (FullyEncrypted=$fullyEncrypted, ProtectionOn=$protectionOn)"
        }
    }
}

# ---------------------------------------------------------------------------
# Public function: Test-STIGCompliance
# ---------------------------------------------------------------------------
function Test-STIGCompliance {
    <#
    .SYNOPSIS
        Audit Windows settings against a DISA STIG JSON subset file.

    .DESCRIPTION
        Loads a JSON STIG file and evaluates each control locally. Emits one row per
        control with Status NotAFinding / Open / NotApplicable / Manual / Error plus
        Expected and Actual delta values and a SUMMARY row at the end.

        Controls with an applicabilityCheck are skipped (NotApplicable) when the check
        does not match the live system (e.g. domain-only controls on a standalone machine).

        Read-only — never calls Set-* or changes any system configuration.

    .PARAMETER ComputerName
        Target(s). Only '.' (local) is currently supported; others emit a warning.

    .PARAMETER STIGPath
        Mandatory path to the JSON STIG file.

    .PARAMETER OutputPath
        When supplied, export all rows as a UTF-8 CSV.

    .PARAMETER HtmlPath
        When supplied, write an HTML report via Write-ComplianceReport.

    .PARAMETER Severity
        Filter controls to only those whose severity matches one of these values.

    .PARAMETER IncludeManual
        Include Manual controls in output (excluded by default).

    .PARAMETER FailOnSeverity
        Comma-separated severities (e.g. 'CAT I,CAT II'). If any Open result matches,
        the SUMMARY row Reason includes WouldFailGate=true. The script does not exit 1.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]]$ComputerName = @('.'),

        [Parameter(Mandatory)]
        [string]$STIGPath,

        [Parameter()]
        [string]$OutputPath,

        [Parameter()]
        [string]$HtmlPath,

        [Parameter()]
        [string[]]$Severity,

        [Parameter()]
        [switch]$IncludeManual,

        [Parameter()]
        [string]$FailOnSeverity = 'CAT I,CAT II'
    )

    # ------------------------------------------------------------------
    # Validate and load STIG JSON.
    # ------------------------------------------------------------------
    if (-not (Test-Path -LiteralPath $STIGPath)) {
        throw "STIG file not found: '$STIGPath'"
    }

    $stig = $null
    try {
        $stig = Get-Content -LiteralPath $STIGPath -Raw |
            ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Failed to parse STIG JSON at '$STIGPath': $($_.Exception.Message)"
    }

    # ------------------------------------------------------------------
    # Pre-fetch live data caches (one call each, failures are tolerated).
    # ------------------------------------------------------------------
    $auditMap = $null
    try {
        $rawAudit = Invoke-TSCAuditPol
        $auditMap = Convert-TSCAuditPolCsv -RawCsv $rawAudit
    }
    catch {
        Write-Warning "Could not retrieve audit policy data: $($_.Exception.Message)"
    }

    $netMap = $null
    try {
        $rawNet = Invoke-TSCNetAccount
        $netMap = Convert-TSCNetAccountsText -RawText $rawNet
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
    # Build FailOnSeverity set (normalise to 'CAT I', 'CAT II', 'CAT III').
    # ------------------------------------------------------------------
    $failSeverities = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($token in ($FailOnSeverity -split ',')) {
        $t = $token.Trim()
        if ($t) {
            # Accept both 'CAT I' and 'I' forms.
            if ($t -notmatch '^CAT ') { $t = "CAT $t" }
            $null = $failSeverities.Add($t)
        }
    }

    # ------------------------------------------------------------------
    # Filter controls.
    # ------------------------------------------------------------------
    $controls = $stig.controls

    if ($Severity -and $Severity.Count -gt 0) {
        $controls = $controls | Where-Object { $_.severity -in $Severity }
    }

    if (-not $IncludeManual) {
        $controls = $controls | Where-Object { $_.type -ne 'Manual' }
    }

    # ------------------------------------------------------------------
    # Evaluate each control.
    # ------------------------------------------------------------------
    $results = [System.Collections.Generic.List[object]]::new()
    $nf = 0; $op = 0; $na = 0; $mc = 0; $ec = 0

    foreach ($control in $controls) {
        $detail = $null

        if ($control.type -eq 'Manual') {
            $detail = @{
                Status   = 'Manual'
                Actual   = $null
                Expected = $null
                Reason   = $control.fix
            }
        }
        else {
            # ----------------------------------------------------------
            # Applicability check (skip main test if not applicable).
            # ----------------------------------------------------------
            $applicable = $true
            try {
                $applicable = Test-TSCApplicabilityCheck -Control $control
            }
            catch {
                Write-Warning "Applicability check failed for $($control.vulnId): $($_.Exception.Message)"
            }

            if (-not $applicable) {
                $detail = @{
                    Status   = 'NotApplicable'
                    Actual   = $null
                    Expected = $null
                    Reason   = 'Applicability check did not match'
                }
            }
            else {
                try {
                    switch ($control.type) {
                        'RegistryValue'   { $detail = Test-TSCRegistryValue  -Control $control }
                        'AuditPolicy'     { $detail = Test-TSCAuditPolicy    -Control $control -AuditMap $auditMap }
                        'ServiceState'    { $detail = Test-TSCServiceState   -Control $control }
                        'SecurityPolicy'  { $detail = Test-TSCSecurityPolicy -Control $control -NetMap $netMap }
                        'BitLockerStatus' { $detail = Test-TSCBitLockerStatus -Control $control }
                        default {
                            $detail = @{
                                Status   = 'Error'
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
        }

        switch ($detail.Status) {
            'NotAFinding'   { $nf++ }
            'Open'          { $op++ }
            'NotApplicable' { $na++ }
            'Manual'        { $mc++ }
            'Error'         { $ec++ }
        }

        $row = [PSCustomObject]@{
            VulnId   = $control.vulnId
            Title    = $control.title
            Severity = $control.severity
            Type     = $control.type
            Status   = $detail.Status
            Expected = $detail.Expected
            Actual   = $detail.Actual
            Reason   = $detail.Reason
            Fix      = $control.fix
        }

        $results.Add($row)
    }

    # ------------------------------------------------------------------
    # Determine WouldFailGate.
    # ------------------------------------------------------------------
    $gate = $false
    if ($failSeverities.Count -gt 0) {
        foreach ($r in $results) {
            if ($r.Status -eq 'Open' -and $failSeverities.Contains($r.Severity)) {
                $gate = $true
                break
            }
        }
    }

    # ------------------------------------------------------------------
    # Append SUMMARY row.
    # ------------------------------------------------------------------
    $summary = [PSCustomObject]@{
        VulnId   = 'SUMMARY'
        Title    = 'Summary'
        Severity = ''
        Type     = ''
        Status   = ''
        Expected = $null
        Actual   = $null
        Fix      = $null
        Reason   = "NotAFinding=$nf;Open=$op;NotApplicable=$na;Manual=$mc;Error=$ec;WouldFailGate=$gate"
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
        $results | Write-ComplianceReport -OutFile $HtmlPath -Title 'DISA STIG Audit'
    }
}
