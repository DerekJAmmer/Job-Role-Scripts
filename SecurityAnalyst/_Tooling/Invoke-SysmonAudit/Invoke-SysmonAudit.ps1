#requires -Version 7.2

<#
    Invoke-SysmonAudit.ps1
    Read-only audit of Sysmon health on the local host. Five checks:
      - Sysmon service installed
      - Sysmon service running
      - Sysmon driver (SysmonDrv) loaded and running
      - Sysmon binary signed by Sysinternals / Microsoft
      - Sysmon configuration matches a known-good baseline (optional)

    No state changes. Safe to run anywhere.
#>

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Service locator
# ---------------------------------------------------------------------------

function Get-SADSysmonService {
    <#
    .SYNOPSIS
        Returns the first Sysmon service object found on the local host, or $null.
    .DESCRIPTION
        Tries the canonical 64-bit name first, then the 32-bit name. Returns $null
        when neither exists so callers can distinguish "not installed" from errors.
    .OUTPUTS
        System.ServiceProcess.ServiceController or $null
    #>
    [OutputType([System.ServiceProcess.ServiceController])]
    param()

    $svc = Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue |
           Select-Object -First 1
    return $svc
}

# ---------------------------------------------------------------------------
# Check helpers — each returns [pscustomobject]@{ Check; Status; Detail; Remediation }
# ---------------------------------------------------------------------------

function Test-SADSysmonInstalled {
    <#
    .SYNOPSIS
        Check: is Sysmon installed (i.e. the service registered)?
    .OUTPUTS
        PSCustomObject with Check, Status, Detail, Remediation properties.
    #>
    [OutputType([pscustomobject])]
    param(
        [AllowNull()]
        [object]$Service
    )

    if ($null -eq $Service) {
        return [pscustomobject]@{
            Check       = 'Sysmon Installed'
            Status      = 'Fail'
            Detail      = 'No Sysmon service found (tried Sysmon64, Sysmon).'
            Remediation = 'Install Sysmon from https://learn.microsoft.com/sysinternals/downloads/sysmon and run: sysmon64 -accepteula -i <config.xml>'
        }
    }

    return [pscustomobject]@{
        Check       = 'Sysmon Installed'
        Status      = 'Pass'
        Detail      = "Service '$($Service.Name)' is registered."
        Remediation = ''
    }
}

function Test-SADSysmonRunning {
    <#
    .SYNOPSIS
        Check: is the Sysmon service in the Running state?
    .OUTPUTS
        PSCustomObject with Check, Status, Detail, Remediation properties.
    #>
    [OutputType([pscustomobject])]
    param(
        [AllowNull()]
        [object]$Service
    )

    if ($null -eq $Service) {
        return [pscustomobject]@{
            Check       = 'Sysmon Running'
            Status      = 'Fail'
            Detail      = 'Sysmon service not found; cannot determine running state.'
            Remediation = 'Install Sysmon first, then start the service.'
        }
    }

    if ($Service.Status -eq 'Running') {
        return [pscustomobject]@{
            Check       = 'Sysmon Running'
            Status      = 'Pass'
            Detail      = "Service '$($Service.Name)' status: $($Service.Status)."
            Remediation = ''
        }
    }

    return [pscustomobject]@{
        Check       = 'Sysmon Running'
        Status      = 'Fail'
        Detail      = "Service '$($Service.Name)' status: $($Service.Status)."
        Remediation = "Start the service: Start-Service -Name '$($Service.Name)'"
    }
}

function Test-SADSysmonDriver {
    <#
    .SYNOPSIS
        Check: is the SysmonDrv kernel driver loaded and running?
    .OUTPUTS
        PSCustomObject with Check, Status, Detail, Remediation properties.
    #>
    [OutputType([pscustomobject])]
    param()

    $driver = Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name='SysmonDrv'" -ErrorAction SilentlyContinue

    if ($null -eq $driver) {
        return [pscustomobject]@{
            Check       = 'SysmonDrv Loaded'
            Status      = 'Fail'
            Detail      = 'Win32_SystemDriver query returned no SysmonDrv entry.'
            Remediation = 'Reinstall Sysmon; the driver may have been removed manually.'
        }
    }

    if ($driver.State -eq 'Running') {
        return [pscustomobject]@{
            Check       = 'SysmonDrv Loaded'
            Status      = 'Pass'
            Detail      = "SysmonDrv driver state: $($driver.State)."
            Remediation = ''
        }
    }

    return [pscustomobject]@{
        Check       = 'SysmonDrv Loaded'
        Status      = 'Fail'
        Detail      = "SysmonDrv driver found but state is '$($driver.State)'."
        Remediation = 'Start the Sysmon service to reload the driver, or reboot if the driver is in a bad state.'
    }
}

function Test-SADSysmonSignature {
    <#
    .SYNOPSIS
        Check: is the Sysmon binary signed by Sysinternals or Microsoft?
    .OUTPUTS
        PSCustomObject with Check, Status, Detail, Remediation properties.
    #>
    [OutputType([pscustomobject])]
    param(
        [AllowNull()]
        [object]$Service
    )

    if ($null -eq $Service) {
        return [pscustomobject]@{
            Check       = 'Sysmon Binary Signed'
            Status      = 'Skipped'
            Detail      = 'Sysmon service not found; cannot locate binary to check signature.'
            Remediation = 'Install Sysmon from the official Sysinternals source.'
        }
    }

    # The service BinaryPathName may include quoted path and arguments
    $rawPath = $Service.BinaryPathName
    if ([string]::IsNullOrWhiteSpace($rawPath)) {
        return [pscustomobject]@{
            Check       = 'Sysmon Binary Signed'
            Status      = 'Fail'
            Detail      = 'Could not determine Sysmon binary path from service registration.'
            Remediation = 'Verify service registration in SCM.'
        }
    }

    # Strip leading quote if present and take up to the next quote or first space
    $binaryPath = if ($rawPath.StartsWith('"')) {
        ($rawPath -replace '^"([^"]+)".*', '$1')
    } else {
        ($rawPath -split '\s+')[0]
    }

    if (-not (Test-Path -LiteralPath $binaryPath)) {
        return [pscustomobject]@{
            Check       = 'Sysmon Binary Signed'
            Status      = 'Fail'
            Detail      = "Binary not found at resolved path: $binaryPath"
            Remediation = 'Reinstall Sysmon; the binary may have been deleted while the service persists.'
        }
    }

    $sig = Get-AuthenticodeSignature -FilePath $binaryPath

    if ($sig.Status -ne 'Valid') {
        return [pscustomobject]@{
            Check       = 'Sysmon Binary Signed'
            Status      = 'Fail'
            Detail      = "Signature status: $($sig.Status). Path: $binaryPath"
            Remediation = 'Replace the binary with the official signed version from https://learn.microsoft.com/sysinternals/downloads/sysmon'
        }
    }

    $subject = $sig.SignerCertificate.Subject
    if ($subject -match 'Sysinternals|Microsoft') {
        return [pscustomobject]@{
            Check       = 'Sysmon Binary Signed'
            Status      = 'Pass'
            Detail      = "Valid signature. Signer: $subject"
            Remediation = ''
        }
    }

    return [pscustomobject]@{
        Check       = 'Sysmon Binary Signed'
        Status      = 'Fail'
        Detail      = "Signature is valid but signer is unexpected: $subject"
        Remediation = 'Replace with the official Sysinternals binary. An unexpected signer may indicate a trojanised binary.'
    }
}

function Test-SADSysmonConfig {
    <#
    .SYNOPSIS
        Check: does the active Sysmon config match the expected SHA256 hash?
    .DESCRIPTION
        Reads the config file path from the SysmonDrv registry key. If no expected
        hash is provided (directly or via a baseline file), the check is Skipped.
    .OUTPUTS
        PSCustomObject with Check, Status, Detail, Remediation properties.
    #>
    [OutputType([pscustomobject])]
    param(
        [AllowNull()]
        [object]$Service,

        [string]$BaselineConfigPath = '',

        [string]$ExpectedConfigHash = ''
    )

    # Resolve expected hash — either supplied directly or derived from a baseline file
    $resolvedHash = $ExpectedConfigHash

    if ([string]::IsNullOrWhiteSpace($resolvedHash) -and -not [string]::IsNullOrWhiteSpace($BaselineConfigPath)) {
        if (-not (Test-Path -LiteralPath $BaselineConfigPath)) {
            return [pscustomobject]@{
                Check       = 'Config Hash Match'
                Status      = 'Fail'
                Detail      = "Baseline config file not found: $BaselineConfigPath"
                Remediation = 'Provide a valid path to the known-good config XML.'
            }
        }
        $resolvedHash = (Get-FileHash -LiteralPath $BaselineConfigPath -Algorithm SHA256).Hash
    }

    if ([string]::IsNullOrWhiteSpace($resolvedHash)) {
        return [pscustomobject]@{
            Check       = 'Config Hash Match'
            Status      = 'Skipped'
            Detail      = 'No baseline provided. Pass -BaselineConfigPath or -ExpectedConfigHash to enable this check.'
            Remediation = 'Capture a known-good config: sysmon64 -c | Out-File known-good.xml, then pass it via -BaselineConfigPath.'
        }
    }

    # Locate the active config via registry
    $regPath   = 'HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters'
    $configFile = $null

    if (Test-Path -LiteralPath $regPath) {
        try {
            $configFile = (Get-ItemProperty -LiteralPath $regPath -Name 'ConfigFile' -ErrorAction SilentlyContinue).ConfigFile
        } catch {
            $configFile = $null
        }
    }

    if ([string]::IsNullOrWhiteSpace($configFile)) {
        return [pscustomobject]@{
            Check       = 'Config Hash Match'
            Status      = 'Skipped'
            Detail      = 'Active config path not exposed via registry (SysmonDrv\Parameters\ConfigFile absent).'
            Remediation = 'Ensure SysmonDrv registry parameters are intact, or supply the config path manually via -BaselineConfigPath.'
        }
    }

    if (-not (Test-Path -LiteralPath $configFile)) {
        return [pscustomobject]@{
            Check       = 'Config Hash Match'
            Status      = 'Fail'
            Detail      = "Registry points to config '$configFile' but file does not exist."
            Remediation = 'Restore the config file and reload: sysmon64 -c <config.xml>'
        }
    }

    $activeHash = (Get-FileHash -LiteralPath $configFile -Algorithm SHA256).Hash

    if ($activeHash -eq $resolvedHash.ToUpperInvariant()) {
        return [pscustomobject]@{
            Check       = 'Config Hash Match'
            Status      = 'Pass'
            Detail      = "SHA256 match. Active config: $configFile (hash: $activeHash)"
            Remediation = ''
        }
    }

    return [pscustomobject]@{
        Check       = 'Config Hash Match'
        Status      = 'Fail'
        Detail      = "Hash mismatch. Expected: $($resolvedHash.ToUpperInvariant())  Actual: $activeHash  Config: $configFile"
        Remediation = 'Reload the known-good config: sysmon64 -c <known-good.xml>'
    }
}

# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Audits Sysmon health on the local host across five read-only checks.

.DESCRIPTION
    Invoke-SysmonAudit verifies that Sysmon is installed, its service is
    running, the kernel driver is loaded, the binary carries a valid
    Sysinternals/Microsoft signature, and (optionally) the active config
    matches a known-good baseline hash.

    The script makes no state changes and requires no -WhatIf parameter.

.PARAMETER BaselineConfigPath
    Path to a known-good Sysmon config XML. Its SHA256 is computed and
    compared against the active config. Mutually usable with -ExpectedConfigHash;
    if both are given, -ExpectedConfigHash takes precedence.

.PARAMETER ExpectedConfigHash
    SHA256 string to compare directly against the active config hash.

.PARAMETER OutputPath
    If supplied, writes a JSON report to this path.

.PARAMETER Quiet
    Suppresses the console summary table.

.OUTPUTS
    PSCustomObject with HostName, RunTime, PassCount, FailCount, SkipCount,
    OutputPath, and Results (array of per-check objects).

.EXAMPLE
    Invoke-SysmonAudit

.EXAMPLE
    Invoke-SysmonAudit -BaselineConfigPath C:\Configs\sysmon-baseline.xml

.EXAMPLE
    Invoke-SysmonAudit -ExpectedConfigHash 'A1B2C3...' -OutputPath C:\Reports\sysmon.json -Quiet
#>
function Invoke-SysmonAudit {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcess', '',
        Justification = 'Read-only audit; no state changes are made.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$BaselineConfigPath  = '',
        [string]$ExpectedConfigHash  = '',
        [string]$OutputPath          = '',
        [switch]$Quiet
    )

    $started = Get-Date
    $service  = Get-SADSysmonService

    $results = [System.Collections.Generic.List[object]]::new()
    $results.Add((Test-SADSysmonInstalled  -Service $service))
    $results.Add((Test-SADSysmonRunning    -Service $service))
    $results.Add((Test-SADSysmonDriver))
    $results.Add((Test-SADSysmonSignature  -Service $service))
    $results.Add((Test-SADSysmonConfig     -Service $service `
                                            -BaselineConfigPath $BaselineConfigPath `
                                            -ExpectedConfigHash $ExpectedConfigHash))

    $passCount = @($results | Where-Object Status -EQ 'Pass').Count
    $failCount = @($results | Where-Object Status -EQ 'Fail').Count
    $skipCount = @($results | Where-Object Status -EQ 'Skipped').Count

    if (-not $Quiet) {
        $results | Format-Table -AutoSize Check, Status, Detail | Out-String |
            Write-Information -InformationAction Continue
    }

    if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
        $report = [pscustomobject]@{
            HostName    = $env:COMPUTERNAME
            GeneratedAt = (Get-Date -Format 'o')
            Results     = @($results)
            PassCount   = $passCount
            FailCount   = $failCount
            SkipCount   = $skipCount
        }
        $report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    }

    [pscustomobject]@{
        HostName   = $env:COMPUTERNAME
        RunTime    = (Get-Date) - $started
        PassCount  = $passCount
        FailCount  = $failCount
        SkipCount  = $skipCount
        OutputPath = if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
            (Resolve-Path -LiteralPath $OutputPath).Path
        } else {
            $null
        }
        Results    = @($results)
    }
}
