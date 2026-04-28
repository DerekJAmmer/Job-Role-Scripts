#requires -Version 7.2
<#
.SYNOPSIS
    Report per-volume BitLocker posture: protection status, encryption method, key protectors,
    TPM state, and Secure Boot state.

.DESCRIPTION
    Get-BitLockerStatus collects BitLocker volume information, TPM presence/readiness, and Secure
    Boot state for one or more computers and emits one row per fixed volume (OperatingSystem and
    Data volumes; Removable and Network volumes are excluded).

    Each row is classified as:
      Compliant    — ProtectionStatus=On, EncryptionPercentage=100, TpmPresent, TpmReady,
                     SecureBootEnabled=$true.
      NonCompliant — one or more of the above conditions is not met.
      Unknown      — Get-BitLockerVolume is not available on the target (module absent or cmdlet
                     missing); one placeholder row per host is returned.

    TPM and Secure Boot helpers degrade gracefully:
      - Get-Tpm unavailable → TpmPresent/TpmReady reported as $null.
      - Confirm-SecureBootUEFI throws (non-UEFI) → SecureBootEnabled reported as $null.

    Remote hosts are queried via Invoke-Command (PSRemoting). The shared Test-IsLocalHost helper
    is preferred for FQDN-aware local detection; a private fallback handles '.',  'localhost',
    $env:COMPUTERNAME, and '<hostname>.<dnsdomain>' forms.

    This script is read-only — it never calls Enable-BitLocker, Initialize-Tpm, or any
    state-changing cmdlet.

.PARAMETER ComputerName
    One or more host names to evaluate. Defaults to the local machine ('.').
    Use '.' or 'localhost' for an explicit local run. FQDNs whose first label matches the local
    machine name are treated as local (e.g. 'WK01.corp.local' when running on WK01).

.PARAMETER OutputPath
    When supplied, all result rows are exported as a CSV file (UTF-8, no type information).

.OUTPUTS
    PSCustomObject with properties:
      ComputerName          — target host
      MountPoint            — drive letter / volume path (empty for Unknown rows)
      ProtectionStatus      — On | Off | $null
      EncryptionPercentage  — 0-100 integer or $null
      EncryptionMethod      — algorithm string or $null
      VolumeStatus          — FullyEncrypted / EncryptionInProgress / etc. or $null
      KeyProtectorTypes     — semicolon-joined protector types (e.g. 'Tpm;RecoveryPassword')
      TpmPresent            — $true/$false/$null
      TpmReady              — $true/$false/$null
      SecureBootEnabled     — $true/$false/$null
      Status                — Compliant | NonCompliant | Unknown
      Reasons               — semicolon-joined failure reasons or empty string

.EXAMPLE
    Get-BitLockerStatus
    # Evaluate the local machine.

.EXAMPLE
    Get-BitLockerStatus -ComputerName DC01, WK02 -OutputPath .\bitlocker-report.csv
    # Evaluate two remote hosts and export results to CSV.
#>

# ---------------------------------------------------------------------------
# Private helper: Get-GBLSBitLockerVolume
# Wraps Get-BitLockerVolume. Returns $null if cmdlet is missing or throws.
# Tests mock this helper.
# ---------------------------------------------------------------------------
function Get-GBLSBitLockerVolume {
    <#
    .SYNOPSIS
        Wrap Get-BitLockerVolume; return $null if the cmdlet is unavailable or fails.
    #>
    [CmdletBinding()]
    param()

    try {
        if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
            return $null
        }
        return @(Get-BitLockerVolume -ErrorAction Stop)
    }
    catch {
        Write-Verbose "Get-GBLSBitLockerVolume: $($_.Exception.Message)"
        return $null
    }
}

# ---------------------------------------------------------------------------
# Private helper: Get-GBLSTpm
# Wraps Get-Tpm. Returns $null if cmdlet is missing or throws.
# ---------------------------------------------------------------------------
function Get-GBLSTpm {
    <#
    .SYNOPSIS
        Wrap Get-Tpm; return $null if the cmdlet is unavailable or fails.
    #>
    [CmdletBinding()]
    param()

    try {
        if (-not (Get-Command Get-Tpm -ErrorAction SilentlyContinue)) {
            return $null
        }
        return (Get-Tpm -ErrorAction Stop)
    }
    catch {
        Write-Verbose "Get-GBLSTpm: $($_.Exception.Message)"
        return $null
    }
}

# ---------------------------------------------------------------------------
# Private helper: Get-GBLSSecureBoot
# Wraps Confirm-SecureBootUEFI. Returns $null on non-UEFI or any error.
# ---------------------------------------------------------------------------
function Get-GBLSSecureBoot {
    <#
    .SYNOPSIS
        Wrap Confirm-SecureBootUEFI; return $null if unsupported or failing.
    #>
    [CmdletBinding()]
    param()

    try {
        return (Confirm-SecureBootUEFI -ErrorAction Stop)
    }
    catch {
        Write-Verbose "Get-GBLSSecureBoot: $($_.Exception.Message)"
        return $null
    }
}

# ---------------------------------------------------------------------------
# Private helper: Test-GBLSIsLocalHost
# FQDN-aware local-host detection (private fallback).
# Prefers shared Test-IsLocalHost when available.
# ---------------------------------------------------------------------------
function Test-GBLSIsLocalHost {
    <#
    .SYNOPSIS
        Return $true if the supplied name refers to the local machine.
    #>
    param(
        [string]$Name
    )

    if (Get-Command Test-IsLocalHost -ErrorAction SilentlyContinue) {
        return (Test-IsLocalHost -Name $Name)
    }

    # Private fallback.
    if ([string]::IsNullOrWhiteSpace($Name)) { return $true }
    $lower    = $Name.ToLower()
    $compName = $env:COMPUTERNAME.ToLower()
    if ($lower -in @('.', 'localhost', $compName)) { return $true }
    if ($lower.StartsWith("$compName.")) { return $true }
    return $false
}

# ---------------------------------------------------------------------------
# Script-scoped body executed on each host (local or remote).
# Produces a list of raw volume info hashtables.
# Stored in $script:GBLSBody so the public function can pass it to
# Invoke-Command for remote hosts — keeping Pester mock coverage intact.
# ---------------------------------------------------------------------------
$script:GBLSBody = {
    # Helpers must be redefined inside a remote scriptblock.
    # When called locally (&) these inner definitions are ignored because
    # the outer-scope helpers are already in scope.

    function _GBLS_GetVolumes {
        try {
            if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
                return $null
            }
            return @(Get-BitLockerVolume -ErrorAction Stop)
        }
        catch {
            return $null
        }
    }

    function _GBLS_GetTpm {
        try {
            if (-not (Get-Command Get-Tpm -ErrorAction SilentlyContinue)) {
                return $null
            }
            return (Get-Tpm -ErrorAction Stop)
        }
        catch {
            return $null
        }
    }

    function _GBLS_GetSecureBoot {
        try {
            return (Confirm-SecureBootUEFI -ErrorAction Stop)
        }
        catch {
            return $null
        }
    }

    $volumes   = _GBLS_GetVolumes
    $tpm       = _GBLS_GetTpm
    $secureBoot = _GBLS_GetSecureBoot

    return @{
        Volumes     = $volumes
        Tpm         = $tpm
        SecureBoot  = $secureBoot
    }
}

# ---------------------------------------------------------------------------
# Public function: Get-BitLockerStatus
# ---------------------------------------------------------------------------
function Get-BitLockerStatus {
    <#
    .SYNOPSIS
        Report per-volume BitLocker posture for one or more computers.

    .DESCRIPTION
        Collects BitLocker volume data, TPM state, and Secure Boot state, then classifies each
        fixed volume as Compliant, NonCompliant, or Unknown.

        Read-only — never calls Enable-BitLocker, Initialize-Tpm, or any state-changing cmdlet.

    .PARAMETER ComputerName
        Target host names. Defaults to the local machine ('.').

    .PARAMETER OutputPath
        Optional CSV export path (UTF-8).

    .EXAMPLE
        Get-BitLockerStatus

    .EXAMPLE
        Get-BitLockerStatus -ComputerName SRV01, WK02 -OutputPath .\report.csv
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]]$ComputerName = @('.'),

        [Parameter()]
        [string]$OutputPath
    )

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($cn in $ComputerName) {
        Write-Verbose "Processing host: $cn"

        $isLocal = Test-GBLSIsLocalHost -Name $cn

        # Collect raw data — locally (so Pester mocks fire) or via PSRemoting.
        if ($isLocal) {
            # Local path: call private helpers directly so Pester mocks are effective.
            $volumes    = Get-GBLSBitLockerVolume
            $tpm        = Get-GBLSTpm
            $secureBoot = Get-GBLSSecureBoot
        }
        else {
            # Remote path: run the script body via Invoke-Command.
            $remoteData = Invoke-Command -ComputerName $cn -ScriptBlock $script:GBLSBody -ErrorAction Stop
            $volumes    = $remoteData.Volumes
            $tpm        = $remoteData.Tpm
            $secureBoot = $remoteData.SecureBoot
        }

        # If the BitLocker cmdlet wasn't available, emit one Unknown row and move on.
        if ($null -eq $volumes) {
            $row = [PSCustomObject]@{
                ComputerName         = $cn
                MountPoint           = ''
                ProtectionStatus     = $null
                EncryptionPercentage = $null
                EncryptionMethod     = $null
                VolumeStatus         = $null
                KeyProtectorTypes    = ''
                TpmPresent           = $null
                TpmReady             = $null
                SecureBootEnabled    = $null
                Status               = 'Unknown'
                Reasons              = 'Get-BitLockerVolume not available'
            }
            $results.Add($row)
            Write-Output $row
            continue
        }

        # Extract TPM fields (may be $null if Get-Tpm unavailable).
        $tpmPresent = if ($null -ne $tpm) { [bool]$tpm.TpmPresent } else { $null }
        $tpmReady   = if ($null -ne $tpm) { [bool]$tpm.TpmReady   } else { $null }

        # Filter to fixed volumes only (OperatingSystem and Data).
        $fixedVolumes = @($volumes | Where-Object {
            $_.VolumeType -eq 'OperatingSystem' -or $_.VolumeType -eq 'Data'
        })

        foreach ($vol in $fixedVolumes) {
            $keyTypes     = ($vol.KeyProtector.KeyProtectorType -join ';')
            $reasons      = [System.Collections.Generic.List[string]]::new()

            # Evaluate compliance conditions.
            $protOn  = ($vol.ProtectionStatus -eq 'On')
            $enc100  = ($vol.EncryptionPercentage -eq 100)
            $tpOk    = ($tpmPresent -eq $true)
            $trOk    = ($tpmReady   -eq $true)

            if (-not $protOn) {
                $reasons.Add("ProtectionStatus=$($vol.ProtectionStatus)")
            }
            if (-not $enc100) {
                $reasons.Add("EncryptionPercentage=$($vol.EncryptionPercentage)")
            }
            if (-not $tpOk) {
                $reasons.Add('TpmPresent=false')
            }
            if (-not $trOk) {
                $reasons.Add('TpmReady=false')
            }
            if ($secureBoot -eq $false) {
                $reasons.Add('SecureBootEnabled=false')
            }
            elseif ($null -eq $secureBoot) {
                $reasons.Add('SecureBootEnabled=false (non-UEFI or disabled)')
            }

            $status = if ($reasons.Count -eq 0) { 'Compliant' } else { 'NonCompliant' }

            $row = [PSCustomObject]@{
                ComputerName         = $cn
                MountPoint           = $vol.MountPoint
                ProtectionStatus     = $vol.ProtectionStatus
                EncryptionPercentage = $vol.EncryptionPercentage
                EncryptionMethod     = $vol.EncryptionMethod
                VolumeStatus         = $vol.VolumeStatus
                KeyProtectorTypes    = $keyTypes
                TpmPresent           = $tpmPresent
                TpmReady             = $tpmReady
                SecureBootEnabled    = $secureBoot
                Status               = $status
                Reasons              = ($reasons -join ';')
            }
            $results.Add($row)
            Write-Output $row
        }
    }

    # ------------------------------------------------------------------
    # Optional CSV export.
    # ------------------------------------------------------------------
    if ($OutputPath) {
        $results | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Verbose "Results exported to: $OutputPath"
    }
}
