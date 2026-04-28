#requires -Version 7.2
<#
.SYNOPSIS
    Compare installed Windows features or software against a JSON baseline manifest and report drift.

.DESCRIPTION
    Get-FeatureDrift reads a JSON baseline manifest that lists expected Windows features or software
    titles, then checks each target host and identifies:
      - Missing: items in the baseline that are not present on the host.
      - Extra:   items on the host that are not in the baseline.

    In Features mode the script queries installed Windows features via Get-WindowsFeature (Server)
    with automatic fallback to Get-WindowsOptionalFeature (Client/Desktop).

    In Software mode the script walks HKLM Uninstall registry keys (both 64-bit and Wow6432Node)
    to enumerate installed applications.

    For remote hosts the checks run via Invoke-Command using the same scriptblock bodies as local
    checks (single source of truth). Hosts that cannot be reached are recorded with
    Status='Unreachable' rather than causing the entire run to fail.

    Output is a PSCustomObject per host containing ComputerName, Mode, Missing, Extra, MatchPercent,
    BaselineName, Status, and Reason. An optional -OutputPath writes the full result set as UTF-8 JSON.

.PARAMETER BaselinePath
    Path to a JSON baseline manifest file. Required. See samples/baseline-example.json for the schema.

.PARAMETER ComputerName
    One or more host names to evaluate. Defaults to the local machine (localhost).
    Use '.' or 'localhost' to target the local machine explicitly.
    FQDNs whose leftmost label matches the local machine name are also treated as local
    (e.g. 'WK01.corp.local' when running on WK01).

.PARAMETER OutputPath
    Optional path to write results as a JSON file (UTF-8, depth 5).

.PARAMETER Mode
    Which inventory to compare: 'Features' (default) or 'Software'.

.OUTPUTS
    PSCustomObject with properties:
      ComputerName  — target host
      Mode          — 'Features' or 'Software'
      Missing       — items in the baseline absent from the host
      Extra         — items on the host absent from the baseline
      MatchPercent  — percentage of baseline items present on the host
      BaselineName  — name field from the baseline JSON
      Status        — 'OK' on success; 'Unreachable' if the host could not be contacted
      Reason        — empty string on success; error message when Status='Unreachable'

.EXAMPLE
    Get-FeatureDrift -BaselinePath .\samples\baseline-example.json
    # Run features comparison against the local host using the example baseline.

.EXAMPLE
    Get-FeatureDrift -BaselinePath .\dc-baseline.json -ComputerName DC01,DC02 -Mode Features -OutputPath .\drift-report.json
    # Compare features on two domain controllers and write results to JSON.

.EXAMPLE
    Get-FeatureDrift -BaselinePath .\workstation-baseline.json -Mode Software
    # Check installed software on the local host against a software baseline.
#>

# ---------------------------------------------------------------------------
# Stub gate — makes feature cmdlets mockable when modules are not installed.
# Pester's Mock requires commands to exist in scope before they can be mocked.
# ---------------------------------------------------------------------------
if (-not (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue)) {
    function Get-WindowsFeature {
        <#
        .SYNOPSIS
            Stub — replaced at runtime by the ServerManager module.
        #>
        [CmdletBinding()]
        param(
            [Parameter()]
            [string]$Name
        )
        throw 'Get-WindowsFeature not available — install ServerManager module or run on Windows Server.'
    }
}

if (-not (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue)) {
    function Get-WindowsOptionalFeature {
        <#
        .SYNOPSIS
            Stub — replaced at runtime by the DISM module.
        #>
        [CmdletBinding()]
        param(
            [Parameter()]
            [switch]$Online,
            [Parameter()]
            [string]$FeatureName
        )
        throw 'Get-WindowsOptionalFeature not available.'
    }
}

# ---------------------------------------------------------------------------
# Scriptblock bodies — single source of truth for local AND remote execution.
# Passed to Invoke-Command when the target is remote; invoked directly (&)
# when the target is local so that Pester mocks remain effective.
# ---------------------------------------------------------------------------

$script:FDFeatureBody = {
    try {
        @(Get-WindowsFeature -ErrorAction Stop |
            Where-Object { $_.Installed } |
            Select-Object -ExpandProperty Name)
    }
    catch {
        @(Get-WindowsOptionalFeature -Online -ErrorAction Stop |
            Where-Object { $_.State -eq 'Enabled' } |
            Select-Object -ExpandProperty FeatureName)
    }
}

$script:FDSoftwareBody = {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $names = [System.Collections.Generic.List[string]]::new()

    foreach ($p in $paths) {
        $keyPath = $p -replace '\\\*$', ''
        if (Test-Path -LiteralPath $keyPath) {
            $entries = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                Select-Object -ExpandProperty DisplayName
            if ($entries) {
                foreach ($entry in $entries) {
                    $names.Add($entry)
                }
            }
        }
    }

    return $names.ToArray()
}

# ---------------------------------------------------------------------------
# Helper: Get-FDInstalledFeature
# Thin wrapper around $script:FDFeatureBody for any direct callers.
# ---------------------------------------------------------------------------
function Get-FDInstalledFeature {
    <#
    .SYNOPSIS
        Collect installed Windows feature names from the local host.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    & $script:FDFeatureBody
}

# ---------------------------------------------------------------------------
# Helper: Get-FDInstalledSoftware
# Thin wrapper around $script:FDSoftwareBody for any direct callers.
# ---------------------------------------------------------------------------
function Get-FDInstalledSoftware {
    <#
    .SYNOPSIS
        Collect installed software display names from the HKLM Uninstall registry keys.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    & $script:FDSoftwareBody
}

# ---------------------------------------------------------------------------
# Helper: Test-FDIsLocalHost
# FQDN-aware local-host detection.
# Prefers the shared SysAdmin.Common helper when loaded; falls back to the
# private implementation so the script works fully standalone.
# ---------------------------------------------------------------------------
function Test-FDIsLocalHost {
    <#
    .SYNOPSIS
        Returns $true if the supplied name refers to the local machine.
    #>
    param(
        [string]$Name
    )

    if (Get-Command Test-IsLocalHost -ErrorAction SilentlyContinue) {
        return (Test-IsLocalHost -Name $Name)
    }

    # Private fallback when SysAdmin.Common isn't loaded.
    if ([string]::IsNullOrWhiteSpace($Name)) { return $true }
    $lower    = $Name.ToLower()
    $compName = $env:COMPUTERNAME.ToLower()
    if ($lower -in @('.', 'localhost', $compName)) { return $true }
    if ($lower.StartsWith("$compName.")) { return $true }
    return $false
}

# ---------------------------------------------------------------------------
# Helper: Read-FDBaseline
# Reads and validates the JSON baseline manifest.
# ---------------------------------------------------------------------------
function Read-FDBaseline {
    <#
    .SYNOPSIS
        Read and validate a JSON baseline manifest file.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Baseline file not found: '$Path'."
    }

    $raw = Get-Content -LiteralPath $Path -Raw

    try {
        $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Malformed baseline JSON: $($_.Exception.Message)"
    }

    # Default missing keys to empty arrays.
    # ConvertFrom-Json may return $null for empty arrays; ensure we always have [string[]].
    $rawFeatures = $parsed.features
    $rawSoftware = $parsed.software
    $features = if ($rawFeatures) { [string[]]@($rawFeatures) } else { [string[]]@() }
    $software = if ($rawSoftware) { [string[]]@($rawSoftware) } else { [string[]]@() }
    $name     = if ($parsed.name) { [string]$parsed.name } else { 'Unnamed' }

    return @{
        Name     = $name
        Features = $features
        Software = $software
    }
}

# ---------------------------------------------------------------------------
# Public function: Get-FeatureDrift
# ---------------------------------------------------------------------------
function Get-FeatureDrift {
    <#
    .SYNOPSIS
        Compare installed Windows features or software against a JSON baseline and report drift.

    .DESCRIPTION
        Reads a JSON baseline manifest and compares it against what is installed on each target host.
        Reports Missing items (in baseline, not on host), Extra items (on host, not in baseline),
        a MatchPercent score, and the baseline name for traceability.

        Remote hosts are queried via Invoke-Command using the same scriptblock body as local checks.
        Unreachable hosts produce a result row with Status='Unreachable' and Reason containing the
        error message; the remaining hosts in the list are still processed.

    .PARAMETER BaselinePath
        Path to the JSON baseline manifest. Must exist and be valid JSON.

    .PARAMETER ComputerName
        Target host names. Defaults to localhost.

    .PARAMETER OutputPath
        Optional path to write results as UTF-8 JSON.

    .PARAMETER Mode
        'Features' (default) or 'Software'.

    .EXAMPLE
        Get-FeatureDrift -BaselinePath .\samples\baseline-example.json

    .EXAMPLE
        Get-FeatureDrift -BaselinePath .\dc-baseline.json -ComputerName DC01,DC02 -Mode Features -OutputPath .\drift.json
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$BaselinePath,

        [Parameter()]
        [string[]]$ComputerName = @('localhost'),

        [Parameter()]
        [string]$OutputPath,

        [Parameter()]
        [ValidateSet('Features', 'Software')]
        [string]$Mode = 'Features'
    )

    # Read and validate the baseline once.
    $baseline = Read-FDBaseline -Path $BaselinePath

    $baselineSet = if ($Mode -eq 'Features') {
        $baseline.Features
    }
    else {
        $baseline.Software
    }

    # Select the correct scriptblock body for this mode.
    $body = if ($Mode -eq 'Features') { $script:FDFeatureBody } else { $script:FDSoftwareBody }

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($computer in $ComputerName) {
        Write-Verbose "Processing host: $computer"

        $isLocal = Test-FDIsLocalHost -Name $computer

        try {
            # Collect installed items — locally (so Pester mocks fire) or via PSRemoting.
            $installedSet = if ($isLocal) {
                & $body
            }
            else {
                Invoke-Command -ComputerName $computer -ScriptBlock $body -ErrorAction Stop
            }

            # Compute Missing and Extra via Compare-Object.
            $missing = [string[]]@()
            $extra   = [string[]]@()

            # Ensure both sides are non-null arrays before calling Compare-Object.
            $safeBaseline  = if ($baselineSet)  { [string[]]@($baselineSet)  } else { [string[]]@() }
            $safeInstalled = if ($installedSet) { [string[]]@($installedSet) } else { [string[]]@() }

            if ($safeBaseline.Count -gt 0 -and $safeInstalled.Count -gt 0) {
                # Both sides populated — use Compare-Object.
                $comparison = Compare-Object -ReferenceObject $safeBaseline -DifferenceObject $safeInstalled -ErrorAction SilentlyContinue
                if ($comparison) {
                    $missing = @($comparison | Where-Object { $_.SideIndicator -eq '<=' } | Select-Object -ExpandProperty InputObject)
                    $extra   = @($comparison | Where-Object { $_.SideIndicator -eq '=>' } | Select-Object -ExpandProperty InputObject)
                }
            }
            elseif ($safeBaseline.Count -gt 0) {
                # Nothing installed — everything in baseline is missing.
                $missing = $safeBaseline
            }
            elseif ($safeInstalled.Count -gt 0) {
                # Empty baseline — everything installed is extra.
                $extra = $safeInstalled
            }

            # MatchPercent: if baseline is empty, 0. Else (baseline - missing) / baseline * 100.
            $matchPercent = if ($safeBaseline.Count -eq 0) {
                0.0
            }
            else {
                [math]::Round((($safeBaseline.Count - $missing.Count) / $safeBaseline.Count) * 100, 1)
            }

            $entry = [PSCustomObject]@{
                ComputerName  = $computer
                Mode          = $Mode
                Missing       = $missing
                Extra         = $extra
                MatchPercent  = $matchPercent
                BaselineName  = $baseline.Name
                Status        = 'OK'
                Reason        = ''
            }

            $results.Add($entry)
            Write-Output $entry
        }
        catch {
            Write-Warning "Could not reach host '$computer': $($_.Exception.Message)"

            $entry = [PSCustomObject]@{
                ComputerName  = $computer
                Mode          = $Mode
                Missing       = [string[]]@()
                Extra         = [string[]]@()
                MatchPercent  = 0.0
                BaselineName  = $baseline.Name
                Status        = 'Unreachable'
                Reason        = $_.Exception.Message
            }

            $results.Add($entry)
            Write-Output $entry
        }
    }

    # Write JSON output if requested.
    if ($OutputPath) {
        $results | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputPath -Encoding UTF8
        Write-Verbose "Results written to: $OutputPath"
    }
}
