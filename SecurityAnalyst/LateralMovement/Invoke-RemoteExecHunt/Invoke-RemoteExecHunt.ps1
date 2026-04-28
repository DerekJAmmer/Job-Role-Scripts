#requires -Version 7.2

<#
    Invoke-RemoteExecHunt.ps1

    Hunt for remote execution artifacts in Windows event logs.
    Covers four vectors attackers use to run code across the network:
      - Remote service installs  (Security 4697)       — PsExec, custom droppers
      - Remote scheduled tasks   (Security 4698/4702)  — schtasks /create /s
      - WMI execution            (WMI-Activity 5857/5860/5861)
      - PSRemoting / WinRM       (WinRM/Operational 91)

    See README.md for full details and examples.
#>

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function New-REHFinding {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'In-memory factory only.')]
    param(
        [Parameter(Mandatory)][string]$Detection,
        [Parameter(Mandatory)][datetime]$TimeCreated,
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string]$Detail,
        [string]$Evidence = ''
    )
    [pscustomobject]@{
        Detection   = $Detection
        TimeCreated = $TimeCreated
        Subject     = $Subject
        Detail      = $Detail
        Evidence    = $Evidence
    }
}

$script:REHSignerCache = @{}
function Get-REHSigner {
    # Authenticode lookup with path cache — same approach as PersistenceAudit.
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return 'Unknown' }

    $clean = $Path.Trim('"') -replace '\s+-.*$', '' -replace '\s+/.*$', ''
    if (-not (Test-Path -LiteralPath $clean -PathType Leaf -ErrorAction SilentlyContinue)) {
        return 'Unknown'
    }
    if ($script:REHSignerCache.ContainsKey($clean)) { return $script:REHSignerCache[$clean] }

    $sig = Get-AuthenticodeSignature -FilePath $clean -ErrorAction SilentlyContinue
    $result = if ($null -eq $sig -or $sig.Status -ne 'Valid' -or -not $sig.SignerCertificate) {
        'Unsigned'
    } else {
        $sig.SignerCertificate.Subject -replace '^CN=', '' -replace ',.*$', ''
    }
    $script:REHSignerCache[$clean] = $result
    return $result
}

function Test-REHMicrosoftSigned {
    param([string]$Signer)
    return $Signer -match '(?i)Microsoft|Windows Publisher'
}

# ---------------------------------------------------------------------------
# Event reader
# ---------------------------------------------------------------------------

function Read-REHEvents {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseSingularNouns', '',
        Justification = 'Internal helper; reads a batch of events by design.')]
    param(
        [string]$LogName,
        [int[]]$EventIds,
        [datetime]$StartTime,
        [datetime]$EndTime,
        [int]$MaxEvents
    )
    $filter = @{
        LogName   = $LogName
        Id        = $EventIds
        StartTime = $StartTime
        EndTime   = $EndTime
    }
    try {
        $raw = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop
        return @($raw)
    } catch {
        if ($_.Exception.Message -match 'No events were found') { return @() }
        # Log missing, disabled, or access denied — degrade gracefully
        Write-Warning "[$LogName] $($_.Exception.Message)"
        return @()
    }
}

# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------

function Get-REHServiceInstalls {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseSingularNouns', '',
        Justification = 'Internal collector; returns multiple findings by design.')]
    <#
        Security 4697 — a service was installed on the system.
        Classic PsExec indicator (PSEXESVC), but any remote dropper does this.
        Flag: unsigned or non-Microsoft binary.
    #>
    param(
        [datetime]$StartTime,
        [datetime]$EndTime,
        [int]$MaxEvents
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $events   = @(Read-REHEvents -LogName 'Security' -EventIds @(4697) `
                    -StartTime $StartTime -EndTime $EndTime -MaxEvents $MaxEvents)

    foreach ($ev in $events) {
        try {
            $xml  = [xml]$ev.ToXml()
            $data = $xml.Event.EventData.Data
            function xval4697([string]$n) {
                ($data | Where-Object { $_.Name -eq $n } | Select-Object -First 1).'#text'
            }

            $svcName = xval4697 'ServiceName'
            $svcFile = xval4697 'ServiceFileName'
            $user    = xval4697 'SubjectUserName'
            $domain  = xval4697 'SubjectDomainName'
            $subject = if ($domain -and $domain -ne '-') { "$domain\$user" } else { $user }

            $signer  = Get-REHSigner -Path ($svcFile -replace '"', '')
            $flagged = -not (Test-REHMicrosoftSigned -Signer $signer)

            if ($flagged) {
                $findings.Add((New-REHFinding `
                    -Detection   'ServiceInstall' `
                    -TimeCreated $ev.TimeCreated `
                    -Subject     $subject `
                    -Detail      "Service '$svcName' installed | Signer: $signer" `
                    -Evidence    $svcFile
                ))
            }
        } catch { }
    }

    return $findings, $events.Count
}

function Get-REHRemoteTaskCreates {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseSingularNouns', '',
        Justification = 'Internal collector; returns multiple findings by design.')]
    <#
        Security 4698 (task created) and 4702 (task updated).
        Flag tasks whose action command contains common LOLBin patterns.
    #>
    param(
        [datetime]$StartTime,
        [datetime]$EndTime,
        [int]$MaxEvents
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $events   = @(Read-REHEvents -LogName 'Security' -EventIds @(4698, 4702) `
                    -StartTime $StartTime -EndTime $EndTime -MaxEvents $MaxEvents)

    # Patterns commonly abused for execution via scheduled tasks
    $suspiciousPattern = '(?i)(powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msiexec|wmic)'

    foreach ($ev in $events) {
        try {
            $xml  = [xml]$ev.ToXml()
            $data = $xml.Event.EventData.Data
            function xval4698([string]$n) {
                $node = ($data | Where-Object { $_.Name -eq $n } | Select-Object -First 1)
                if ($null -eq $node) { return $null }
                # Real events store TaskContent as a text node; test fakes may use child XML
                if ($node.'#text') { return $node.'#text' }
                return $node.InnerXml
            }

            $taskName    = xval4698 'TaskName'
            $user        = xval4698 'SubjectUserName'
            $domain      = xval4698 'SubjectDomainName'
            $subject     = if ($domain -and $domain -ne '-') { "$domain\$user" } else { $user }
            $taskContent = xval4698 'TaskContent'
            $evLabel     = if ($ev.Id -eq 4698) { 'Created' } else { 'Modified' }

            $flagged = $taskContent -match $suspiciousPattern

            if ($flagged) {
                # Pull just the <Exec> action block so Evidence doesn't dump the full XML
                $actionSnippet = if ($taskContent -match '(?s)<Exec>(.{0,300})') {
                    $Matches[0] -replace '\s+', ' '
                } else { $taskContent.Substring(0, [Math]::Min(200, $taskContent.Length)) }

                $findings.Add((New-REHFinding `
                    -Detection   'RemoteTaskCreate' `
                    -TimeCreated $ev.TimeCreated `
                    -Subject     $subject `
                    -Detail      "Task $evLabel '$taskName'" `
                    -Evidence    $actionSnippet
                ))
            }
        } catch { }
    }

    return $findings, $events.Count
}

function Get-REHWMIExecution {
    <#
        Microsoft-Windows-WMI-Activity/Operational
          5857 — WMI provider host loaded (flag if non-standard namespace)
          5860 — temporary WMI event subscription registered
          5861 — permanent WMI event subscription registered (most suspicious)

        5860/5861 are always flagged — legitimate software rarely registers
        WMI event subscriptions at runtime.
    #>
    param(
        [datetime]$StartTime,
        [datetime]$EndTime,
        [int]$MaxEvents
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $events   = @(Read-REHEvents -LogName 'Microsoft-Windows-WMI-Activity/Operational' `
                    -EventIds @(5857, 5860, 5861) `
                    -StartTime $StartTime -EndTime $EndTime -MaxEvents $MaxEvents)

    $standardNamespaces = @('root/cimv2', 'root\cimv2', 'root/microsoft', 'root\microsoft',
                             'root/default', 'root\default')

    foreach ($ev in $events) {
        try {
            $xml     = [xml]$ev.ToXml()
            $evData  = $xml.Event.EventData.Data

            switch ($ev.Id) {
                5857 {
                    # Provider loaded — only flag non-standard namespaces
                    $namespace = ($evData | Where-Object { $_.Name -eq 'NamespaceName' } |
                                  Select-Object -First 1).'#text'
                    $provider  = ($evData | Where-Object { $_.Name -eq 'ProviderName' } |
                                  Select-Object -First 1).'#text'
                    $isStandard = $standardNamespaces | Where-Object { $namespace -like "$_*" }
                    if (-not $isStandard) {
                        $findings.Add((New-REHFinding `
                            -Detection   'WMIExecution' `
                            -TimeCreated $ev.TimeCreated `
                            -Subject     "Provider: $provider" `
                            -Detail      'WMI provider loaded in non-standard namespace' `
                            -Evidence    "Namespace: $namespace"
                        ))
                    }
                }
                5860 {
                    $consumer  = ($evData | Where-Object { $_.Name -eq 'CONSUMER' } |
                                  Select-Object -First 1).'#text'
                    $query     = ($evData | Where-Object { $_.Name -eq 'QUERY' } |
                                  Select-Object -First 1).'#text'
                    $findings.Add((New-REHFinding `
                        -Detection   'WMIExecution' `
                        -TimeCreated $ev.TimeCreated `
                        -Subject     'Temporary subscription' `
                        -Detail      "Consumer: $consumer" `
                        -Evidence    ($query -replace '\s+', ' ')
                    ))
                }
                5861 {
                    $consumer  = ($evData | Where-Object { $_.Name -eq 'CONSUMER' } |
                                  Select-Object -First 1).'#text'
                    $query     = ($evData | Where-Object { $_.Name -eq 'QUERY' } |
                                  Select-Object -First 1).'#text'
                    $findings.Add((New-REHFinding `
                        -Detection   'WMIExecution' `
                        -TimeCreated $ev.TimeCreated `
                        -Subject     'Permanent subscription' `
                        -Detail      "Consumer: $consumer" `
                        -Evidence    ($query -replace '\s+', ' ')
                    ))
                }
            }
        } catch { }
    }

    return $findings, $events.Count
}

function Get-REHPSRemoting {
    <#
        Microsoft-Windows-WinRM/Operational event 91 — WSMan session created.
        Fires for every Enter-PSSession, Invoke-Command, or WinRM tool connection.

        All sessions flagged by default.  Pass -AllowedSourceIPs to suppress
        known-good sources (e.g. your jump box or monitoring system).
    #>
    param(
        [datetime]$StartTime,
        [datetime]$EndTime,
        [int]$MaxEvents,
        [string[]]$AllowedSourceIPs = @()
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $events   = @(Read-REHEvents -LogName 'Microsoft-Windows-WinRM/Operational' `
                    -EventIds @(91) `
                    -StartTime $StartTime -EndTime $EndTime -MaxEvents $MaxEvents)

    foreach ($ev in $events) {
        try {
            $xml      = [xml]$ev.ToXml()
            $evData   = $xml.Event.EventData.Data

            $clientIP = ($evData | Where-Object { $_.Name -eq 'clientIp' } |
                         Select-Object -First 1).'#text'
            $resource = ($evData | Where-Object { $_.Name -eq 'resourceUri' } |
                         Select-Object -First 1).'#text'
            $user     = ($evData | Where-Object { $_.Name -eq 'userName' } |
                         Select-Object -First 1).'#text'

            # Suppress if the source IP is on the allow list
            if ($AllowedSourceIPs.Count -gt 0 -and $clientIP -in $AllowedSourceIPs) { continue }

            $findings.Add((New-REHFinding `
                -Detection   'PSRemoting' `
                -TimeCreated $ev.TimeCreated `
                -Subject     ($user ?? 'Unknown') `
                -Detail      "WinRM session from $clientIP" `
                -Evidence    $resource
            ))
        } catch { }
    }

    return $findings, $events.Count
}

# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

function ConvertTo-REHMarkdownTable {
    param([object[]]$Rows)
    if (-not $Rows -or $Rows.Count -eq 0) { return '_(no findings)_' }
    $keys   = $Rows[0].PSObject.Properties.Name | Where-Object { $_ -ne 'Detection' }
    $header = '| ' + ($keys -join ' | ') + ' |'
    $sep    = '| ' + (($keys | ForEach-Object { '---' }) -join ' | ') + ' |'
    $lines  = foreach ($r in $Rows) {
        $cells = foreach ($k in $keys) {
            $v = $r.$k
            if ($null -eq $v) { '' }
            else { ($v.ToString() -replace '\|', '\|' -replace '\r?\n', ' ') }
        }
        '| ' + ($cells -join ' | ') + ' |'
    }
    ($header, $sep) + $lines -join "`n"
}

function ConvertTo-REHMarkdownReport {
    param(
        [Parameter(Mandatory)][string]$HostName,
        [object[]]$Findings = @(),
        [Parameter(Mandatory)][hashtable]$Stats
    )

    $md = [System.Collections.Generic.List[string]]::new()
    $md.Add("# RemoteExecHunt: $HostName")
    $md.Add('')
    $md.Add("_Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')_")
    $md.Add("_Window: $($Stats.StartTime) → $($Stats.EndTime)_")
    $md.Add('')
    $md.Add("**Events scanned:** $($Stats.EventsScanned) | **Findings:** $($Findings.Count)")
    if ($Stats.AllowedSourceIPs.Count -gt 0) {
        $md.Add("**Suppressed source IPs:** $($Stats.AllowedSourceIPs -join ', ')")
    }
    $md.Add('')

    if ($Findings.Count -eq 0) {
        $md.Add('No suspicious remote execution artifacts found in the selected window.')
        return $md -join "`n"
    }

    $types = $Findings | Select-Object -ExpandProperty Detection -Unique
    foreach ($t in $types) {
        $subset = @($Findings | Where-Object Detection -EQ $t)
        $md.Add("## $t ($($subset.Count))")
        $md.Add('')
        $md.Add((ConvertTo-REHMarkdownTable -Rows $subset))
        $md.Add('')
    }

    $md -join "`n"
}

# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

function Invoke-RemoteExecHunt {
    <#
    .SYNOPSIS
        Hunt event logs for remote execution artifacts.

    .DESCRIPTION
        Checks four vectors attackers use to run code across the network:
          - Remote service installs  (Security 4697)
          - Remote scheduled tasks   (Security 4698 / 4702)
          - WMI event subscriptions  (WMI-Activity 5857 / 5860 / 5861)
          - PSRemoting / WinRM       (WinRM/Operational 91)

        Writes a Markdown report and returns a summary object.

    .PARAMETER HoursBack
        How far back to look. Default 24.

    .PARAMETER StartTime
        Explicit start time (overrides -HoursBack).

    .PARAMETER EndTime
        Explicit end time. Defaults to now.

    .PARAMETER MaxEvents
        Cap on events fetched per event ID. Default 5000.

    .PARAMETER AllowedSourceIPs
        IP addresses to suppress from PSRemoting findings.
        Useful for jump boxes or monitoring systems that WinRM into this host routinely.

    .PARAMETER OutFile
        Where to write the Markdown report.
        Defaults to .\RemoteExecHunt-<host>-<yyyyMMdd-HHmm>.md.

    .PARAMETER Skip
        Detections to skip entirely.
        Valid: ServiceInstall, RemoteTaskCreate, WMIExecution, PSRemoting

    .EXAMPLE
        Invoke-RemoteExecHunt

    .EXAMPLE
        Invoke-RemoteExecHunt -HoursBack 72 -AllowedSourceIPs '10.0.0.50','10.0.0.51'

    .EXAMPLE
        Invoke-RemoteExecHunt -Skip PSRemoting -OutFile C:\IR\remote-exec.md
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [int]$HoursBack                 = 24,
        [datetime]$StartTime            = [datetime]::MinValue,
        [datetime]$EndTime              = [datetime]::Now,

        [ValidateRange(100, 500000)]
        [int]$MaxEvents                 = 5000,

        [string[]]$AllowedSourceIPs     = @(),

        [string]$OutFile,

        [ValidateSet('ServiceInstall', 'RemoteTaskCreate', 'WMIExecution', 'PSRemoting')]
        [string[]]$Skip                 = @()
    )

    $clock = Get-Date
    $script:REHSignerCache = @{}   # reset cache each run

    if ($StartTime -eq [datetime]::MinValue) {
        $StartTime = $clock.AddHours(-$HoursBack)
    }

    $findings     = [System.Collections.Generic.List[object]]::new()
    $totalScanned = 0

    $collectors = [ordered]@{
        ServiceInstall   = {
            Get-REHServiceInstalls -StartTime $StartTime -EndTime $EndTime -MaxEvents $MaxEvents
        }
        RemoteTaskCreate = {
            Get-REHRemoteTaskCreates -StartTime $StartTime -EndTime $EndTime -MaxEvents $MaxEvents
        }
        WMIExecution     = {
            Get-REHWMIExecution -StartTime $StartTime -EndTime $EndTime -MaxEvents $MaxEvents
        }
        PSRemoting       = {
            Get-REHPSRemoting -StartTime $StartTime -EndTime $EndTime `
                -MaxEvents $MaxEvents -AllowedSourceIPs $AllowedSourceIPs
        }
    }

    foreach ($name in $collectors.Keys) {
        if ($Skip -contains $name) { continue }
        Write-Verbose "Collecting: $name"
        $result, $count = & $collectors[$name]
        $totalScanned  += $count
        foreach ($f in $result) { $findings.Add($f) }
    }

    $stats = @{
        StartTime        = $StartTime
        EndTime          = $EndTime
        EventsScanned    = $totalScanned
        AllowedSourceIPs = @($AllowedSourceIPs)
    }

    if (-not $OutFile) {
        $ts      = $clock.ToString('yyyyMMdd-HHmm')
        $OutFile = ".\RemoteExecHunt-$($env:COMPUTERNAME)-$ts.md"
    }

    $markdown = ConvertTo-REHMarkdownReport -HostName $env:COMPUTERNAME `
                    -Findings $findings -Stats $stats
    Set-Content -LiteralPath $OutFile -Value $markdown -Encoding UTF8

    [pscustomobject]@{
        HostName      = $env:COMPUTERNAME
        RunTime       = (Get-Date) - $clock
        FindingCount  = $findings.Count
        EventsScanned = $totalScanned
        OutFile       = (Resolve-Path -LiteralPath $OutFile).Path
    }
}
