#requires -Version 7.2

<#
    Invoke-LogonHunt.ps1

    Hunt 4624/4625 logon events for patterns that stick out:
      - Rapid-burst failures from the same source (brute force)
      - Multi-source logons for a single account (credential spray / reuse)
      - Explicit-credential logons (type 9) — often lateral movement via runas/PTH
      - Off-hours logon activity

    Needs access to the Security event log.  Elevation gives you more events
    (the log can be large); non-elevated works on the recent cached events.

    See README.md for full details.
#>

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function New-LHFinding {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'In-memory factory only.')]
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string]$Detail,
        [string]$Evidence = ''
    )
    [pscustomobject]@{
        Type     = $Type
        Subject  = $Subject
        Detail   = $Detail
        Evidence = $Evidence
    }
}

function Get-LHLogonTypeLabel {
    param([int]$Type)
    switch ($Type) {
        2  { 'Interactive' }
        3  { 'Network' }
        4  { 'Batch' }
        5  { 'Service' }
        7  { 'Unlock' }
        8  { 'NetworkCleartext' }
        9  { 'NewCredentials(runas/PTH)' }
        10 { 'RemoteInteractive(RDP)' }
        11 { 'CachedInteractive' }
        default { "Type$Type" }
    }
}

function Get-LHWorkHours {
    # Returns $true if the given DateTime falls within normal business hours.
    # Defaults: Mon–Fri, 07:00–19:00 local time.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'Refers to a working-hours window, not a single hour.')]
    param(
        [Parameter(Mandatory)][datetime]$Time,
        [int]$StartHour = 7,
        [int]$EndHour   = 19
    )
    $dow = [int]$Time.DayOfWeek
    if ($dow -eq 0 -or $dow -eq 6) { return $false }   # weekend
    return ($Time.Hour -ge $StartHour -and $Time.Hour -lt $EndHour)
}

# ---------------------------------------------------------------------------
# Event log reader
# ---------------------------------------------------------------------------

function Read-LHSecurityEvents {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'Reads a collection of Security event log records.')]
    param(
        [datetime]$StartTime,
        [datetime]$EndTime,
        [int]$MaxEvents,
        [int[]]$EventIds
    )

    $filter = @{
        LogName   = 'Security'
        Id        = $EventIds
        StartTime = $StartTime
        EndTime   = $EndTime
    }

    try {
        $raw = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop
        return $raw
    } catch [System.Exception] {
        if ($_.Exception.Message -match 'No events were found') { return @() }
        throw
    }
}

# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

function ConvertFrom-LHLogonEvent {
    # Parse a 4624 or 4625 event into a flat object.
    param([System.Diagnostics.Eventing.Reader.EventLogRecord]$Event)

    try {
        $xml  = [xml]$Event.ToXml()
        $data = $xml.Event.EventData.Data

        function xval([string]$Name) {
            ($data | Where-Object { $_.Name -eq $Name } | Select-Object -First 1).'#text'
        }

        [pscustomobject]@{
            TimeCreated    = $Event.TimeCreated
            EventId        = $Event.Id
            AccountName    = xval 'TargetUserName'
            AccountDomain  = xval 'TargetDomainName'
            LogonType      = [int](xval 'LogonType')
            LogonTypeLabel = Get-LHLogonTypeLabel -Type ([int](xval 'LogonType'))
            WorkstationName= xval 'WorkstationName'
            IpAddress      = xval 'IpAddress'
            IpPort         = xval 'IpPort'
            ProcessName    = xval 'ProcessName'
            FailureReason  = xval 'FailureReason'   # 4625 only
            Status         = xval 'Status'
            SubStatus      = xval 'SubStatus'
        }
    } catch {
        $null
    }
}

# ---------------------------------------------------------------------------
# Detections
# ---------------------------------------------------------------------------

function Find-LHBurstFailures {
    <#
        Brute-force / spray indicator: same source IP or workstation causes
        N or more failures within a rolling window (minutes).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'Returns a collection of burst-failure findings.')]
    param(
        [object[]]$Events4625,
        [int]$Threshold  = 5,
        [int]$WindowMin  = 5
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $window   = [timespan]::FromMinutes($WindowMin)

    # Group by source IP (fall back to workstation name when IP is absent/loopback)
    $grouped = $Events4625 | Group-Object -Property {
        if ($_.IpAddress -and $_.IpAddress -notin @('-','::1','127.0.0.1')) { $_.IpAddress }
        else { $_.WorkstationName }
    }

    foreach ($g in $grouped) {
        if (-not $g.Name) { continue }
        $sorted = @($g.Group | Sort-Object TimeCreated)
        for ($i = 0; $i -lt $sorted.Count; $i++) {
            $windowEnd = $sorted[$i].TimeCreated + $window
            $burst     = @($sorted[$i..($sorted.Count - 1)] | Where-Object { $_.TimeCreated -le $windowEnd })
            if ($burst.Count -ge $Threshold) {
                $accounts = ($burst | Select-Object -ExpandProperty AccountName -Unique) -join ', '
                $findings.Add((New-LHFinding `
                    -Type    'BurstFailures' `
                    -Subject $g.Name `
                    -Detail  "$($burst.Count) failures in $WindowMin min targeting: $accounts" `
                    -Evidence "First: $($burst[0].TimeCreated)  Last: $($burst[-1].TimeCreated)"
                ))
                # Jump past this burst to avoid duplicate findings for the same cluster
                $i += $burst.Count - 1
                break
            }
        }
    }

    return $findings
}

function Find-LHMultiSourceLogons {
    <#
        Credential-reuse / lateral movement indicator: a single account
        successfully logs on from N or more distinct IPs within the window.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'Returns a collection of multi-source logon findings.')]
    param(
        [object[]]$Events4624,
        [int]$Threshold = 3,
        [int]$WindowHours = 1
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $window   = [timespan]::FromHours($WindowHours)

    # Only care about network-type logons (types 3, 10) — skip SYSTEM/SERVICE accounts
    $net = $Events4624 | Where-Object {
        $_.LogonType -in @(3, 10) -and
        $_.AccountName -notin @('ANONYMOUS LOGON', '-', '') -and
        $_.AccountName -notmatch '\$$'   # skip computer accounts
    }

    $grouped = $net | Group-Object AccountName
    foreach ($g in $grouped) {
        $sorted = @($g.Group | Sort-Object TimeCreated)
        for ($i = 0; $i -lt $sorted.Count; $i++) {
            $windowEnd   = $sorted[$i].TimeCreated + $window
            $inWindow    = @($sorted[$i..($sorted.Count - 1)] | Where-Object { $_.TimeCreated -le $windowEnd })
            $distinctIPs = @($inWindow | Where-Object {
                $_.IpAddress -and $_.IpAddress -notin @('-','::1','127.0.0.1','')
            } | Select-Object -ExpandProperty IpAddress -Unique)

            if ($distinctIPs.Count -ge $Threshold) {
                $findings.Add((New-LHFinding `
                    -Type    'MultiSourceLogon' `
                    -Subject $g.Name `
                    -Detail  "$($distinctIPs.Count) distinct source IPs in $WindowHours h" `
                    -Evidence ($distinctIPs -join ', ')
                ))
                $i += $inWindow.Count - 1
                break
            }
        }
    }

    return $findings
}

function Find-LHExplicitCredentialLogons {
    <#
        Logon type 9 (NewCredentials) means someone used explicit credentials
        (runas /netonly, pass-the-hash style impersonation).  Flag any non-SYSTEM
        account doing this, especially outside business hours.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'Returns a collection of explicit-credential logon findings.')]
    param(
        [object[]]$Events4624,
        [int]$WorkHourStart = 7,
        [int]$WorkHourEnd   = 19
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    $type9 = $Events4624 | Where-Object {
        $_.LogonType -eq 9 -and
        $_.AccountName -notin @('SYSTEM', '-', '') -and
        $_.AccountName -notmatch '\$$'
    }

    foreach ($e in $type9) {
        $offHours = -not (Get-LHWorkHours -Time $e.TimeCreated -StartHour $WorkHourStart -EndHour $WorkHourEnd)
        $findings.Add((New-LHFinding `
            -Type    'ExplicitCredential' `
            -Subject $e.AccountName `
            -Detail  "Type-9 logon$(if ($offHours) { ' [OFF-HOURS]' }) from $($e.IpAddress) via $($e.ProcessName)" `
            -Evidence $e.TimeCreated.ToString('o')
        ))
    }

    return $findings
}

function Find-LHOffHoursLogons {
    <#
        Successful interactive or RDP logons outside business hours for
        accounts that also log on during normal hours (so we filter out
        pure service/batch accounts).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'Returns a collection of off-hours logon findings.')]
    param(
        [object[]]$Events4624,
        [int]$WorkHourStart = 7,
        [int]$WorkHourEnd   = 19
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    # Only interactive-ish logon types
    $human = $Events4624 | Where-Object {
        $_.LogonType -in @(2, 10) -and
        $_.AccountName -notin @('SYSTEM', '-', '') -and
        $_.AccountName -notmatch '\$$'
    }

    if (-not $human) { return $findings }

    # Accounts that also log on during work hours (not pure off-hours accounts)
    $workHourAccounts = @($human | Where-Object {
        Get-LHWorkHours -Time $_.TimeCreated -StartHour $WorkHourStart -EndHour $WorkHourEnd
    } | Select-Object -ExpandProperty AccountName -Unique)

    $offHours = $human | Where-Object {
        $_.AccountName -in $workHourAccounts -and
        -not (Get-LHWorkHours -Time $_.TimeCreated -StartHour $WorkHourStart -EndHour $WorkHourEnd)
    }

    foreach ($e in $offHours) {
        $findings.Add((New-LHFinding `
            -Type    'OffHoursLogon' `
            -Subject $e.AccountName `
            -Detail  "$($e.LogonTypeLabel) logon at $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) from $($e.IpAddress)" `
            -Evidence $e.TimeCreated.DayOfWeek.ToString()
        ))
    }

    return $findings
}

# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

function ConvertTo-LHMarkdownTable {
    param([object[]]$Rows)
    if (-not $Rows -or $Rows.Count -eq 0) { return '_(no findings)_' }
    $keys   = $Rows[0].PSObject.Properties.Name
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

function ConvertTo-LHMarkdownReport {
    param(
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Findings,
        [Parameter(Mandatory)][hashtable]$Stats
    )

    $md = [System.Collections.Generic.List[string]]::new()
    $md.Add("# LogonHunt: $HostName")
    $md.Add('')
    $md.Add("_Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')_")
    $md.Add("_Window: $($Stats.StartTime) → $($Stats.EndTime)_")
    $md.Add('')
    $md.Add("**Events analysed:** 4624=$($Stats.Count4624)  4625=$($Stats.Count4625) | **Findings:** $($Findings.Count)")
    $md.Add('')

    if ($Findings.Count -eq 0) {
        $md.Add('No anomalies detected in the selected time window.')
        return $md -join "`n"
    }

    $types = $Findings | Select-Object -ExpandProperty Type -Unique
    foreach ($t in $types) {
        $subset = @($Findings | Where-Object Type -EQ $t)
        $md.Add("## $t ($($subset.Count))")
        $md.Add('')
        $md.Add((ConvertTo-LHMarkdownTable -Rows $subset))
        $md.Add('')
    }

    $md -join "`n"
}

# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

function Invoke-LogonHunt {
    <#
    .SYNOPSIS
        Hunt Security event log 4624/4625 for logon anomalies.

    .DESCRIPTION
        Pulls logon success (4624) and failure (4625) events, then looks for:
          - Burst failures from the same source (brute force)
          - Multi-source logons for the same account (credential reuse)
          - Type-9 explicit-credential logons (runas / PTH style)
          - Off-hours interactive logons for accounts that also use business hours

        Returns a summary object and writes a Markdown report.

    .PARAMETER HoursBack
        How far back to look.  Default 24.

    .PARAMETER StartTime
        Explicit start time (overrides -HoursBack).

    .PARAMETER EndTime
        Explicit end time (defaults to now).

    .PARAMETER MaxEvents
        Cap on events fetched per event ID.  Default 10000.

    .PARAMETER BurstThreshold
        Failures from the same source in -BurstWindowMin to call it a burst.
        Default 5.

    .PARAMETER BurstWindowMin
        Rolling window size for burst detection, in minutes.  Default 5.

    .PARAMETER MultiSourceThreshold
        Distinct source IPs for the same account to call it multi-source.
        Default 3.

    .PARAMETER WorkHourStart
        Business-hours start (24h).  Default 7.

    .PARAMETER WorkHourEnd
        Business-hours end (24h).  Default 19.

    .PARAMETER OutFile
        Where to write the Markdown report.

    .PARAMETER Skip
        Detections to skip.
        Valid: BurstFailures, MultiSourceLogons, ExplicitCredentials, OffHoursLogons

    .EXAMPLE
        Invoke-LogonHunt

    .EXAMPLE
        Invoke-LogonHunt -HoursBack 48 -BurstThreshold 10 -OutFile .\logon-hunt.md
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [int]$HoursBack             = 24,
        [datetime]$StartTime        = [datetime]::MinValue,
        [datetime]$EndTime          = [datetime]::Now,

        [ValidateRange(100, 1000000)]
        [int]$MaxEvents             = 10000,

        [ValidateRange(2, 1000)]
        [int]$BurstThreshold        = 5,

        [ValidateRange(1, 60)]
        [int]$BurstWindowMin        = 5,

        [ValidateRange(2, 100)]
        [int]$MultiSourceThreshold  = 3,

        [ValidateRange(0, 23)]
        [int]$WorkHourStart         = 7,

        [ValidateRange(1, 24)]
        [int]$WorkHourEnd           = 19,

        [string]$OutFile,

        [ValidateSet('BurstFailures', 'MultiSourceLogons', 'ExplicitCredentials', 'OffHoursLogons')]
        [string[]]$Skip = @()
    )

    $clock = Get-Date

    if ($StartTime -eq [datetime]::MinValue) {
        $StartTime = $clock.AddHours(-$HoursBack)
    }

    Write-Verbose "Fetching 4624 events from $StartTime to $EndTime (max $MaxEvents)..."
    $raw4624 = @(Read-LHSecurityEvents -StartTime $StartTime -EndTime $EndTime `
                   -MaxEvents $MaxEvents -EventIds @(4624))

    Write-Verbose "Fetching 4625 events..."
    $raw4625 = @(Read-LHSecurityEvents -StartTime $StartTime -EndTime $EndTime `
                   -MaxEvents $MaxEvents -EventIds @(4625))

    Write-Verbose "Parsing $($raw4624.Count) success + $($raw4625.Count) failure events..."
    $parsed4624 = @($raw4624 | ForEach-Object { ConvertFrom-LHLogonEvent $_ } | Where-Object { $null -ne $_ })
    $parsed4625 = @($raw4625 | ForEach-Object { ConvertFrom-LHLogonEvent $_ } | Where-Object { $null -ne $_ })

    $findings = [System.Collections.Generic.List[object]]::new()

    if ('BurstFailures' -notin $Skip) {
        Write-Verbose 'Running: BurstFailures...'
        Find-LHBurstFailures -Events4625 $parsed4625 -Threshold $BurstThreshold -WindowMin $BurstWindowMin |
            ForEach-Object { $findings.Add($_) }
    }

    if ('MultiSourceLogons' -notin $Skip) {
        Write-Verbose 'Running: MultiSourceLogons...'
        Find-LHMultiSourceLogons -Events4624 $parsed4624 -Threshold $MultiSourceThreshold |
            ForEach-Object { $findings.Add($_) }
    }

    if ('ExplicitCredentials' -notin $Skip) {
        Write-Verbose 'Running: ExplicitCredentials...'
        Find-LHExplicitCredentialLogons -Events4624 $parsed4624 `
            -WorkHourStart $WorkHourStart -WorkHourEnd $WorkHourEnd |
            ForEach-Object { $findings.Add($_) }
    }

    if ('OffHoursLogons' -notin $Skip) {
        Write-Verbose 'Running: OffHoursLogons...'
        Find-LHOffHoursLogons -Events4624 $parsed4624 `
            -WorkHourStart $WorkHourStart -WorkHourEnd $WorkHourEnd |
            ForEach-Object { $findings.Add($_) }
    }

    $stats = @{
        StartTime  = $StartTime
        EndTime    = $EndTime
        Count4624  = $parsed4624.Count
        Count4625  = $parsed4625.Count
    }

    if (-not $OutFile) {
        $ts = $clock.ToString('yyyyMMdd-HHmm')
        $OutFile = ".\LogonHunt-$($env:COMPUTERNAME)-$ts.md"
    }

    $markdown = ConvertTo-LHMarkdownReport -HostName $env:COMPUTERNAME `
                    -Findings $findings -Stats $stats
    Set-Content -LiteralPath $OutFile -Value $markdown -Encoding UTF8

    [pscustomobject]@{
        HostName      = $env:COMPUTERNAME
        RunTime       = (Get-Date) - $clock
        Events4624    = $parsed4624.Count
        Events4625    = $parsed4625.Count
        FindingCount  = $findings.Count
        OutFile       = (Resolve-Path -LiteralPath $OutFile).Path
    }
}
