#requires -Version 7.2

<#
    Invoke-QuickTriage.ps1

    Quick snapshot of a suspect host — run this first, ask questions later.
    Spits out a Markdown report covering processes, listeners, recent persistence,
    Defender, drop-site files, and who's in the Admins group.

    See README.md for full details.
#>

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function New-QTSection {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'In-memory factory only; touches nothing on disk.')]
    param(
        [Parameter(Mandatory)][string]$Name,
        [object[]]$Rows = @(),
        [int]$Flags = 0,
        [string]$Notes = ''
    )
    [pscustomobject]@{
        Name  = $Name
        Rows  = @($Rows)
        Flags = [int]$Flags
        Notes = $Notes
    }
}

function Test-QTSuspiciousPath {
    # Is this path somewhere a legit installer would never put a binary?
    # Checks Temp/AppData/ProgramData; skips System32 and Program Files.
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $p = $Path.ToLowerInvariant()

    $trusted = @(
        "$($env:WINDIR.ToLower())\system32",
        "$($env:WINDIR.ToLower())\syswow64",
        $env:ProgramFiles.ToLower(),
        ${env:ProgramFiles(x86)}.ToLower()
    ) | Where-Object { $_ }
    foreach ($t in $trusted) { if ($p.StartsWith($t)) { return $false } }

    $suspicious = @(
        '\appdata\local\temp\',
        '\appdata\roaming\',
        '\programdata\',
        '\users\public\',
        '\windows\temp\'
    )
    foreach ($s in $suspicious) { if ($p.Contains($s)) { return $true } }

    return $false
}

function Test-QTProcessFlag {
    # Unsigned + running from a user-writable path = worth a second look.
    param([Parameter(Mandatory)]$Process)

    $path   = [string]$Process.Path
    $signer = [string]$Process.Signer

    $isSuspiciousPath = Test-QTSuspiciousPath -Path $path
    $isTrustedSigner  = $signer -match '(?i)Microsoft|Windows Publisher'
    return ($isSuspiciousPath -and -not $isTrustedSigner)
}

$script:SignerCache = @{}
function Get-QTSigner {
    # Caching because calling Get-AuthenticodeSignature on every process is slow.
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return 'Unknown'
    }
    if ($script:SignerCache.ContainsKey($Path)) { return $script:SignerCache[$Path] }

    $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction SilentlyContinue
    $result = if ($null -eq $sig -or $sig.Status -ne 'Valid' -or -not $sig.SignerCertificate) {
        'Unsigned'
    } else {
        $sig.SignerCertificate.Subject -replace '^CN=', '' -replace ',.*$', ''
    }
    $script:SignerCache[$Path] = $result
    return $result
}

# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------

function Get-QTHost {
    param()
    try {
        $os  = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $cs  = Get-CimInstance -ClassName Win32_ComputerSystem  -ErrorAction Stop
        $rows = @([pscustomobject]@{
            HostName     = $cs.Name
            Domain       = $cs.Domain
            OS           = $os.Caption
            Version      = $os.Version
            Build        = $os.BuildNumber
            LastBoot     = $os.LastBootUpTime
            UptimeHours  = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1)
            InstallDate  = $os.InstallDate
        })
        return New-QTSection -Name 'Host' -Rows $rows
    } catch {
        return New-QTSection -Name 'Host' -Notes "Failed: $($_.Exception.Message)"
    }
}

function Get-QTSession {
    param([int]$MaxItems = 20)
    try {
        $raw = & quser.exe 2>$null
        if (-not $raw) {
            return New-QTSection -Name 'Sessions' -Notes 'No active sessions (quser returned nothing).'
        }
        $rows = @()
        foreach ($line in ($raw | Select-Object -Skip 1)) {
            if (-not $line.Trim()) { continue }
            $cols = ($line.Trim() -split '\s{2,}')
            if ($cols.Count -ge 4) {
                $rows += [pscustomobject]@{
                    User        = $cols[0].TrimStart('>')
                    SessionName = $cols[1]
                    State       = $cols[-3]
                    IdleTime    = $cols[-2]
                    LogonTime   = $cols[-1]
                }
            }
        }
        return New-QTSection -Name 'Sessions' -Rows ($rows | Select-Object -First $MaxItems)
    } catch {
        return New-QTSection -Name 'Sessions' -Notes "Failed: $($_.Exception.Message)"
    }
}

function Get-QTProcess {
    param([int]$MaxItems = 20)
    try {
        $procs = Get-CimInstance -ClassName Win32_Process -ErrorAction Stop |
            Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine
        $rows = @()
        foreach ($p in $procs) {
            $signer = Get-QTSigner -Path $p.ExecutablePath
            $row = [pscustomobject]@{
                PID         = $p.ProcessId
                PPID        = $p.ParentProcessId
                Name        = $p.Name
                Path        = $p.ExecutablePath
                Signer      = $signer
                CommandLine = if ($p.CommandLine) { $p.CommandLine.Substring(0, [math]::Min(120, $p.CommandLine.Length)) } else { '' }
                Flagged     = $false
            }
            $row.Flagged = Test-QTProcessFlag -Process $row
            $rows += $row
        }
        $flaggedFirst = @($rows | Where-Object Flagged) + @($rows | Where-Object { -not $_.Flagged })
        $shown = $flaggedFirst | Select-Object -First $MaxItems
        $flags = @($rows | Where-Object Flagged).Count
        return New-QTSection -Name 'Processes' -Rows $shown -Flags $flags
    } catch {
        return New-QTSection -Name 'Processes' -Notes "Failed: $($_.Exception.Message)"
    }
}

function Get-QTListener {
    # Covers both listening ports and established outbound — both matter for C2 hunting.
    param([int]$MaxItems = 30)
    try {
        $conns = Get-NetTCPConnection -State Listen, Established -ErrorAction Stop
        $rows = @()
        $flags = 0
        foreach ($c in $conns) {
            $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
            $path = if ($proc) { $proc.Path } else { $null }
            $suspiciousPath = Test-QTSuspiciousPath -Path $path
            # Flag: listening on high port from a weird path, or established to external IP from weird path
            $isExternal = $c.State -eq 'Established' -and
                          $c.RemoteAddress -notin @('0.0.0.0','::','127.0.0.1','::1') -and
                          -not $c.RemoteAddress.StartsWith('10.') -and
                          -not $c.RemoteAddress.StartsWith('192.168.') -and
                          -not $c.RemoteAddress.StartsWith('172.')
            $flagged = $suspiciousPath -and ($c.LocalPort -ge 1024 -or $isExternal)
            if ($flagged) { $flags++ }
            $rows += [pscustomobject]@{
                State         = $c.State
                LocalAddress  = $c.LocalAddress
                LocalPort     = $c.LocalPort
                RemoteAddress = $c.RemoteAddress
                RemotePort    = $c.RemotePort
                PID           = $c.OwningProcess
                Process       = if ($proc) { $proc.ProcessName } else { '?' }
                Path          = $path
                Flagged       = $flagged
            }
        }
        $flaggedFirst = @($rows | Where-Object Flagged) + @($rows | Where-Object { -not $_.Flagged })
        return New-QTSection -Name 'Connections' -Rows ($flaggedFirst | Select-Object -First $MaxItems) -Flags $flags
    } catch {
        return New-QTSection -Name 'Connections' -Notes "Failed: $($_.Exception.Message)"
    }
}

function Get-QTRecentPersistence {
    param([int]$MaxItems = 20)
    try {
        $cutoff = (Get-Date).AddDays(-30)
        $rows = @()
        $flags = 0

        $services = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
            Select-Object Name, DisplayName, PathName, StartMode, State
        foreach ($s in $services) {
            if (-not $s.PathName) { continue }
            $exePath = ($s.PathName -replace '^"([^"]+)".*$', '$1') -replace '\s.*$', ''
            $file = Get-Item -LiteralPath $exePath -ErrorAction SilentlyContinue
            if ($file -and $file.CreationTime -ge $cutoff) {
                $signer = Get-QTSigner -Path $file.FullName
                $flagged = $signer -notmatch '(?i)Microsoft|Windows Publisher'
                if ($flagged) { $flags++ }
                $rows += [pscustomobject]@{
                    Kind    = 'Service'
                    Name    = $s.Name
                    Path    = $file.FullName
                    Created = $file.CreationTime
                    Signer  = $signer
                    Flagged = $flagged
                }
            }
        }

        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        foreach ($t in $tasks) {
            if ($t.Date -and ([datetime]$t.Date) -ge $cutoff) {
                $action = ($t.Actions | Select-Object -First 1).Execute
                $signer = if ($action) { Get-QTSigner -Path $action } else { 'Unknown' }
                $flagged = $signer -notmatch '(?i)Microsoft|Windows Publisher'
                if ($flagged) { $flags++ }
                $rows += [pscustomobject]@{
                    Kind    = 'Task'
                    Name    = "$($t.TaskPath)$($t.TaskName)"
                    Path    = $action
                    Created = $t.Date
                    Signer  = $signer
                    Flagged = $flagged
                }
            }
        }

        $rows = $rows | Sort-Object Created -Descending
        return New-QTSection -Name 'RecentPersistence' -Rows ($rows | Select-Object -First $MaxItems) -Flags $flags
    } catch {
        return New-QTSection -Name 'RecentPersistence' -Notes "Failed: $($_.Exception.Message)"
    }
}

function Get-QTDropsiteFile {
    param([int]$MaxItems = 20)
    try {
        $cutoff = (Get-Date).AddDays(-7)
        $roots = @(
            $env:TEMP,
            (Join-Path $env:APPDATA ''),
            $env:ProgramData
        ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

        $rows = @()
        foreach ($root in $roots) {
            $hits = Get-ChildItem -Path $root -Recurse -File -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $cutoff -and $_.Extension -match '(?i)^\.(exe|dll|ps1|bat|vbs|js|hta|lnk|scr|cpl|jar)$' } |
                Select-Object -First 50
            foreach ($f in $hits) {
                $rows += [pscustomobject]@{
                    Path       = $f.FullName
                    SizeKB     = [math]::Round($f.Length / 1KB, 1)
                    Modified   = $f.LastWriteTime
                    Extension  = $f.Extension
                }
            }
        }
        $rows = $rows | Sort-Object Modified -Descending | Select-Object -First $MaxItems
        return New-QTSection -Name 'DropsiteFiles' -Rows $rows -Flags $rows.Count
    } catch {
        return New-QTSection -Name 'DropsiteFiles' -Notes "Failed: $($_.Exception.Message)"
    }
}

function Get-QTDefender {
    # Status goes in Notes (single-row tables look silly); threats go in Rows.
    param([int]$MaxItems = 20)
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        $statusNote = "AM=$($status.AMServiceEnabled) | RealTime=$($status.RealTimeProtectionEnabled) | " +
                      "Tamper=$($status.IsTamperProtected) | DefsAge=$($status.AntivirusSignatureAge)d | " +
                      "Engine=$($status.AMEngineVersion)"

        $threats = Get-MpThreatDetection -ErrorAction SilentlyContinue |
            Select-Object -First $MaxItems ThreatID, InitialDetectionTime, ProcessName, Resources

        $threatRows = foreach ($t in $threats) {
            [pscustomobject]@{
                DetectedAt = $t.InitialDetectionTime
                ThreatID   = $t.ThreatID
                Process    = $t.ProcessName
                Resources  = ($t.Resources -join '; ')
            }
        }

        $flags = @($threats).Count
        return New-QTSection -Name 'Defender' -Rows @($threatRows) -Flags $flags -Notes $statusNote
    } catch {
        return New-QTSection -Name 'Defender' -Notes "Failed: $($_.Exception.Message)"
    }
}

function Get-QTPSHistory {
    param([int]$MaxItems = 20)
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-PowerShell/Operational'
            Id      = 4104
        } -MaxEvents 100 -ErrorAction Stop

        $rows = foreach ($e in ($events | Select-Object -First $MaxItems)) {
            $text = ($e.Message -split "`n" | Select-Object -First 1).Trim()
            [pscustomobject]@{
                Time     = $e.TimeCreated
                User     = $e.UserId
                Level    = $e.LevelDisplayName
                Preview  = if ($text.Length -gt 120) { $text.Substring(0, 120) + '...' } else { $text }
            }
        }
        return New-QTSection -Name 'PSHistory' -Rows $rows
    } catch {
        return New-QTSection -Name 'PSHistory' -Notes 'Unavailable (requires elevation and ScriptBlock logging enabled).'
    }
}

function Get-QTAdminMembership {
    param([int]$MaxItems = 20)
    try {
        $members = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
        $rows = foreach ($m in ($members | Select-Object -First $MaxItems)) {
            [pscustomobject]@{
                Name         = $m.Name
                ObjectClass  = $m.ObjectClass
                PrincipalSrc = $m.PrincipalSource
                SID          = $m.SID
            }
        }
        return New-QTSection -Name 'AdminMembership' -Rows $rows
    } catch {
        return New-QTSection -Name 'AdminMembership' -Notes "Failed: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

function ConvertTo-QTMarkdownTable {
    param([object[]]$Rows)

    if (-not $Rows -or $Rows.Count -eq 0) { return '_(no rows)_' }
    $keys = $Rows[0].PSObject.Properties.Name
    $header = '| ' + ($keys -join ' | ') + ' |'
    $sep    = '| ' + (($keys | ForEach-Object { '---' }) -join ' | ') + ' |'
    $lines  = foreach ($r in $Rows) {
        $cells = foreach ($k in $keys) {
            $v = $r.$k
            if ($null -eq $v) { '' }
            else { (($v.ToString() -replace '\|', '\|') -replace '\r?\n', ' ') }
        }
        '| ' + ($cells -join ' | ') + ' |'
    }
    ($header, $sep) + $lines -join "`n"
}

function ConvertTo-QTMarkdownReport {
    param(
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][object[]]$Sections
    )

    $md = [System.Collections.Generic.List[string]]::new()
    $md.Add("# QuickTriage: $HostName")
    $md.Add('')
    $md.Add("_Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')_")
    $md.Add('')
    $totalFlags = ($Sections | Measure-Object -Property Flags -Sum).Sum
    $md.Add("**Sections:** $($Sections.Count) | **Flagged items:** $totalFlags")
    $md.Add('')

    foreach ($s in $Sections) {
        $flagMark = if ($s.Flags -gt 0) { ' ⚠' } else { '' }
        $md.Add("## $($s.Name)$flagMark")
        if ($s.Notes) { $md.Add("_$($s.Notes)_"); $md.Add('') }
        if ($s.Flags -gt 0) { $md.Add("**Flagged: $($s.Flags)**"); $md.Add('') }
        $md.Add((ConvertTo-QTMarkdownTable -Rows $s.Rows))
        $md.Add('')
    }
    $md -join "`n"
}

# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------

function Invoke-QuickTriage {
    <#
    .SYNOPSIS
        Quick-and-dirty triage snapshot of the local host, written to Markdown.

    .DESCRIPTION
        Pulls together the stuff you'd check in the first few minutes on a
        suspect box: process list with signers, open listeners, recent
        persistence (services/tasks), drop-site files, Defender state, PS
        ScriptBlock history, and who's in the Admins group.

        Anything that looks off gets flagged with ⚠ in the report. Works
        without admin — some sections just skip and say why.

    .PARAMETER ComputerName
        Who to run against. Remote support isn't wired up yet (v1 = localhost
        only), but the parameter is there for when it is.

    .PARAMETER OutFile
        Where to write the .md report. Defaults to
        ./QuickTriage-<host>-<yyyyMMdd-HHmm>.md.

    .PARAMETER Skip
        Sections to leave out. Handy when you don't have admin and just want
        the stuff that doesn't need it.
        Valid: Host, Sessions, Processes, Connections, RecentPersistence,
               DropsiteFiles, Defender, PSHistory, AdminMembership

    .PARAMETER MaxItems
        Row cap per section. Default 20.

    .EXAMPLE
        Invoke-QuickTriage

    .EXAMPLE
        Invoke-QuickTriage -OutFile .\triage.md -Skip PSHistory,DropsiteFiles -MaxItems 10
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string[]]$ComputerName = @($env:COMPUTERNAME),

        [string]$OutFile,

        [ValidateSet('Host', 'Sessions', 'Processes', 'Connections',
                     'RecentPersistence', 'DropsiteFiles', 'Defender',
                     'PSHistory', 'AdminMembership')]
        [string[]]$Skip = @(),

        [ValidateRange(1, 1000)]
        [int]$MaxItems = 20
    )

    if ($ComputerName.Count -gt 1 -or $ComputerName[0] -ne $env:COMPUTERNAME) {
        Write-Warning "Remote execution isn't wired up yet — running against localhost."
    }

    $started = Get-Date
    $hostName = $env:COMPUTERNAME

    $allCollectors = [ordered]@{
        Host              = 'Get-QTHost'
        Sessions          = 'Get-QTSession'
        Processes         = 'Get-QTProcess'
        Connections       = 'Get-QTListener'
        RecentPersistence = 'Get-QTRecentPersistence'
        DropsiteFiles     = 'Get-QTDropsiteFile'
        Defender          = 'Get-QTDefender'
        PSHistory         = 'Get-QTPSHistory'
        AdminMembership   = 'Get-QTAdminMembership'
    }

    $sections = [System.Collections.Generic.List[object]]::new()
    foreach ($name in $allCollectors.Keys) {
        if ($Skip -contains $name) { continue }
        Write-Verbose "Collecting: $name"
        $fn = $allCollectors[$name]
        $sections.Add((& $fn -MaxItems $MaxItems))
    }

    if (-not $OutFile) {
        $ts = $started.ToString('yyyyMMdd-HHmm')
        $OutFile = ".\QuickTriage-$hostName-$ts.md"
    }

    $markdown = ConvertTo-QTMarkdownReport -HostName $hostName -Sections $sections
    Set-Content -LiteralPath $OutFile -Value $markdown -Encoding UTF8

    $totalFlags = ($sections | Measure-Object -Property Flags -Sum).Sum
    [pscustomobject]@{
        HostName     = $hostName
        RunTime      = (Get-Date) - $started
        SectionCount = $sections.Count
        FlagCount    = [int]$totalFlags
        OutFile      = (Resolve-Path -LiteralPath $OutFile).Path
    }
}
