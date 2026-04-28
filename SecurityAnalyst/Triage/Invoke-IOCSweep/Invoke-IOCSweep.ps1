#requires -Version 7.2

<#
    Invoke-IOCSweep.ps1

    Sweep a host for IOC matches across four surfaces:
      - File SHA256 hashes under common exec paths (ProgramData, AppData,
        Temp, Users\Public)
      - Active TCP connections to IOC IP addresses
      - Running processes whose name matches an IOC
      - DNS client cache entries matching IOC domains

    IOCs come from a CSV or JSON file with columns/keys: type, value.
    Recognised types: sha256, ip, process, domain.

    See README.md for details and examples.
#>

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# IOC file loader
# ---------------------------------------------------------------------------

function Read-ISIocFile {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'Returns a collection of IOC entries.')]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "IOC file not found: $Path"
    }

    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    $items = switch ($ext) {
        '.json' {
            (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
        }
        '.csv' {
            Import-Csv -LiteralPath $Path
        }
        default { throw "Unsupported IOC file extension '$ext' (use .csv or .json)." }
    }

    $iocs = [System.Collections.Generic.List[object]]::new()
    foreach ($i in $items) {
        $type  = ($i.type  | Out-String).Trim().ToLowerInvariant()
        $value = ($i.value | Out-String).Trim()
        if (-not $type -or -not $value) { continue }
        if ($type -notin 'sha256','ip','process','domain') {
            Write-Warning "Skipping unsupported IOC type '$type' (value: $value)"
            continue
        }
        $iocs.Add([pscustomobject]@{ Type = $type; Value = $value })
    }

    return $iocs
}

# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

function Get-ISExecCandidatePath {
    # Default roots to scan for binary IOCs. Returns only roots that exist.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'Returns a collection of candidate exec paths.')]
    param()

    $roots = @(
        $env:ProgramData,
        (Join-Path $env:SystemDrive 'Users\Public'),
        $env:TEMP,
        (Join-Path $env:LOCALAPPDATA 'Temp'),
        $env:LOCALAPPDATA,
        $env:APPDATA
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } |
        Sort-Object -Unique

    return $roots
}

function Find-ISHashMatches {
    <#
        Walk candidate exec paths, hash files matching common executable
        extensions, and emit a finding for any SHA256 match against -HashIocs.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'Returns a collection of hash-match findings.')]
    param(
        [string[]]$HashIocs,
        [string[]]$Roots,
        [int]$MaxFiles = 5000,
        [string[]]$Extensions = @('.exe','.dll','.ps1','.psm1','.bat','.cmd','.vbs','.js','.scr')
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    if (-not $HashIocs -or $HashIocs.Count -eq 0) { return $findings }

    $wantSet = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]($HashIocs | ForEach-Object { $_.ToLowerInvariant() }),
        [System.StringComparer]::OrdinalIgnoreCase)

    $scanned = 0
    foreach ($root in $Roots) {
        $files = Get-ChildItem -LiteralPath $root -File -Recurse -Force `
                    -ErrorAction SilentlyContinue |
                 Where-Object { $Extensions -contains $_.Extension.ToLowerInvariant() }
        foreach ($f in $files) {
            if ($scanned -ge $MaxFiles) { break }
            $scanned++
            try {
                $hash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 `
                            -ErrorAction Stop).Hash
            } catch { continue }
            if ($wantSet.Contains($hash)) {
                $findings.Add([pscustomobject]@{
                    Category = 'HashMatch'
                    Ioc      = $hash
                    Subject  = $f.FullName
                    Detail   = "SHA256 match in $($f.DirectoryName) (size=$($f.Length) modified=$($f.LastWriteTime.ToString('s')))"
                })
            }
        }
        if ($scanned -ge $MaxFiles) { break }
    }
    return $findings
}

function Find-ISConnectionMatches {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'Returns a collection of TCP-connection findings.')]
    param(
        [string[]]$IpIocs
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    if (-not $IpIocs -or $IpIocs.Count -eq 0) { return $findings }

    $want = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]$IpIocs, [System.StringComparer]::OrdinalIgnoreCase)

    try {
        $conns = Get-NetTCPConnection -ErrorAction Stop
    } catch {
        Write-Warning "Get-NetTCPConnection failed: $($_.Exception.Message)"
        return $findings
    }

    foreach ($c in $conns) {
        if ($want.Contains($c.RemoteAddress)) {
            $findings.Add([pscustomobject]@{
                Category = 'NetConnection'
                Ioc      = $c.RemoteAddress
                Subject  = "$($c.RemoteAddress):$($c.RemotePort)"
                Detail   = "State=$($c.State) Local=$($c.LocalAddress):$($c.LocalPort) PID=$($c.OwningProcess)"
            })
        }
    }
    return $findings
}

function Find-ISProcessMatches {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'Returns a collection of process-match findings.')]
    param(
        [string[]]$ProcessIocs
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    if (-not $ProcessIocs -or $ProcessIocs.Count -eq 0) { return $findings }

    # Strip .exe so 'mimi.exe' and 'mimi' both compare equal.
    $want = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]($ProcessIocs | ForEach-Object { ($_ -replace '\.exe$','').ToLowerInvariant() }),
        [System.StringComparer]::OrdinalIgnoreCase)

    try {
        $procs = Get-Process -ErrorAction Stop
    } catch {
        Write-Warning "Get-Process failed: $($_.Exception.Message)"
        return $findings
    }

    foreach ($p in $procs) {
        $name = ($p.ProcessName -replace '\.exe$','').ToLowerInvariant()
        if ($want.Contains($name)) {
            $findings.Add([pscustomobject]@{
                Category = 'Process'
                Ioc      = $p.ProcessName
                Subject  = "$($p.ProcessName) (PID $($p.Id))"
                Detail   = "Path=$($p.Path) Started=$(if ($p.StartTime) { $p.StartTime.ToString('s') } else { 'unknown' })"
            })
        }
    }
    return $findings
}

function Find-ISDnsMatches {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'Returns a collection of DNS cache findings.')]
    param(
        [string[]]$DomainIocs
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    if (-not $DomainIocs -or $DomainIocs.Count -eq 0) { return $findings }

    try {
        $entries = Get-DnsClientCache -ErrorAction Stop
    } catch {
        Write-Warning "Get-DnsClientCache failed: $($_.Exception.Message)"
        return $findings
    }

    foreach ($d in $DomainIocs) {
        $needle = $d.ToLowerInvariant().TrimEnd('.')
        foreach ($e in $entries) {
            $entry = ($e.Entry      | Out-String).Trim().ToLowerInvariant().TrimEnd('.')
            $name  = ($e.Name       | Out-String).Trim().ToLowerInvariant().TrimEnd('.')
            if ($entry -eq $needle -or $name -eq $needle -or $entry.EndsWith(".$needle") -or $name.EndsWith(".$needle")) {
                $findings.Add([pscustomobject]@{
                    Category = 'Dns'
                    Ioc      = $d
                    Subject  = $e.Entry
                    Detail   = "Data=$($e.Data) Type=$($e.Type) Status=$($e.Status) TTL=$($e.TimeToLive)"
                })
            }
        }
    }
    return $findings
}

# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

function Invoke-IOCSweep {
    <#
    .SYNOPSIS
        Sweep a host for IOC matches across files, network, processes, and DNS.

    .DESCRIPTION
        Loads IOCs from a CSV or JSON file (columns: type, value) and runs
        four checks on the local host:
          - file SHA256 matches under common exec paths
          - active TCP connections to IOC IPs
          - running processes by name
          - DNS client cache entries

        Writes a JSON report at -OutputPath and returns a summary object.

    .PARAMETER IocFile
        Path to a CSV or JSON file with type and value fields.
        Supported types: sha256, ip, process, domain.

    .PARAMETER ComputerName
        Reserved for future remote use; only the local host is supported today.

    .PARAMETER OutputPath
        Where to write the JSON report. Defaults to
        .\IOCSweep-<host>-<yyyyMMdd-HHmm>.json.

    .PARAMETER MaxFiles
        Cap on files to hash (defaults to 5000). Useful to bound runtime on
        big AppData trees.

    .PARAMETER Skip
        Categories to skip. One or more of: Hash, Connection, Process, Dns.

    .EXAMPLE
        Invoke-IOCSweep -IocFile .\iocs.json

    .EXAMPLE
        Invoke-IOCSweep -IocFile .\iocs.csv -OutputPath .\out.json -Skip Dns
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$IocFile,
        [string]$ComputerName = $env:COMPUTERNAME,
        [string]$OutputPath,
        [int]$MaxFiles = 5000,
        [ValidateSet('Hash','Connection','Process','Dns')]
        [string[]]$Skip = @()
    )

    $started = Get-Date

    if ($ComputerName -ne $env:COMPUTERNAME) {
        Write-Warning "Remote sweeps are not implemented yet — running locally on $env:COMPUTERNAME."
    }

    $iocs = Read-ISIocFile -Path $IocFile
    $byType = @{
        sha256  = @($iocs | Where-Object Type -EQ 'sha256'  | ForEach-Object Value)
        ip      = @($iocs | Where-Object Type -EQ 'ip'      | ForEach-Object Value)
        process = @($iocs | Where-Object Type -EQ 'process' | ForEach-Object Value)
        domain  = @($iocs | Where-Object Type -EQ 'domain'  | ForEach-Object Value)
    }

    $findings = [System.Collections.Generic.List[object]]::new()

    if ('Hash' -notin $Skip -and $byType.sha256.Count -gt 0) {
        Write-Verbose 'Scanning files for hash matches...'
        $roots = Get-ISExecCandidatePath
        foreach ($f in (Find-ISHashMatches -HashIocs $byType.sha256 -Roots $roots -MaxFiles $MaxFiles)) {
            $findings.Add($f)
        }
    }

    if ('Connection' -notin $Skip -and $byType.ip.Count -gt 0) {
        Write-Verbose 'Checking TCP connections...'
        foreach ($f in (Find-ISConnectionMatches -IpIocs $byType.ip)) { $findings.Add($f) }
    }

    if ('Process' -notin $Skip -and $byType.process.Count -gt 0) {
        Write-Verbose 'Checking running processes...'
        foreach ($f in (Find-ISProcessMatches -ProcessIocs $byType.process)) { $findings.Add($f) }
    }

    if ('Dns' -notin $Skip -and $byType.domain.Count -gt 0) {
        Write-Verbose 'Checking DNS client cache...'
        foreach ($f in (Find-ISDnsMatches -DomainIocs $byType.domain)) { $findings.Add($f) }
    }

    if (-not $OutputPath) {
        $ts = $started.ToString('yyyyMMdd-HHmm')
        $OutputPath = ".\IOCSweep-$ComputerName-$ts.json"
    }

    $report = [pscustomobject]@{
        HostName    = $ComputerName
        GeneratedAt = (Get-Date -Format 'o')
        IocFile     = (Resolve-Path -LiteralPath $IocFile).Path
        IocCounts   = [pscustomobject]@{
            sha256  = $byType.sha256.Count
            ip      = $byType.ip.Count
            process = $byType.process.Count
            domain  = $byType.domain.Count
        }
        Findings    = @($findings)
    }

    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputPath -Encoding UTF8

    if ($findings.Count -gt 0) {
        Write-Information ("[IOCSweep] {0} match(es) found on {1}" -f $findings.Count, $ComputerName) `
            -InformationAction Continue
        $findings | Format-Table -AutoSize Category, Ioc, Subject |
            Out-String | Write-Information -InformationAction Continue
    } else {
        Write-Information "[IOCSweep] No IOC matches on $ComputerName." -InformationAction Continue
    }

    [pscustomobject]@{
        HostName     = $ComputerName
        RunTime      = (Get-Date) - $started
        IocCount     = $iocs.Count
        FindingCount = $findings.Count
        OutputPath   = (Resolve-Path -LiteralPath $OutputPath).Path
    }
}
