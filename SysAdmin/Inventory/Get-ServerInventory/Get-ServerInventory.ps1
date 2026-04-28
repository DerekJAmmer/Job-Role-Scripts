#requires -Version 7.2

<#
    Get-ServerInventory.ps1

    Collect hardware, OS, CPU, memory, disk, uptime, and pending-reboot
    status for one or more Windows hosts, then write the results to CSV,
    HTML, or both.

    See README.md for details and examples.
#>

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Private helpers — each returns one PSCustomObject
# ---------------------------------------------------------------------------

function Get-SIComputerInfo {
    <#
        Returns manufacturer, model, OS name, OS version, OS build, and
        install date from Win32_ComputerSystem and Win32_OperatingSystem.
    #>
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $ComputerName
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $ComputerName

    [PSCustomObject]@{
        Manufacturer = $cs.Manufacturer
        Model        = $cs.Model
        OSName       = $os.Caption
        OSVersion    = $os.Version
        OSBuild      = $os.BuildNumber
        InstallDate  = $os.InstallDate
    }
}

function Get-SICpuInfo {
    <#
        Returns processor name, physical cores, and logical processor count
        from Win32_Processor.
    #>
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    $cpu = Get-CimInstance -ClassName Win32_Processor -ComputerName $ComputerName |
           Select-Object -First 1

    [PSCustomObject]@{
        CpuName          = $cpu.Name.Trim()
        Cores            = $cpu.NumberOfCores
        LogicalProcessors = $cpu.NumberOfLogicalProcessors
    }
}

function Get-SIMemoryInfo {
    <#
        Returns total visible memory and free physical memory (both in MB)
        from Win32_OperatingSystem.
    #>
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $ComputerName

    [PSCustomObject]@{
        TotalMemoryMB = [math]::Round($os.TotalVisibleMemorySize / 1KB, 0)
        FreeMemoryMB  = [math]::Round($os.FreePhysicalMemory / 1KB, 0)
    }
}

function Get-SIDiskInfo {
    <#
        Returns an array of objects — one per fixed disk — with drive letter,
        size in GB, free space in GB, and percent free.
    #>
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    $disks = Get-CimInstance -ClassName Win32_LogicalDisk `
                 -Filter 'DriveType=3' -ComputerName $ComputerName

    $rows = foreach ($d in $disks) {
        $sizeGB  = [math]::Round($d.Size      / 1GB, 2)
        $freeGB  = [math]::Round($d.FreeSpace / 1GB, 2)
        $pctFree = if ($d.Size -gt 0) { [math]::Round($freeGB / $sizeGB * 100, 1) } else { 0 }

        [PSCustomObject]@{
            Drive   = $d.DeviceID
            SizeGB  = $sizeGB
            FreeGB  = $freeGB
            PctFree = $pctFree
        }
    }

    return $rows
}

function Get-SIUptime {
    <#
        Returns last boot time and computed uptime (as a TimeSpan) from
        Win32_OperatingSystem.
    #>
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $ComputerName

    [PSCustomObject]@{
        LastBootTime = $os.LastBootUpTime
        Uptime       = (Get-Date) - $os.LastBootUpTime
    }
}

function Get-SIPendingReboot {
    <#
        Checks three registry locations for pending-reboot indicators and
        returns a bool plus a list of reasons.

        Keys checked:
          HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending
          HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired
          HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager  (PendingFileRenameOperations value)
    #>
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    $reasons = [System.Collections.Generic.List[string]]::new()

    # For remote hosts this would need Invoke-Command; local-only for now.
    $cbsKey  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    $wuKey   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    $smKey   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'

    if (Test-Path -LiteralPath $cbsKey) {
        $reasons.Add('CBS reboot pending')
    }

    if (Test-Path -LiteralPath $wuKey) {
        $reasons.Add('Windows Update reboot required')
    }

    try {
        $smProps = Get-ItemProperty -LiteralPath $smKey -ErrorAction Stop
        if ($smProps.PendingFileRenameOperations) {
            $reasons.Add('PendingFileRenameOperations set')
        }
    } catch {
        # Key missing or inaccessible — not a pending reboot signal
    }

    [PSCustomObject]@{
        RebootRequired = ($reasons.Count -gt 0)
        Reasons        = $reasons.ToArray()
    }
}

# ---------------------------------------------------------------------------
# Private helper — FQDN-aware local host detection
# ---------------------------------------------------------------------------
# Fallback used when SysAdmin.Common is not loaded.  When the module IS
# imported, Get-ServerInventory delegates to the shared Test-IsLocalHost
# instead (see the reboot probe below).

function Test-SIIsLocalHost {
    param(
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Name)) { return $true }
    $lower    = $Name.ToLower()
    $compName = $env:COMPUTERNAME.ToLower()
    if ($lower -in @('.', 'localhost', $compName)) { return $true }
    if ($lower.StartsWith("$compName.")) { return $true }
    return $false
}

# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Collect hardware, OS, CPU, memory, disk, uptime, and pending-reboot
    status for one or more Windows hosts.

.DESCRIPTION
    Run this when you need a quick baseline of what's actually on a set of
    servers — OS versions, hardware specs, free disk space, uptime, and
    whether a reboot is pending. Useful before patching, after onboarding
    new machines, or as part of a regular audit cycle.

    Results go to a CSV file, an HTML report, or both. The HTML includes a
    summary line showing how many hosts were queried and how many responded.

    Unreachable hosts are recorded in the output with Status='Unreachable'
    rather than causing the whole run to fail.

.PARAMETER ComputerName
    One or more host names to inventory. Defaults to the local machine.

.PARAMETER OutputPath
    Directory where output files are written. Defaults to the current
    working directory.

.PARAMETER Format
    Output format: Csv, Html, or Both. Defaults to Both.

.EXAMPLE
    Get-ServerInventory

    Inventories the local machine and writes CSV + HTML to the current directory.

.EXAMPLE
    Get-ServerInventory -ComputerName SRV01,SRV02,SRV03 -OutputPath C:\Reports -Format Html

    Queries three servers and writes an HTML report to C:\Reports.
#>
function Get-ServerInventory {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter()]
        [string[]]$ComputerName = @($env:COMPUTERNAME),

        [Parameter()]
        [string]$OutputPath = (Get-Location).Path,

        [Parameter()]
        [ValidateSet('Csv', 'Html', 'Both')]
        [string]$Format = 'Both'
    )

    $rows    = [System.Collections.Generic.List[object]]::new()
    $reached = 0

    foreach ($h in $ComputerName) {
        Write-Verbose "Querying $h ..."

        $reachable = Test-Connection -ComputerName $h -Count 1 -Quiet -ErrorAction SilentlyContinue

        if (-not $reachable) {
            Write-Warning "Host unreachable: $h"
            $rows.Add([PSCustomObject]@{
                ComputerName      = $h
                Status            = 'Unreachable'
                Manufacturer      = $null
                Model             = $null
                OSName            = $null
                OSVersion         = $null
                OSBuild           = $null
                InstallDate       = $null
                CpuName           = $null
                Cores             = $null
                LogicalProcessors = $null
                TotalMemoryMB     = $null
                FreeMemoryMB      = $null
                Disks             = $null
                LastBootTime      = $null
                UptimeDays        = $null
                RebootRequired    = $null
                RebootReasons     = $null
            })
            continue
        }

        $reached++
        $status = 'OK'
        $errors = [System.Collections.Generic.List[string]]::new()

        # Computer / OS info
        $ci = $null
        try { $ci = Get-SIComputerInfo -ComputerName $h }
        catch { $errors.Add("ComputerInfo: $($_.Exception.Message)"); $status = 'PartialFailure' }

        # CPU
        $cpu = $null
        try { $cpu = Get-SICpuInfo -ComputerName $h }
        catch { $errors.Add("CpuInfo: $($_.Exception.Message)"); $status = 'PartialFailure' }

        # Memory
        $mem = $null
        try { $mem = Get-SIMemoryInfo -ComputerName $h }
        catch { $errors.Add("MemoryInfo: $($_.Exception.Message)"); $status = 'PartialFailure' }

        # Disks
        $disks = $null
        try { $disks = @(Get-SIDiskInfo -ComputerName $h) }
        catch { $errors.Add("DiskInfo: $($_.Exception.Message)"); $status = 'PartialFailure' }

        # Uptime
        $up = $null
        try { $up = Get-SIUptime -ComputerName $h }
        catch { $errors.Add("Uptime: $($_.Exception.Message)"); $status = 'PartialFailure' }

        # Pending reboot (local only — CIM-based remote check not implemented)
        # Use the shared helper when SysAdmin.Common is loaded; fall back to the
        # private Test-SIIsLocalHost so the script works standalone.
        $pr = $null
        $isLocal = if (Get-Command Test-IsLocalHost -ErrorAction SilentlyContinue) {
            Test-IsLocalHost -Name $h
        } else {
            Test-SIIsLocalHost -Name $h
        }
        if ($isLocal) {
            try { $pr = Get-SIPendingReboot -ComputerName $h }
            catch { $errors.Add("PendingReboot: $($_.Exception.Message)"); $status = 'PartialFailure' }
        }

        # Flatten disks to a readable string for CSV
        $diskSummary = if ($disks) {
            ($disks | ForEach-Object { "$($_.Drive) $($_.FreeGB)GB free/$($_.SizeGB)GB ($($_.PctFree)%)" }) -join '; '
        } else { $null }

        $rows.Add([PSCustomObject]@{
            ComputerName      = $h
            Status            = if ($errors.Count -gt 0) { "PartialFailure: $($errors -join ' | ')" } else { $status }
            Manufacturer      = if ($null -ne $ci)  { $ci.Manufacturer }  else { $null }
            Model             = if ($null -ne $ci)  { $ci.Model }         else { $null }
            OSName            = if ($null -ne $ci)  { $ci.OSName }        else { $null }
            OSVersion         = if ($null -ne $ci)  { $ci.OSVersion }     else { $null }
            OSBuild           = if ($null -ne $ci)  { $ci.OSBuild }       else { $null }
            InstallDate       = if ($null -ne $ci)  { $ci.InstallDate }   else { $null }
            CpuName           = if ($null -ne $cpu) { $cpu.CpuName }      else { $null }
            Cores             = if ($null -ne $cpu) { $cpu.Cores }        else { $null }
            LogicalProcessors = if ($null -ne $cpu) { $cpu.LogicalProcessors } else { $null }
            TotalMemoryMB     = if ($null -ne $mem) { $mem.TotalMemoryMB } else { $null }
            FreeMemoryMB      = if ($null -ne $mem) { $mem.FreeMemoryMB }  else { $null }
            Disks             = $diskSummary
            LastBootTime      = if ($null -ne $up)  { $up.LastBootTime }  else { $null }
            UptimeDays        = if ($null -ne $up -and $null -ne $up.Uptime) { [math]::Round($up.Uptime.TotalDays, 1) } else { $null }
            RebootRequired    = if ($null -ne $pr)  { $pr.RebootRequired } else { $null }
            RebootReasons     = if ($null -ne $pr -and $null -ne $pr.Reasons -and $pr.Reasons.Count -gt 0) { $pr.Reasons -join '; ' } else { $null }
        })
    }

    # Ensure OutputPath exists
    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $ts       = (Get-Date).ToString('yyyyMMdd-HHmm')
    $allRows  = $rows.ToArray()
    $queried  = $ComputerName.Count

    if ($Format -in 'Csv', 'Both') {
        $csvPath = Join-Path $OutputPath "ServerInventory-$ts.csv"
        $allRows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Information "CSV written to $csvPath" -InformationAction Continue
    }

    if ($Format -in 'Html', 'Both') {
        $htmlPath = Join-Path $OutputPath "ServerInventory-$ts.html"

        $css = @'
<style>
  body  { font-family: Consolas, monospace; font-size: 13px; margin: 20px; background: #f8f8f8; }
  h1    { color: #1a1a1a; }
  p     { color: #444; margin-top: 0; }
  table { border-collapse: collapse; width: 100%; background: #fff; }
  th    { background: #2c5f8a; color: #fff; padding: 6px 10px; text-align: left; }
  td    { padding: 5px 10px; border-bottom: 1px solid #ddd; }
  tr:nth-child(even) td { background: #f0f5fa; }
  tr:hover td { background: #dceaf7; }
  .status-ok       { color: #1a7a1a; font-weight: bold; }
  .status-bad      { color: #a01010; font-weight: bold; }
</style>
'@

        $preContent = @"
<h1>Server Inventory Report</h1>
<p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm') &nbsp;|&nbsp;
Hosts queried: <strong>$queried</strong> &nbsp;|&nbsp;
Hosts reachable: <strong>$reached</strong></p>
"@

        $html = $allRows |
            ConvertTo-Html -Head $css -PreContent $preContent -Title 'Server Inventory'

        $html | Set-Content -Path $htmlPath -Encoding UTF8
        Write-Information "HTML written to $htmlPath" -InformationAction Continue
    }

    return $allRows
}
