#requires -Version 7.2
<#
.SYNOPSIS
    Delete temporary files and old logs from common Windows locations.

.DESCRIPTION
    Invoke-DiskCleanup scans well-known temp and log directories, collects
    the files that match each enabled target, then deletes them — but only
    after PowerShell's ShouldProcess mechanism gives you a chance to confirm.

    By default the ConfirmImpact is 'High', so PowerShell will prompt before
    removing anything. Run with -Confirm:$false to skip the prompt (e.g. in
    scheduled tasks). Run with -WhatIf to see what would be deleted without
    touching any files.

    After the run, a report object is emitted to the pipeline. Use -OutputPath
    to also write it as a JSON file.

.PARAMETER Targets
    Names of the cleanup categories to run. Valid values:
      UserTemp      - Current user TEMP + all users AppData\Local\Temp
      WindowsTemp   - C:\Windows\Temp
      IISLogs       - IIS log files older than 7 days (skipped silently if IIS is not installed)
      OldLogs       - Windows event/CBS/WER logs older than -OldLogDays days

    Default: UserTemp, WindowsTemp, IISLogs, OldLogs (all four).

.PARAMETER OldLogDays
    For the OldLogs target: delete files that have not been modified in this
    many days. Default: 30.

.PARAMETER MinFreeGB
    Only run cleanup if the C: drive has less free space than this threshold
    (in GB). When set to 0 (the default), cleanup always runs regardless of
    free space.

.PARAMETER OutputPath
    Optional path to write a JSON report. The report includes every file
    considered, bytes reclaimed per target, and totals.

.EXAMPLE
    Invoke-DiskCleanup -WhatIf
    # Shows what would be deleted. Nothing is removed.

.EXAMPLE
    Invoke-DiskCleanup -Confirm:$false
    # Deletes files without prompting. Suitable for scheduled tasks.

.EXAMPLE
    Invoke-DiskCleanup -Targets UserTemp,WindowsTemp -Confirm:$false -OutputPath C:\Logs\cleanup.json
    # Cleans only temp dirs, skips prompts, writes a JSON report.

.EXAMPLE
    Invoke-DiskCleanup -MinFreeGB 10 -Confirm:$false
    # Only cleans if C: has less than 10 GB free.
#>
function Invoke-DiskCleanup {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter()]
        [ValidateSet('UserTemp', 'WindowsTemp', 'IISLogs', 'OldLogs')]
        [string[]]$Targets = @('UserTemp', 'WindowsTemp', 'IISLogs', 'OldLogs'),

        [Parameter()]
        [int]$OldLogDays = 30,

        [Parameter()]
        [int]$MinFreeGB = 0,

        [Parameter()]
        [string]$OutputPath
    )

    $started = [datetime]::UtcNow

    # MinFreeGB short-circuit: skip everything if drive has enough free space.
    if ($MinFreeGB -gt 0) {
        $drive = Get-PSDrive -Name C -ErrorAction SilentlyContinue
        if ($drive -and ($drive.Free / 1GB) -ge $MinFreeGB) {
            Write-Verbose "C: has $([math]::Round($drive.Free / 1GB, 1)) GB free, which meets the $MinFreeGB GB threshold. Skipping cleanup."
            $report = [PSCustomObject]@{
                Host             = $env:COMPUTERNAME
                Started          = $started
                Finished         = [datetime]::UtcNow
                Targets          = $Targets | ForEach-Object {
                    [PSCustomObject]@{
                        Name           = $_
                        Files          = @()
                        BytesReclaimed = 0
                        Skipped        = 'AboveThreshold'
                    }
                }
                TotalReclaimedMB = [double]0
            }
            if ($OutputPath) {
                $report | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputPath -Encoding UTF8
            }
            return $report
        }
    }

    $targetResults = [System.Collections.Generic.List[object]]::new()
    $totalBytes    = 0L

    foreach ($target in $Targets) {
        $files = switch ($target) {
            'UserTemp'    { @(Get-DCUserTempFile) }
            'WindowsTemp' { @(Get-DCWindowsTempFile) }
            'IISLogs'     { @(Get-DCIISLogFile) }
            'OldLogs'     { @(Get-DCOldLogFile -OldLogDays $OldLogDays) }
        }

        $deletedFiles   = [System.Collections.Generic.List[string]]::new()
        $bytesReclaimed = 0L

        foreach ($file in $files) {
            $filePath = if ($file -is [string]) { $file } else { $file.FullName }
            $fileSize = if ($file -is [string]) {
                try { (Get-Item -LiteralPath $filePath -ErrorAction Stop).Length } catch { 0 }
            }
            else {
                $file.Length
            }

            if ($PSCmdlet.ShouldProcess($filePath, 'Remove')) {
                Remove-Item -Path $filePath -Force -Recurse -ErrorAction SilentlyContinue
                $deletedFiles.Add($filePath)
                $bytesReclaimed += $fileSize
            }
        }

        $totalBytes += $bytesReclaimed
        $targetResults.Add([PSCustomObject]@{
            Name           = $target
            Files          = $deletedFiles.ToArray()
            BytesReclaimed = $bytesReclaimed
            Skipped        = ''
        })
    }

    $report = [PSCustomObject]@{
        Host             = $env:COMPUTERNAME
        Started          = $started
        Finished         = [datetime]::UtcNow
        Targets          = $targetResults.ToArray()
        TotalReclaimedMB = [double][math]::Round($totalBytes / 1MB, 2)
    }

    if ($OutputPath) {
        $report | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputPath -Encoding UTF8
    }

    return $report
}

# ---------------------------------------------------------------------------
# Collector functions — each returns FileInfo objects (or empty array).
# They accept optional -Root params so tests can pass TestDrive paths
# instead of the real system directories.
# ---------------------------------------------------------------------------

function Get-DCUserTempFile {
    <#
    .SYNOPSIS
        Returns files from the current user's TEMP folder and all user profile Temp dirs.
    #>
    [CmdletBinding()]
    param(
        [string]$Root = $env:TEMP,
        [string]$AllUsersRoot = 'C:\Users'
    )

    $results = [System.Collections.Generic.List[object]]::new()

    # Current user TEMP — top-level files only
    if (Test-Path -LiteralPath $Root) {
        Get-ChildItem -Path $Root -File -ErrorAction SilentlyContinue |
            ForEach-Object { $results.Add($_) }
    }

    # All user profiles AppData\Local\Temp — top-level files only
    if (Test-Path -LiteralPath $AllUsersRoot) {
        Get-ChildItem -Path $AllUsersRoot -Directory -ErrorAction SilentlyContinue |
            ForEach-Object {
                $tempPath = Join-Path $_.FullName 'AppData\Local\Temp'
                if (Test-Path -LiteralPath $tempPath) {
                    Get-ChildItem -Path $tempPath -File -ErrorAction SilentlyContinue |
                        ForEach-Object { $results.Add($_) }
                }
            }
    }

    return $results.ToArray()
}

function Get-DCWindowsTempFile {
    <#
    .SYNOPSIS
        Returns files from C:\Windows\Temp.
    #>
    [CmdletBinding()]
    param(
        [string]$Root = 'C:\Windows\Temp'
    )

    if (-not (Test-Path -LiteralPath $Root)) { return @() }
    return @(Get-ChildItem -Path $Root -File -ErrorAction SilentlyContinue)
}

function Get-DCIISLogFile {
    <#
    .SYNOPSIS
        Returns IIS log files older than 7 days. Returns empty if IIS is not installed.
    #>
    [CmdletBinding()]
    param(
        [string]$Root = 'C:\inetpub\logs\LogFiles'
    )

    if (-not (Test-Path -LiteralPath $Root)) { return @() }

    $cutoff = (Get-Date).AddDays(-7)
    return @(
        Get-ChildItem -Path $Root -Filter '*.log' -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $cutoff }
    )
}

function Get-DCOldLogFile {
    <#
    .SYNOPSIS
        Returns Windows log files older than the specified number of days.
    #>
    [CmdletBinding()]
    param(
        [int]$OldLogDays = 30,
        [string]$WindowsLogsRoot = 'C:\Windows\Logs',
        [string]$CbsLogsRoot     = 'C:\Windows\Logs\CBS',
        [string]$WerRoot         = 'C:\ProgramData\Microsoft\Windows\WER'
    )

    $cutoff  = (Get-Date).AddDays(-$OldLogDays)
    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($root in @($WindowsLogsRoot, $CbsLogsRoot, $WerRoot)) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        Get-ChildItem -Path $root -Filter '*.log' -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $cutoff } |
            ForEach-Object { $results.Add($_) }
    }

    return $results.ToArray()
}
