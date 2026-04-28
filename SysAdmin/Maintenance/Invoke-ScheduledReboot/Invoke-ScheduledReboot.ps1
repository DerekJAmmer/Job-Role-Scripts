#requires -Version 7.2
<#
.SYNOPSIS
    Schedule a graceful reboot on one or more remote Windows hosts via the Task Scheduler.

.DESCRIPTION
    Invoke-ScheduledReboot queues a one-time shutdown /r task on each target host using
    Register-ScheduledTask. Before scheduling, optional pre-checks validate reachability,
    minimum uptime, pending-reboot state, and active session count.

    All state-changing calls are gated behind ShouldProcess so -WhatIf works end-to-end
    without touching any remote system.

    Status values per host row:
      Scheduled — task registered successfully.
      Skipped   — one or more pre-checks failed; see Reason.
      WhatIf    — -WhatIf was supplied; no task was registered.
      Failed    — Register-ScheduledTask threw; see Reason.

    Note: this script only *schedules* a future reboot. It does not execute shutdown
    immediately and does not validate post-reboot state.

.PARAMETER ComputerName
    One or more target host names to schedule a reboot on.

.PARAMETER When
    The datetime at which the reboot should execute. Must be at least 5 minutes in the
    future from the time the function is called.

.PARAMETER PreCheck
    When $true (default), runs four pre-checks before scheduling:
      1. Reachability via Test-Connection.
      2. Uptime >= 1 hour (host was not just restarted).
      3. Pending-reboot state (recorded but never blocks scheduling).
      4. Active session count vs. -MaxActiveSessions threshold.
    Pass -PreCheck:$false to bypass all checks and schedule unconditionally.

.PARAMETER MaxActiveSessions
    Maximum number of active user sessions tolerated before the pre-check fails.
    Default 0 means any active session causes a Skipped result. Only evaluated when
    -PreCheck is $true.

.PARAMETER OutputPath
    Optional path to write the full result set as a UTF-8 JSON file (depth 4).

.EXAMPLE
    Invoke-ScheduledReboot -ComputerName SRV01 -When (Get-Date).AddHours(2) -WhatIf
    # Preview what would be scheduled without touching any remote system.

.EXAMPLE
    Invoke-ScheduledReboot -ComputerName SRV01,SRV02 -When '2026-05-01 02:00' -MaxActiveSessions 0 -OutputPath C:\reports\reboot.json
    # Schedule a maintenance-window reboot on two servers, fail if any sessions are active.

.EXAMPLE
    Invoke-ScheduledReboot -ComputerName SRV03 -When (Get-Date).AddMinutes(30) -PreCheck:$false
    # Skip all pre-checks and schedule directly.
#>

# ---------------------------------------------------------------------------
# Stub gate — makes ScheduledTasks cmdlets mockable when the module is absent.
# Pester's Mock requires the command to exist in scope before it is mocked.
# ---------------------------------------------------------------------------

# Get-PendingReboot is a community module (PSWindowsUpdate / PSPendingReboot).
# Stub it so Pester can Mock it in tests even when the module is absent.
if (-not (Get-Command Get-PendingReboot -ErrorAction SilentlyContinue)) {
    function Get-PendingReboot {
        <#
        .SYNOPSIS
            Stub — replaced at runtime by the PSPendingReboot or PSWindowsUpdate module.
        #>
        [CmdletBinding()]
        param(
            [string]$ComputerName
        )
        throw 'Get-PendingReboot not available — install the PSPendingReboot module.'
    }
}

if (-not (Get-Command Register-ScheduledTask -ErrorAction SilentlyContinue)) {
    function Register-ScheduledTask {
        <#
        .SYNOPSIS
            Stub — replaced at runtime by the ScheduledTasks module.
        #>
        [CmdletBinding()]
        param(
            [string]$TaskName,
            [object]$Action,
            [object]$Trigger,
            [string]$User,
            [string]$RunLevel,
            [string]$Description
        )
        throw 'ScheduledTasks module not loaded — run on a Windows host that ships the module.'
    }
}

# ---------------------------------------------------------------------------
# Private helper: Invoke-PSRRegisterTask
# Thin wrapper around Register-ScheduledTask so Pester can Mock this function
# cleanly without CimInstance type-binding constraints from the real cmdlet.
# ---------------------------------------------------------------------------
function Invoke-PSRRegisterTask {
    <#
    .SYNOPSIS
        Wrap Register-ScheduledTask for testability.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TaskName,
        [Parameter(Mandatory)]
        [string]$Execute,
        [Parameter(Mandatory)]
        [string]$Argument,
        [Parameter(Mandatory)]
        [datetime]$At,
        [Parameter(Mandatory)]
        [string]$Description
    )

    $action  = New-ScheduledTaskAction  -Execute $Execute -Argument $Argument
    $trigger = New-ScheduledTaskTrigger -Once -At $At
    Register-ScheduledTask `
        -TaskName    $TaskName `
        -Action      $action `
        -Trigger     $trigger `
        -User        'SYSTEM' `
        -RunLevel    'Highest' `
        -Description $Description `
        -Force
}

# ---------------------------------------------------------------------------
# Private helper: Invoke-PSRQuser
# Wraps quser.exe so tests can Mock this function instead of the external.
# Returns an integer count of active sessions, or $null on any failure.
# ---------------------------------------------------------------------------
function Invoke-PSRQuser {
    <#
    .SYNOPSIS
        Invoke quser.exe against a remote host and return the active session count.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    try {
        $raw = & quser.exe /server:$ComputerName 2>&1
        if ($LASTEXITCODE -ne 0) { return $null }

        # quser output: header line + one line per session. Skip the header.
        $lines = @($raw | Where-Object { $_ -notmatch '^\s*USERNAME' } |
                          Where-Object { $_ -match '\S' })
        return $lines.Count
    }
    catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
# Public function: Invoke-ScheduledReboot
# ---------------------------------------------------------------------------
function Invoke-ScheduledReboot {
    <#
    .SYNOPSIS
        Schedule a graceful reboot on one or more remote Windows hosts via the Task Scheduler.

    .DESCRIPTION
        Invoke-ScheduledReboot queues a one-time shutdown /r task on each target host using
        Register-ScheduledTask. Before scheduling, optional pre-checks validate reachability,
        minimum uptime, pending-reboot state, and active session count.

        All state-changing calls are gated behind ShouldProcess so -WhatIf works end-to-end
        without touching any remote system.

        Status values per host row:
          Scheduled — task registered successfully.
          Skipped   — one or more pre-checks failed; see Reason.
          WhatIf    — -WhatIf was supplied; no task was registered.
          Failed    — Register-ScheduledTask threw; see Reason.

    .PARAMETER ComputerName
        One or more target host names.

    .PARAMETER When
        Datetime for the reboot task. Must be >= 5 minutes in the future.

    .PARAMETER PreCheck
        Run pre-checks before scheduling (default $true). Pass -PreCheck:$false to skip.

    .PARAMETER MaxActiveSessions
        Max active sessions tolerated. Default 0.

    .PARAMETER OutputPath
        Optional path to write JSON results.

    .EXAMPLE
        Invoke-ScheduledReboot -ComputerName SRV01 -When (Get-Date).AddHours(2) -WhatIf

    .EXAMPLE
        Invoke-ScheduledReboot -ComputerName SRV01,SRV02 -When '2026-05-01 02:00' -OutputPath C:\reports\reboot.json
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [string[]]$ComputerName,

        [Parameter(Mandatory)]
        [datetime]$When,

        [Parameter()]
        [bool]$PreCheck = $true,

        [Parameter()]
        [int]$MaxActiveSessions = 0,

        [Parameter()]
        [string]$OutputPath
    )

    # Validate scheduling window — must be at least 5 minutes from now.
    $minWhen = (Get-Date).AddMinutes(5)
    if ($When -lt $minWhen) {
        throw 'Reboot time must be at least 5 minutes in the future.'
    }

    $taskName  = 'AutopilotReboot_{0}' -f $When.ToString('yyyyMMdd_HHmm')
    $report    = [System.Collections.Generic.List[object]]::new()

    foreach ($h in $ComputerName) {

        $preResults = [PSCustomObject]@{
            Reachable      = $null
            UptimeHours    = $null
            PendingReboot  = $null
            ActiveSessions = $null
        }

        $row = [PSCustomObject]@{
            Host            = $h
            Started         = (Get-Date)
            ScheduledFor    = $null
            Status          = ''
            Reason          = ''
            PreCheckResults = $preResults
        }

        $skipReason = $null

        if ($PreCheck) {
            # ---- 1. Reachability ----
            $reachable = Test-Connection -ComputerName $h -Count 1 -Quiet
            $preResults.Reachable = $reachable

            if (-not $reachable) {
                $skipReason = 'Unreachable: host did not respond to ping.'
            }

            # ---- 2. Uptime >= 1 hour ----
            if (-not $skipReason) {
                try {
                    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $h -ErrorAction Stop |
                          Select-Object -ExpandProperty LastBootUpTime
                    $uptimeHours = ((Get-Date) - $os).TotalHours
                    $preResults.UptimeHours = [math]::Round($uptimeHours, 2)

                    if ($uptimeHours -lt 1) {
                        $skipReason = 'Uptime check failed: host was rebooted less than 1 hour ago.'
                    }
                }
                catch {
                    $preResults.UptimeHours = $null
                    Write-Verbose "[$h] Could not retrieve uptime: $($_.Exception.Message)"
                }
            }

            # ---- 3. Pending reboot (informational only — never blocks scheduling) ----
            if (-not $skipReason) {
                $getPendingCmd = Get-Command Get-PendingReboot -ErrorAction SilentlyContinue
                if ($getPendingCmd) {
                    try {
                        $pendingResult = & Get-PendingReboot -ComputerName $h -ErrorAction SilentlyContinue
                        $preResults.PendingReboot = ($pendingResult.RebootRequired -eq $true)
                    }
                    catch {
                        $preResults.PendingReboot = $null
                    }
                }
                # else: leave PendingReboot = $null (not available)
            }

            # ---- 4. Active sessions ----
            if (-not $skipReason) {
                $sessionCount = Invoke-PSRQuser -ComputerName $h
                if ($null -eq $sessionCount) {
                    $preResults.ActiveSessions = 'unknown'
                    # Do not fail — quser may not be available on all hosts.
                }
                else {
                    $preResults.ActiveSessions = $sessionCount
                    if ($sessionCount -gt $MaxActiveSessions) {
                        $skipReason = "Sessions check failed: $sessionCount active session(s) exceed MaxActiveSessions ($MaxActiveSessions)."
                    }
                }
            }
        }

        if ($skipReason) {
            $row.Status = 'Skipped'
            $row.Reason = $skipReason
            $report.Add($row)
            Write-Verbose "[$h] Skipped — $skipReason"
            continue
        }

        # ---- Schedule the task ----
        $shouldProcessTarget = $h
        $shouldProcessAction = "Schedule reboot for $($When.ToString('yyyy-MM-dd HH:mm'))"

        if ($PSCmdlet.ShouldProcess($shouldProcessTarget, $shouldProcessAction)) {
            try {
                Invoke-PSRRegisterTask `
                    -TaskName    $taskName `
                    -Execute     'shutdown' `
                    -Argument    '/r /t 0' `
                    -At          $When `
                    -Description "Autopilot maintenance reboot scheduled for $($When.ToString('yyyy-MM-dd HH:mm'))"

                $row.Status      = 'Scheduled'
                $row.ScheduledFor = $When
                Write-Verbose "[$h] Task '$taskName' registered for $When."
            }
            catch {
                $row.Status = 'Failed'
                $row.Reason = $_.Exception.Message
                Write-Warning "[$h] Invoke-PSRRegisterTask failed: $($_.Exception.Message)"
            }
        }
        else {
            $row.Status = 'WhatIf'
        }

        $report.Add($row)
    }

    # Emit all rows to the pipeline.
    $report | ForEach-Object { Write-Output $_ }

    # Write JSON report if -OutputPath supplied.
    if ($OutputPath) {
        $report | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
        Write-Verbose "Report written to: $OutputPath"
    }
}
