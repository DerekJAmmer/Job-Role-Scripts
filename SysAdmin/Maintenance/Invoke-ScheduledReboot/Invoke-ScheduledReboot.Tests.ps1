#requires -Version 7.2

BeforeAll {
    . (Join-Path $PSScriptRoot 'Invoke-ScheduledReboot.ps1')

    # Shared helpers — defined inside BeforeAll so they live in Pester's script scope.
    # Returns a datetime guaranteed to be at least 5 minutes and 1 second in the future.
    function script:Get-BoundaryWhen { (Get-Date).AddMinutes(5).AddSeconds(1) }

    # Returns a datetime well in the future — no $When validation concern.
    function script:Get-FutureWhen   { (Get-Date).AddHours(2) }
}

# ---------------------------------------------------------------------------
# T01 — $When in the past throws with the pinned message
# ---------------------------------------------------------------------------
Describe 'Invoke-ScheduledReboot — When validation: past' {
    It 'throws with exact message when When is in the past' {
        $past = (Get-Date).AddHours(-1)
        { Invoke-ScheduledReboot -ComputerName 'SRV01' -When $past } |
            Should -Throw -ExpectedMessage 'Reboot time must be at least 5 minutes in the future.'
    }
}

# ---------------------------------------------------------------------------
# T02 — $When < 5 minutes future throws
# ---------------------------------------------------------------------------
Describe 'Invoke-ScheduledReboot — When validation: less than 5 minutes' {
    It 'throws when When is only 4 minutes in the future' {
        $tooSoon = (Get-Date).AddMinutes(4)
        { Invoke-ScheduledReboot -ComputerName 'SRV01' -When $tooSoon } |
            Should -Throw -ExpectedMessage 'Reboot time must be at least 5 minutes in the future.'
    }
}

# ---------------------------------------------------------------------------
# T03 — $When exactly 5 minutes future does NOT throw (boundary test)
# -Confirm:$false bypasses the HighImpact ShouldProcess prompt in test context.
# ---------------------------------------------------------------------------
Describe 'Invoke-ScheduledReboot — When validation: boundary 5 minutes' {
    BeforeAll {
        Mock Test-Connection        { $true }
        Mock Get-CimInstance        { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddHours(-5) } }
        Mock Invoke-PSRQuser        { return 0 }
        Mock Invoke-PSRRegisterTask { }
    }

    It 'does not throw when When is exactly 5 minutes and 1 second in the future' {
        $boundary = Get-BoundaryWhen
        { Invoke-ScheduledReboot -ComputerName 'SRV01' -When $boundary -Confirm:$false } | Should -Not -Throw
    }
}

# ---------------------------------------------------------------------------
# T04 — Pre-check fail: unreachable
# ---------------------------------------------------------------------------
Describe 'Invoke-ScheduledReboot — Pre-check: unreachable host' {
    BeforeAll {
        Mock Test-Connection        { $false }
        Mock Invoke-PSRRegisterTask { }
    }

    It 'sets Status=Skipped when host is unreachable' {
        $result = @(Invoke-ScheduledReboot -ComputerName 'SRV01' -When (Get-FutureWhen) -Confirm:$false)
        $result[0].Status | Should -Be 'Skipped'
    }

    It 'sets Reason matching /Unreachable/i when host is unreachable' {
        $result = @(Invoke-ScheduledReboot -ComputerName 'SRV01' -When (Get-FutureWhen) -Confirm:$false)
        $result[0].Reason | Should -Match 'Unreachable'
    }

    It 'does not call Invoke-PSRRegisterTask when host is unreachable' {
        Invoke-ScheduledReboot -ComputerName 'SRV01' -When (Get-FutureWhen) -Confirm:$false | Out-Null
        Should -Invoke Invoke-PSRRegisterTask -Times 0 -Exactly
    }
}

# ---------------------------------------------------------------------------
# T05 — Pre-check fail: uptime < 1 hour
# ---------------------------------------------------------------------------
Describe 'Invoke-ScheduledReboot — Pre-check: uptime too low' {
    BeforeAll {
        Mock Test-Connection        { $true }
        Mock Get-CimInstance        { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddMinutes(-30) } }
        Mock Invoke-PSRRegisterTask { }
    }

    It 'sets Status=Skipped when uptime is less than 1 hour' {
        $result = @(Invoke-ScheduledReboot -ComputerName 'SRV01' -When (Get-FutureWhen) -Confirm:$false)
        $result[0].Status | Should -Be 'Skipped'
    }

    It 'sets Reason matching /uptime/i when uptime check fails' {
        $result = @(Invoke-ScheduledReboot -ComputerName 'SRV01' -When (Get-FutureWhen) -Confirm:$false)
        $result[0].Reason | Should -Match 'uptime'
    }
}

# ---------------------------------------------------------------------------
# T06 — Pre-check fail: too many active sessions
# ---------------------------------------------------------------------------
Describe 'Invoke-ScheduledReboot — Pre-check: too many sessions' {
    BeforeAll {
        Mock Test-Connection        { $true }
        Mock Get-CimInstance        { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddHours(-5) } }
        Mock Invoke-PSRQuser        { return 3 }
        Mock Invoke-PSRRegisterTask { }
    }

    It 'sets Status=Skipped when active sessions exceed MaxActiveSessions' {
        $result = @(Invoke-ScheduledReboot -ComputerName 'SRV01' -When (Get-FutureWhen) -MaxActiveSessions 0 -Confirm:$false)
        $result[0].Status | Should -Be 'Skipped'
    }

    It 'sets Reason matching /sessions/i when session check fails' {
        $result = @(Invoke-ScheduledReboot -ComputerName 'SRV01' -When (Get-FutureWhen) -MaxActiveSessions 0 -Confirm:$false)
        $result[0].Reason | Should -Match 'sessions'
    }
}

# ---------------------------------------------------------------------------
# T07 — quser failure tolerated: Status=Scheduled, ActiveSessions='unknown'
# ---------------------------------------------------------------------------
Describe 'Invoke-ScheduledReboot — quser failure is tolerated' {
    BeforeAll {
        Mock Test-Connection        { $true }
        Mock Get-CimInstance        { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddHours(-5) } }
        Mock Invoke-PSRQuser        { return $null }
        Mock Invoke-PSRRegisterTask { }
    }

    It 'sets Status=Scheduled when quser returns null (failure tolerated)' {
        $result = @(Invoke-ScheduledReboot -ComputerName 'SRV01' -When (Get-FutureWhen) -Confirm:$false)
        $result[0].Status | Should -Be 'Scheduled'
    }

    It 'sets PreCheckResults.ActiveSessions to ''unknown'' when quser returns null' {
        $result = @(Invoke-ScheduledReboot -ComputerName 'SRV01' -When (Get-FutureWhen) -Confirm:$false)
        $result[0].PreCheckResults.ActiveSessions | Should -Be 'unknown'
    }
}

# ---------------------------------------------------------------------------
# T08 — Happy path: all checks pass, task registered once
# ---------------------------------------------------------------------------
Describe 'Invoke-ScheduledReboot — happy path' {
    BeforeAll {
        Mock Test-Connection        { $true }
        Mock Get-CimInstance        { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddHours(-5) } }
        Mock Invoke-PSRQuser        { return 0 }
        Mock Invoke-PSRRegisterTask { }
    }

    It 'sets Status=Scheduled on success' {
        $result = @(Invoke-ScheduledReboot -ComputerName 'SRV01' -When (Get-FutureWhen) -Confirm:$false)
        $result[0].Status | Should -Be 'Scheduled'
    }

    It 'populates ScheduledFor on success' {
        $when   = Get-FutureWhen
        $result = @(Invoke-ScheduledReboot -ComputerName 'SRV01' -When $when -Confirm:$false)
        $result[0].ScheduledFor | Should -Be $when
    }

    It 'calls Invoke-PSRRegisterTask exactly once' {
        Invoke-ScheduledReboot -ComputerName 'SRV01' -When (Get-FutureWhen) -Confirm:$false | Out-Null
        Should -Invoke Invoke-PSRRegisterTask -Times 1 -Exactly
    }
}

# ---------------------------------------------------------------------------
# T09 — -WhatIf mode: no task registered, Status=WhatIf
# ---------------------------------------------------------------------------
Describe 'Invoke-ScheduledReboot — WhatIf mode' {
    BeforeAll {
        Mock Test-Connection        { $true }
        Mock Get-CimInstance        { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddHours(-5) } }
        Mock Invoke-PSRQuser        { return 0 }
        Mock Invoke-PSRRegisterTask { }
    }

    It 'sets Status=WhatIf when -WhatIf is supplied' {
        $result = @(Invoke-ScheduledReboot -ComputerName 'SRV01' -When (Get-FutureWhen) -WhatIf)
        $result[0].Status | Should -Be 'WhatIf'
    }

    It 'does not call Invoke-PSRRegisterTask when -WhatIf is supplied' {
        Invoke-ScheduledReboot -ComputerName 'SRV01' -When (Get-FutureWhen) -WhatIf | Out-Null
        Should -Invoke Invoke-PSRRegisterTask -Times 0 -Exactly
    }
}

# ---------------------------------------------------------------------------
# T10 — Multi-host mixed result
# ---------------------------------------------------------------------------
Describe 'Invoke-ScheduledReboot — multi-host mixed result' {
    BeforeAll {
        # Host 1: reachable, good uptime, no sessions → Scheduled
        # Host 2: unreachable → Skipped
        # Host 3: uptime too low → Skipped

        Mock Test-Connection -ParameterFilter { $ComputerName -eq 'SRV01' } { $true }
        Mock Test-Connection -ParameterFilter { $ComputerName -eq 'SRV02' } { $false }
        Mock Test-Connection -ParameterFilter { $ComputerName -eq 'SRV03' } { $true }

        Mock Get-CimInstance -ParameterFilter { $ComputerName -eq 'SRV01' } {
            [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddHours(-5) }
        }
        Mock Get-CimInstance -ParameterFilter { $ComputerName -eq 'SRV03' } {
            [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddMinutes(-10) }
        }

        Mock Invoke-PSRQuser        { return 0 }
        Mock Invoke-PSRRegisterTask { }
    }

    It 'returns 3 rows for 3 hosts' {
        $result = @(Invoke-ScheduledReboot -ComputerName 'SRV01','SRV02','SRV03' -When (Get-FutureWhen) -Confirm:$false)
        $result.Count | Should -Be 3
    }

    It 'first host (SRV01) is Scheduled' {
        $result = @(Invoke-ScheduledReboot -ComputerName 'SRV01','SRV02','SRV03' -When (Get-FutureWhen) -Confirm:$false)
        $result[0].Status | Should -Be 'Scheduled'
    }

    It 'second host (SRV02) is Skipped (unreachable)' {
        $result = @(Invoke-ScheduledReboot -ComputerName 'SRV01','SRV02','SRV03' -When (Get-FutureWhen) -Confirm:$false)
        $result[1].Status | Should -Be 'Skipped'
    }

    It 'third host (SRV03) is Skipped (uptime)' {
        $result = @(Invoke-ScheduledReboot -ComputerName 'SRV01','SRV02','SRV03' -When (Get-FutureWhen) -Confirm:$false)
        $result[2].Status | Should -Be 'Skipped'
    }
}

# ---------------------------------------------------------------------------
# T11 — -PreCheck:$false skips all checks, schedules even unreachable host
# ---------------------------------------------------------------------------
Describe 'Invoke-ScheduledReboot — PreCheck disabled' {
    BeforeAll {
        Mock Test-Connection        { $false }   # Would fail if checked
        Mock Invoke-PSRRegisterTask { }
    }

    It 'sets Status=Scheduled when -PreCheck:$false even if host is unreachable' {
        $result = @(Invoke-ScheduledReboot -ComputerName 'SRV01' -When (Get-FutureWhen) -PreCheck:$false -Confirm:$false)
        $result[0].Status | Should -Be 'Scheduled'
    }

    It 'does not call Test-Connection when -PreCheck:$false' {
        Invoke-ScheduledReboot -ComputerName 'SRV01' -When (Get-FutureWhen) -PreCheck:$false -Confirm:$false | Out-Null
        Should -Invoke Test-Connection -Times 0 -Exactly
    }

    It 'does not call Get-CimInstance when -PreCheck:$false' {
        Mock Get-CimInstance { }
        Invoke-ScheduledReboot -ComputerName 'SRV01' -When (Get-FutureWhen) -PreCheck:$false -Confirm:$false | Out-Null
        Should -Invoke Get-CimInstance -Times 0 -Exactly
    }
}

# ---------------------------------------------------------------------------
# T12 — -OutputPath writes JSON file
# ---------------------------------------------------------------------------
Describe 'Invoke-ScheduledReboot — OutputPath writes JSON' {
    BeforeAll {
        Mock Test-Connection        { $true }
        Mock Get-CimInstance        { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddHours(-5) } }
        Mock Invoke-PSRQuser        { return 0 }
        Mock Invoke-PSRRegisterTask { }
    }

    It 'creates a file at -OutputPath' {
        $outFile = Join-Path $TestDrive 'reboot-report.json'
        Invoke-ScheduledReboot -ComputerName 'SRV01' -When (Get-FutureWhen) -OutputPath $outFile -Confirm:$false | Out-Null
        Test-Path -LiteralPath $outFile | Should -Be $true
    }

    It 'written file contains valid JSON with the host row' {
        $outFile = Join-Path $TestDrive 'reboot-report2.json'
        Invoke-ScheduledReboot -ComputerName 'SRV01' -When (Get-FutureWhen) -OutputPath $outFile -Confirm:$false | Out-Null
        $json = Get-Content -LiteralPath $outFile -Raw | ConvertFrom-Json
        $json[0].Host | Should -Be 'SRV01'
    }
}

# ---------------------------------------------------------------------------
# T13 — Invoke-PSRRegisterTask throws: Status=Failed, continues to next host
# ---------------------------------------------------------------------------
Describe 'Invoke-ScheduledReboot — Invoke-PSRRegisterTask throws' {
    BeforeAll {
        Mock Test-Connection        { $true }
        Mock Get-CimInstance        { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddHours(-5) } }
        Mock Invoke-PSRQuser        { return 0 }
        Mock Invoke-PSRRegisterTask { throw 'Access denied' }
    }

    It 'sets Status=Failed when Invoke-PSRRegisterTask throws' {
        $result = @(Invoke-ScheduledReboot -ComputerName 'SRV01' -When (Get-FutureWhen) -Confirm:$false)
        $result[0].Status | Should -Be 'Failed'
    }

    It 'sets Reason containing the exception message' {
        $result = @(Invoke-ScheduledReboot -ComputerName 'SRV01' -When (Get-FutureWhen) -Confirm:$false)
        $result[0].Reason | Should -Match 'Access denied'
    }

    It 'continues processing next host after Invoke-PSRRegisterTask throws' {
        # First host fails, second host succeeds.
        $script:registerCallCount = 0
        Mock Invoke-PSRRegisterTask {
            $script:registerCallCount++
            if ($script:registerCallCount -eq 1) { throw 'Access denied' }
        }

        $script:registerCallCount = 0
        $result = @(Invoke-ScheduledReboot -ComputerName 'SRV01','SRV02' -When (Get-FutureWhen) -Confirm:$false)
        $result.Count | Should -Be 2
        $result[1].Status | Should -Be 'Scheduled'
    }
}

# ---------------------------------------------------------------------------
# T14 — PendingReboot recorded but does not gate scheduling
#
# The stub in Invoke-ScheduledReboot.ps1 means Get-PendingReboot is always in
# scope after dot-sourcing. Get-Command finds it and the try block runs.
# We mock its output to RebootRequired=$true and verify it is recorded without
# blocking the Scheduled status.
# ---------------------------------------------------------------------------
Describe 'Invoke-ScheduledReboot — PendingReboot informational only' {
    BeforeAll {
        Mock Test-Connection        { $true }
        Mock Get-CimInstance        { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddHours(-5) } }
        Mock Invoke-PSRQuser        { return 0 }
        Mock Invoke-PSRRegisterTask { }

        # Stub is always present after dot-source; mock its output.
        Mock Get-PendingReboot {
            [PSCustomObject]@{ RebootRequired = $true }
        }
    }

    It 'records PendingReboot=$true in PreCheckResults' {
        $result = @(Invoke-ScheduledReboot -ComputerName 'SRV01' -When (Get-FutureWhen) -Confirm:$false)
        $result[0].PreCheckResults.PendingReboot | Should -Be $true
    }

    It 'still sets Status=Scheduled even when PendingReboot=$true' {
        $result = @(Invoke-ScheduledReboot -ComputerName 'SRV01' -When (Get-FutureWhen) -Confirm:$false)
        $result[0].Status | Should -Be 'Scheduled'
    }
}

# ---------------------------------------------------------------------------
# T15 — Get-PendingReboot throws: PendingReboot=$null, still Scheduled
#
# The script calls Get-PendingReboot inside a try/catch. When it throws,
# PendingReboot is left $null and processing continues to scheduling.
# ---------------------------------------------------------------------------
Describe 'Invoke-ScheduledReboot — Get-PendingReboot throws' {
    BeforeAll {
        Mock Test-Connection        { $true }
        Mock Get-CimInstance        { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddHours(-5) } }
        Mock Invoke-PSRQuser        { return 0 }
        Mock Invoke-PSRRegisterTask { }

        # Simulate Get-PendingReboot failing at runtime (caught gracefully).
        Mock Get-PendingReboot { throw 'Get-PendingReboot module not available' }
    }

    It 'leaves PreCheckResults.PendingReboot as $null when Get-PendingReboot throws' {
        $result = @(Invoke-ScheduledReboot -ComputerName 'SRV01' -When (Get-FutureWhen) -Confirm:$false)
        $result[0].PreCheckResults.PendingReboot | Should -BeNullOrEmpty
    }

    It 'sets Status=Scheduled even when Get-PendingReboot throws' {
        $result = @(Invoke-ScheduledReboot -ComputerName 'SRV01' -When (Get-FutureWhen) -Confirm:$false)
        $result[0].Status | Should -Be 'Scheduled'
    }
}

# ---------------------------------------------------------------------------
# T16 — Task name matches deterministic format AutopilotReboot_yyyyMMdd_HHmm
# ---------------------------------------------------------------------------
Describe 'Invoke-ScheduledReboot — task name deterministic format' {
    BeforeAll {
        Mock Test-Connection { $true }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddHours(-5) } }
        Mock Invoke-PSRQuser { return 0 }

        $script:capturedTaskName = $null
        Mock Invoke-PSRRegisterTask {
            $script:capturedTaskName = $TaskName
        }
    }

    It 'task name matches AutopilotReboot_yyyyMMdd_HHmm pattern' {
        $script:capturedTaskName = $null
        Invoke-ScheduledReboot -ComputerName 'SRV01' -When (Get-FutureWhen) -Confirm:$false | Out-Null
        $script:capturedTaskName | Should -Match '^AutopilotReboot_\d{8}_\d{4}$'
    }
}

# ---------------------------------------------------------------------------
# T17 — No -OutputPath: pipeline rows emitted, no file written
# ---------------------------------------------------------------------------
Describe 'Invoke-ScheduledReboot — no OutputPath' {
    BeforeAll {
        Mock Test-Connection        { $true }
        Mock Get-CimInstance        { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddHours(-5) } }
        Mock Invoke-PSRQuser        { return 0 }
        Mock Invoke-PSRRegisterTask { }
    }

    It 'still emits pipeline rows when -OutputPath is not supplied' {
        $result = @(Invoke-ScheduledReboot -ComputerName 'SRV01' -When (Get-FutureWhen) -Confirm:$false)
        $result.Count | Should -Be 1
    }

    It 'does not write any file to TestDrive when -OutputPath is not supplied' {
        Invoke-ScheduledReboot -ComputerName 'SRV01' -When (Get-FutureWhen) -Confirm:$false | Out-Null
        $files = @(Get-ChildItem -Path $TestDrive -File -ErrorAction SilentlyContinue)
        $files.Count | Should -Be 0
    }
}
