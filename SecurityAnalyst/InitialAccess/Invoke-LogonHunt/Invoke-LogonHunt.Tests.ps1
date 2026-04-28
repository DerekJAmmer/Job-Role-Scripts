BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'Invoke-LogonHunt.ps1'
    . $scriptPath

    function New-FakeEvent {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSUseShouldProcessForStateChangingFunctions', '',
            Justification = 'Test helper that returns a synthetic event object only.')]
        param(
            [datetime]$Time,
            [string]$Account   = 'testuser',
            [string]$IpAddress = '10.0.0.1',
            [int]$LogonType    = 3
        )
        [pscustomobject]@{
            TimeCreated     = $Time
            EventId         = 4624
            AccountName     = $Account
            AccountDomain   = 'TESTDOMAIN'
            LogonType       = $LogonType
            LogonTypeLabel  = Get-LHLogonTypeLabel -Type $LogonType
            WorkstationName = 'WS01'
            IpAddress       = $IpAddress
            IpPort          = '49200'
            ProcessName     = 'C:\Windows\System32\winlogon.exe'
            FailureReason   = ''
            Status          = ''
            SubStatus       = ''
        }
    }
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

Describe 'Get-LHLogonTypeLabel' {
    It 'returns correct label for type 2' {
        Get-LHLogonTypeLabel -Type 2 | Should -Be 'Interactive'
    }
    It 'returns correct label for type 3' {
        Get-LHLogonTypeLabel -Type 3 | Should -Be 'Network'
    }
    It 'returns correct label for type 9' {
        Get-LHLogonTypeLabel -Type 9 | Should -Be 'NewCredentials(runas/PTH)'
    }
    It 'returns generic label for unknown type' {
        Get-LHLogonTypeLabel -Type 42 | Should -Match 'Type42'
    }
}

Describe 'Get-LHWorkHours' {
    It 'returns true for Wednesday 10:00' {
        Get-LHWorkHours -Time ([datetime]'2026-04-15T10:00:00') | Should -BeTrue
    }
    It 'returns false for Saturday' {
        Get-LHWorkHours -Time ([datetime]'2026-04-18T10:00:00') | Should -BeFalse
    }
    It 'returns false before StartHour' {
        Get-LHWorkHours -Time ([datetime]'2026-04-15T06:00:00') | Should -BeFalse
    }
    It 'returns false at or after EndHour' {
        Get-LHWorkHours -Time ([datetime]'2026-04-15T19:00:00') | Should -BeFalse
    }
}

Describe 'New-LHFinding' {
    It 'builds a finding with correct fields' {
        $f = New-LHFinding -Type 'BurstFailures' -Subject '10.0.0.1' -Detail '20 failures in 2 min'
        $f.Type    | Should -Be 'BurstFailures'
        $f.Subject | Should -Be '10.0.0.1'
        $f.Detail  | Should -Match '20 failures'
        $f.Evidence | Should -Be ''
    }
}

# ---------------------------------------------------------------------------
# Detection unit tests using synthetic events
# ---------------------------------------------------------------------------

Describe 'Find-LHBurstFailures' {
    It 'detects a burst of failures from the same source' {
        $base = [datetime]'2026-04-15T09:00:00'
        $events = 0..6 | ForEach-Object { New-FakeEvent -Time $base.AddSeconds($_) -Account 'admin' }
        $results = Find-LHBurstFailures -Events4625 $events -Threshold 5 -WindowMin 5
        $results.Count | Should -BeGreaterOrEqual 1
        $results[0].Type | Should -Be 'BurstFailures'
    }

    It 'does not flag when below threshold' {
        $base = [datetime]'2026-04-15T09:00:00'
        $events = 0..2 | ForEach-Object { New-FakeEvent -Time $base.AddSeconds($_) -Account 'admin' }
        $results = Find-LHBurstFailures -Events4625 $events -Threshold 5 -WindowMin 5
        @($results).Count | Should -Be 0
    }

    It 'does not flag when spread across different sources' {
        $base = [datetime]'2026-04-15T09:00:00'
        $events = 0..9 | ForEach-Object { New-FakeEvent -Time $base.AddSeconds($_) -IpAddress "10.0.0.$_" }
        $results = Find-LHBurstFailures -Events4625 $events -Threshold 5 -WindowMin 5
        @($results).Count | Should -Be 0
    }
}

Describe 'Find-LHMultiSourceLogons' {
    It 'detects multi-source logon' {
        $base = [datetime]'2026-04-15T09:00:00'
        $events = 1..5 | ForEach-Object {
            New-FakeEvent -Time $base.AddMinutes($_) -Account 'bob' -IpAddress "10.0.0.$_"
        }
        $results = Find-LHMultiSourceLogons -Events4624 $events -Threshold 3 -WindowHours 1
        $results.Count | Should -BeGreaterOrEqual 1
        $results[0].Subject | Should -Be 'bob'
    }

    It 'skips computer accounts' {
        $base = [datetime]'2026-04-15T09:00:00'
        $events = 1..5 | ForEach-Object {
            New-FakeEvent -Time $base.AddMinutes($_) -Account 'MACHINE$' -IpAddress "10.0.0.$_"
        }
        $results = Find-LHMultiSourceLogons -Events4624 $events -Threshold 3 -WindowHours 1
        @($results).Count | Should -Be 0
    }
}

Describe 'Find-LHExplicitCredentialLogons' {
    It 'flags type-9 logon' {
        $e = New-FakeEvent -Time ([datetime]'2026-04-15T09:00:00') -Account 'alice' -LogonType 9
        $results = Find-LHExplicitCredentialLogons -Events4624 @($e)
        $results.Count | Should -Be 1
        $results[0].Type | Should -Be 'ExplicitCredential'
    }

    It 'marks off-hours type-9 logon' {
        $e = New-FakeEvent -Time ([datetime]'2026-04-15T02:00:00') -Account 'alice' -LogonType 9
        $results = Find-LHExplicitCredentialLogons -Events4624 @($e)
        $results[0].Detail | Should -Match 'OFF-HOURS'
    }

    It 'skips SYSTEM account' {
        $e = New-FakeEvent -Time ([datetime]'2026-04-15T09:00:00') -Account 'SYSTEM' -LogonType 9
        $results = Find-LHExplicitCredentialLogons -Events4624 @($e)
        @($results).Count | Should -Be 0
    }
}

Describe 'Find-LHOffHoursLogons' {
    It 'detects off-hours interactive logon for an account that also logs on during work hours' {
        $dayEvent   = New-FakeEvent -Time ([datetime]'2026-04-15T10:00:00') -Account 'bob' -LogonType 2
        $nightEvent = New-FakeEvent -Time ([datetime]'2026-04-15T03:00:00') -Account 'bob' -LogonType 2
        $results = Find-LHOffHoursLogons -Events4624 @($dayEvent, $nightEvent)
        $results.Count | Should -Be 1
        $results[0].Subject | Should -Be 'bob'
    }

    It 'does not flag purely off-hours service account' {
        # No work-hours baseline logon → should not be flagged
        $nightEvent = New-FakeEvent -Time ([datetime]'2026-04-15T03:00:00') -Account 'svcacct' -LogonType 2
        $results = Find-LHOffHoursLogons -Events4624 @($nightEvent)
        @($results).Count | Should -Be 0
    }
}

# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

Describe 'ConvertTo-LHMarkdownTable' {
    It 'builds a valid pipe table' {
        $rows = @(
            [pscustomobject]@{ Type = 'X'; Subject = 'Y'; Detail = 'Z'; Evidence = '' }
        )
        $md = ConvertTo-LHMarkdownTable -Rows $rows
        $md | Should -Match '^\|'
        ($md -split "`n").Count | Should -Be 3  # header + sep + 1 row
    }

    It 'returns no-findings note when empty' {
        (ConvertTo-LHMarkdownTable -Rows @()) | Should -Match '(?i)no findings'
    }
}

# ---------------------------------------------------------------------------
# Integration smoke test
# ---------------------------------------------------------------------------

Describe 'Invoke-LogonHunt (smoke)' -Tag 'Integration' {
    It 'runs, writes a report, and returns a summary object' {
        $out = Join-Path $TestDrive 'logon-hunt.md'
        # Short window and small max to keep the test quick
        $result = Invoke-LogonHunt -HoursBack 1 -MaxEvents 500 -OutFile $out `
                      -Skip OffHoursLogons -ErrorAction Stop
        $result              | Should -Not -BeNullOrEmpty
        $result.HostName     | Should -Be $env:COMPUTERNAME
        Test-Path $out       | Should -BeTrue
        (Get-Content $out -Raw) | Should -Match '^# LogonHunt:'
    }
}
