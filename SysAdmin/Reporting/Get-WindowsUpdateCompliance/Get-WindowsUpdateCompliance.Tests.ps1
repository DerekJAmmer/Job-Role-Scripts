#requires -Version 7.2

BeforeAll {
    . (Join-Path $PSScriptRoot 'Get-WindowsUpdateCompliance.ps1')

    # ---------------------------------------------------------------------------
    # Helper: build a mock WU session that returns $MissingCount pending updates
    # The session exposes CreateUpdateSearcher() -> Search() -> Updates.Count
    # ---------------------------------------------------------------------------
    function New-MockWUCSession {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pester fixture builder — pure function, no state change.')]
        param(
            [int]$MissingCount
        )

        $missingCountCapture = $MissingCount

        $updateList = [PSCustomObject]@{ Count = $missingCountCapture }
        $searchResult = [PSCustomObject]@{ Updates = $updateList }

        $searcher = [PSCustomObject]@{}
        $searchResultRef = $searchResult
        $searcher | Add-Member -MemberType ScriptMethod -Name Search -Value {
            param($q)
            return $searchResultRef
        }.GetNewClosure()

        $searcherRef = $searcher
        $session = [PSCustomObject]@{}
        $session | Add-Member -MemberType ScriptMethod -Name CreateUpdateSearcher -Value {
            return $searcherRef
        }.GetNewClosure()

        return $session
    }
}

# ---------------------------------------------------------------------------
# T1: COM happy path — local host, session returns 5 missing updates
# ---------------------------------------------------------------------------
Describe 'Get-WindowsUpdateCompliance — COM happy path (local)' {
    BeforeAll {
        $mockSession = New-MockWUCSession -MissingCount 5
        Mock Get-WUCSession { return $mockSession }
        Mock Get-WUCLastInstallTimeFromRegistry { return (Get-Date).AddDays(-15) }
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'Get-PendingReboot' }
    }

    It 'Source is COM' {
        $result = Get-WindowsUpdateCompliance -ComputerName $env:COMPUTERNAME
        $result.Source | Should -Be 'COM'
    }

    It 'MissingUpdateCount is 5' {
        $result = Get-WindowsUpdateCompliance -ComputerName $env:COMPUTERNAME
        $result.MissingUpdateCount | Should -Be 5
    }

    It 'LastInstalledDate is populated' {
        $result = Get-WindowsUpdateCompliance -ComputerName $env:COMPUTERNAME
        $result.LastInstalledDate | Should -Not -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# T2: COM unavailable — fallback to registry
# ---------------------------------------------------------------------------
Describe 'Get-WindowsUpdateCompliance — COM unavailable, registry fallback' {
    BeforeAll {
        Mock Get-WUCSession { return $null }
        $script:fakeDate = (Get-Date).AddDays(-20)
        Mock Get-WUCLastInstallTimeFromRegistry { return $script:fakeDate }
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'Get-PendingReboot' }
    }

    It 'Source is Registry' {
        $result = Get-WindowsUpdateCompliance -ComputerName $env:COMPUTERNAME
        $result.Source | Should -Be 'Registry'
    }

    It 'MissingUpdateCount is Unknown' {
        $result = Get-WindowsUpdateCompliance -ComputerName $env:COMPUTERNAME
        $result.MissingUpdateCount | Should -Be 'Unknown'
    }

    It 'LastInstalledDate is populated from registry' {
        $result = Get-WindowsUpdateCompliance -ComputerName $env:COMPUTERNAME
        $result.LastInstalledDate | Should -Not -BeNullOrEmpty
    }

    It 'DaysSinceLastUpdate is calculated correctly' {
        $result = Get-WindowsUpdateCompliance -ComputerName $env:COMPUTERNAME
        $result.DaysSinceLastUpdate | Should -BeGreaterOrEqual 19
        $result.DaysSinceLastUpdate | Should -BeLessOrEqual 21
    }
}

# ---------------------------------------------------------------------------
# T3: Both COM and registry unavailable
# ---------------------------------------------------------------------------
Describe 'Get-WindowsUpdateCompliance — both sources unavailable' {
    BeforeAll {
        Mock Get-WUCSession { return $null }
        Mock Get-WUCLastInstallTimeFromRegistry { return $null }
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'Get-PendingReboot' }
    }

    It 'Source is Registry when COM is null and registry returns null' {
        $result = Get-WindowsUpdateCompliance -ComputerName $env:COMPUTERNAME
        $result.Source | Should -Be 'Registry'
    }

    It 'MissingUpdateCount is Unknown when both sources unavailable' {
        $result = Get-WindowsUpdateCompliance -ComputerName $env:COMPUTERNAME
        $result.MissingUpdateCount | Should -Be 'Unknown'
    }

    It 'LastInstalledDate is null when both sources unavailable' {
        $result = Get-WindowsUpdateCompliance -ComputerName $env:COMPUTERNAME
        $result.LastInstalledDate | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# T4: MissingUpdateCount is correctly populated from COM
# ---------------------------------------------------------------------------
Describe 'Get-WindowsUpdateCompliance — MissingUpdateCount from COM' {
    BeforeAll {
        $mockSession = New-MockWUCSession -MissingCount 12
        Mock Get-WUCSession { return $mockSession }
        Mock Get-WUCLastInstallTimeFromRegistry { return (Get-Date).AddDays(-5) }
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'Get-PendingReboot' }
    }

    It 'MissingUpdateCount equals the value returned by the COM searcher' {
        $result = Get-WindowsUpdateCompliance -ComputerName $env:COMPUTERNAME
        $result.MissingUpdateCount | Should -Be 12
    }
}

# ---------------------------------------------------------------------------
# T5: RebootRequired = $true when Get-PendingReboot is available and reports true
# ---------------------------------------------------------------------------
Describe 'Get-WindowsUpdateCompliance — RebootRequired true when Get-PendingReboot available' {
    BeforeAll {
        Mock Get-WUCSession { return $null }
        Mock Get-WUCLastInstallTimeFromRegistry { return (Get-Date).AddDays(-10) }
        Mock Get-Command { return [PSCustomObject]@{ Name = 'Get-PendingReboot' } } `
            -ParameterFilter { $Name -eq 'Get-PendingReboot' }
        Mock Get-PendingReboot { return [PSCustomObject]@{ RebootRequired = $true } }
    }

    It 'RebootRequired is true' {
        $result = Get-WindowsUpdateCompliance -ComputerName $env:COMPUTERNAME
        $result.RebootRequired | Should -Be $true
    }
}

# ---------------------------------------------------------------------------
# T6: RebootRequired = $null when Get-PendingReboot is NOT available
# ---------------------------------------------------------------------------
Describe 'Get-WindowsUpdateCompliance — RebootRequired null when Get-PendingReboot not available' {
    BeforeAll {
        Mock Get-WUCSession { return $null }
        Mock Get-WUCLastInstallTimeFromRegistry { return (Get-Date).AddDays(-10) }
        Mock Get-Command { return $null } -ParameterFilter { $Name -eq 'Get-PendingReboot' }
    }

    It 'RebootRequired is null' {
        $result = Get-WindowsUpdateCompliance -ComputerName $env:COMPUTERNAME
        $result.RebootRequired | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# T7: IsStale = $true when LastInstalledDate is older than StaleDays
# ---------------------------------------------------------------------------
Describe 'Get-WindowsUpdateCompliance — IsStale true when update is old' {
    BeforeAll {
        Mock Get-WUCSession { return $null }
        Mock Get-WUCLastInstallTimeFromRegistry { return (Get-Date).AddDays(-45) }
        Mock Get-Command { return $null } -ParameterFilter { $Name -eq 'Get-PendingReboot' }
    }

    It 'IsStale is true when DaysSinceLastUpdate exceeds StaleDays' {
        $result = Get-WindowsUpdateCompliance -ComputerName $env:COMPUTERNAME -StaleDays 30
        $result.IsStale | Should -Be $true
    }
}

# ---------------------------------------------------------------------------
# T8: IsStale = $false when LastInstalledDate is recent
# ---------------------------------------------------------------------------
Describe 'Get-WindowsUpdateCompliance — IsStale false when update is recent' {
    BeforeAll {
        Mock Get-WUCSession { return $null }
        Mock Get-WUCLastInstallTimeFromRegistry { return (Get-Date).AddDays(-10) }
        Mock Get-Command { return $null } -ParameterFilter { $Name -eq 'Get-PendingReboot' }
    }

    It 'IsStale is false when DaysSinceLastUpdate is within StaleDays' {
        $result = Get-WindowsUpdateCompliance -ComputerName $env:COMPUTERNAME -StaleDays 30
        $result.IsStale | Should -Be $false
    }
}

# ---------------------------------------------------------------------------
# T9: IsStale = $null when LastInstalledDate is null
# ---------------------------------------------------------------------------
Describe 'Get-WindowsUpdateCompliance — IsStale null when no date available' {
    BeforeAll {
        Mock Get-WUCSession { return $null }
        Mock Get-WUCLastInstallTimeFromRegistry { return $null }
        Mock Get-Command { return $null } -ParameterFilter { $Name -eq 'Get-PendingReboot' }
    }

    It 'IsStale is null when LastInstalledDate is null' {
        $result = Get-WindowsUpdateCompliance -ComputerName $env:COMPUTERNAME
        $result.IsStale | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# T10: Unreachable host — Test-Connection returns false
# ---------------------------------------------------------------------------
Describe 'Get-WindowsUpdateCompliance — unreachable host' {
    BeforeAll {
        Mock Test-Connection { return $false }
    }

    It 'Source is Unreachable' {
        $result = Get-WindowsUpdateCompliance -ComputerName 'REMOTEHOST-FAKE'
        $result.Source | Should -Be 'Unreachable'
    }

    It 'LastInstalledDate is null for unreachable host' {
        $result = Get-WindowsUpdateCompliance -ComputerName 'REMOTEHOST-FAKE'
        $result.LastInstalledDate | Should -BeNullOrEmpty
    }

    It 'MissingUpdateCount is null for unreachable host' {
        $result = Get-WindowsUpdateCompliance -ComputerName 'REMOTEHOST-FAKE'
        $result.MissingUpdateCount | Should -BeNullOrEmpty
    }

    It 'RebootRequired is null for unreachable host' {
        $result = Get-WindowsUpdateCompliance -ComputerName 'REMOTEHOST-FAKE'
        $result.RebootRequired | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# T11: Remote host happy path — Invoke-Command returns synthetic result
# ---------------------------------------------------------------------------
Describe 'Get-WindowsUpdateCompliance — remote host happy path' {
    BeforeAll {
        $script:fakeRemoteDate = (Get-Date).AddDays(-10)
        Mock Test-Connection { return $true }
        Mock Invoke-Command {
            return [PSCustomObject]@{
                LastInstalledDate   = $script:fakeRemoteDate
                DaysSinceLastUpdate = 10
                MissingUpdateCount  = 2
                Source              = 'COM'
            }
        }
    }

    It 'Source matches the value returned by Invoke-Command' {
        $result = Get-WindowsUpdateCompliance -ComputerName 'REMOTEHOST'
        $result.Source | Should -Be 'COM'
    }

    It 'MissingUpdateCount matches the value returned by Invoke-Command' {
        $result = Get-WindowsUpdateCompliance -ComputerName 'REMOTEHOST'
        $result.MissingUpdateCount | Should -Be 2
    }

    It 'DaysSinceLastUpdate matches the value returned by Invoke-Command' {
        $result = Get-WindowsUpdateCompliance -ComputerName 'REMOTEHOST'
        $result.DaysSinceLastUpdate | Should -Be 10
    }

    It 'IsStale is false when DaysSinceLastUpdate (10) is within StaleDays (30)' {
        $result = Get-WindowsUpdateCompliance -ComputerName 'REMOTEHOST' -StaleDays 30
        $result.IsStale | Should -Be $false
    }
}

# ---------------------------------------------------------------------------
# T12: Multi-host mix — local + reachable remote + unreachable remote
# ---------------------------------------------------------------------------
Describe 'Get-WindowsUpdateCompliance — multi-host mix' {
    BeforeAll {
        Mock Get-WUCSession { return $null }
        Mock Get-WUCLastInstallTimeFromRegistry { return (Get-Date).AddDays(-5) }
        Mock Get-Command { return $null } -ParameterFilter { $Name -eq 'Get-PendingReboot' }
        Mock Test-Connection -ParameterFilter { $ComputerName -eq 'REACHABLE' } { return $true }
        Mock Test-Connection -ParameterFilter { $ComputerName -eq 'DEAD' } { return $false }
        Mock Invoke-Command -ParameterFilter { $ComputerName -eq 'REACHABLE' } {
            return [PSCustomObject]@{
                LastInstalledDate   = (Get-Date).AddDays(-5)
                DaysSinceLastUpdate = 5
                MissingUpdateCount  = 0
                Source              = 'COM'
            }
        }
    }

    It 'returns 3 rows for local + 2 remote hosts' {
        $results = @(Get-WindowsUpdateCompliance -ComputerName $env:COMPUTERNAME, 'REACHABLE', 'DEAD')
        $results.Count | Should -Be 3
    }

    It 'unreachable host row has Source=Unreachable' {
        $results = @(Get-WindowsUpdateCompliance -ComputerName $env:COMPUTERNAME, 'REACHABLE', 'DEAD')
        $dead = $results | Where-Object { $_.ComputerName -eq 'DEAD' }
        $dead.Source | Should -Be 'Unreachable'
    }

    It 'reachable remote row has Source=COM' {
        $results = @(Get-WindowsUpdateCompliance -ComputerName $env:COMPUTERNAME, 'REACHABLE', 'DEAD')
        $reachable = $results | Where-Object { $_.ComputerName -eq 'REACHABLE' }
        $reachable.Source | Should -Be 'COM'
    }
}

# ---------------------------------------------------------------------------
# T13: OutputPath writes CSV
# ---------------------------------------------------------------------------
Describe 'Get-WindowsUpdateCompliance — OutputPath writes CSV' {
    BeforeAll {
        Mock Get-WUCSession { return $null }
        Mock Get-WUCLastInstallTimeFromRegistry { return (Get-Date).AddDays(-5) }
        Mock Get-Command { return $null } -ParameterFilter { $Name -eq 'Get-PendingReboot' }
    }

    It 'creates the CSV file at OutputPath' {
        $csvPath = Join-Path $TestDrive 'report.csv'
        Get-WindowsUpdateCompliance -ComputerName $env:COMPUTERNAME -OutputPath $csvPath | Out-Null
        Test-Path -LiteralPath $csvPath | Should -Be $true
    }

    It 'CSV contains expected columns' {
        $csvPath = Join-Path $TestDrive 'report-cols.csv'
        Get-WindowsUpdateCompliance -ComputerName $env:COMPUTERNAME -OutputPath $csvPath | Out-Null
        $imported = Import-Csv -Path $csvPath
        $imported[0].PSObject.Properties.Name | Should -Contain 'ComputerName'
        $imported[0].PSObject.Properties.Name | Should -Contain 'Source'
        $imported[0].PSObject.Properties.Name | Should -Contain 'MissingUpdateCount'
    }
}

# ---------------------------------------------------------------------------
# T14: OutputPath writes JSON sidecar
# ---------------------------------------------------------------------------
Describe 'Get-WindowsUpdateCompliance — OutputPath writes JSON sidecar' {
    BeforeAll {
        Mock Get-WUCSession { return $null }
        Mock Get-WUCLastInstallTimeFromRegistry { return (Get-Date).AddDays(-5) }
        Mock Get-Command { return $null } -ParameterFilter { $Name -eq 'Get-PendingReboot' }
    }

    It 'creates a .json sidecar file derived from the CSV path' {
        $csvPath  = Join-Path $TestDrive 'sidecar-report.csv'
        $jsonPath = [System.IO.Path]::ChangeExtension($csvPath, '.json')
        Get-WindowsUpdateCompliance -ComputerName $env:COMPUTERNAME -OutputPath $csvPath | Out-Null
        Test-Path -LiteralPath $jsonPath | Should -Be $true
    }

    It 'JSON sidecar parses to an object with ComputerName property' {
        $csvPath  = Join-Path $TestDrive 'sidecar-parse.csv'
        $jsonPath = [System.IO.Path]::ChangeExtension($csvPath, '.json')
        Get-WindowsUpdateCompliance -ComputerName $env:COMPUTERNAME -OutputPath $csvPath | Out-Null
        $parsed = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
        # ConvertFrom-Json may return an array or a single object
        $first = if ($parsed -is [array]) { $parsed[0] } else { $parsed }
        $first.PSObject.Properties.Name | Should -Contain 'ComputerName'
    }
}

# ---------------------------------------------------------------------------
# T15: FQDN of local box treated as local — Invoke-Command NOT called
# ---------------------------------------------------------------------------
Describe 'Get-WindowsUpdateCompliance — FQDN of local host treated as local' {
    BeforeAll {
        Mock Get-WUCSession { return $null }
        Mock Get-WUCLastInstallTimeFromRegistry { return (Get-Date).AddDays(-5) }
        Mock Get-Command { return $null } -ParameterFilter { $Name -eq 'Get-PendingReboot' }
        Mock Invoke-Command { throw 'Should not be called for local host' }
    }

    It 'does not call Invoke-Command when FQDN leftmost label matches COMPUTERNAME' {
        $fqdn = "$($env:COMPUTERNAME).corp.local"
        { Get-WindowsUpdateCompliance -ComputerName $fqdn } | Should -Not -Throw
        Should -Invoke Invoke-Command -Times 0 -Exactly
    }
}

# ---------------------------------------------------------------------------
# T16: Stale threshold boundary — exactly 30 days ago is NOT stale (strict >)
# ---------------------------------------------------------------------------
Describe 'Get-WindowsUpdateCompliance — staleness boundary (exactly StaleDays)' {
    BeforeAll {
        Mock Get-WUCSession { return $null }
        # 30 days ago exactly: DaysSinceLastUpdate will be 30
        Mock Get-WUCLastInstallTimeFromRegistry { return (Get-Date).AddDays(-30) }
        Mock Get-Command { return $null } -ParameterFilter { $Name -eq 'Get-PendingReboot' }
    }

    It 'IsStale is false when DaysSinceLastUpdate equals StaleDays (boundary is exclusive)' {
        $result = Get-WindowsUpdateCompliance -ComputerName $env:COMPUTERNAME -StaleDays 30
        # DaysSinceLastUpdate = 30, StaleDays = 30 → 30 > 30 is false → not stale
        $result.IsStale | Should -Be $false
    }
}
