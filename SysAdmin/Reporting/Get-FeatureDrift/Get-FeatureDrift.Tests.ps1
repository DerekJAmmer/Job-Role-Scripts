#requires -Version 7.2

BeforeAll {
    . (Join-Path $PSScriptRoot 'Get-FeatureDrift.ps1')
}

# ---------------------------------------------------------------------------
# T1–T4: Baseline file validation
# ---------------------------------------------------------------------------

Describe 'Get-FeatureDrift — baseline file validation' {

    It 'T1: throws when baseline path does not exist' {
        { Get-FeatureDrift -BaselinePath (Join-Path $TestDrive 'nonexistent.json') } |
            Should -Throw
    }

    It 'T2: throws on malformed JSON' {
        $badPath = Join-Path $TestDrive 'bad.json'
        Set-Content -Path $badPath -Value 'this is { not valid json [' -Encoding UTF8
        { Get-FeatureDrift -BaselinePath $badPath } |
            Should -Throw
    }

    It 'T3: reads valid JSON and parses name, features, and software' {
        $t3Path = Join-Path $TestDrive 'baseline-t3.json'
        @{
            name     = 'Test-Baseline'
            features = @('AD-Domain-Services', 'DNS')
            software = @('Git', '7-Zip')
        } | ConvertTo-Json -Depth 5 | Set-Content -Path $t3Path -Encoding UTF8

        Mock Get-WindowsFeature {
            @(
                [PSCustomObject]@{ Name = 'AD-Domain-Services'; Installed = $true }
                [PSCustomObject]@{ Name = 'DNS'; Installed = $true }
            )
        }

        $result = Get-FeatureDrift -BaselinePath $t3Path -Mode Features
        $result.BaselineName | Should -Be 'Test-Baseline'
    }

    It 'T4: missing features key in baseline is treated as empty array' {
        $noFeaturePath = Join-Path $TestDrive 'no-features.json'
        @{ name = 'Minimal'; software = @() } | ConvertTo-Json | Set-Content -Path $noFeaturePath -Encoding UTF8

        Mock Get-WindowsFeature {
            @([PSCustomObject]@{ Name = 'SomeFeature'; Installed = $true })
        }

        $result = Get-FeatureDrift -BaselinePath $noFeaturePath -Mode Features
        $result.Missing.Count | Should -Be 0
        $result.MatchPercent  | Should -Be 0
    }
}

# ---------------------------------------------------------------------------
# T5–T7: Features mode — missing / extra detection
# ---------------------------------------------------------------------------

Describe 'Get-FeatureDrift — Features mode' {
    BeforeAll {
        $baselinePath = Join-Path $TestDrive 'features-baseline.json'
        @{
            name     = 'Server-Standard'
            features = @('AD-Domain-Services', 'DNS', 'RSAT-AD-Tools')
            software = @()
        } | ConvertTo-Json -Depth 5 | Set-Content -Path $baselinePath -Encoding UTF8
    }

    It 'T5: host has all baseline features — Missing is empty and MatchPercent is 100' {
        Mock Get-WindowsFeature {
            @(
                [PSCustomObject]@{ Name = 'AD-Domain-Services'; Installed = $true }
                [PSCustomObject]@{ Name = 'DNS';                Installed = $true }
                [PSCustomObject]@{ Name = 'RSAT-AD-Tools';     Installed = $true }
            )
        }

        $result = Get-FeatureDrift -BaselinePath $baselinePath -Mode Features
        $result.Missing.Count | Should -Be 0
        $result.MatchPercent  | Should -Be 100
    }

    It 'T6: host missing one baseline feature — Missing contains it and MatchPercent is correct' {
        Mock Get-WindowsFeature {
            @(
                [PSCustomObject]@{ Name = 'AD-Domain-Services'; Installed = $true }
                [PSCustomObject]@{ Name = 'DNS';                Installed = $true }
                # RSAT-AD-Tools intentionally absent
            )
        }

        $result = Get-FeatureDrift -BaselinePath $baselinePath -Mode Features
        $result.Missing       | Should -Contain 'RSAT-AD-Tools'
        $result.Missing.Count | Should -Be 1
        # (3 - 1) / 3 * 100 = 66.7
        $result.MatchPercent  | Should -Be 66.7
    }

    It 'T7: host has extra features not in baseline — Extra is populated' {
        Mock Get-WindowsFeature {
            @(
                [PSCustomObject]@{ Name = 'AD-Domain-Services'; Installed = $true }
                [PSCustomObject]@{ Name = 'DNS';                Installed = $true }
                [PSCustomObject]@{ Name = 'RSAT-AD-Tools';     Installed = $true }
                [PSCustomObject]@{ Name = 'Web-Server';         Installed = $true }
            )
        }

        $result = Get-FeatureDrift -BaselinePath $baselinePath -Mode Features
        $result.Extra | Should -Contain 'Web-Server'
    }
}

# ---------------------------------------------------------------------------
# T8–T9: Software mode — missing / extra detection including Wow6432Node
# ---------------------------------------------------------------------------

Describe 'Get-FeatureDrift — Software mode' {
    BeforeAll {
        $softwarePath = Join-Path $TestDrive 'software-baseline.json'
        @{
            name     = 'Workstation-Standard'
            features = @()
            software = @('Git', '7-Zip')
        } | ConvertTo-Json -Depth 5 | Set-Content -Path $softwarePath -Encoding UTF8
    }

    It 'T8: software mode Missing/Extra detection from registry data' {
        Mock Test-Path { $true } -ParameterFilter { $LiteralPath -like '*Uninstall*' }

        # 64-bit path: Git present, 7-Zip absent; extra app present
        Mock Get-ItemProperty {
            @(
                [PSCustomObject]@{ DisplayName = 'Git' }
                [PSCustomObject]@{ DisplayName = 'Visual Studio Code' }
            )
        } -ParameterFilter { $Path -like '*\Uninstall\*' -and $Path -notlike '*Wow6432Node*' }

        # Wow6432Node: empty
        Mock Get-ItemProperty {
            @()
        } -ParameterFilter { $Path -like '*Wow6432Node*' }

        $result = Get-FeatureDrift -BaselinePath $softwarePath -Mode Software
        $result.Missing | Should -Contain '7-Zip'
        $result.Extra   | Should -Contain 'Visual Studio Code'
    }

    It 'T9: Wow6432Node entries are included in software collection' {
        Mock Test-Path { $true } -ParameterFilter { $LiteralPath -like '*Uninstall*' }

        # 64-bit key has Git only
        Mock Get-ItemProperty {
            @([PSCustomObject]@{ DisplayName = 'Git' })
        } -ParameterFilter { $Path -like '*\Uninstall\*' -and $Path -notlike '*Wow6432Node*' }

        # Wow6432Node has 7-Zip (32-bit install)
        Mock Get-ItemProperty {
            @([PSCustomObject]@{ DisplayName = '7-Zip' })
        } -ParameterFilter { $Path -like '*Wow6432Node*' }

        $result = Get-FeatureDrift -BaselinePath $softwarePath -Mode Software
        # Both baseline items found across both hives → no Missing
        $result.Missing.Count | Should -Be 0
        $result.MatchPercent  | Should -Be 100
    }
}

# ---------------------------------------------------------------------------
# T10: Fallback from Get-WindowsFeature to Get-WindowsOptionalFeature
# ---------------------------------------------------------------------------

Describe 'Get-FeatureDrift — features fallback to Get-WindowsOptionalFeature' {
    BeforeAll {
        $fbPath = Join-Path $TestDrive 'fallback-baseline.json'
        @{
            name     = 'Client-Baseline'
            features = @('Microsoft-Hyper-V')
            software = @()
        } | ConvertTo-Json -Depth 5 | Set-Content -Path $fbPath -Encoding UTF8
    }

    It 'T10: when Get-WindowsFeature throws, Get-WindowsOptionalFeature is called instead' {
        Mock Get-WindowsFeature { throw 'ServerManager not available' }
        Mock Get-WindowsOptionalFeature {
            @([PSCustomObject]@{ FeatureName = 'Microsoft-Hyper-V'; State = 'Enabled' })
        }

        $result = Get-FeatureDrift -BaselinePath $fbPath -Mode Features
        Should -Invoke Get-WindowsOptionalFeature -Times 1
        $result.Missing.Count | Should -Be 0
        $result.MatchPercent  | Should -Be 100
    }
}

# ---------------------------------------------------------------------------
# T11–T12: Output object shape and BaselineName
# ---------------------------------------------------------------------------

Describe 'Get-FeatureDrift — output object shape' {
    BeforeAll {
        $shapePath = Join-Path $TestDrive 'shape-baseline.json'
        @{
            name     = 'Shape-Test'
            features = @('DNS')
            software = @()
        } | ConvertTo-Json -Depth 5 | Set-Content -Path $shapePath -Encoding UTF8

        Mock Get-WindowsFeature {
            @([PSCustomObject]@{ Name = 'DNS'; Installed = $true })
        }
    }

    It 'T11: output object has all required properties' {
        $result = Get-FeatureDrift -BaselinePath $shapePath -Mode Features
        $props = $result.PSObject.Properties.Name
        $props | Should -Contain 'ComputerName'
        $props | Should -Contain 'Mode'
        $props | Should -Contain 'Missing'
        $props | Should -Contain 'Extra'
        $props | Should -Contain 'MatchPercent'
        $props | Should -Contain 'BaselineName'
        $props | Should -Contain 'Status'
        $props | Should -Contain 'Reason'
    }

    It 'T12: BaselineName comes from the name field in the baseline JSON' {
        $result = Get-FeatureDrift -BaselinePath $shapePath -Mode Features
        $result.BaselineName | Should -Be 'Shape-Test'
    }
}

# ---------------------------------------------------------------------------
# T13: -OutputPath writes a JSON file
# ---------------------------------------------------------------------------

Describe 'Get-FeatureDrift — OutputPath' {
    BeforeAll {
        $outBaseline = Join-Path $TestDrive 'out-baseline.json'
        @{
            name     = 'OutputTest'
            features = @('DNS')
            software = @()
        } | ConvertTo-Json -Depth 5 | Set-Content -Path $outBaseline -Encoding UTF8

        Mock Get-WindowsFeature {
            @([PSCustomObject]@{ Name = 'DNS'; Installed = $true })
        }
    }

    It 'T13: -OutputPath writes a valid JSON file at the specified path' {
        $jsonOut = Join-Path $TestDrive 'drift-output.json'
        Get-FeatureDrift -BaselinePath $outBaseline -Mode Features -OutputPath $jsonOut | Out-Null
        Test-Path -LiteralPath $jsonOut | Should -Be $true
        $parsed = Get-Content -LiteralPath $jsonOut -Raw | ConvertFrom-Json
        $parsed | Should -Not -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# T14: Empty baseline features array
# ---------------------------------------------------------------------------

Describe 'Get-FeatureDrift — empty baseline' {
    It 'T14: empty features baseline yields MatchPercent=0 and Missing empty' {
        $emptyPath = Join-Path $TestDrive 'empty-baseline.json'
        @{
            name     = 'Empty'
            features = @()
            software = @()
        } | ConvertTo-Json -Depth 5 | Set-Content -Path $emptyPath -Encoding UTF8

        Mock Get-WindowsFeature {
            @([PSCustomObject]@{ Name = 'SomeFeature'; Installed = $true })
        }

        $result = Get-FeatureDrift -BaselinePath $emptyPath -Mode Features
        $result.MatchPercent  | Should -Be 0
        $result.Missing.Count | Should -Be 0
    }
}

# ---------------------------------------------------------------------------
# T15: Multi-host loop emits one object per host
# ---------------------------------------------------------------------------

Describe 'Get-FeatureDrift — multi-host' {
    It 'T15: emits one result object per host when multiple ComputerNames are given' {
        $multiPath = Join-Path $TestDrive 'multi-baseline.json'
        @{
            name     = 'Multi-Test'
            features = @('DNS')
            software = @()
        } | ConvertTo-Json -Depth 5 | Set-Content -Path $multiPath -Encoding UTF8

        # HOST1/HOST2/HOST3 are remote — mock Invoke-Command to return DNS installed.
        Mock Invoke-Command {
            @('DNS')
        }

        $results = @(Get-FeatureDrift -BaselinePath $multiPath -ComputerName 'HOST1', 'HOST2', 'HOST3' -Mode Features)
        $results.Count           | Should -Be 3
        $results[0].ComputerName | Should -Be 'HOST1'
        $results[1].ComputerName | Should -Be 'HOST2'
        $results[2].ComputerName | Should -Be 'HOST3'
    }
}

# ---------------------------------------------------------------------------
# T16–T19: F1 — Single-item Compare-Object edge cases (pinning three-branch guard)
# ---------------------------------------------------------------------------

Describe 'Get-FeatureDrift — single-item baseline edge cases (F1)' {
    BeforeAll {
        $singleBaselinePath = Join-Path $TestDrive 'single-item-baseline.json'
        @{
            name     = 'Single-Item-Test'
            features = @('DNS')
            software = @()
        } | ConvertTo-Json -Depth 5 | Set-Content -Path $singleBaselinePath -Encoding UTF8

        $emptyBaselinePath = Join-Path $TestDrive 'empty-installed-baseline.json'
        @{
            name     = 'Empty-Installed-Test'
            features = @()
            software = @()
        } | ConvertTo-Json -Depth 5 | Set-Content -Path $emptyBaselinePath -Encoding UTF8
    }

    It 'T16 F1a: single-item baseline, empty installed — Missing=DNS, Extra empty, MatchPercent=0' {
        Mock Get-WindowsFeature { @() }

        $result = Get-FeatureDrift -BaselinePath $singleBaselinePath -Mode Features
        $result.Missing       | Should -Contain 'DNS'
        $result.Missing.Count | Should -Be 1
        $result.Extra.Count   | Should -Be 0
        $result.MatchPercent  | Should -Be 0
    }

    It 'T17 F1b: single-item baseline, exact match — all empty, MatchPercent=100' {
        Mock Get-WindowsFeature {
            @([PSCustomObject]@{ Name = 'DNS'; Installed = $true })
        }

        $result = Get-FeatureDrift -BaselinePath $singleBaselinePath -Mode Features
        $result.Missing.Count | Should -Be 0
        $result.Extra.Count   | Should -Be 0
        $result.MatchPercent  | Should -Be 100
    }

    It 'T18 F1c: single-item baseline, different installed — Missing=DNS, Extra=DHCP, MatchPercent=0' {
        Mock Get-WindowsFeature {
            @([PSCustomObject]@{ Name = 'DHCP'; Installed = $true })
        }

        $result = Get-FeatureDrift -BaselinePath $singleBaselinePath -Mode Features
        $result.Missing       | Should -Contain 'DNS'
        $result.Missing.Count | Should -Be 1
        $result.Extra         | Should -Contain 'DHCP'
        $result.Extra.Count   | Should -Be 1
        $result.MatchPercent  | Should -Be 0
    }

    It 'T19 F1d: empty baseline, populated installed — MatchPercent=0, Extra populated, Missing empty' {
        Mock Get-WindowsFeature {
            @(
                [PSCustomObject]@{ Name = 'DNS';  Installed = $true }
                [PSCustomObject]@{ Name = 'DHCP'; Installed = $true }
            )
        }

        $result = Get-FeatureDrift -BaselinePath $emptyBaselinePath -Mode Features
        $result.MatchPercent  | Should -Be 0
        $result.Missing.Count | Should -Be 0
        $result.Extra         | Should -Contain 'DNS'
        $result.Extra         | Should -Contain 'DHCP'
    }
}

# ---------------------------------------------------------------------------
# T20: F1e — Empty baseline, empty installed (pin existing no-throw behavior)
# ---------------------------------------------------------------------------

Describe 'Get-FeatureDrift — empty/empty edge case (F1e)' {
    It 'T20 F1e: empty baseline and empty installed — no throw, MatchPercent=0, all empty' {
        $emptyBothPath = Join-Path $TestDrive 'empty-both-baseline.json'
        @{
            name     = 'Empty-Both'
            features = @()
            software = @()
        } | ConvertTo-Json -Depth 5 | Set-Content -Path $emptyBothPath -Encoding UTF8

        Mock Get-WindowsFeature { @() }

        $result = Get-FeatureDrift -BaselinePath $emptyBothPath -Mode Features
        $result.MatchPercent  | Should -Be 0
        $result.Missing.Count | Should -Be 0
        $result.Extra.Count   | Should -Be 0
    }
}

# ---------------------------------------------------------------------------
# T21–T23: F2/F3 — Software registry walk edge cases
# ---------------------------------------------------------------------------

Describe 'Get-FeatureDrift — software registry walk edge cases (F2, F3)' {
    BeforeAll {
        $swEdgePath = Join-Path $TestDrive 'sw-edge-baseline.json'
        @{
            name     = 'SW-Edge-Test'
            features = @()
            software = @('Git')
        } | ConvertTo-Json -Depth 5 | Set-Content -Path $swEdgePath -Encoding UTF8
    }

    It 'T21 F2a: entries missing DisplayName are excluded; entries with DisplayName are included' {
        Mock Test-Path { $true } -ParameterFilter { $LiteralPath -like '*Uninstall*' }

        # 64-bit path: one entry has DisplayName, one does not
        Mock Get-ItemProperty {
            @(
                [PSCustomObject]@{ DisplayName = 'Git' }
                [PSCustomObject]@{ DisplayName = $null }
                [PSCustomObject]@{}
            )
        } -ParameterFilter { $Path -like '*\Uninstall\*' -and $Path -notlike '*Wow6432Node*' }

        Mock Get-ItemProperty { @() } -ParameterFilter { $Path -like '*Wow6432Node*' }

        $result = Get-FeatureDrift -BaselinePath $swEdgePath -Mode Software
        # Git found, no Missing; entries without DisplayName excluded so no spurious Extra
        $result.Missing.Count | Should -Be 0
        $result.Extra.Count   | Should -Be 0
    }

    It 'T22 F3a: null return from one registry path does not error; populated path still used' {
        Mock Test-Path { $true } -ParameterFilter { $LiteralPath -like '*Uninstall*' }

        # 64-bit path returns Git
        Mock Get-ItemProperty {
            @([PSCustomObject]@{ DisplayName = 'Git' })
        } -ParameterFilter { $Path -like '*\Uninstall\*' -and $Path -notlike '*Wow6432Node*' }

        # Wow6432Node returns $null (simulates -ErrorAction SilentlyContinue returning nothing)
        Mock Get-ItemProperty { $null } -ParameterFilter { $Path -like '*Wow6432Node*' }

        $result = Get-FeatureDrift -BaselinePath $swEdgePath -Mode Software
        $result | Should -Not -BeNullOrEmpty
        $result.Missing.Count | Should -Be 0
        $result.MatchPercent  | Should -Be 100
    }

    It 'T23 F2b: single-DisplayName entry from registry is collected and included in diff' {
        Mock Test-Path { $true } -ParameterFilter { $LiteralPath -like '*Uninstall*' }

        # 64-bit path returns a single object (not wrapped in array)
        Mock Get-ItemProperty {
            [PSCustomObject]@{ DisplayName = 'Git' }
        } -ParameterFilter { $Path -like '*\Uninstall\*' -and $Path -notlike '*Wow6432Node*' }

        Mock Get-ItemProperty { @() } -ParameterFilter { $Path -like '*Wow6432Node*' }

        $result = Get-FeatureDrift -BaselinePath $swEdgePath -Mode Software
        $result.Missing.Count | Should -Be 0
        $result.MatchPercent  | Should -Be 100
    }
}

# ---------------------------------------------------------------------------
# T24–T28: Multi-host routing — local vs remote dispatch
# ---------------------------------------------------------------------------

Describe 'Get-FeatureDrift — multi-host routing' {
    BeforeAll {
        $routingBaseline = Join-Path $TestDrive 'routing-baseline.json'
        @{
            name     = 'Routing-Test'
            features = @('DNS', 'DHCP')
            software = @()
        } | ConvertTo-Json -Depth 5 | Set-Content -Path $routingBaseline -Encoding UTF8
    }

    It 'T24: multi-host — local row uses local path; remote row goes through Invoke-Command' {
        # Local host returns DNS+DHCP (exact match). Remote returns only DNS (drift).
        Mock Get-WindowsFeature {
            @(
                [PSCustomObject]@{ Name = 'DNS';  Installed = $true }
                [PSCustomObject]@{ Name = 'DHCP'; Installed = $true }
            )
        }

        Mock Invoke-Command {
            @('DNS')
        } -ParameterFilter { $ComputerName -eq 'REMOTE-SRV01' }

        $results = @(Get-FeatureDrift -BaselinePath $routingBaseline -ComputerName 'localhost', 'REMOTE-SRV01' -Mode Features)

        $results.Count | Should -Be 2

        $localRow  = $results | Where-Object { $_.ComputerName -eq 'localhost' }
        $remoteRow = $results | Where-Object { $_.ComputerName -eq 'REMOTE-SRV01' }

        # Local row: full match, data from Get-WindowsFeature mock
        $localRow.MatchPercent  | Should -Be 100
        $localRow.Missing.Count | Should -Be 0
        $localRow.Status        | Should -Be 'OK'

        # Remote row: DHCP missing, data from Invoke-Command mock
        $remoteRow.Missing      | Should -Contain 'DHCP'
        $remoteRow.Status       | Should -Be 'OK'

        # Invoke-Command called exactly once for the remote host
        Should -Invoke Invoke-Command -Times 1 -ParameterFilter { $ComputerName -eq 'REMOTE-SRV01' }
    }

    It 'T25: single local host does not call Invoke-Command' {
        Mock Get-WindowsFeature {
            @([PSCustomObject]@{ Name = 'DNS'; Installed = $true })
        }
        Mock Invoke-Command { throw 'Should not be called' }

        Get-FeatureDrift -BaselinePath $routingBaseline -ComputerName 'localhost' -Mode Features | Out-Null

        Should -Invoke Invoke-Command -Times 0
    }

    It 'T26: FQDN of local box is treated as local — Invoke-Command not called' {
        $originalName = $env:COMPUTERNAME
        $env:COMPUTERNAME = 'WK01'

        try {
            Mock Get-WindowsFeature {
                @([PSCustomObject]@{ Name = 'DNS'; Installed = $true })
            }
            Mock Invoke-Command { throw 'Should not be called' }

            Get-FeatureDrift -BaselinePath $routingBaseline -ComputerName 'wk01.corp.local' -Mode Features | Out-Null

            Should -Invoke Invoke-Command -Times 0
        }
        finally {
            $env:COMPUTERNAME = $originalName
        }
    }

    It 'T27: unreachable remote host produces Status=Unreachable row with Reason' {
        Mock Invoke-Command { throw 'WS-Management not enabled on the remote host' }

        $result = Get-FeatureDrift -BaselinePath $routingBaseline -ComputerName 'DEAD-SRV' -Mode Features

        $result.Status | Should -Be 'Unreachable'
        $result.Reason | Should -Match 'WS-Management'
    }

    It 'T28: mixed local + two remotes — each row has correct data, Invoke-Command called twice' {
        # Local returns DNS+DHCP. Remote-A returns DNS only. Remote-B returns DHCP only.
        Mock Get-WindowsFeature {
            @(
                [PSCustomObject]@{ Name = 'DNS';  Installed = $true }
                [PSCustomObject]@{ Name = 'DHCP'; Installed = $true }
            )
        }

        Mock Invoke-Command {
            @('DNS')
        } -ParameterFilter { $ComputerName -eq 'REMOTE-A' }

        Mock Invoke-Command {
            @('DHCP')
        } -ParameterFilter { $ComputerName -eq 'REMOTE-B' }

        $results = @(Get-FeatureDrift -BaselinePath $routingBaseline -ComputerName 'localhost', 'REMOTE-A', 'REMOTE-B' -Mode Features)

        $results.Count | Should -Be 3

        $local   = $results | Where-Object { $_.ComputerName -eq 'localhost' }
        $remoteA = $results | Where-Object { $_.ComputerName -eq 'REMOTE-A' }
        $remoteB = $results | Where-Object { $_.ComputerName -eq 'REMOTE-B' }

        # Local: full match
        $local.MatchPercent | Should -Be 100

        # REMOTE-A: only DNS — DHCP missing
        $remoteA.Missing | Should -Contain 'DHCP'
        $remoteA.Missing | Should -Not -Contain 'DNS'

        # REMOTE-B: only DHCP — DNS missing
        $remoteB.Missing | Should -Contain 'DNS'
        $remoteB.Missing | Should -Not -Contain 'DHCP'

        # Invoke-Command called exactly twice (once per remote)
        Should -Invoke Invoke-Command -Times 2
    }
}
