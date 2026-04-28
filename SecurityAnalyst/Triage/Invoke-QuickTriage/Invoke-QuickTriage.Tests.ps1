BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'Invoke-QuickTriage.ps1'
    . $scriptPath
}

Describe 'Test-QTSuspiciousPath' {
    It 'flags paths under AppData\Local\Temp' {
        Test-QTSuspiciousPath -Path 'C:\Users\bob\AppData\Local\Temp\foo.exe' | Should -BeTrue
    }
    It 'flags paths under ProgramData' {
        Test-QTSuspiciousPath -Path 'C:\ProgramData\x\y.exe' | Should -BeTrue
    }
    It 'does not flag System32 paths' {
        Test-QTSuspiciousPath -Path 'C:\Windows\System32\svchost.exe' | Should -BeFalse
    }
    It 'does not flag Program Files paths' {
        Test-QTSuspiciousPath -Path 'C:\Program Files\Something\app.exe' | Should -BeFalse
    }
    It 'returns false for empty or null input' {
        Test-QTSuspiciousPath -Path '' | Should -BeFalse
        Test-QTSuspiciousPath -Path $null | Should -BeFalse
    }
}

Describe 'Test-QTProcessFlag' {
    It 'flags unsigned process in Temp' {
        $p = [pscustomobject]@{
            Path   = 'C:\Users\bob\AppData\Local\Temp\evil.exe'
            Signer = 'Unsigned'
        }
        Test-QTProcessFlag -Process $p | Should -BeTrue
    }
    It 'does not flag Microsoft-signed process anywhere' {
        $p = [pscustomobject]@{
            Path   = 'C:\Users\bob\AppData\Local\Temp\tool.exe'
            Signer = 'Microsoft Corporation'
        }
        Test-QTProcessFlag -Process $p | Should -BeFalse
    }
    It 'does not flag unsigned process in System32' {
        $p = [pscustomobject]@{
            Path   = 'C:\Windows\System32\foo.exe'
            Signer = 'Unsigned'
        }
        Test-QTProcessFlag -Process $p | Should -BeFalse
    }
}

Describe 'New-QTSection' {
    It 'builds a section object with the right shape' {
        $s = New-QTSection -Name 'Test' -Rows @([pscustomobject]@{ A = 1 }) -Flags 1
        $s.Name  | Should -Be 'Test'
        $s.Rows.Count | Should -Be 1
        $s.Flags | Should -Be 1
        $s.Notes | Should -Be ''
    }
}

Describe 'ConvertTo-QTMarkdownTable' {
    It 'produces a valid pipe table with header, separator, and data rows' {
        $rows = @(
            [pscustomobject]@{ Name = 'a'; Value = 1 },
            [pscustomobject]@{ Name = 'b'; Value = 2 }
        )
        $md = ConvertTo-QTMarkdownTable -Rows $rows
        $lines = $md -split "`n"
        $lines[0] | Should -Match '^\|\s*Name\s*\|\s*Value\s*\|$'
        $lines[1] | Should -Match '^\|\s*---\s*\|\s*---\s*\|$'
        $lines.Count | Should -Be 4
    }
    It 'handles empty row set' {
        (ConvertTo-QTMarkdownTable -Rows @()) | Should -Match '(?i)no rows'
    }
}

Describe 'ConvertTo-QTMarkdownReport' {
    It 'has a title, timestamp, and a heading for each section' {
        $sections = @(
            (New-QTSection -Name 'Host' -Rows @([pscustomobject]@{ X = 1 })),
            (New-QTSection -Name 'Processes' -Rows @([pscustomobject]@{ Y = 2 }) -Flags 1)
        )
        $md = ConvertTo-QTMarkdownReport -HostName 'TESTHOST' -Sections $sections
        $md | Should -Match '^# QuickTriage: TESTHOST'
        $md | Should -Match '_Generated:'
        ($md -split "`n" | Where-Object { $_ -match '^## ' }).Count | Should -Be 2
        $md | Should -Match '## Processes ⚠'
    }
}

Describe 'Invoke-QuickTriage (smoke)' -Tag 'Integration' {
    It 'runs against localhost, writes the report, and returns a summary object' {
        $out = Join-Path $TestDrive 'triage.md'
        $skip = @('PSHistory', 'Defender', 'DropsiteFiles', 'RecentPersistence', 'Connections')
        $result = Invoke-QuickTriage -OutFile $out -Skip $skip -MaxItems 5 -ErrorAction Stop
        $result                  | Should -Not -BeNullOrEmpty
        $result.HostName         | Should -Be $env:COMPUTERNAME
        $result.SectionCount     | Should -Be (9 - $skip.Count)  # 9 total sections minus skipped
        Test-Path $out           | Should -BeTrue
        (Get-Content $out -Raw)  | Should -Match '^# QuickTriage:'
    }
}
