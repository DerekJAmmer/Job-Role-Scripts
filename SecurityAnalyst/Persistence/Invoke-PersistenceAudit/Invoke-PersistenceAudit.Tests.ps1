BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'Invoke-PersistenceAudit.ps1'
    . $scriptPath
}

# ---------------------------------------------------------------------------
# Unit tests — helpers
# ---------------------------------------------------------------------------

Describe 'New-PASection' {
    It 'builds a section with correct shape' {
        $s = New-PASection -Name 'Test' -Rows @([pscustomobject]@{ A = 1 }) -Flags 2 -New 1
        $s.Name   | Should -Be 'Test'
        $s.Flags  | Should -Be 2
        $s.New    | Should -Be 1
        $s.Notes  | Should -Be ''
        $s.Rows.Count | Should -Be 1
    }

    It 'defaults Rows to empty array' {
        $s = New-PASection -Name 'Empty'
        $s.Rows | Should -Not -BeNullOrEmpty -Because 'Rows defaults to @()'
        $s.Rows.Count | Should -Be 0
    }
}

Describe 'Get-PASigner' {
    It 'returns Unknown for null path' {
        Get-PASigner -Path $null | Should -Be 'Unknown'
    }

    It 'returns Unknown for empty string' {
        Get-PASigner -Path '' | Should -Be 'Unknown'
    }

    It 'returns Unknown for non-existent path' {
        Get-PASigner -Path 'C:\DoesNotExist_ABC123.exe' | Should -Be 'Unknown'
    }

    It 'caches results for the same path' {
        # Seed the cache manually and verify it returns the cached value
        $script:SignerCache['C:\FakeCached.exe'] = 'CachedVendor'
        Get-PASigner -Path 'C:\FakeCached.exe' | Should -Be 'CachedVendor'
        $script:SignerCache.Remove('C:\FakeCached.exe')
    }
}

Describe 'Test-PAMicrosoftSigned' {
    It 'matches Microsoft Corporation' {
        Test-PAMicrosoftSigned -Signer 'Microsoft Corporation' | Should -BeTrue
    }
    It 'matches case-insensitively' {
        Test-PAMicrosoftSigned -Signer 'MICROSOFT WINDOWS' | Should -BeTrue
    }
    It 'returns false for unsigned' {
        Test-PAMicrosoftSigned -Signer 'Unsigned' | Should -BeFalse
    }
    It 'returns false for third-party vendor' {
        Test-PAMicrosoftSigned -Signer 'SomeRandom Corp' | Should -BeFalse
    }
}

Describe 'Get-PACleanExePath' {
    It 'extracts path from quoted service PathName' {
        Get-PACleanExePath -Raw '"C:\Windows\System32\svchost.exe" -k netsvcs' |
            Should -Be 'C:\Windows\System32\svchost.exe'
    }

    It 'extracts plain exe path' {
        Get-PACleanExePath -Raw 'C:\Program Files\tool\app.exe --flag' |
            Should -Be 'C:\Program Files\tool\app.exe'
    }

    It 'returns null for null input' {
        Get-PACleanExePath -Raw $null | Should -BeNullOrEmpty
    }
}

Describe 'ConvertTo-PAMarkdownTable' {
    It 'produces a valid pipe table' {
        $rows = @(
            [pscustomobject]@{ Name = 'A'; Value = '1'; Flagged = $false; IsNew = $false },
            [pscustomobject]@{ Name = 'B'; Value = '2'; Flagged = $true;  IsNew = $false }
        )
        $md = ConvertTo-PAMarkdownTable -Rows $rows
        $lines = $md -split "`n"
        # Header should contain Name and Value but NOT Flagged/IsNew (they're stripped)
        $lines[0] | Should -Match '\|\s*Name\s*\|'
        $lines[0] | Should -Not -Match 'Flagged'
        $lines[1] | Should -Match '---'
        # Flagged row should have the warning marker
        $md | Should -Match '⚠'
    }

    It 'handles empty rows' {
        (ConvertTo-PAMarkdownTable -Rows @()) | Should -Match '(?i)no entries'
    }
}

Describe 'Import-PABaseline' {
    It 'returns null when path is empty' {
        Import-PABaseline -Path '' | Should -BeNullOrEmpty
    }

    It 'returns null when file does not exist' {
        Import-PABaseline -Path 'C:\DoesNotExist_PABaseline.json' | Should -BeNullOrEmpty
    }

    It 'loads a valid baseline JSON' {
        $tmp = Join-Path $TestDrive 'baseline.json'
        @{ RunKeys = @('HKLM\\...\\Run:test') } | ConvertTo-Json | Set-Content $tmp
        $bl = Import-PABaseline -Path $tmp
        $bl | Should -Not -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# Integration smoke test
# ---------------------------------------------------------------------------

Describe 'Invoke-PersistenceAudit (smoke)' -Tag 'Integration' {
    It 'runs, writes a report, and returns a summary object' {
        $out = Join-Path $TestDrive 'audit.md'
        # Skip WMI (needs elevation) to keep the test fast and non-privileged
        $result = Invoke-PersistenceAudit -OutFile $out -Skip WMISubscriptions -ErrorAction Stop
        $result               | Should -Not -BeNullOrEmpty
        $result.HostName      | Should -Be $env:COMPUTERNAME
        $result.SectionCount  | Should -Be 5   # 6 sections minus 1 skipped
        Test-Path $out        | Should -BeTrue
        (Get-Content $out -Raw) | Should -Match '^# PersistenceAudit:'
    }

    It 'writes and reloads a baseline without errors' {
        $blPath = Join-Path $TestDrive 'baseline.json'
        $out    = Join-Path $TestDrive 'audit2.md'
        # First run: save baseline
        Invoke-PersistenceAudit -OutFile $out -SaveBaseline -BaselinePath $blPath `
            -Skip WMISubscriptions -ErrorAction Stop
        Test-Path $blPath | Should -BeTrue
        # Second run: load baseline
        $result = Invoke-PersistenceAudit -OutFile $out -BaselinePath $blPath `
            -Skip WMISubscriptions -ErrorAction Stop
        # NewCount should be 0 because nothing changed
        $result.NewCount | Should -Be 0
    }
}
