#requires -Version 7.2

BeforeAll {
    . (Join-Path $PSScriptRoot 'Get-PasswordPolicy.ps1')

    # ---------------------------------------------------------------------------
    # Synthetic AD domain policy object — matches real Get-ADDefaultDomainPasswordPolicy shape.
    # ---------------------------------------------------------------------------
    $script:FakeDomainPolicy = [PSCustomObject]@{
        MinPasswordLength    = 12
        ComplexityEnabled    = $true
        PasswordHistoryCount = 24
        MaxPasswordAge       = [timespan]::FromDays(60)
        MinPasswordAge       = [timespan]::FromDays(1)
        LockoutThreshold     = 5
        LockoutDuration      = [timespan]::FromMinutes(15)
    }

    # ---------------------------------------------------------------------------
    # Synthetic FGPP objects.
    # ---------------------------------------------------------------------------
    $script:FakeFGPP1 = [PSCustomObject]@{
        Name                 = 'AdminPolicy'
        MinPasswordLength    = 16
        ComplexityEnabled    = $true
        PasswordHistoryCount = 24
        MaxPasswordAge       = [timespan]::FromDays(30)
        MinPasswordAge       = [timespan]::FromDays(1)
        LockoutThreshold     = 3
        LockoutDuration      = [timespan]::FromMinutes(30)
    }
    $script:FakeFGPP2 = [PSCustomObject]@{
        Name                 = 'ServiceAccounts'
        MinPasswordLength    = 20
        ComplexityEnabled    = $true
        PasswordHistoryCount = 48
        MaxPasswordAge       = [timespan]::FromDays(365)
        MinPasswordAge       = [timespan]::FromDays(0)
        LockoutThreshold     = 0
        LockoutDuration      = [timespan]::FromMinutes(0)
    }

    # ---------------------------------------------------------------------------
    # Synthetic net accounts hashtable.
    # ---------------------------------------------------------------------------
    $script:FakeLocalPolicy = @{
        MinLength         = 8
        MaxAge            = 90
        MinAge            = 0
        History           = 10
        LockoutThreshold  = 10
        LockoutDuration   = 30
        ComplexityEnabled = $null
    }

    # ---------------------------------------------------------------------------
    # Baseline JSON path helpers.
    # ---------------------------------------------------------------------------
    function New-BaselineFile {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pester fixture builder — pure function, no state change.')]
        param([string]$Name = 'baseline.json', [hashtable]$Values)
        $path = Join-Path $TestDrive $Name
        $Values | ConvertTo-Json | Set-Content -LiteralPath $path -Encoding UTF8
        return $path
    }
}

# ===========================================================================
# T1: Domain policy — fields copied correctly
# ===========================================================================
Describe 'Get-PasswordPolicy — Domain policy fields' {
    BeforeAll {
        Mock Get-ADDefaultDomainPasswordPolicy { return $script:FakeDomainPolicy }
        Mock Get-GPPNetAccount { return $script:FakeLocalPolicy }
    }

    It 'Domain row Source is "Domain"' {
        $rows = @(Get-PasswordPolicy -IncludeLocal:$false)
        $rows[0].Source | Should -Be 'Domain'
    }
    It 'Domain row MinLength matches mock' {
        $rows = @(Get-PasswordPolicy -IncludeLocal:$false)
        $rows[0].MinLength | Should -Be 12
    }
    It 'Domain row ComplexityEnabled matches mock' {
        $rows = @(Get-PasswordPolicy -IncludeLocal:$false)
        $rows[0].ComplexityEnabled | Should -Be $true
    }
    It 'Domain row HistoryCount matches mock' {
        $rows = @(Get-PasswordPolicy -IncludeLocal:$false)
        $rows[0].HistoryCount | Should -Be 24
    }
    It 'Domain row MaxAgeDays matches mock (60)' {
        $rows = @(Get-PasswordPolicy -IncludeLocal:$false)
        $rows[0].MaxAgeDays | Should -Be 60
    }
    It 'Domain row MinAgeDays matches mock (1)' {
        $rows = @(Get-PasswordPolicy -IncludeLocal:$false)
        $rows[0].MinAgeDays | Should -Be 1
    }
    It 'Domain row LockoutThreshold matches mock' {
        $rows = @(Get-PasswordPolicy -IncludeLocal:$false)
        $rows[0].LockoutThreshold | Should -Be 5
    }
    It 'Domain row LockoutDurationMinutes matches mock (15)' {
        $rows = @(Get-PasswordPolicy -IncludeLocal:$false)
        $rows[0].LockoutDurationMinutes | Should -Be 15
    }
}

# ===========================================================================
# T2: Local policy — fields copied correctly
# ===========================================================================
Describe 'Get-PasswordPolicy — Local policy fields' {
    BeforeAll {
        Mock Get-ADDefaultDomainPasswordPolicy { return $script:FakeDomainPolicy }
        Mock Get-GPPNetAccount { return $script:FakeLocalPolicy }
    }

    It 'Local row Source is "Local"' {
        $rows = @(Get-PasswordPolicy -IncludeDomain:$false)
        $rows[0].Source | Should -Be 'Local'
    }
    It 'Local row MinLength matches mock (8)' {
        $rows = @(Get-PasswordPolicy -IncludeDomain:$false)
        $rows[0].MinLength | Should -Be 8
    }
    It 'Local row HistoryCount matches mock (10)' {
        $rows = @(Get-PasswordPolicy -IncludeDomain:$false)
        $rows[0].HistoryCount | Should -Be 10
    }
    It 'Local row MaxAgeDays matches mock (90)' {
        $rows = @(Get-PasswordPolicy -IncludeDomain:$false)
        $rows[0].MaxAgeDays | Should -Be 90
    }
    It 'Local row LockoutThreshold matches mock (10)' {
        $rows = @(Get-PasswordPolicy -IncludeDomain:$false)
        $rows[0].LockoutThreshold | Should -Be 10
    }
    It 'Local row LockoutDurationMinutes matches mock (30)' {
        $rows = @(Get-PasswordPolicy -IncludeDomain:$false)
        $rows[0].LockoutDurationMinutes | Should -Be 30
    }
}

# ===========================================================================
# T3: FGPP off by default — Get-ADFineGrainedPasswordPolicy NOT invoked
# ===========================================================================
Describe 'Get-PasswordPolicy — FGPP off by default' {
    BeforeAll {
        Mock Get-ADDefaultDomainPasswordPolicy { return $script:FakeDomainPolicy }
        Mock Get-GPPNetAccount { return $script:FakeLocalPolicy }
        Mock Get-ADFineGrainedPasswordPolicy { throw 'Should not be called' }
    }

    It 'does not call Get-ADFineGrainedPasswordPolicy when -IncludeFGPP is not set' {
        { Get-PasswordPolicy } | Should -Not -Throw
        Should -Invoke Get-ADFineGrainedPasswordPolicy -Times 0 -Exactly
    }
}

# ===========================================================================
# T4: FGPP on — 2 FGPPs → 4 total rows (Domain + Local + 2 FGPPs)
# ===========================================================================
Describe 'Get-PasswordPolicy — FGPP on returns correct row count' {
    BeforeAll {
        Mock Get-ADDefaultDomainPasswordPolicy { return $script:FakeDomainPolicy }
        Mock Get-GPPNetAccount { return $script:FakeLocalPolicy }
        Mock Get-ADFineGrainedPasswordPolicy { return @($script:FakeFGPP1, $script:FakeFGPP2) }
    }

    It 'returns 4 rows: Domain + Local + 2 FGPPs' {
        $rows = @(Get-PasswordPolicy -IncludeFGPP)
        $rows.Count | Should -Be 4
    }
    It 'FGPP row 1 Source starts with FGPP:' {
        $rows = @(Get-PasswordPolicy -IncludeFGPP)
        $rows[2].Source | Should -BeLike 'FGPP:*'
    }
    It 'FGPP row 2 Source starts with FGPP:' {
        $rows = @(Get-PasswordPolicy -IncludeFGPP)
        $rows[3].Source | Should -BeLike 'FGPP:*'
    }
}

# ===========================================================================
# T5: -IncludeDomain:$false suppresses domain row
# ===========================================================================
Describe 'Get-PasswordPolicy — IncludeDomain false' {
    BeforeAll {
        Mock Get-ADDefaultDomainPasswordPolicy { return $script:FakeDomainPolicy }
        Mock Get-GPPNetAccount { return $script:FakeLocalPolicy }
    }

    It 'returns only 1 row when -IncludeDomain:$false' {
        $rows = @(Get-PasswordPolicy -IncludeDomain:$false)
        $rows.Count | Should -Be 1
    }
    It 'the single row is Local when -IncludeDomain:$false' {
        $rows = @(Get-PasswordPolicy -IncludeDomain:$false)
        $rows[0].Source | Should -Be 'Local'
    }
    It 'does not call Get-ADDefaultDomainPasswordPolicy when -IncludeDomain:$false' {
        Get-PasswordPolicy -IncludeDomain:$false | Out-Null
        Should -Invoke Get-ADDefaultDomainPasswordPolicy -Times 0 -Exactly
    }
}

# ===========================================================================
# T6: -IncludeLocal:$false suppresses local row
# ===========================================================================
Describe 'Get-PasswordPolicy — IncludeLocal false' {
    BeforeAll {
        Mock Get-ADDefaultDomainPasswordPolicy { return $script:FakeDomainPolicy }
        Mock Get-GPPNetAccount { return $script:FakeLocalPolicy }
    }

    It 'returns only 1 row when -IncludeLocal:$false' {
        $rows = @(Get-PasswordPolicy -IncludeLocal:$false)
        $rows.Count | Should -Be 1
    }
    It 'the single row is Domain when -IncludeLocal:$false' {
        $rows = @(Get-PasswordPolicy -IncludeLocal:$false)
        $rows[0].Source | Should -Be 'Domain'
    }
    It 'does not call Get-GPPNetAccounts when -IncludeLocal:$false' {
        Get-PasswordPolicy -IncludeLocal:$false | Out-Null
        Should -Invoke Get-GPPNetAccount -Times 0 -Exactly
    }
}

# ===========================================================================
# T7: Both off, no FGPP → 0 rows, no error
# ===========================================================================
Describe 'Get-PasswordPolicy — both sources off' {
    BeforeAll {
        Mock Get-ADDefaultDomainPasswordPolicy { return $script:FakeDomainPolicy }
        Mock Get-GPPNetAccount { return $script:FakeLocalPolicy }
    }

    It 'returns 0 rows without error when both domain and local are disabled' {
        $rows = @(Get-PasswordPolicy -IncludeDomain:$false -IncludeLocal:$false)
        $rows.Count | Should -Be 0
    }
    It 'does not throw when both sources are disabled' {
        { Get-PasswordPolicy -IncludeDomain:$false -IncludeLocal:$false } | Should -Not -Throw
    }
}

# ===========================================================================
# T8: No baseline → Status='Unknown', Deltas=@()
# ===========================================================================
Describe 'Get-PasswordPolicy — no baseline gives Status Unknown' {
    BeforeAll {
        Mock Get-ADDefaultDomainPasswordPolicy { return $script:FakeDomainPolicy }
        Mock Get-GPPNetAccount { return $script:FakeLocalPolicy }
    }

    It 'all rows have Status=Unknown when no -BaselinePath' {
        $rows = @(Get-PasswordPolicy)
        $rows | ForEach-Object { $_.Status | Should -Be 'Unknown' }
    }
    It 'all rows have empty Deltas when no -BaselinePath' {
        $rows = @(Get-PasswordPolicy)
        $rows | ForEach-Object { $_.Deltas | Should -BeNullOrEmpty }
    }
}

# ===========================================================================
# T9: Baseline exact match → Status='Compliant', Deltas=@()
# ===========================================================================
Describe 'Get-PasswordPolicy — baseline exact match is Compliant' {
    BeforeAll {
        Mock Get-ADDefaultDomainPasswordPolicy { return $script:FakeDomainPolicy }
        Mock Get-GPPNetAccount { return $script:FakeLocalPolicy }
    }

    It 'Status is Compliant when all fields match the baseline' {
        $bPath = New-BaselineFile -Name 'match.json' -Values @{
            MinLength              = 12
            ComplexityEnabled      = $true
            HistoryCount           = 24
            MaxAgeDays             = 60
            MinAgeDays             = 1
            LockoutThreshold       = 5
            LockoutDurationMinutes = 15
        }
        $rows = @(Get-PasswordPolicy -IncludeLocal:$false -BaselinePath $bPath)
        $rows[0].Status | Should -Be 'Compliant'
    }
    It 'Deltas is empty when all fields match the baseline' {
        $bPath = New-BaselineFile -Name 'match2.json' -Values @{
            MinLength              = 12
            ComplexityEnabled      = $true
            HistoryCount           = 24
            MaxAgeDays             = 60
            MinAgeDays             = 1
            LockoutThreshold       = 5
            LockoutDurationMinutes = 15
        }
        $rows = @(Get-PasswordPolicy -IncludeLocal:$false -BaselinePath $bPath)
        $rows[0].Deltas | Should -BeNullOrEmpty
    }
}

# ===========================================================================
# T10: Baseline single-field drift on MinLength → NonCompliant with correct delta
# ===========================================================================
Describe 'Get-PasswordPolicy — baseline MinLength drift' {
    BeforeAll {
        Mock Get-ADDefaultDomainPasswordPolicy { return $script:FakeDomainPolicy }
        Mock Get-GPPNetAccount { return $script:FakeLocalPolicy }
    }

    It 'Status is NonCompliant when MinLength differs from baseline' {
        $bPath = New-BaselineFile -Name 'minlen-drift.json' -Values @{
            MinLength              = 14
            ComplexityEnabled      = $true
            HistoryCount           = 24
            MaxAgeDays             = 60
            MinAgeDays             = 1
            LockoutThreshold       = 5
            LockoutDurationMinutes = 15
        }
        $rows = @(Get-PasswordPolicy -IncludeLocal:$false -BaselinePath $bPath)
        $rows[0].Status | Should -Be 'NonCompliant'
    }
    It 'Deltas contains one entry for MinLength with Expected=14, Actual=12' {
        $bPath = New-BaselineFile -Name 'minlen-drift2.json' -Values @{
            MinLength              = 14
            ComplexityEnabled      = $true
            HistoryCount           = 24
            MaxAgeDays             = 60
            MinAgeDays             = 1
            LockoutThreshold       = 5
            LockoutDurationMinutes = 15
        }
        $rows = @(Get-PasswordPolicy -IncludeLocal:$false -BaselinePath $bPath)
        $delta = $rows[0].Deltas | Where-Object { $_.Field -eq 'MinLength' }
        $delta | Should -Not -BeNullOrEmpty
        $delta.Expected | Should -Be 14
        $delta.Actual   | Should -Be 12
    }
}

# ===========================================================================
# T11: Drift on multiple fields — each Deltas entry has the right Field name
# ===========================================================================
Describe 'Get-PasswordPolicy — baseline multi-field drift' {
    BeforeAll {
        Mock Get-ADDefaultDomainPasswordPolicy { return $script:FakeDomainPolicy }
        Mock Get-GPPNetAccount { return $script:FakeLocalPolicy }
    }

    It 'Deltas contains HistoryCount field when HistoryCount differs' {
        $bPath = New-BaselineFile -Name 'history-drift.json' -Values @{
            MinLength = 12; ComplexityEnabled = $true; HistoryCount = 99
            MaxAgeDays = 60; MinAgeDays = 1; LockoutThreshold = 5; LockoutDurationMinutes = 15
        }
        $rows  = @(Get-PasswordPolicy -IncludeLocal:$false -BaselinePath $bPath)
        ($rows[0].Deltas | Where-Object { $_.Field -eq 'HistoryCount' }) | Should -Not -BeNullOrEmpty
    }
    It 'Deltas contains MaxAgeDays field when MaxAgeDays differs' {
        $bPath = New-BaselineFile -Name 'maxage-drift.json' -Values @{
            MinLength = 12; ComplexityEnabled = $true; HistoryCount = 24
            MaxAgeDays = 30; MinAgeDays = 1; LockoutThreshold = 5; LockoutDurationMinutes = 15
        }
        $rows  = @(Get-PasswordPolicy -IncludeLocal:$false -BaselinePath $bPath)
        ($rows[0].Deltas | Where-Object { $_.Field -eq 'MaxAgeDays' }) | Should -Not -BeNullOrEmpty
    }
    It 'Deltas contains LockoutThreshold field when LockoutThreshold differs' {
        $bPath = New-BaselineFile -Name 'lockout-drift.json' -Values @{
            MinLength = 12; ComplexityEnabled = $true; HistoryCount = 24
            MaxAgeDays = 60; MinAgeDays = 1; LockoutThreshold = 3; LockoutDurationMinutes = 15
        }
        $rows  = @(Get-PasswordPolicy -IncludeLocal:$false -BaselinePath $bPath)
        ($rows[0].Deltas | Where-Object { $_.Field -eq 'LockoutThreshold' }) | Should -Not -BeNullOrEmpty
    }
    It 'Deltas contains LockoutDurationMinutes field when LockoutDurationMinutes differs' {
        $bPath = New-BaselineFile -Name 'lockdur-drift.json' -Values @{
            MinLength = 12; ComplexityEnabled = $true; HistoryCount = 24
            MaxAgeDays = 60; MinAgeDays = 1; LockoutThreshold = 5; LockoutDurationMinutes = 60
        }
        $rows  = @(Get-PasswordPolicy -IncludeLocal:$false -BaselinePath $bPath)
        ($rows[0].Deltas | Where-Object { $_.Field -eq 'LockoutDurationMinutes' }) | Should -Not -BeNullOrEmpty
    }
    It 'Deltas contains MinAgeDays field when MinAgeDays differs' {
        $bPath = New-BaselineFile -Name 'minage-drift.json' -Values @{
            MinLength = 12; ComplexityEnabled = $true; HistoryCount = 24
            MaxAgeDays = 60; MinAgeDays = 5; LockoutThreshold = 5; LockoutDurationMinutes = 15
        }
        $rows  = @(Get-PasswordPolicy -IncludeLocal:$false -BaselinePath $bPath)
        ($rows[0].Deltas | Where-Object { $_.Field -eq 'MinAgeDays' }) | Should -Not -BeNullOrEmpty
    }
}

# ===========================================================================
# T12: Missing baseline file → throw with clear message
# ===========================================================================
Describe 'Get-PasswordPolicy — missing baseline file throws' {
    It 'throws when -BaselinePath points to a non-existent file' {
        { Get-PasswordPolicy -BaselinePath 'C:\NoSuchFile_xyz_baseline.json' } |
            Should -Throw -ExpectedMessage '*not found*'
    }
}

# ===========================================================================
# T13: Unparseable baseline JSON → throw with clear message
# ===========================================================================
Describe 'Get-PasswordPolicy — unparseable JSON throws' {
    It 'throws when baseline file contains invalid JSON' {
        $badPath = Join-Path $TestDrive 'bad.json'
        Set-Content -LiteralPath $badPath -Value 'NOT { valid json %%' -Encoding UTF8
        { Get-PasswordPolicy -BaselinePath $badPath } | Should -Throw -ExpectedMessage '*Failed to parse*'
    }
}

# ===========================================================================
# T14: -OutputPath writes a CSV with expected columns
# ===========================================================================
Describe 'Get-PasswordPolicy — OutputPath writes CSV' {
    BeforeAll {
        Mock Get-ADDefaultDomainPasswordPolicy { return $script:FakeDomainPolicy }
        Mock Get-GPPNetAccount { return $script:FakeLocalPolicy }
    }

    It 'creates the CSV file at -OutputPath' {
        $csvPath = Join-Path $TestDrive 'output.csv'
        Get-PasswordPolicy -OutputPath $csvPath | Out-Null
        Test-Path -LiteralPath $csvPath | Should -Be $true
    }
    It 'CSV contains a Source column' {
        $csvPath = Join-Path $TestDrive 'output-cols.csv'
        Get-PasswordPolicy -OutputPath $csvPath | Out-Null
        $imported = Import-Csv -LiteralPath $csvPath
        $imported[0].PSObject.Properties.Name | Should -Contain 'Source'
    }
    It 'CSV contains a MinLength column' {
        $csvPath = Join-Path $TestDrive 'output-minlen.csv'
        Get-PasswordPolicy -OutputPath $csvPath | Out-Null
        $imported = Import-Csv -LiteralPath $csvPath
        $imported[0].PSObject.Properties.Name | Should -Contain 'MinLength'
    }
    It 'CSV contains a Status column' {
        $csvPath = Join-Path $TestDrive 'output-status.csv'
        Get-PasswordPolicy -OutputPath $csvPath | Out-Null
        $imported = Import-Csv -LiteralPath $csvPath
        $imported[0].PSObject.Properties.Name | Should -Contain 'Status'
    }
    It 'CSV has 2 rows (Domain + Local)' {
        $csvPath = Join-Path $TestDrive 'output-rowcount.csv'
        Get-PasswordPolicy -OutputPath $csvPath | Out-Null
        $imported = @(Import-Csv -LiteralPath $csvPath)
        $imported.Count | Should -Be 2
    }
}

# ===========================================================================
# T15: Empty FGPP list — no FGPP rows emitted, no error
# ===========================================================================
Describe 'Get-PasswordPolicy — empty FGPP list' {
    BeforeAll {
        Mock Get-ADDefaultDomainPasswordPolicy { return $script:FakeDomainPolicy }
        Mock Get-GPPNetAccount { return $script:FakeLocalPolicy }
        Mock Get-ADFineGrainedPasswordPolicy { return @() }
    }

    It 'does not throw when FGPP returns empty list' {
        { Get-PasswordPolicy -IncludeFGPP } | Should -Not -Throw
    }
    It 'returns only Domain + Local rows when FGPP list is empty' {
        $rows = @(Get-PasswordPolicy -IncludeFGPP)
        $rows.Count | Should -Be 2
    }
}

# ===========================================================================
# T16: net accounts ComplexityEnabled=$null — row carries null, no StrictMode throw
# ===========================================================================
Describe 'Get-PasswordPolicy — ComplexityEnabled null from local policy' {
    BeforeAll {
        Mock Get-ADDefaultDomainPasswordPolicy { return $script:FakeDomainPolicy }
        Mock Get-GPPNetAccount {
            return @{
                MinLength         = 8
                MaxAge            = 90
                MinAge            = 0
                History           = 10
                LockoutThreshold  = 10
                LockoutDuration   = 30
                ComplexityEnabled = $null
            }
        }
    }

    It 'does not throw under normal execution when ComplexityEnabled is null' {
        { Get-PasswordPolicy -IncludeDomain:$false } | Should -Not -Throw
    }
    It 'Local row ComplexityEnabled is null when net accounts returns null' {
        $rows = @(Get-PasswordPolicy -IncludeDomain:$false)
        $rows[0].ComplexityEnabled | Should -BeNullOrEmpty
    }
}
