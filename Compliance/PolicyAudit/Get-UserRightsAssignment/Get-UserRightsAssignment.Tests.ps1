#requires -Version 7.2

BeforeAll {
    . (Join-Path $PSScriptRoot 'Get-UserRightsAssignment.ps1')

    # ---------------------------------------------------------------------------
    # Helper: write a synthetic INF to TestDrive and return the path.
    # The mock for Invoke-GURASecedit MUST call this each time it runs because the
    # public function deletes the INF in its finally block after every call.
    # ---------------------------------------------------------------------------
    function New-MockInfFile {
        <#
        .SYNOPSIS
            Write a secedit-style INF fixture to TestDrive and return its path.
        #>
        param(
            [string]$Name    = "mock-$(New-Guid).inf",
            [string]$Content
        )
        $path = Join-Path $TestDrive $Name
        Set-Content -LiteralPath $path -Value $Content -Encoding UTF8
        return $path
    }

    # ---------------------------------------------------------------------------
    # Canonical INF content used by most tests.
    # ---------------------------------------------------------------------------
    $script:CanonicalInf = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
[Privilege Rights]
SeDebugPrivilege = *S-1-5-32-544
SeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551
SeShutdownPrivilege = *S-1-5-32-544,*S-1-5-32-545
'@

    # ---------------------------------------------------------------------------
    # Standard SID map used in most Describe blocks.
    # ---------------------------------------------------------------------------
    $script:StandardSidMap = @{
        'S-1-5-32-544' = 'BUILTIN\Administrators'
        'S-1-5-32-551' = 'BUILTIN\Backup Operators'
        'S-1-5-32-545' = 'BUILTIN\Users'
    }

    # ---------------------------------------------------------------------------
    # Helper: build a baseline JSON file and return its path.
    # ---------------------------------------------------------------------------
    function New-BaselineFile {
        <#
        .SYNOPSIS
            Write a CIS-style JSON baseline to TestDrive and return the path.
        #>
        param(
            [string]$Name = "baseline-$(New-Guid).json",
            [object[]]$Privileges
        )
        $path = Join-Path $TestDrive $Name
        @{ privileges = $Privileges } | ConvertTo-Json -Depth 5 |
            Set-Content -LiteralPath $path -Encoding UTF8
        return $path
    }
}

# ===========================================================================
# T1: Happy parse — canned INF returns expected privileges and account names
# ===========================================================================
Describe 'Get-UserRightsAssignment — happy parse' {
    BeforeAll {
        # Mock recreates the INF on every call because the finally block removes it.
        Mock Invoke-GURASecedit {
            New-MockInfFile -Content $script:CanonicalInf
        }
        Mock Get-GURAResolveSid {
            param($Sid)
            $clean = $Sid.TrimStart('*')
            if ($script:StandardSidMap.ContainsKey($clean)) { return $script:StandardSidMap[$clean] } else { return $clean }
        }
    }

    It 'returns a row for each privilege in the INF' {
        $rows = @(Get-UserRightsAssignment)
        $rows.Count | Should -Be 3
    }

    It 'SeDebugPrivilege row has correct AccountNames' {
        $rows = @(Get-UserRightsAssignment)
        $row  = $rows | Where-Object { $_.Privilege -eq 'SeDebugPrivilege' }
        $row.AccountNames | Should -Be 'BUILTIN\Administrators'
    }

    It 'SeBackupPrivilege row has two account names semicolon-joined' {
        $rows = @(Get-UserRightsAssignment)
        $row  = $rows | Where-Object { $_.Privilege -eq 'SeBackupPrivilege' }
        $row.AccountNames | Should -Be 'BUILTIN\Administrators;BUILTIN\Backup Operators'
    }
}

# ===========================================================================
# T2: SID resolution failure — AccountName falls back to raw SID
# ===========================================================================
Describe 'Get-UserRightsAssignment — SID resolution fallback' {
    BeforeAll {
        Mock Invoke-GURASecedit {
            New-MockInfFile -Content $script:CanonicalInf
        }
        Mock Get-GURAResolveSid {
            param($Sid)
            $clean = $Sid.TrimStart('*')
            # Simulate resolution failure for S-1-5-32-544 → return raw SID
            if ($clean -eq 'S-1-5-32-544') { return $clean }
            return 'BUILTIN\Backup Operators'
        }
    }

    It 'unresolvable SID appears as the raw SID string in AccountNames' {
        $rows = @(Get-UserRightsAssignment)
        $row  = $rows | Where-Object { $_.Privilege -eq 'SeDebugPrivilege' }
        $row.AccountNames | Should -Be 'S-1-5-32-544'
    }
}

# ===========================================================================
# T3: Compliant — parsed set equals baseline ExpectedAccounts
# ===========================================================================
Describe 'Get-UserRightsAssignment — Compliant match' {
    BeforeAll {
        Mock Invoke-GURASecedit {
            New-MockInfFile -Content $script:CanonicalInf
        }
        Mock Get-GURAResolveSid {
            param($Sid)
            $clean = $Sid.TrimStart('*')
            if ($script:StandardSidMap.ContainsKey($clean)) { return $script:StandardSidMap[$clean] } else { return $clean }
        }
    }

    It 'row Status is Compliant when live accounts match baseline ExpectedAccounts' {
        $bPath = New-BaselineFile -Privileges @(
            @{ Privilege = 'SeDebugPrivilege'; ExpectedAccounts = @('BUILTIN\Administrators') }
        )
        $rows = @(Get-UserRightsAssignment -BaselinePath $bPath)
        $row  = $rows | Where-Object { $_.Privilege -eq 'SeDebugPrivilege' }
        $row.Status | Should -Be 'Compliant'
    }
}

# ===========================================================================
# T4: Drift — extra account in parsed
# ===========================================================================
Describe 'Get-UserRightsAssignment — Drift extra account' {
    BeforeAll {
        Mock Invoke-GURASecedit {
            New-MockInfFile -Content $script:CanonicalInf
        }
        Mock Get-GURAResolveSid {
            param($Sid)
            $clean = $Sid.TrimStart('*')
            if ($script:StandardSidMap.ContainsKey($clean)) { return $script:StandardSidMap[$clean] } else { return $clean }
        }
    }

    It 'Status is Drift when live has extra account not in baseline' {
        # Baseline expects only Administrators; live has Administrators+Backup Operators.
        $bPath = New-BaselineFile -Privileges @(
            @{ Privilege = 'SeBackupPrivilege'; ExpectedAccounts = @('BUILTIN\Administrators') }
        )
        $rows = @(Get-UserRightsAssignment -BaselinePath $bPath)
        $row  = $rows | Where-Object { $_.Privilege -eq 'SeBackupPrivilege' }
        $row.Status | Should -Be 'Drift'
    }

    It 'Reason includes "Added:" when live has extra account' {
        $bPath = New-BaselineFile -Privileges @(
            @{ Privilege = 'SeBackupPrivilege'; ExpectedAccounts = @('BUILTIN\Administrators') }
        )
        $rows = @(Get-UserRightsAssignment -BaselinePath $bPath)
        $row  = $rows | Where-Object { $_.Privilege -eq 'SeBackupPrivilege' }
        $row.Reason | Should -Match 'Added:'
    }
}

# ===========================================================================
# T5: Drift — account removed from parsed
# ===========================================================================
Describe 'Get-UserRightsAssignment — Drift removed account' {
    BeforeAll {
        Mock Invoke-GURASecedit {
            New-MockInfFile -Content $script:CanonicalInf
        }
        Mock Get-GURAResolveSid {
            param($Sid)
            $clean = $Sid.TrimStart('*')
            if ($script:StandardSidMap.ContainsKey($clean)) { return $script:StandardSidMap[$clean] } else { return $clean }
        }
    }

    It 'Reason includes "Removed:" when baseline account absent from live' {
        # Baseline expects Admins+BackupOps+ExtraGroup; live only has Admins+BackupOps.
        $bPath = New-BaselineFile -Privileges @(
            @{ Privilege = 'SeBackupPrivilege'
               ExpectedAccounts = @('BUILTIN\Administrators', 'BUILTIN\Backup Operators', 'BUILTIN\Extra Group') }
        )
        $rows = @(Get-UserRightsAssignment -BaselinePath $bPath)
        $row  = $rows | Where-Object { $_.Privilege -eq 'SeBackupPrivilege' }
        $row.Reason | Should -Match 'Removed:'
    }
}

# ===========================================================================
# T6: Missing — baseline privilege absent from parsed
# ===========================================================================
Describe 'Get-UserRightsAssignment — Missing privilege' {
    BeforeAll {
        Mock Invoke-GURASecedit {
            New-MockInfFile -Content $script:CanonicalInf
        }
        Mock Get-GURAResolveSid { param($Sid) return $Sid.TrimStart('*') }
    }

    It 'Status is Missing when baseline privilege not present in live INF' {
        $bPath = New-BaselineFile -Privileges @(
            @{ Privilege = 'SeAuditPrivilege'; ExpectedAccounts = @('NT AUTHORITY\LOCAL SERVICE') }
        )
        $rows = @(Get-UserRightsAssignment -BaselinePath $bPath)
        $row  = $rows | Where-Object { $_.Privilege -eq 'SeAuditPrivilege' }
        $row.Status | Should -Be 'Missing'
    }

    It 'Missing row has Actual null or empty' {
        $bPath = New-BaselineFile -Privileges @(
            @{ Privilege = 'SeAuditPrivilege'; ExpectedAccounts = @('NT AUTHORITY\LOCAL SERVICE') }
        )
        $rows = @(Get-UserRightsAssignment -BaselinePath $bPath)
        $row  = $rows | Where-Object { $_.Privilege -eq 'SeAuditPrivilege' }
        $row.Actual | Should -BeNullOrEmpty
    }
}

# ===========================================================================
# T7: Empty [Privilege Rights] section
# ===========================================================================
Describe 'Get-UserRightsAssignment — empty Privilege Rights section' {
    BeforeAll {
        $emptyInf = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
[Privilege Rights]
[System Access]
MinimumPasswordAge = 0
'@
        Mock Invoke-GURASecedit {
            New-MockInfFile -Content $emptyInf
        }
        Mock Get-GURAResolveSid { param($Sid) return $Sid.TrimStart('*') }
    }

    It 'returns 0 rows when section is empty and no baseline supplied' {
        $rows = @(Get-UserRightsAssignment)
        $rows.Count | Should -Be 0
    }

    It 'all baseline privileges are Missing when section is empty' {
        $bPath = New-BaselineFile -Privileges @(
            @{ Privilege = 'SeDebugPrivilege';  ExpectedAccounts = @('BUILTIN\Administrators') },
            @{ Privilege = 'SeBackupPrivilege'; ExpectedAccounts = @('BUILTIN\Administrators') }
        )
        $rows    = @(Get-UserRightsAssignment -BaselinePath $bPath)
        $missing = @($rows | Where-Object { $_.Status -eq 'Missing' })
        $missing.Count | Should -Be 2
    }
}

# ===========================================================================
# T8: secedit non-zero exit — throws
# ===========================================================================
Describe 'Get-UserRightsAssignment — secedit failure throws' {
    BeforeAll {
        Mock Invoke-GURASecedit { throw 'secedit failed (exit 1): Access denied' }
    }

    It 'Get-UserRightsAssignment throws when Invoke-GURASecedit throws' {
        { Get-UserRightsAssignment } | Should -Throw
    }
}

# ===========================================================================
# T9: Temp file cleanup on success
# ===========================================================================
Describe 'Get-UserRightsAssignment — temp file removed on success' {
    BeforeAll {
        # Use a fixed name so the test can assert the path is gone afterward.
        $script:CleanupInfPath = Join-Path $TestDrive 'cleanup-success.inf'
        Set-Content -LiteralPath $script:CleanupInfPath -Value $script:CanonicalInf -Encoding UTF8

        Mock Invoke-GURASecedit { return $script:CleanupInfPath }
        Mock Get-GURAResolveSid { param($Sid) return $Sid.TrimStart('*') }
    }

    It 'the INF file is removed after a successful run' {
        Get-UserRightsAssignment | Out-Null
        Test-Path -LiteralPath $script:CleanupInfPath | Should -Be $false
    }
}

# ===========================================================================
# T10: Temp file cleanup on throw (mid-execution error via Get-Content mock)
# ===========================================================================
Describe 'Get-UserRightsAssignment — temp file removed on error' {
    BeforeAll {
        $script:ErrorInfPath = Join-Path $TestDrive 'cleanup-error.inf'
        Set-Content -LiteralPath $script:ErrorInfPath -Value $script:CanonicalInf -Encoding UTF8

        Mock Invoke-GURASecedit { return $script:ErrorInfPath }
        # Simulate a read failure INSIDE the try block after secedit returns.
        Mock Get-Content {
            throw 'Simulated read error inside try block'
        } -ParameterFilter { $LiteralPath -eq $script:ErrorInfPath }
    }

    It 'the INF file is removed even when an error occurs inside the try block' {
        try { Get-UserRightsAssignment } catch { }
        Test-Path -LiteralPath $script:ErrorInfPath | Should -Be $false
    }
}

# ===========================================================================
# T11: Privilege in parsed but not in baseline → Unknown row
# ===========================================================================
Describe 'Get-UserRightsAssignment — Unknown row for unbaselined privilege' {
    BeforeAll {
        Mock Invoke-GURASecedit {
            New-MockInfFile -Content $script:CanonicalInf
        }
        Mock Get-GURAResolveSid {
            param($Sid)
            $clean = $Sid.TrimStart('*')
            if ($script:StandardSidMap.ContainsKey($clean)) { return $script:StandardSidMap[$clean] } else { return $clean }
        }
    }

    It 'privilege present in live but absent from baseline emits Status=Unknown' {
        # Baseline only covers SeDebugPrivilege; SeBackupPrivilege and SeShutdownPrivilege are extras.
        $bPath = New-BaselineFile -Privileges @(
            @{ Privilege = 'SeDebugPrivilege'; ExpectedAccounts = @('BUILTIN\Administrators') }
        )
        $rows    = @(Get-UserRightsAssignment -BaselinePath $bPath)
        $unknown = @($rows | Where-Object { $_.Status -eq 'Unknown' })
        $unknown.Count | Should -BeGreaterOrEqual 1
        ($unknown | Where-Object { $_.Privilege -eq 'SeBackupPrivilege' }) | Should -Not -BeNullOrEmpty
    }
}

# ===========================================================================
# T12: CSV roundtrip — -OutputPath writes a file with expected columns
# ===========================================================================
Describe 'Get-UserRightsAssignment — CSV export' {
    BeforeAll {
        Mock Invoke-GURASecedit {
            New-MockInfFile -Content $script:CanonicalInf
        }
        Mock Get-GURAResolveSid { param($Sid) return $Sid.TrimStart('*') }
    }

    It 'creates the CSV file at -OutputPath' {
        $csvPath = Join-Path $TestDrive 'output.csv'
        Get-UserRightsAssignment -OutputPath $csvPath | Out-Null
        Test-Path -LiteralPath $csvPath | Should -Be $true
    }

    It 'CSV contains a Privilege column' {
        $csvPath = Join-Path $TestDrive 'output-priv.csv'
        Get-UserRightsAssignment -OutputPath $csvPath | Out-Null
        $imported = Import-Csv -LiteralPath $csvPath
        $imported[0].PSObject.Properties.Name | Should -Contain 'Privilege'
    }

    It 'CSV contains an AccountNames column' {
        $csvPath = Join-Path $TestDrive 'output-names.csv'
        Get-UserRightsAssignment -OutputPath $csvPath | Out-Null
        $imported = Import-Csv -LiteralPath $csvPath
        $imported[0].PSObject.Properties.Name | Should -Contain 'AccountNames'
    }

    It 'CSV contains a Status column' {
        $csvPath = Join-Path $TestDrive 'output-stat.csv'
        Get-UserRightsAssignment -OutputPath $csvPath | Out-Null
        $imported = Import-Csv -LiteralPath $csvPath
        $imported[0].PSObject.Properties.Name | Should -Contain 'Status'
    }
}

# ===========================================================================
# T13: Bad baseline path → '*not found*'
# ===========================================================================
Describe 'Get-UserRightsAssignment — missing baseline file throws' {
    It 'throws when -BaselinePath points to a non-existent file' {
        { Get-UserRightsAssignment -BaselinePath 'C:\NoSuchFile_xyz_ura_baseline.json' } |
            Should -Throw -ExpectedMessage '*not found*'
    }
}

# ===========================================================================
# T14: Malformed baseline JSON → '*Failed to parse*'
# ===========================================================================
Describe 'Get-UserRightsAssignment — malformed baseline JSON throws' {
    It 'throws when baseline file contains invalid JSON' {
        $badPath = Join-Path $TestDrive 'bad-ura.json'
        Set-Content -LiteralPath $badPath -Value 'NOT { valid json %%' -Encoding UTF8
        { Get-UserRightsAssignment -BaselinePath $badPath } |
            Should -Throw -ExpectedMessage '*Failed to parse*'
    }
}

# ===========================================================================
# T15: Multiple SIDs per privilege parsed correctly (comma-split)
# ===========================================================================
Describe 'Get-UserRightsAssignment — multiple SIDs per privilege' {
    BeforeAll {
        $multiInf = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
[Privilege Rights]
SeImpersonatePrivilege = *S-1-5-32-544,*S-1-5-6,*S-1-5-19,*S-1-5-20
'@
        $sidMap4 = @{
            'S-1-5-32-544' = 'BUILTIN\Administrators'
            'S-1-5-6'      = 'NT AUTHORITY\SERVICE'
            'S-1-5-19'     = 'NT AUTHORITY\LOCAL SERVICE'
            'S-1-5-20'     = 'NT AUTHORITY\NETWORK SERVICE'
        }

        Mock Invoke-GURASecedit {
            New-MockInfFile -Content $multiInf
        }
        Mock Get-GURAResolveSid {
            param($Sid)
            $clean = $Sid.TrimStart('*')
            if ($sidMap4.ContainsKey($clean)) { return $sidMap4[$clean] } else { return $clean }
        }
    }

    It 'SeImpersonatePrivilege row has all four account names' {
        $rows = @(Get-UserRightsAssignment)
        $row  = $rows | Where-Object { $_.Privilege -eq 'SeImpersonatePrivilege' }
        $names = $row.AccountNames -split ';'
        $names.Count | Should -Be 4
    }

    It 'all four SIDs appear in AccountSids' {
        $rows = @(Get-UserRightsAssignment)
        $row  = $rows | Where-Object { $_.Privilege -eq 'SeImpersonatePrivilege' }
        $row.AccountSids | Should -Match 'S-1-5-32-544'
        $row.AccountSids | Should -Match 'S-1-5-20'
    }
}

# ===========================================================================
# T16: Leading '*' prefix on SIDs handled (stripped before SID resolution)
# ===========================================================================
Describe 'Get-UserRightsAssignment — leading asterisk stripped before resolution' {
    BeforeAll {
        $starInf = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
[Privilege Rights]
SeDebugPrivilege = *S-1-5-32-544
'@
        $script:SidPassedToResolver = $null

        Mock Invoke-GURASecedit {
            New-MockInfFile -Content $starInf
        }
        Mock Get-GURAResolveSid {
            param($Sid)
            $script:SidPassedToResolver = $Sid
            return 'BUILTIN\Administrators'
        }
    }

    It 'Get-GURAResolveSid is called (SID is passed for resolution)' {
        Get-UserRightsAssignment | Out-Null
        $script:SidPassedToResolver | Should -Not -BeNullOrEmpty
    }

    It 'AccountSids retains the raw * prefix for transparency' {
        $rows = @(Get-UserRightsAssignment)
        $row  = $rows | Where-Object { $_.Privilege -eq 'SeDebugPrivilege' }
        $row.AccountSids | Should -Match '\*S-1-5-32-544'
    }
}
