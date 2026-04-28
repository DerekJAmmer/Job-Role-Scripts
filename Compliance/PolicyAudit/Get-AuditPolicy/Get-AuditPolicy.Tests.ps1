#requires -Version 7.2

BeforeAll {
    . (Join-Path $PSScriptRoot 'Get-AuditPolicy.ps1')

    # ---------------------------------------------------------------------------
    # Helper: build a mock auditpol CSV string.
    # Uses 'Get-' prefix to avoid PSScriptAnalyzer PSUseShouldProcessForStateChangingFunctions.
    # ---------------------------------------------------------------------------
    function Get-MockAuditCsv {
        <#
        .SYNOPSIS
            Return a synthetic auditpol /r CSV string for testing.
        #>
        @"
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting

PC,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,
PC,System,Logoff,{0CCE9216-69AE-11D9-BED3-505054503030},Success,
PC,System,Account Lockout,{0CCE9217-69AE-11D9-BED3-505054503030},Failure,
PC,System,Special Logon,{0CCE921B-69AE-11D9-BED3-505054503030},Success,
PC,System,Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},No Auditing,
PC,System,Credential Validation,{0CCE923F-69AE-11D9-BED3-505054503030},Success and Failure,
PC,System,Audit Policy Change,{0CCE922F-69AE-11D9-BED3-505054503030},Success,
PC,System,User Account Management,{0CCE9235-69AE-11D9-BED3-505054503030},Success and Failure,
PC,System,Security Group Management,{0CCE9237-69AE-11D9-BED3-505054503030},Success and Failure,
PC,System,Other Logon/Logoff Events,{0CCE921C-69AE-11D9-BED3-505054503030},Success and Failure,
"@
    }

    # ---------------------------------------------------------------------------
    # Helper: build a baseline JSON file and return its path.
    # ---------------------------------------------------------------------------
    function Get-BaselineFilePath {
        <#
        .SYNOPSIS
            Write a CIS-style JSON baseline to TestDrive and return the path.
        #>
        param(
            [string]$Name = 'baseline.json',
            [object[]]$Subcategories
        )
        $path = Join-Path $TestDrive $Name
        @{ subcategories = $Subcategories } | ConvertTo-Json -Depth 5 |
            Set-Content -LiteralPath $path -Encoding UTF8
        return $path
    }
}

# ===========================================================================
# T1: No-baseline mode — all rows Status='Unknown', Expected/Actual null
# ===========================================================================
Describe 'Get-AuditPolicy — no-baseline mode' {
    BeforeAll {
        Mock Invoke-GAPAuditPol { Get-MockAuditCsv }
    }

    It 'all rows have Status=Unknown when no -BaselinePath is given' {
        $rows = @(Get-AuditPolicy)
        $rows.Count | Should -BeGreaterThan 0
        $rows | ForEach-Object { $_.Status | Should -Be 'Unknown' }
    }

    It 'all rows have Expected=null when no -BaselinePath is given' {
        $rows = @(Get-AuditPolicy)
        $rows | ForEach-Object { $_.Expected | Should -BeNullOrEmpty }
    }

    It 'all rows have Actual=null when no -BaselinePath is given' {
        $rows = @(Get-AuditPolicy)
        $rows | ForEach-Object { $_.Actual | Should -BeNullOrEmpty }
    }
}

# ===========================================================================
# T2: Full pass — all baseline subcategories Compliant when settings match
# ===========================================================================
Describe 'Get-AuditPolicy — full pass all Compliant' {
    BeforeAll {
        Mock Invoke-GAPAuditPol { Get-MockAuditCsv }
    }

    It 'rows present in both baseline and live data with matching settings are Compliant' {
        $bPath = Get-BaselineFilePath -Name 'full-match.json' -Subcategories @(
            @{ Subcategory = 'Logon';                   Expected = 'Success and Failure' },
            @{ Subcategory = 'Logoff';                  Expected = 'Success' },
            @{ Subcategory = 'Account Lockout';         Expected = 'Failure' },
            @{ Subcategory = 'Credential Validation';   Expected = 'Success and Failure' }
        )
        $rows = @(Get-AuditPolicy -BaselinePath $bPath)
        $compliant = $rows | Where-Object { $_.Status -eq 'Compliant' }
        $compliant.Count | Should -Be 4
    }
}

# ===========================================================================
# T3: Single drift detected
# ===========================================================================
Describe 'Get-AuditPolicy — single drift' {
    BeforeAll {
        Mock Invoke-GAPAuditPol { Get-MockAuditCsv }
    }

    It 'row Status is Drift when baseline expected differs from actual setting' {
        $bPath = Get-BaselineFilePath -Name 'single-drift.json' -Subcategories @(
            @{ Subcategory = 'Logon'; Expected = 'Success' }   # actual is 'Success and Failure'
        )
        $rows = @(Get-AuditPolicy -BaselinePath $bPath)
        $drift = $rows | Where-Object { $_.Subcategory -eq 'Logon' -and $_.Status -eq 'Drift' }
        $drift | Should -Not -BeNullOrEmpty
    }

    It 'Drift row Expected is populated with the baseline value' {
        $bPath = Get-BaselineFilePath -Name 'single-drift-exp.json' -Subcategories @(
            @{ Subcategory = 'Logon'; Expected = 'Success' }
        )
        $rows = @(Get-AuditPolicy -BaselinePath $bPath)
        $drift = $rows | Where-Object { $_.Subcategory -eq 'Logon' }
        $drift.Expected | Should -Be 'Success'
    }

    It 'Drift row Actual is populated with the live setting' {
        $bPath = Get-BaselineFilePath -Name 'single-drift-act.json' -Subcategories @(
            @{ Subcategory = 'Logon'; Expected = 'Success' }
        )
        $rows = @(Get-AuditPolicy -BaselinePath $bPath)
        $drift = $rows | Where-Object { $_.Subcategory -eq 'Logon' }
        $drift.Actual | Should -Be 'Success and Failure'
    }
}

# ===========================================================================
# T4: Missing subcategory — in baseline but absent from auditpol output
# ===========================================================================
Describe 'Get-AuditPolicy — missing subcategory' {
    BeforeAll {
        Mock Invoke-GAPAuditPol {
            # CSV without Process Creation
            @"
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting

PC,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,
PC,System,Logoff,{0CCE9216-69AE-11D9-BED3-505054503030},Success,
"@
        }
    }

    It 'baseline subcategory absent from live output gets Status=Missing' {
        $bPath = Get-BaselineFilePath -Name 'missing.json' -Subcategories @(
            @{ Subcategory = 'Logon';           Expected = 'Success and Failure' },
            @{ Subcategory = 'Process Creation'; Expected = 'Success' }
        )
        $rows = @(Get-AuditPolicy -BaselinePath $bPath)
        $missing = $rows | Where-Object { $_.Subcategory -eq 'Process Creation' -and $_.Status -eq 'Missing' }
        $missing | Should -Not -BeNullOrEmpty
    }

    It 'Missing row has Expected populated and Actual null' {
        $bPath = Get-BaselineFilePath -Name 'missing-vals.json' -Subcategories @(
            @{ Subcategory = 'Process Creation'; Expected = 'Success' }
        )
        $rows = @(Get-AuditPolicy -BaselinePath $bPath)
        $missing = $rows | Where-Object { $_.Subcategory -eq 'Process Creation' }
        $missing.Expected | Should -Be 'Success'
        $missing.Actual   | Should -BeNullOrEmpty
    }
}

# ===========================================================================
# T5: Malformed CSV row — warning emitted, valid rows still parsed
# ===========================================================================
Describe 'Get-AuditPolicy — malformed CSV row' {
    BeforeAll {
        Mock Invoke-GAPAuditPol {
            @"
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting

PC,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,
this,is,bad
PC,System,Logoff,{0CCE9216-69AE-11D9-BED3-505054503030},Success,
"@
        }
    }

    It 'emits a warning for the malformed line' {
        $warnings = @()
        Get-AuditPolicy -WarningVariable warnings | Out-Null
        ($warnings | Where-Object { $_ -match 'Could not parse' }) | Should -Not -BeNullOrEmpty
    }

    It 'still parses and returns valid rows despite a malformed line' {
        $rows = @(Get-AuditPolicy)
        $rows.Count | Should -BeGreaterOrEqual 2
        ($rows | Where-Object { $_.Subcategory -eq 'Logon' }) | Should -Not -BeNullOrEmpty
        ($rows | Where-Object { $_.Subcategory -eq 'Logoff' }) | Should -Not -BeNullOrEmpty
    }
}

# ===========================================================================
# T6: -OutputPath writes CSV with expected columns
# ===========================================================================
Describe 'Get-AuditPolicy — OutputPath writes CSV' {
    BeforeAll {
        Mock Invoke-GAPAuditPol { Get-MockAuditCsv }
    }

    It 'creates the CSV file at -OutputPath' {
        $csvPath = Join-Path $TestDrive 'output.csv'
        Get-AuditPolicy -OutputPath $csvPath | Out-Null
        Test-Path -LiteralPath $csvPath | Should -Be $true
    }

    It 'CSV contains a Category column' {
        $csvPath = Join-Path $TestDrive 'output-cat.csv'
        Get-AuditPolicy -OutputPath $csvPath | Out-Null
        $imported = Import-Csv -LiteralPath $csvPath
        $imported[0].PSObject.Properties.Name | Should -Contain 'Category'
    }

    It 'CSV contains a Subcategory column' {
        $csvPath = Join-Path $TestDrive 'output-sub.csv'
        Get-AuditPolicy -OutputPath $csvPath | Out-Null
        $imported = Import-Csv -LiteralPath $csvPath
        $imported[0].PSObject.Properties.Name | Should -Contain 'Subcategory'
    }

    It 'CSV contains a Setting column' {
        $csvPath = Join-Path $TestDrive 'output-set.csv'
        Get-AuditPolicy -OutputPath $csvPath | Out-Null
        $imported = Import-Csv -LiteralPath $csvPath
        $imported[0].PSObject.Properties.Name | Should -Contain 'Setting'
    }

    It 'CSV contains a Status column' {
        $csvPath = Join-Path $TestDrive 'output-stat.csv'
        Get-AuditPolicy -OutputPath $csvPath | Out-Null
        $imported = Import-Csv -LiteralPath $csvPath
        $imported[0].PSObject.Properties.Name | Should -Contain 'Status'
    }
}

# ===========================================================================
# T7: Multiple baseline drifts — 3 drift rows
# ===========================================================================
Describe 'Get-AuditPolicy — multiple drifts' {
    BeforeAll {
        Mock Invoke-GAPAuditPol { Get-MockAuditCsv }
    }

    It 'three different subcategories with wrong expected values all get Status=Drift' {
        $bPath = Get-BaselineFilePath -Name 'multi-drift.json' -Subcategories @(
            @{ Subcategory = 'Logon';           Expected = 'Failure' },          # actual: Success and Failure
            @{ Subcategory = 'Logoff';          Expected = 'Success and Failure' }, # actual: Success
            @{ Subcategory = 'Process Creation'; Expected = 'Success and Failure' } # actual: No Auditing
        )
        $rows   = @(Get-AuditPolicy -BaselinePath $bPath)
        $drifts = @($rows | Where-Object { $_.Status -eq 'Drift' })
        $drifts.Count | Should -Be 3
    }
}

# ===========================================================================
# T8: All No Auditing — everything drifts when baseline expects auditing
# ===========================================================================
Describe 'Get-AuditPolicy — all No Auditing drifts' {
    BeforeAll {
        Mock Invoke-GAPAuditPol {
            @"
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting

PC,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},No Auditing,
PC,System,Logoff,{0CCE9216-69AE-11D9-BED3-505054503030},No Auditing,
"@
        }
    }

    It 'rows are Drift and Actual=No Auditing when policy has nothing enabled' {
        $bPath = Get-BaselineFilePath -Name 'noaudit.json' -Subcategories @(
            @{ Subcategory = 'Logon';  Expected = 'Success and Failure' },
            @{ Subcategory = 'Logoff'; Expected = 'Success' }
        )
        $rows   = @(Get-AuditPolicy -BaselinePath $bPath)
        $drifts = @($rows | Where-Object { $_.Status -eq 'Drift' })
        $drifts.Count | Should -Be 2
        $drifts | ForEach-Object { $_.Actual | Should -Be 'No Auditing' }
    }
}

# ===========================================================================
# T9: Baseline file missing — throws with clear message
# ===========================================================================
Describe 'Get-AuditPolicy — missing baseline file throws' {
    It 'throws when -BaselinePath points to a non-existent file' {
        { Get-AuditPolicy -BaselinePath 'C:\NoSuchFile_xyz_auditbaseline.json' } |
            Should -Throw -ExpectedMessage '*not found*'
    }
}

# ===========================================================================
# T10: Unparseable baseline JSON — throws with clear message
# ===========================================================================
Describe 'Get-AuditPolicy — unparseable JSON throws' {
    It 'throws when baseline file contains invalid JSON' {
        $badPath = Join-Path $TestDrive 'bad-audit.json'
        Set-Content -LiteralPath $badPath -Value 'NOT { valid json %%' -Encoding UTF8
        { Get-AuditPolicy -BaselinePath $badPath } | Should -Throw -ExpectedMessage '*Failed to parse*'
    }
}

# ===========================================================================
# T11: Invoke-GAPAuditPol throws — function re-throws the message
# ===========================================================================
Describe 'Get-AuditPolicy — Invoke-GAPAuditPol failure propagates' {
    BeforeAll {
        Mock Invoke-GAPAuditPol { throw 'auditpol failed (exit 1): Access denied' }
    }

    It 'Get-AuditPolicy re-throws when Invoke-GAPAuditPol throws' {
        { Get-AuditPolicy } | Should -Throw
    }
}

# ===========================================================================
# T12: Empty auditpol output — no rows emitted, no error
# ===========================================================================
Describe 'Get-AuditPolicy — empty auditpol output' {
    BeforeAll {
        Mock Invoke-GAPAuditPol {
            "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting"
        }
    }

    It 'does not throw when auditpol returns only the header' {
        { Get-AuditPolicy } | Should -Not -Throw
    }

    It 'returns zero rows when auditpol CSV has no data rows' {
        $rows = @(Get-AuditPolicy)
        $rows.Count | Should -Be 0
    }
}

# ===========================================================================
# T13: Category mapping — known subcategories resolve correctly
# ===========================================================================
Describe 'Get-AuditPolicy — category mapping' {
    BeforeAll {
        Mock Invoke-GAPAuditPol { Get-MockAuditCsv }
    }

    It 'Logon subcategory maps to Logon/Logoff category' {
        $rows = @(Get-AuditPolicy)
        $row  = $rows | Where-Object { $_.Subcategory -eq 'Logon' }
        $row.Category | Should -Be 'Logon/Logoff'
    }

    It 'Process Creation subcategory maps to Detailed Tracking category' {
        $rows = @(Get-AuditPolicy)
        $row  = $rows | Where-Object { $_.Subcategory -eq 'Process Creation' }
        $row.Category | Should -Be 'Detailed Tracking'
    }

    It 'Credential Validation subcategory maps to Account Logon category' {
        $rows = @(Get-AuditPolicy)
        $row  = $rows | Where-Object { $_.Subcategory -eq 'Credential Validation' }
        $row.Category | Should -Be 'Account Logon'
    }

    It 'User Account Management subcategory maps to Account Management category' {
        $rows = @(Get-AuditPolicy)
        $row  = $rows | Where-Object { $_.Subcategory -eq 'User Account Management' }
        $row.Category | Should -Be 'Account Management'
    }
}

# ===========================================================================
# T14: Unknown subcategory maps to 'Other'
# ===========================================================================
Describe 'Get-AuditPolicy — unknown subcategory category' {
    BeforeAll {
        Mock Invoke-GAPAuditPol {
            @"
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting

PC,System,Totally Unknown Subcategory XYZ,{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF},No Auditing,
"@
        }
    }

    It 'unknown subcategory gets Category=Other' {
        $rows = @(Get-AuditPolicy)
        $row  = $rows | Where-Object { $_.Subcategory -eq 'Totally Unknown Subcategory XYZ' }
        $row.Category | Should -Be 'Other'
    }
}

# ===========================================================================
# T15: Setting passthrough — strings are not normalized
# ===========================================================================
Describe 'Get-AuditPolicy — setting passthrough' {
    BeforeAll {
        Mock Invoke-GAPAuditPol { Get-MockAuditCsv }
    }

    It '"Success and Failure" passes through unchanged as the Setting value' {
        $rows = @(Get-AuditPolicy)
        $row  = $rows | Where-Object { $_.Subcategory -eq 'Logon' }
        $row.Setting | Should -Be 'Success and Failure'
    }

    It '"No Auditing" passes through unchanged as the Setting value' {
        $rows = @(Get-AuditPolicy)
        $row  = $rows | Where-Object { $_.Subcategory -eq 'Process Creation' }
        $row.Setting | Should -Be 'No Auditing'
    }

    It '"Success" passes through unchanged as the Setting value' {
        $rows = @(Get-AuditPolicy)
        $row  = $rows | Where-Object { $_.Subcategory -eq 'Logoff' }
        $row.Setting | Should -Be 'Success'
    }
}

# ===========================================================================
# T16: Baseline mode — all baseline subcategories absent from live = all Missing
# ===========================================================================
Describe 'Get-AuditPolicy — all baseline entries missing from live' {
    BeforeAll {
        Mock Invoke-GAPAuditPol {
            "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting"
        }
    }

    It 'all baseline subcategories get Status=Missing when live data is empty' {
        $bPath = Get-BaselineFilePath -Name 'all-missing.json' -Subcategories @(
            @{ Subcategory = 'Logon';  Expected = 'Success and Failure' },
            @{ Subcategory = 'Logoff'; Expected = 'Success' }
        )
        $rows   = @(Get-AuditPolicy -BaselinePath $bPath)
        $missing = @($rows | Where-Object { $_.Status -eq 'Missing' })
        $missing.Count | Should -Be 2
    }
}
