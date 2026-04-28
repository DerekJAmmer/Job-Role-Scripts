#requires -Version 7.2

BeforeAll {
    . (Join-Path $PSScriptRoot 'Test-CISBenchmark.ps1')

    # ---------------------------------------------------------------------------
    # Helper: write a benchmark JSON to TestDrive and return its path.
    # ---------------------------------------------------------------------------
    function Get-BenchmarkFilePath {
        <#
        .SYNOPSIS
            Write a minimal benchmark JSON to TestDrive and return the path.
        #>
        param(
            [string]  $Name     = 'benchmark.json',
            [object[]]$Controls = @()
        )
        $path = Join-Path $TestDrive $Name
        @{
            name     = 'Test Benchmark'
            version  = 'test'
            controls = $Controls
        } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8
        return $path
    }

    # ---------------------------------------------------------------------------
    # Helper: mock auditpol CSV string with a few subcategories.
    # ---------------------------------------------------------------------------
    function Get-MockAuditCsv {
        @"
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting

PC,System,Credential Validation,{0CCE923F-69AE-11D9-BED3-505054503030},Success and Failure,
PC,System,Account Lockout,{0CCE9217-69AE-11D9-BED3-505054503030},Failure,
PC,System,Audit Policy Change,{0CCE922F-69AE-11D9-BED3-505054503030},Success,
PC,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},No Auditing,
"@
    }

    # ---------------------------------------------------------------------------
    # Helper: mock 'net accounts' text output.
    # ---------------------------------------------------------------------------
    function Get-MockNetAccounts {
        @"
Force user logoff how long after time expires?:    Never
Minimum password age (days):    1
Maximum password age (days):    42
Minimum password length:    10
Length of password history maintained:    24
Lockout threshold:    5
Lockout duration (minutes):    30
Lockout observation window (minutes):    30
Computer role:    WORKSTATION
The command completed successfully.
"@
    }
}

# ===========================================================================
# T1: RegistryValue — Compliant when actual matches expected DWord
# ===========================================================================
Describe 'Test-CISBenchmark — RegistryValue Compliant' {
    BeforeAll {
        Mock Invoke-TCBAuditPol    { '' }
        Mock Invoke-TCBNetAccount { '' }
        Mock Get-TCBRegValue { return 0 } -ParameterFilter { $Name -eq 'DisableCAD' }
    }

    It 'returns Compliant when registry value matches expected DWord' {
        $ctrl = @{
            id          = '2.3.7.1'
            title       = 'DisableCAD test'
            section     = 'Security Options'
            type        = 'RegistryValue'
            expected    = @{ Path = 'HKLM:\Test'; Name = 'DisableCAD'; Value = 0; ValueType = 'DWord' }
            remediation = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-BenchmarkFilePath -Name 'reg-compliant.json' -Controls @($ctrl)
        $rows  = @(Test-CISBenchmark -BenchmarkPath $bPath)
        $row   = $rows | Where-Object { $_.ControlId -eq '2.3.7.1' }
        $row.Status | Should -Be 'Compliant'
    }
}

# ===========================================================================
# T2: RegistryValue — NonCompliant when actual differs from expected DWord
# ===========================================================================
Describe 'Test-CISBenchmark — RegistryValue NonCompliant' {
    BeforeAll {
        Mock Invoke-TCBAuditPol    { '' }
        Mock Invoke-TCBNetAccount { '' }
        Mock Get-TCBRegValue { return 1 } -ParameterFilter { $Name -eq 'DisableCAD' }
    }

    It 'returns NonCompliant when registry DWord value does not match expected' {
        $ctrl = @{
            id          = '2.3.7.1'
            title       = 'DisableCAD test'
            section     = 'Security Options'
            type        = 'RegistryValue'
            expected    = @{ Path = 'HKLM:\Test'; Name = 'DisableCAD'; Value = 0; ValueType = 'DWord' }
            remediation = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-BenchmarkFilePath -Name 'reg-noncompliant.json' -Controls @($ctrl)
        $rows  = @(Test-CISBenchmark -BenchmarkPath $bPath)
        $row   = $rows | Where-Object { $_.ControlId -eq '2.3.7.1' }
        $row.Status | Should -Be 'NonCompliant'
    }

    It 'NonCompliant row Actual is the value returned by Get-TCBRegValue' {
        $ctrl = @{
            id          = '2.3.7.1'
            title       = 'DisableCAD test'
            section     = 'Security Options'
            type        = 'RegistryValue'
            expected    = @{ Path = 'HKLM:\Test'; Name = 'DisableCAD'; Value = 0; ValueType = 'DWord' }
            remediation = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-BenchmarkFilePath -Name 'reg-noncompliant-actual.json' -Controls @($ctrl)
        $rows  = @(Test-CISBenchmark -BenchmarkPath $bPath)
        $row   = $rows | Where-Object { $_.ControlId -eq '2.3.7.1' }
        $row.Actual | Should -Be 1
    }
}

# ===========================================================================
# T3: RegistryValue — NonCompliant when Get-TCBRegValue returns $null (missing key)
# ===========================================================================
Describe 'Test-CISBenchmark — RegistryValue missing key' {
    BeforeAll {
        Mock Invoke-TCBAuditPol    { '' }
        Mock Invoke-TCBNetAccount { '' }
        Mock Get-TCBRegValue { return $null }
    }

    It 'returns NonCompliant with reason about missing key when Get-TCBRegValue returns null' {
        $ctrl = @{
            id          = '2.3.1.1'
            title       = 'NoConnectedUser test'
            section     = 'Security Options'
            type        = 'RegistryValue'
            expected    = @{ Path = 'HKLM:\Test'; Name = 'NoConnectedUser'; Value = 3; ValueType = 'DWord' }
            remediation = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-BenchmarkFilePath -Name 'reg-missing.json' -Controls @($ctrl)
        $rows  = @(Test-CISBenchmark -BenchmarkPath $bPath)
        $row   = $rows | Where-Object { $_.ControlId -eq '2.3.1.1' }
        $row.Status | Should -Be 'NonCompliant'
        $row.Reason | Should -Match 'not present'
    }
}

# ===========================================================================
# T4: AuditPolicy — Compliant
# ===========================================================================
Describe 'Test-CISBenchmark — AuditPolicy Compliant' {
    BeforeAll {
        Mock Invoke-TCBAuditPol    { Get-MockAuditCsv }
        Mock Invoke-TCBNetAccount { '' }
        Mock Get-TCBRegValue       { return $null }
    }

    It 'returns Compliant when audit subcategory setting matches expected' {
        $ctrl = @{
            id          = '17.1.1'
            title       = 'Credential Validation test'
            section     = 'Advanced Audit Policy'
            type        = 'AuditPolicy'
            expected    = @{ Subcategory = 'Credential Validation'; Setting = 'Success and Failure' }
            remediation = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-BenchmarkFilePath -Name 'audit-compliant.json' -Controls @($ctrl)
        $rows  = @(Test-CISBenchmark -BenchmarkPath $bPath)
        $row   = $rows | Where-Object { $_.ControlId -eq '17.1.1' }
        $row.Status | Should -Be 'Compliant'
    }
}

# ===========================================================================
# T5: AuditPolicy — NonCompliant
# ===========================================================================
Describe 'Test-CISBenchmark — AuditPolicy NonCompliant' {
    BeforeAll {
        Mock Invoke-TCBAuditPol    { Get-MockAuditCsv }
        Mock Invoke-TCBNetAccount { '' }
        Mock Get-TCBRegValue       { return $null }
    }

    It 'returns NonCompliant when audit subcategory setting does not match expected' {
        $ctrl = @{
            id          = '17.1.1x'
            title       = 'Credential Validation drift test'
            section     = 'Advanced Audit Policy'
            type        = 'AuditPolicy'
            expected    = @{ Subcategory = 'Credential Validation'; Setting = 'Failure' }
            remediation = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-BenchmarkFilePath -Name 'audit-noncompliant.json' -Controls @($ctrl)
        $rows  = @(Test-CISBenchmark -BenchmarkPath $bPath)
        $row   = $rows | Where-Object { $_.ControlId -eq '17.1.1x' }
        $row.Status | Should -Be 'NonCompliant'
    }
}

# ===========================================================================
# T6: AuditPolicy — Error when subcategory not in live data
# ===========================================================================
Describe 'Test-CISBenchmark — AuditPolicy subcategory not found' {
    BeforeAll {
        Mock Invoke-TCBAuditPol    { Get-MockAuditCsv }
        Mock Invoke-TCBNetAccount { '' }
        Mock Get-TCBRegValue       { return $null }
    }

    It 'returns Status=Error when subcategory is absent from live audit data' {
        $ctrl = @{
            id          = '17.x.x'
            title       = 'Nonexistent subcategory'
            section     = 'Advanced Audit Policy'
            type        = 'AuditPolicy'
            expected    = @{ Subcategory = 'Nonexistent Subcategory XYZ'; Setting = 'Success' }
            remediation = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-BenchmarkFilePath -Name 'audit-missing-sub.json' -Controls @($ctrl)
        $rows  = @(Test-CISBenchmark -BenchmarkPath $bPath)
        $row   = $rows | Where-Object { $_.ControlId -eq '17.x.x' }
        $row.Status | Should -Be 'Error'
        $row.Reason | Should -Match 'not found'
    }
}

# ===========================================================================
# T7: ServiceState — Compliant
# ===========================================================================
Describe 'Test-CISBenchmark — ServiceState Compliant' {
    BeforeAll {
        Mock Invoke-TCBAuditPol    { '' }
        Mock Invoke-TCBNetAccount { '' }
        Mock Get-TCBRegValue       { return $null }
        Mock Get-TCBService {
            return [PSCustomObject]@{ Name = 'BTAGService'; Status = 'Stopped'; StartType = 'Disabled' }
        } -ParameterFilter { $Name -eq 'BTAGService' }
    }

    It 'returns Compliant when service StartType matches expected' {
        $ctrl = @{
            id          = '5.10'
            title       = 'BTAGService test'
            section     = 'System Services'
            type        = 'ServiceState'
            expected    = @{ Name = 'BTAGService'; StartType = 'Disabled' }
            remediation = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-BenchmarkFilePath -Name 'svc-compliant.json' -Controls @($ctrl)
        $rows  = @(Test-CISBenchmark -BenchmarkPath $bPath)
        $row   = $rows | Where-Object { $_.ControlId -eq '5.10' }
        $row.Status | Should -Be 'Compliant'
    }
}

# ===========================================================================
# T8: ServiceState — NonCompliant (wrong StartType)
# ===========================================================================
Describe 'Test-CISBenchmark — ServiceState NonCompliant wrong StartType' {
    BeforeAll {
        Mock Invoke-TCBAuditPol    { '' }
        Mock Invoke-TCBNetAccount { '' }
        Mock Get-TCBRegValue       { return $null }
        Mock Get-TCBService {
            return [PSCustomObject]@{ Name = 'bthserv'; Status = 'Running'; StartType = 'Automatic' }
        } -ParameterFilter { $Name -eq 'bthserv' }
    }

    It 'returns NonCompliant when service StartType does not match expected' {
        $ctrl = @{
            id          = '5.11'
            title       = 'bthserv test'
            section     = 'System Services'
            type        = 'ServiceState'
            expected    = @{ Name = 'bthserv'; StartType = 'Disabled' }
            remediation = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-BenchmarkFilePath -Name 'svc-noncompliant.json' -Controls @($ctrl)
        $rows  = @(Test-CISBenchmark -BenchmarkPath $bPath)
        $row   = $rows | Where-Object { $_.ControlId -eq '5.11' }
        $row.Status | Should -Be 'NonCompliant'
        $row.Actual | Should -Be 'Automatic'
    }
}

# ===========================================================================
# T9: ServiceState — NonCompliant when service not found
# ===========================================================================
Describe 'Test-CISBenchmark — ServiceState service not found' {
    BeforeAll {
        Mock Invoke-TCBAuditPol    { '' }
        Mock Invoke-TCBNetAccount { '' }
        Mock Get-TCBRegValue       { return $null }
        Mock Get-TCBService        { return $null }
    }

    It 'returns NonCompliant with reason Service not found when Get-TCBService returns null' {
        $ctrl = @{
            id          = '5.10'
            title       = 'BTAGService missing test'
            section     = 'System Services'
            type        = 'ServiceState'
            expected    = @{ Name = 'BTAGService'; StartType = 'Disabled' }
            remediation = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-BenchmarkFilePath -Name 'svc-notfound.json' -Controls @($ctrl)
        $rows  = @(Test-CISBenchmark -BenchmarkPath $bPath)
        $row   = $rows | Where-Object { $_.ControlId -eq '5.10' }
        $row.Status | Should -Be 'NonCompliant'
        $row.Reason | Should -Match 'not found'
    }
}

# ===========================================================================
# T10: SecurityPolicy — Compliant
# ===========================================================================
Describe 'Test-CISBenchmark — SecurityPolicy Compliant' {
    BeforeAll {
        Mock Invoke-TCBAuditPol    { '' }
        Mock Invoke-TCBNetAccount { Get-MockNetAccounts }
        Mock Get-TCBRegValue       { return $null }
    }

    It 'returns Compliant when net accounts value matches expected (numeric compare)' {
        $ctrl = @{
            id          = '1.1.1'
            title       = 'Password history test'
            section     = 'Account Policies'
            type        = 'SecurityPolicy'
            expected    = @{ Setting = 'Length of password history maintained'; Value = '24' }
            remediation = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-BenchmarkFilePath -Name 'sec-compliant.json' -Controls @($ctrl)
        $rows  = @(Test-CISBenchmark -BenchmarkPath $bPath)
        $row   = $rows | Where-Object { $_.ControlId -eq '1.1.1' }
        $row.Status | Should -Be 'Compliant'
    }
}

# ===========================================================================
# T11: SecurityPolicy — NonCompliant
# ===========================================================================
Describe 'Test-CISBenchmark — SecurityPolicy NonCompliant' {
    BeforeAll {
        Mock Invoke-TCBAuditPol    { '' }
        Mock Invoke-TCBNetAccount { Get-MockNetAccounts }
        Mock Get-TCBRegValue       { return $null }
    }

    It 'returns NonCompliant when net accounts value does not match expected' {
        $ctrl = @{
            id          = '1.1.2'
            title       = 'Max password age test'
            section     = 'Account Policies'
            type        = 'SecurityPolicy'
            expected    = @{ Setting = 'Maximum password age (days)'; Value = '365' }
            remediation = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-BenchmarkFilePath -Name 'sec-noncompliant.json' -Controls @($ctrl)
        $rows  = @(Test-CISBenchmark -BenchmarkPath $bPath)
        $row   = $rows | Where-Object { $_.ControlId -eq '1.1.2' }
        $row.Status   | Should -Be 'NonCompliant'
        $row.Actual   | Should -Be '42'
        $row.Expected | Should -Be '365'
    }
}

# ===========================================================================
# T12: Manual — excluded by default
# ===========================================================================
Describe 'Test-CISBenchmark — Manual control excluded by default' {
    BeforeAll {
        Mock Invoke-TCBAuditPol    { '' }
        Mock Invoke-TCBNetAccount { '' }
        Mock Get-TCBRegValue       { return $null }
    }

    It 'does not emit a Manual control row when -IncludeManual is not set' {
        $ctrl = @{
            id          = '18.9.47.2'
            title       = 'ASR rules test'
            section     = 'Administrative Templates'
            type        = 'Manual'
            expected    = $null
            remediation = 'Do this manually.'
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-BenchmarkFilePath -Name 'manual-excluded.json' -Controls @($ctrl)
        $rows  = @(Test-CISBenchmark -BenchmarkPath $bPath)
        $manualRows = $rows | Where-Object { $_.Type -eq 'Manual' }
        $manualRows | Should -BeNullOrEmpty
    }
}

# ===========================================================================
# T13: Manual — included when -IncludeManual passed
# ===========================================================================
Describe 'Test-CISBenchmark — Manual control included with -IncludeManual' {
    BeforeAll {
        Mock Invoke-TCBAuditPol    { '' }
        Mock Invoke-TCBNetAccount { '' }
        Mock Get-TCBRegValue       { return $null }
    }

    It 'emits Status=Manual when -IncludeManual switch is used' {
        $ctrl = @{
            id          = '18.9.47.2'
            title       = 'ASR rules test'
            section     = 'Administrative Templates'
            type        = 'Manual'
            expected    = $null
            remediation = 'Do this manually.'
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-BenchmarkFilePath -Name 'manual-included.json' -Controls @($ctrl)
        $rows  = @(Test-CISBenchmark -BenchmarkPath $bPath -IncludeManual)
        $row   = $rows | Where-Object { $_.ControlId -eq '18.9.47.2' }
        $row         | Should -Not -BeNullOrEmpty
        $row.Status  | Should -Be 'Manual'
    }
}

# ===========================================================================
# T14: -Section filter narrows results
# ===========================================================================
Describe 'Test-CISBenchmark — Section filter' {
    BeforeAll {
        Mock Invoke-TCBAuditPol    { Get-MockAuditCsv }
        Mock Invoke-TCBNetAccount { Get-MockNetAccounts }
        Mock Get-TCBRegValue       { return 0 }
    }

    It 'only returns controls from the specified section' {
        $c1 = @{
            id = 'A1'; title = 'A'; section = 'Section A'; type = 'RegistryValue'
            expected = @{ Path = 'HKLM:\Test'; Name = 'Foo'; Value = 0; ValueType = 'DWord' }
            remediation = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $c2 = @{
            id = 'B1'; title = 'B'; section = 'Section B'; type = 'RegistryValue'
            expected = @{ Path = 'HKLM:\Test'; Name = 'Bar'; Value = 0; ValueType = 'DWord' }
            remediation = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-BenchmarkFilePath -Name 'section-filter.json' -Controls @($c1, $c2)
        $rows  = @(Test-CISBenchmark -BenchmarkPath $bPath -Section 'Section A')
        $dataRows = $rows | Where-Object { $_.ControlId -ne 'SUMMARY' }
        $dataRows.Count              | Should -Be 1
        $dataRows[0].Section         | Should -Be 'Section A'
    }
}

# ===========================================================================
# T15: -OutputPath writes CSV with all expected columns
# ===========================================================================
Describe 'Test-CISBenchmark — OutputPath writes CSV' {
    BeforeAll {
        Mock Invoke-TCBAuditPol    { '' }
        Mock Invoke-TCBNetAccount { '' }
        Mock Get-TCBRegValue       { return 0 }
    }

    It 'creates the CSV file at -OutputPath' {
        $ctrl = @{
            id = 'C1'; title = 'CSV test'; section = 'Test'; type = 'RegistryValue'
            expected = @{ Path = 'HKLM:\Test'; Name = 'Val'; Value = 0; ValueType = 'DWord' }
            remediation = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath   = Get-BenchmarkFilePath -Name 'csv-check.json' -Controls @($ctrl)
        $csvPath = Join-Path $TestDrive 'output.csv'
        Test-CISBenchmark -BenchmarkPath $bPath -OutputPath $csvPath | Out-Null
        Test-Path -LiteralPath $csvPath | Should -Be $true
    }

    It 'CSV contains ControlId, Title, Section, Type, Status, Expected, Actual, Reason, Remediation columns' {
        $ctrl = @{
            id = 'C2'; title = 'CSV cols test'; section = 'Test'; type = 'RegistryValue'
            expected = @{ Path = 'HKLM:\Test'; Name = 'Val'; Value = 0; ValueType = 'DWord' }
            remediation = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath   = Get-BenchmarkFilePath -Name 'csv-cols.json' -Controls @($ctrl)
        $csvPath = Join-Path $TestDrive 'output-cols.csv'
        Test-CISBenchmark -BenchmarkPath $bPath -OutputPath $csvPath | Out-Null
        $imported = Import-Csv -LiteralPath $csvPath
        $cols = $imported[0].PSObject.Properties.Name
        $cols | Should -Contain 'ControlId'
        $cols | Should -Contain 'Title'
        $cols | Should -Contain 'Section'
        $cols | Should -Contain 'Type'
        $cols | Should -Contain 'Status'
        $cols | Should -Contain 'Expected'
        $cols | Should -Contain 'Actual'
        $cols | Should -Contain 'Reason'
        $cols | Should -Contain 'Remediation'
    }
}

# ===========================================================================
# T16: Bad benchmark path throws '*not found*'
# ===========================================================================
Describe 'Test-CISBenchmark — bad benchmark path throws' {
    It 'throws when -BenchmarkPath points to a non-existent file' {
        { Test-CISBenchmark -BenchmarkPath 'C:\NoSuchFile_xyz_benchmark.json' } |
            Should -Throw -ExpectedMessage '*not found*'
    }
}

# ===========================================================================
# T17: Malformed JSON throws '*Failed to parse*'
# ===========================================================================
Describe 'Test-CISBenchmark — malformed JSON throws' {
    It 'throws when benchmark file contains invalid JSON' {
        $badPath = Join-Path $TestDrive 'bad-benchmark.json'
        Set-Content -LiteralPath $badPath -Value 'NOT { valid json %%' -Encoding UTF8
        { Test-CISBenchmark -BenchmarkPath $badPath } |
            Should -Throw -ExpectedMessage '*Failed to parse*'
    }
}

# ===========================================================================
# T18: Unknown control type emits Status=Unknown, does not throw
# ===========================================================================
Describe 'Test-CISBenchmark — unknown control type' {
    BeforeAll {
        Mock Invoke-TCBAuditPol    { '' }
        Mock Invoke-TCBNetAccount { '' }
        Mock Get-TCBRegValue       { return $null }
    }

    It 'emits Status=Unknown and does not throw for an unrecognised control type' {
        $ctrl = @{
            id = 'UNK1'; title = 'Unknown type'; section = 'Test'; type = 'FutureType'
            expected = @{}
            remediation = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-BenchmarkFilePath -Name 'unknown-type.json' -Controls @($ctrl)
        $rows  = @(Test-CISBenchmark -BenchmarkPath $bPath)
        $row   = $rows | Where-Object { $_.ControlId -eq 'UNK1' }
        $row.Status | Should -Be 'Unknown'
        $row.Reason | Should -Match 'Unknown control type'
    }
}

# ===========================================================================
# T19: SUMMARY row present with correct counts
# ===========================================================================
Describe 'Test-CISBenchmark — SUMMARY row' {
    BeforeAll {
        Mock Invoke-TCBAuditPol    { Get-MockAuditCsv }
        Mock Invoke-TCBNetAccount { Get-MockNetAccounts }
        # DisableCAD = 0 → Compliant (expected 0)
        Mock Get-TCBRegValue { return 0 } -ParameterFilter { $Name -eq 'DisableCAD' }
        # NoConnectedUser = 99 → NonCompliant (expected 3)
        Mock Get-TCBRegValue { return 99 } -ParameterFilter { $Name -eq 'NoConnectedUser' }
    }

    It 'last row has ControlId=SUMMARY' {
        $c1 = @{
            id = '2.3.7.1'; title = 'CAD'; section = 'S'; type = 'RegistryValue'
            expected = @{ Path = 'HKLM:\T'; Name = 'DisableCAD'; Value = 0; ValueType = 'DWord' }
            remediation = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $c2 = @{
            id = '2.3.1.1'; title = 'MSA'; section = 'S'; type = 'RegistryValue'
            expected = @{ Path = 'HKLM:\T'; Name = 'NoConnectedUser'; Value = 3; ValueType = 'DWord' }
            remediation = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath   = Get-BenchmarkFilePath -Name 'summary-check.json' -Controls @($c1, $c2)
        $rows    = @(Test-CISBenchmark -BenchmarkPath $bPath)
        $lastRow = $rows[-1]
        $lastRow.ControlId | Should -Be 'SUMMARY'
    }

    It 'SUMMARY Reason contains correct Compliant and NonCompliant counts' {
        $c1 = @{
            id = '2.3.7.1'; title = 'CAD'; section = 'S'; type = 'RegistryValue'
            expected = @{ Path = 'HKLM:\T'; Name = 'DisableCAD'; Value = 0; ValueType = 'DWord' }
            remediation = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $c2 = @{
            id = '2.3.1.1'; title = 'MSA'; section = 'S'; type = 'RegistryValue'
            expected = @{ Path = 'HKLM:\T'; Name = 'NoConnectedUser'; Value = 3; ValueType = 'DWord' }
            remediation = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath   = Get-BenchmarkFilePath -Name 'summary-counts.json' -Controls @($c1, $c2)
        $rows    = @(Test-CISBenchmark -BenchmarkPath $bPath)
        $summary = $rows | Where-Object { $_.ControlId -eq 'SUMMARY' }
        $summary.Reason | Should -Match 'Compliant=1'
        $summary.Reason | Should -Match 'NonCompliant=1'
    }
}

# ===========================================================================
# T20: Test-TCB* exception caught → Status=Error
# ===========================================================================
Describe 'Test-CISBenchmark — dispatcher catches exceptions as Status=Error' {
    BeforeAll {
        Mock Invoke-TCBAuditPol    { '' }
        Mock Invoke-TCBNetAccount { '' }
        Mock Get-TCBRegValue       { throw 'Simulated registry read failure' }
    }

    It 'emits Status=Error and does not throw when Get-TCBRegValue throws' {
        $ctrl = @{
            id = 'ERR1'; title = 'Error test'; section = 'Test'; type = 'RegistryValue'
            expected = @{ Path = 'HKLM:\Test'; Name = 'Anything'; Value = 1; ValueType = 'DWord' }
            remediation = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-BenchmarkFilePath -Name 'error-catch.json' -Controls @($ctrl)
        $rows  = @(Test-CISBenchmark -BenchmarkPath $bPath)
        $row   = $rows | Where-Object { $_.ControlId -eq 'ERR1' }
        $row.Status | Should -Be 'Error'
        $row.Reason | Should -Match 'Simulated registry read failure'
    }
}

# ===========================================================================
# T21: Full sample benchmark loads without error
# ===========================================================================
Describe 'Test-CISBenchmark — sample benchmark file loads' {
    BeforeAll {
        Mock Invoke-TCBAuditPol    { Get-MockAuditCsv }
        Mock Invoke-TCBNetAccount { Get-MockNetAccounts }
        Mock Get-TCBRegValue       { return $null }
        Mock Get-TCBService        { return $null }
    }

    It 'does not throw when loading the shipped sample benchmark' {
        $samplePath = Join-Path $PSScriptRoot 'samples' 'cis-win11-subset.json'
        { Test-CISBenchmark -BenchmarkPath $samplePath -IncludeManual } | Should -Not -Throw
    }

    It 'emits more than one row (data rows + SUMMARY) for the sample benchmark' {
        $samplePath = Join-Path $PSScriptRoot 'samples' 'cis-win11-subset.json'
        $rows = @(Test-CISBenchmark -BenchmarkPath $samplePath -IncludeManual)
        $rows.Count | Should -BeGreaterThan 1
    }
}
