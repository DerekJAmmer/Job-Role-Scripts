#requires -Version 7.2

BeforeAll {
    . (Join-Path $PSScriptRoot 'Test-STIGCompliance.ps1')

    # ---------------------------------------------------------------------------
    # Helper: write a STIG JSON to TestDrive and return its path.
    # ---------------------------------------------------------------------------
    function Get-STIGFilePath {
        <#
        .SYNOPSIS
            Write a minimal STIG JSON to TestDrive and return the path.
        #>
        param(
            [string]  $Name     = 'stig.json',
            [object[]]$Controls = @()
        )
        $path = Join-Path $TestDrive $Name
        @{
            name     = 'Test STIG'
            version  = 'test'
            controls = $Controls
        } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8
        return $path
    }

    # ---------------------------------------------------------------------------
    # Helper: mock auditpol CSV string.
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
    # Helper: mock 'net accounts' text output with lockout threshold = 3.
    # ---------------------------------------------------------------------------
    function Get-MockNetAccounts {
        @"
Force user logoff how long after time expires?:    Never
Minimum password age (days):    1
Maximum password age (days):    42
Minimum password length:    10
Length of password history maintained:    24
Lockout threshold:    3
Lockout duration (minutes):    30
Lockout observation window (minutes):    30
Computer role:    WORKSTATION
The command completed successfully.
"@
    }

    # ---------------------------------------------------------------------------
    # Helper: mock manage-bde output — fully encrypted.
    # ---------------------------------------------------------------------------
    function Get-MockManageBdeEncrypted {
        @"
BitLocker Drive Encryption: Configuration Tool version 10.0.22000
Copyright (C) 2013 Microsoft Corporation. All Rights Reserved.

Volume C: [OS]
All Key Protectors

    TPM:
      ID: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}

    Conversion Status:     Fully Encrypted
    Percentage Encrypted:  100.0%
    Encryption Method:     XTS-AES 256
    Protection Status:     Protection On
    Lock Status:           Unlocked
    Identification Field:  Unknown
    Key Protectors:        TPM
"@
    }

    # ---------------------------------------------------------------------------
    # Helper: mock manage-bde output — NOT encrypted.
    # ---------------------------------------------------------------------------
    function Get-MockManageBdeNotEncrypted {
        @"
BitLocker Drive Encryption: Configuration Tool version 10.0.22000
Copyright (C) 2013 Microsoft Corporation. All Rights Reserved.

Volume C: [OS]
All Key Protectors

    Conversion Status:     Fully Decrypted
    Percentage Encrypted:  0.0%
    Encryption Method:     None
    Protection Status:     Protection Off
    Lock Status:           Unlocked
"@
    }
}

# ===========================================================================
# T1: RegistryValue — NotAFinding when actual matches expected DWord
# ===========================================================================
Describe 'Test-STIGCompliance — RegistryValue NotAFinding' {
    BeforeAll {
        Mock Invoke-TSCAuditPol   { '' }
        Mock Invoke-TSCNetAccount { '' }
        Mock Get-TSCRegValue { return 4 } -ParameterFilter { $Name -eq 'Start' }
    }

    It 'returns NotAFinding when registry DWord value matches expected' {
        $ctrl = @{
            vulnId   = 'V-253256'
            title    = 'SMBv1 client disabled'
            severity = 'CAT I'
            type     = 'RegistryValue'
            expected = @{ Path = 'HKLM:\Test'; Name = 'Start'; Value = 4; ValueType = 'DWord' }
            fix      = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-STIGFilePath -Name 'reg-naf.json' -Controls @($ctrl)
        $rows  = @(Test-STIGCompliance -STIGPath $bPath)
        $row   = $rows | Where-Object { $_.VulnId -eq 'V-253256' }
        $row.Status | Should -Be 'NotAFinding'
    }
}

# ===========================================================================
# T2: RegistryValue — Open when actual differs from expected DWord
# ===========================================================================
Describe 'Test-STIGCompliance — RegistryValue Open' {
    BeforeAll {
        Mock Invoke-TSCAuditPol   { '' }
        Mock Invoke-TSCNetAccount { '' }
        Mock Get-TSCRegValue { return 2 } -ParameterFilter { $Name -eq 'Start' }
    }

    It 'returns Open when registry DWord value does not match expected' {
        $ctrl = @{
            vulnId   = 'V-253256'
            title    = 'SMBv1 client disabled'
            severity = 'CAT I'
            type     = 'RegistryValue'
            expected = @{ Path = 'HKLM:\Test'; Name = 'Start'; Value = 4; ValueType = 'DWord' }
            fix      = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-STIGFilePath -Name 'reg-open.json' -Controls @($ctrl)
        $rows  = @(Test-STIGCompliance -STIGPath $bPath)
        $row   = $rows | Where-Object { $_.VulnId -eq 'V-253256' }
        $row.Status | Should -Be 'Open'
        $row.Actual | Should -Be 2
    }
}

# ===========================================================================
# T3: AuditPolicy — NotAFinding when subcategory setting matches expected
# ===========================================================================
Describe 'Test-STIGCompliance — AuditPolicy NotAFinding' {
    BeforeAll {
        Mock Invoke-TSCAuditPol   { Get-MockAuditCsv }
        Mock Invoke-TSCNetAccount { '' }
        Mock Get-TSCRegValue      { return $null }
    }

    It 'returns NotAFinding when audit subcategory matches expected' {
        $ctrl = @{
            vulnId   = 'V-253386'
            title    = 'Audit Credential Validation'
            severity = 'CAT II'
            type     = 'AuditPolicy'
            expected = @{ Subcategory = 'Credential Validation'; Setting = 'Success and Failure' }
            fix      = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-STIGFilePath -Name 'audit-naf.json' -Controls @($ctrl)
        $rows  = @(Test-STIGCompliance -STIGPath $bPath)
        $row   = $rows | Where-Object { $_.VulnId -eq 'V-253386' }
        $row.Status | Should -Be 'NotAFinding'
    }
}

# ===========================================================================
# T4: AuditPolicy — Open when subcategory setting does not match
# ===========================================================================
Describe 'Test-STIGCompliance — AuditPolicy Open' {
    BeforeAll {
        Mock Invoke-TSCAuditPol   { Get-MockAuditCsv }
        Mock Invoke-TSCNetAccount { '' }
        Mock Get-TSCRegValue      { return $null }
    }

    It 'returns Open when audit subcategory setting does not match expected' {
        $ctrl = @{
            vulnId   = 'V-253399'
            title    = 'Audit Account Lockout'
            severity = 'CAT III'
            type     = 'AuditPolicy'
            expected = @{ Subcategory = 'Account Lockout'; Setting = 'Success and Failure' }
            fix      = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-STIGFilePath -Name 'audit-open.json' -Controls @($ctrl)
        $rows  = @(Test-STIGCompliance -STIGPath $bPath)
        $row   = $rows | Where-Object { $_.VulnId -eq 'V-253399' }
        $row.Status | Should -Be 'Open'
    }
}

# ===========================================================================
# T5: ServiceState — NotAFinding when service is absent and NotPresent=true
# ===========================================================================
Describe 'Test-STIGCompliance — ServiceState NotAFinding (service absent, NotPresent expected)' {
    BeforeAll {
        Mock Invoke-TSCAuditPol   { '' }
        Mock Invoke-TSCNetAccount { '' }
        Mock Get-TSCRegValue      { return $null }
        Mock Get-TSCService       { return $null }
    }

    It 'returns NotAFinding when service is not present and NotPresent=true' {
        $ctrl = @{
            vulnId   = 'V-253260'
            title    = 'Telnet Client not installed'
            severity = 'CAT III'
            type     = 'ServiceState'
            expected = @{ Name = 'TlntSvr'; NotPresent = $true }
            fix      = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-STIGFilePath -Name 'svc-absent-naf.json' -Controls @($ctrl)
        $rows  = @(Test-STIGCompliance -STIGPath $bPath)
        $row   = $rows | Where-Object { $_.VulnId -eq 'V-253260' }
        $row.Status | Should -Be 'NotAFinding'
    }
}

# ===========================================================================
# T6: ServiceState — Open when service exists but should be absent
# ===========================================================================
Describe 'Test-STIGCompliance — ServiceState Open (service present, NotPresent expected)' {
    BeforeAll {
        Mock Invoke-TSCAuditPol   { '' }
        Mock Invoke-TSCNetAccount { '' }
        Mock Get-TSCRegValue      { return $null }
        Mock Get-TSCService {
            return [PSCustomObject]@{ Name = 'TlntSvr'; Status = 'Running'; StartType = 'Automatic' }
        } -ParameterFilter { $Name -eq 'TlntSvr' }
    }

    It 'returns Open when service exists but NotPresent=true is expected' {
        $ctrl = @{
            vulnId   = 'V-253260'
            title    = 'Telnet Client not installed'
            severity = 'CAT III'
            type     = 'ServiceState'
            expected = @{ Name = 'TlntSvr'; NotPresent = $true }
            fix      = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-STIGFilePath -Name 'svc-present-open.json' -Controls @($ctrl)
        $rows  = @(Test-STIGCompliance -STIGPath $bPath)
        $row   = $rows | Where-Object { $_.VulnId -eq 'V-253260' }
        $row.Status | Should -Be 'Open'
        $row.Reason | Should -Match 'exists but should not be installed'
    }
}

# ===========================================================================
# T7: SecurityPolicy — NotAFinding when lockout threshold <= 3 (LessThanOrEqual)
# ===========================================================================
Describe 'Test-STIGCompliance — SecurityPolicy NotAFinding (LessThanOrEqual)' {
    BeforeAll {
        Mock Invoke-TSCAuditPol   { '' }
        Mock Invoke-TSCNetAccount { Get-MockNetAccounts }
        Mock Get-TSCRegValue      { return $null }
    }

    It 'returns NotAFinding when lockout threshold is <= 3' {
        $ctrl = @{
            vulnId   = 'V-253283'
            title    = 'Account lockout threshold'
            severity = 'CAT II'
            type     = 'SecurityPolicy'
            expected = @{ Setting = 'Lockout threshold'; Value = '3'; Operator = 'LessThanOrEqual' }
            fix      = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-STIGFilePath -Name 'sec-naf.json' -Controls @($ctrl)
        $rows  = @(Test-STIGCompliance -STIGPath $bPath)
        $row   = $rows | Where-Object { $_.VulnId -eq 'V-253283' }
        $row.Status | Should -Be 'NotAFinding'
    }
}

# ===========================================================================
# T8: SecurityPolicy — Open when lockout threshold > 3 (LessThanOrEqual fails)
# ===========================================================================
Describe 'Test-STIGCompliance — SecurityPolicy Open (LessThanOrEqual fails)' {
    BeforeAll {
        Mock Invoke-TSCAuditPol   { '' }
        Mock Invoke-TSCNetAccount {
            @"
Lockout threshold:    5
The command completed successfully.
"@
        }
        Mock Get-TSCRegValue { return $null }
    }

    It 'returns Open when lockout threshold exceeds the maximum' {
        $ctrl = @{
            vulnId   = 'V-253283'
            title    = 'Account lockout threshold'
            severity = 'CAT II'
            type     = 'SecurityPolicy'
            expected = @{ Setting = 'Lockout threshold'; Value = '3'; Operator = 'LessThanOrEqual' }
            fix      = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-STIGFilePath -Name 'sec-open.json' -Controls @($ctrl)
        $rows  = @(Test-STIGCompliance -STIGPath $bPath)
        $row   = $rows | Where-Object { $_.VulnId -eq 'V-253283' }
        $row.Status | Should -Be 'Open'
        $row.Actual | Should -Be '5'
    }
}

# ===========================================================================
# T9: BitLockerStatus — NotAFinding when drive is fully encrypted and protected
# ===========================================================================
Describe 'Test-STIGCompliance — BitLockerStatus NotAFinding' {
    BeforeAll {
        Mock Invoke-TSCAuditPol   { '' }
        Mock Invoke-TSCNetAccount { '' }
        Mock Get-TSCRegValue      { return $null }
        Mock Invoke-TSCManageBde  { Get-MockManageBdeEncrypted } -ParameterFilter { $MountPoint -eq 'C:' }
    }

    It 'returns NotAFinding when BitLocker is fully encrypted and protection is on' {
        $ctrl = @{
            vulnId   = 'V-253474'
            title    = 'BitLocker enabled on system drive'
            severity = 'CAT II'
            type     = 'BitLockerStatus'
            expected = @{ MountPoint = 'C:'; Required = $true }
            fix      = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-STIGFilePath -Name 'bde-naf.json' -Controls @($ctrl)
        $rows  = @(Test-STIGCompliance -STIGPath $bPath)
        $row   = $rows | Where-Object { $_.VulnId -eq 'V-253474' }
        $row.Status | Should -Be 'NotAFinding'
    }
}

# ===========================================================================
# T10: BitLockerStatus — Open when drive is not encrypted
# ===========================================================================
Describe 'Test-STIGCompliance — BitLockerStatus Open' {
    BeforeAll {
        Mock Invoke-TSCAuditPol   { '' }
        Mock Invoke-TSCNetAccount { '' }
        Mock Get-TSCRegValue      { return $null }
        Mock Invoke-TSCManageBde  { Get-MockManageBdeNotEncrypted } -ParameterFilter { $MountPoint -eq 'C:' }
    }

    It 'returns Open when BitLocker is not enabled or protection is off' {
        $ctrl = @{
            vulnId   = 'V-253474'
            title    = 'BitLocker enabled on system drive'
            severity = 'CAT II'
            type     = 'BitLockerStatus'
            expected = @{ MountPoint = 'C:'; Required = $true }
            fix      = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-STIGFilePath -Name 'bde-open.json' -Controls @($ctrl)
        $rows  = @(Test-STIGCompliance -STIGPath $bPath)
        $row   = $rows | Where-Object { $_.VulnId -eq 'V-253474' }
        $row.Status | Should -Be 'Open'
        $row.Reason | Should -Match 'BitLocker not fully enabled'
    }
}

# ===========================================================================
# T11: Manual — excluded by default
# ===========================================================================
Describe 'Test-STIGCompliance — Manual control excluded by default' {
    BeforeAll {
        Mock Invoke-TSCAuditPol   { '' }
        Mock Invoke-TSCNetAccount { '' }
        Mock Get-TSCRegValue      { return $null }
    }

    It 'does not emit a Manual control row when -IncludeManual is not set' {
        $ctrl = @{
            vulnId   = 'V-253505'
            title    = 'AppLocker policy review'
            severity = 'CAT II'
            type     = 'Manual'
            expected = $null
            fix      = 'Review AppLocker policies.'
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath      = Get-STIGFilePath -Name 'manual-excluded.json' -Controls @($ctrl)
        $rows       = @(Test-STIGCompliance -STIGPath $bPath)
        $manualRows = $rows | Where-Object { $_.Type -eq 'Manual' }
        $manualRows | Should -BeNullOrEmpty
    }
}

# ===========================================================================
# T12: Manual — included when -IncludeManual passed
# ===========================================================================
Describe 'Test-STIGCompliance — Manual control included with -IncludeManual' {
    BeforeAll {
        Mock Invoke-TSCAuditPol   { '' }
        Mock Invoke-TSCNetAccount { '' }
        Mock Get-TSCRegValue      { return $null }
    }

    It 'emits Status=Manual when -IncludeManual switch is used' {
        $ctrl = @{
            vulnId   = 'V-253505'
            title    = 'AppLocker policy review'
            severity = 'CAT II'
            type     = 'Manual'
            expected = $null
            fix      = 'Review AppLocker policies.'
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-STIGFilePath -Name 'manual-included.json' -Controls @($ctrl)
        $rows  = @(Test-STIGCompliance -STIGPath $bPath -IncludeManual)
        $row   = $rows | Where-Object { $_.VulnId -eq 'V-253505' }
        $row        | Should -Not -BeNullOrEmpty
        $row.Status | Should -Be 'Manual'
    }
}

# ===========================================================================
# T13: NotApplicable — applicabilityCheck fails → Status=NotApplicable, main check not run
# ===========================================================================
Describe 'Test-STIGCompliance — NotApplicable when applicabilityCheck does not match' {
    BeforeAll {
        Mock Invoke-TSCAuditPol   { '' }
        Mock Invoke-TSCNetAccount { '' }
        # Applicability check returns $null (key absent) → not applicable
        Mock Get-TSCRegValue { return $null } -ParameterFilter { $Name -eq 'DomainMember' }
        # Main check helper — should NOT be called
        Mock Get-TSCRegValue { return 0 } -ParameterFilter { $Name -eq 'SomePolicy' }
    }

    It 'emits Status=NotApplicable and does not invoke the main check helper' {
        $ctrl = @{
            vulnId             = 'V-TEST-NA'
            title              = 'Domain-only control'
            severity           = 'CAT II'
            type               = 'RegistryValue'
            applicabilityCheck = @{
                type  = 'RegistryValue'
                Path  = 'HKLM:\Test\Domain'
                Name  = 'DomainMember'
                Value = 1
            }
            expected           = @{ Path = 'HKLM:\Test'; Name = 'SomePolicy'; Value = 0; ValueType = 'DWord' }
            fix                = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-STIGFilePath -Name 'na-check.json' -Controls @($ctrl)
        $rows  = @(Test-STIGCompliance -STIGPath $bPath)
        $row   = $rows | Where-Object { $_.VulnId -eq 'V-TEST-NA' }
        $row.Status | Should -Be 'NotApplicable'
        $row.Reason | Should -Match 'Applicability check did not match'
        # SomePolicy should never have been queried
        Should -Invoke Get-TSCRegValue -ParameterFilter { $Name -eq 'SomePolicy' } -Times 0 -Exactly
    }
}

# ===========================================================================
# T14: -FailOnSeverity — WouldFailGate=true when open CAT I present and 'CAT I' in gate
# ===========================================================================
Describe 'Test-STIGCompliance — FailOnSeverity WouldFailGate=true (CAT I open, CAT I in gate)' {
    BeforeAll {
        Mock Invoke-TSCAuditPol   { '' }
        Mock Invoke-TSCNetAccount { '' }
        Mock Get-TSCRegValue { return 2 } -ParameterFilter { $Name -eq 'Start' }
    }

    It 'SUMMARY Reason contains WouldFailGate=true when an Open CAT I is present' {
        $ctrl = @{
            vulnId   = 'V-253256'
            title    = 'SMBv1 client'
            severity = 'CAT I'
            type     = 'RegistryValue'
            expected = @{ Path = 'HKLM:\T'; Name = 'Start'; Value = 4; ValueType = 'DWord' }
            fix      = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath   = Get-STIGFilePath -Name 'gate-cat1-open.json' -Controls @($ctrl)
        $rows    = @(Test-STIGCompliance -STIGPath $bPath -FailOnSeverity 'CAT I')
        $summary = $rows | Where-Object { $_.VulnId -eq 'SUMMARY' }
        $summary.Reason | Should -Match 'WouldFailGate=True'
    }
}

# ===========================================================================
# T15: -FailOnSeverity — WouldFailGate=false when no open CAT I (only CAT II open)
# ===========================================================================
Describe 'Test-STIGCompliance — FailOnSeverity WouldFailGate=false (CAT II open, only CAT I in gate)' {
    BeforeAll {
        Mock Invoke-TSCAuditPol   { '' }
        Mock Invoke-TSCNetAccount { '' }
        Mock Get-TSCRegValue { return 0 } -ParameterFilter { $Name -eq 'RunAsPPL' }
    }

    It 'SUMMARY Reason contains WouldFailGate=false when no Open rows match gate severity' {
        $ctrl = @{
            vulnId   = 'V-253265'
            title    = 'LSA Protection'
            severity = 'CAT II'
            type     = 'RegistryValue'
            expected = @{ Path = 'HKLM:\T'; Name = 'RunAsPPL'; Value = 1; ValueType = 'DWord' }
            fix      = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath   = Get-STIGFilePath -Name 'gate-cat2-notcat1.json' -Controls @($ctrl)
        $rows    = @(Test-STIGCompliance -STIGPath $bPath -FailOnSeverity 'CAT I')
        $summary = $rows | Where-Object { $_.VulnId -eq 'SUMMARY' }
        $summary.Reason | Should -Match 'WouldFailGate=False'
    }
}

# ===========================================================================
# T16: -FailOnSeverity — WouldFailGate=true when 'CAT I,II,III' and any open
# ===========================================================================
Describe 'Test-STIGCompliance — FailOnSeverity WouldFailGate=true (all cats in gate, CAT III open)' {
    BeforeAll {
        Mock Invoke-TSCAuditPol   { '' }
        Mock Invoke-TSCNetAccount { '' }
        Mock Get-TSCRegValue { return 0 } -ParameterFilter { $Name -eq 'EnableScriptBlockLogging' }
    }

    It 'SUMMARY Reason contains WouldFailGate=true when CAT I,II,III gate and a CAT III is Open' {
        $ctrl = @{
            vulnId   = 'V-253466'
            title    = 'ScriptBlock logging'
            severity = 'CAT III'
            type     = 'RegistryValue'
            expected = @{ Path = 'HKLM:\T'; Name = 'EnableScriptBlockLogging'; Value = 1; ValueType = 'DWord' }
            fix      = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath   = Get-STIGFilePath -Name 'gate-all-open.json' -Controls @($ctrl)
        $rows    = @(Test-STIGCompliance -STIGPath $bPath -FailOnSeverity 'CAT I,CAT II,CAT III')
        $summary = $rows | Where-Object { $_.VulnId -eq 'SUMMARY' }
        $summary.Reason | Should -Match 'WouldFailGate=True'
    }
}

# ===========================================================================
# T17: SUMMARY row — has all five status counts
# ===========================================================================
Describe 'Test-STIGCompliance — SUMMARY row has all five status counts' {
    BeforeAll {
        Mock Invoke-TSCAuditPol   { Get-MockAuditCsv }
        Mock Invoke-TSCNetAccount { Get-MockNetAccounts }
        Mock Invoke-TSCManageBde  { Get-MockManageBdeEncrypted }
        # RunAsPPL = 1 → NotAFinding
        Mock Get-TSCRegValue { return 1 } -ParameterFilter { $Name -eq 'RunAsPPL' }
        # Start = 2 (not 4) → Open
        Mock Get-TSCRegValue { return 2 } -ParameterFilter { $Name -eq 'Start' }
    }

    It 'last row has VulnId=SUMMARY' {
        $c1 = @{
            vulnId = 'V-253265'; title = 'LSA'; severity = 'CAT II'; type = 'RegistryValue'
            expected = @{ Path = 'HKLM:\T'; Name = 'RunAsPPL'; Value = 1; ValueType = 'DWord' }
            fix = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $c2 = @{
            vulnId = 'V-253256'; title = 'SMBv1'; severity = 'CAT I'; type = 'RegistryValue'
            expected = @{ Path = 'HKLM:\T'; Name = 'Start'; Value = 4; ValueType = 'DWord' }
            fix = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath   = Get-STIGFilePath -Name 'summary-last.json' -Controls @($c1, $c2)
        $rows    = @(Test-STIGCompliance -STIGPath $bPath)
        $lastRow = $rows[-1]
        $lastRow.VulnId | Should -Be 'SUMMARY'
    }

    It 'SUMMARY Reason contains all five counters' {
        $c1 = @{
            vulnId = 'V-253265'; title = 'LSA'; severity = 'CAT II'; type = 'RegistryValue'
            expected = @{ Path = 'HKLM:\T'; Name = 'RunAsPPL'; Value = 1; ValueType = 'DWord' }
            fix = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $c2 = @{
            vulnId = 'V-253256'; title = 'SMBv1'; severity = 'CAT I'; type = 'RegistryValue'
            expected = @{ Path = 'HKLM:\T'; Name = 'Start'; Value = 4; ValueType = 'DWord' }
            fix = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath   = Get-STIGFilePath -Name 'summary-counts.json' -Controls @($c1, $c2)
        $rows    = @(Test-STIGCompliance -STIGPath $bPath)
        $summary = $rows | Where-Object { $_.VulnId -eq 'SUMMARY' }
        $summary.Reason | Should -Match 'NotAFinding='
        $summary.Reason | Should -Match 'Open='
        $summary.Reason | Should -Match 'NotApplicable='
        $summary.Reason | Should -Match 'Manual='
        $summary.Reason | Should -Match 'Error='
    }
}

# ===========================================================================
# T18: Bad STIG path throws '*not found*'
# ===========================================================================
Describe 'Test-STIGCompliance — bad STIG path throws' {
    It 'throws when -STIGPath points to a non-existent file' {
        { Test-STIGCompliance -STIGPath 'C:\NoSuchFile_xyz_stig.json' } |
            Should -Throw -ExpectedMessage '*not found*'
    }
}

# ===========================================================================
# T19: Malformed JSON throws '*Failed to parse*'
# ===========================================================================
Describe 'Test-STIGCompliance — malformed JSON throws' {
    It 'throws when STIG file contains invalid JSON' {
        $badPath = Join-Path $TestDrive 'bad-stig.json'
        Set-Content -LiteralPath $badPath -Value 'NOT { valid json %%' -Encoding UTF8
        { Test-STIGCompliance -STIGPath $badPath } |
            Should -Throw -ExpectedMessage '*Failed to parse*'
    }
}

# ===========================================================================
# T20: Unknown control type emits Status=Error, does not throw
# ===========================================================================
Describe 'Test-STIGCompliance — unknown control type emits Status=Error' {
    BeforeAll {
        Mock Invoke-TSCAuditPol   { '' }
        Mock Invoke-TSCNetAccount { '' }
        Mock Get-TSCRegValue      { return $null }
    }

    It 'emits Status=Error and does not throw for an unrecognised control type' {
        $ctrl = @{
            vulnId   = 'V-TEST-UNK'
            title    = 'Unknown type'
            severity = 'CAT II'
            type     = 'FutureType'
            expected = @{}
            fix      = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-STIGFilePath -Name 'unknown-type.json' -Controls @($ctrl)
        $rows  = @(Test-STIGCompliance -STIGPath $bPath)
        $row   = $rows | Where-Object { $_.VulnId -eq 'V-TEST-UNK' }
        $row.Status | Should -Be 'Error'
        $row.Reason | Should -Match 'Unknown control type'
    }
}

# ===========================================================================
# T21: Dispatcher catches exceptions → Status=Error (not throw)
# ===========================================================================
Describe 'Test-STIGCompliance — dispatcher catches exceptions as Status=Error' {
    BeforeAll {
        Mock Invoke-TSCAuditPol   { '' }
        Mock Invoke-TSCNetAccount { '' }
        Mock Get-TSCRegValue      { throw 'Simulated registry read failure' }
    }

    It 'emits Status=Error and does not throw when Get-TSCRegValue throws' {
        $ctrl = @{
            vulnId   = 'V-ERR1'
            title    = 'Error test'
            severity = 'CAT II'
            type     = 'RegistryValue'
            expected = @{ Path = 'HKLM:\Test'; Name = 'Anything'; Value = 1; ValueType = 'DWord' }
            fix      = ''
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json

        $bPath = Get-STIGFilePath -Name 'error-catch.json' -Controls @($ctrl)
        $rows  = @(Test-STIGCompliance -STIGPath $bPath)
        $row   = $rows | Where-Object { $_.VulnId -eq 'V-ERR1' }
        $row.Status | Should -Be 'Error'
        $row.Reason | Should -Match 'Simulated registry read failure'
    }
}

# ===========================================================================
# T22: Full sample STIG file loads without error and returns multiple rows
# ===========================================================================
Describe 'Test-STIGCompliance — sample STIG file loads' {
    BeforeAll {
        Mock Invoke-TSCAuditPol   { Get-MockAuditCsv }
        Mock Invoke-TSCNetAccount { Get-MockNetAccounts }
        Mock Get-TSCRegValue      { return $null }
        Mock Get-TSCService       { return $null }
        Mock Invoke-TSCManageBde  { Get-MockManageBdeEncrypted }
    }

    It 'does not throw when loading the shipped sample STIG file' {
        $samplePath = Join-Path $PSScriptRoot 'samples' 'stig-win11-subset.json'
        { Test-STIGCompliance -STIGPath $samplePath -IncludeManual } | Should -Not -Throw
    }

    It 'emits more than one row (data rows + SUMMARY) for the sample STIG file' {
        $samplePath = Join-Path $PSScriptRoot 'samples' 'stig-win11-subset.json'
        $rows = @(Test-STIGCompliance -STIGPath $samplePath -IncludeManual)
        $rows.Count | Should -BeGreaterThan 1
    }
}
