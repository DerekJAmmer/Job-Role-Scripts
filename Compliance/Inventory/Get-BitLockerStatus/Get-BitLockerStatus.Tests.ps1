#requires -Version 7.2

BeforeAll {
    . (Join-Path $PSScriptRoot 'Get-BitLockerStatus.ps1')

    # ---------------------------------------------------------------------------
    # Helper: build a fake BitLocker volume object.
    # ---------------------------------------------------------------------------
    function New-FakeVolume {
        param(
            [string]$MountPoint          = 'C:',
            [string]$ProtectionStatus    = 'On',
            [int]   $EncryptionPercentage = 100,
            [string]$EncryptionMethod    = 'XtsAes256',
            [string]$VolumeStatus        = 'FullyEncrypted',
            [string]$VolumeType          = 'OperatingSystem',
            [object[]]$KeyProtector      = @(
                [PSCustomObject]@{ KeyProtectorType = 'Tpm' },
                [PSCustomObject]@{ KeyProtectorType = 'RecoveryPassword' }
            )
        )
        [PSCustomObject]@{
            MountPoint           = $MountPoint
            ProtectionStatus     = $ProtectionStatus
            EncryptionPercentage = $EncryptionPercentage
            EncryptionMethod     = $EncryptionMethod
            VolumeStatus         = $VolumeStatus
            VolumeType           = $VolumeType
            KeyProtector         = $KeyProtector
        }
    }

    # ---------------------------------------------------------------------------
    # Helper: build a fake TPM object.
    # ---------------------------------------------------------------------------
    function New-FakeTpm {
        param(
            [bool]$TpmPresent = $true,
            [bool]$TpmReady   = $true
        )
        [PSCustomObject]@{
            TpmPresent = $TpmPresent
            TpmReady   = $TpmReady
        }
    }
}

# ===========================================================================
# T1: Fully compliant — Protection=On, 100%, TPM ready, SecureBoot on
# ===========================================================================
Describe 'Get-BitLockerStatus — fully compliant system' {
    BeforeAll {
        Mock Get-GBLSBitLockerVolume { @(New-FakeVolume) }
        Mock Get-GBLSTpm             { New-FakeTpm }
        Mock Get-GBLSSecureBoot      { $true }
    }

    It 'returns Status=Compliant when all conditions are met' {
        $rows = @(Get-BitLockerStatus)
        $rows.Count | Should -Be 1
        $rows[0].Status | Should -Be 'Compliant'
    }

    It 'Compliant row has empty Reasons string' {
        $rows = @(Get-BitLockerStatus)
        $rows[0].Reasons | Should -BeNullOrEmpty
    }
}

# ===========================================================================
# T2: Unencrypted volume — ProtectionStatus=Off → NonCompliant
# ===========================================================================
Describe 'Get-BitLockerStatus — unencrypted fixed volume' {
    BeforeAll {
        Mock Get-GBLSBitLockerVolume {
            @(New-FakeVolume -ProtectionStatus 'Off' -EncryptionPercentage 0 -VolumeStatus 'FullyDecrypted')
        }
        Mock Get-GBLSTpm        { New-FakeTpm }
        Mock Get-GBLSSecureBoot { $true }
    }

    It 'returns Status=NonCompliant' {
        $rows = @(Get-BitLockerStatus)
        $rows[0].Status | Should -Be 'NonCompliant'
    }

    It 'Reasons mentions ProtectionStatus' {
        $rows = @(Get-BitLockerStatus)
        $rows[0].Reasons | Should -Match 'ProtectionStatus'
    }
}

# ===========================================================================
# T3: Encryption in progress (50%) → NonCompliant, Reasons mentions EncryptionPercentage
# ===========================================================================
Describe 'Get-BitLockerStatus — encryption in progress' {
    BeforeAll {
        Mock Get-GBLSBitLockerVolume {
            @(New-FakeVolume -ProtectionStatus 'On' -EncryptionPercentage 50 -VolumeStatus 'EncryptionInProgress')
        }
        Mock Get-GBLSTpm        { New-FakeTpm }
        Mock Get-GBLSSecureBoot { $true }
    }

    It 'returns Status=NonCompliant' {
        $rows = @(Get-BitLockerStatus)
        $rows[0].Status | Should -Be 'NonCompliant'
    }

    It 'Reasons mentions EncryptionPercentage' {
        $rows = @(Get-BitLockerStatus)
        $rows[0].Reasons | Should -Match 'EncryptionPercentage'
    }
}

# ===========================================================================
# T4: TPM not ready (TpmPresent=true, TpmReady=false) → NonCompliant
# ===========================================================================
Describe 'Get-BitLockerStatus — TPM not ready' {
    BeforeAll {
        Mock Get-GBLSBitLockerVolume { @(New-FakeVolume) }
        Mock Get-GBLSTpm             { New-FakeTpm -TpmPresent $true -TpmReady $false }
        Mock Get-GBLSSecureBoot      { $true }
    }

    It 'returns Status=NonCompliant' {
        $rows = @(Get-BitLockerStatus)
        $rows[0].Status | Should -Be 'NonCompliant'
    }

    It 'Reasons mentions TpmReady' {
        $rows = @(Get-BitLockerStatus)
        $rows[0].Reasons | Should -Match 'TpmReady'
    }
}

# ===========================================================================
# T5: Secure Boot off (helper returns $false) → NonCompliant
# ===========================================================================
Describe 'Get-BitLockerStatus — Secure Boot disabled' {
    BeforeAll {
        Mock Get-GBLSBitLockerVolume { @(New-FakeVolume) }
        Mock Get-GBLSTpm             { New-FakeTpm }
        Mock Get-GBLSSecureBoot      { $false }
    }

    It 'returns Status=NonCompliant' {
        $rows = @(Get-BitLockerStatus)
        $rows[0].Status | Should -Be 'NonCompliant'
    }

    It 'Reasons mentions SecureBootEnabled=false' {
        $rows = @(Get-BitLockerStatus)
        $rows[0].Reasons | Should -Match 'SecureBootEnabled=false'
    }
}

# ===========================================================================
# T6: Non-UEFI machine (Get-GBLSSecureBoot returns $null)
# ===========================================================================
Describe 'Get-BitLockerStatus — non-UEFI machine' {
    BeforeAll {
        Mock Get-GBLSBitLockerVolume { @(New-FakeVolume) }
        Mock Get-GBLSTpm             { New-FakeTpm }
        Mock Get-GBLSSecureBoot      { $null }
    }

    It 'SecureBootEnabled is $null' {
        $rows = @(Get-BitLockerStatus)
        $rows[0].SecureBootEnabled | Should -BeNullOrEmpty
    }

    It 'returns Status=NonCompliant' {
        $rows = @(Get-BitLockerStatus)
        $rows[0].Status | Should -Be 'NonCompliant'
    }

    It 'Reasons mentions non-UEFI or disabled' {
        $rows = @(Get-BitLockerStatus)
        $rows[0].Reasons | Should -Match 'SecureBootEnabled'
    }
}

# ===========================================================================
# T7: Get-GBLSBitLockerVolume returns $null → Status=Unknown, no throw
# ===========================================================================
Describe 'Get-BitLockerStatus — BitLocker cmdlet unavailable' {
    BeforeAll {
        Mock Get-GBLSBitLockerVolume { $null }
        Mock Get-GBLSTpm             { $null }
        Mock Get-GBLSSecureBoot      { $null }
    }

    It 'does not throw' {
        { Get-BitLockerStatus } | Should -Not -Throw
    }

    It 'returns exactly one row with Status=Unknown' {
        $rows = @(Get-BitLockerStatus)
        $rows.Count | Should -Be 1
        $rows[0].Status | Should -Be 'Unknown'
    }

    It 'Reasons mentions Get-BitLockerVolume not available' {
        $rows = @(Get-BitLockerStatus)
        $rows[0].Reasons | Should -Match 'Get-BitLockerVolume not available'
    }
}

# ===========================================================================
# T8: Removable/Network volumes excluded — only OS + Data evaluated
# ===========================================================================
Describe 'Get-BitLockerStatus — removable and network volumes excluded' {
    BeforeAll {
        Mock Get-GBLSBitLockerVolume {
            @(
                (New-FakeVolume -MountPoint 'C:' -VolumeType 'OperatingSystem'),
                (New-FakeVolume -MountPoint 'D:' -VolumeType 'Data'),
                (New-FakeVolume -MountPoint 'E:' -VolumeType 'Removable' -ProtectionStatus 'Off')
            )
        }
        Mock Get-GBLSTpm        { New-FakeTpm }
        Mock Get-GBLSSecureBoot { $true }
    }

    It 'returns exactly 2 rows (OS and Data only)' {
        $rows = @(Get-BitLockerStatus)
        $rows.Count | Should -Be 2
    }

    It 'no row has MountPoint=E: (Removable excluded)' {
        $rows = @(Get-BitLockerStatus)
        ($rows | Where-Object { $_.MountPoint -eq 'E:' }) | Should -BeNullOrEmpty
    }
}

# ===========================================================================
# T9: Local-vs-remote routing
#   ComputerName='.'     → Invoke-Command NOT called
#   ComputerName='SERVER01' → Invoke-Command called once
# ===========================================================================
Describe 'Get-BitLockerStatus — local vs remote routing' {
    BeforeAll {
        Mock Get-GBLSBitLockerVolume { @(New-FakeVolume) }
        Mock Get-GBLSTpm             { New-FakeTpm }
        Mock Get-GBLSSecureBoot      { $true }
        Mock Invoke-Command          {
            @{
                Volumes    = @(New-FakeVolume)
                Tpm        = New-FakeTpm
                SecureBoot = $true
            }
        }
    }

    It 'ComputerName=. does not call Invoke-Command' {
        Get-BitLockerStatus -ComputerName '.' | Out-Null
        Should -Invoke Invoke-Command -Times 0 -Exactly
    }

    It 'ComputerName=SERVER01 calls Invoke-Command exactly once' {
        Get-BitLockerStatus -ComputerName 'SERVER01' | Out-Null
        Should -Invoke Invoke-Command -Times 1 -Exactly
    }
}

# ===========================================================================
# T10: FQDN-aware local detection
#   ComputerName="$env:COMPUTERNAME.example.com" → no Invoke-Command
# ===========================================================================
Describe 'Get-BitLockerStatus — FQDN treated as local' {
    BeforeAll {
        Mock Get-GBLSBitLockerVolume { @(New-FakeVolume) }
        Mock Get-GBLSTpm             { New-FakeTpm }
        Mock Get-GBLSSecureBoot      { $true }
        Mock Invoke-Command          { throw 'Should not be called' }
    }

    It 'FQDN matching local hostname does not call Invoke-Command' {
        $fqdn = "$($env:COMPUTERNAME).example.com"
        { Get-BitLockerStatus -ComputerName $fqdn | Out-Null } | Should -Not -Throw
        Should -Invoke Invoke-Command -Times 0 -Exactly
    }
}

# ===========================================================================
# T11: Multi-host aggregation
#   ComputerName=@('.', 'REMOTE01') → rows from both hosts combined
# ===========================================================================
Describe 'Get-BitLockerStatus — multi-host aggregation' {
    BeforeAll {
        Mock Get-GBLSBitLockerVolume { @(New-FakeVolume -MountPoint 'C:') }
        Mock Get-GBLSTpm             { New-FakeTpm }
        Mock Get-GBLSSecureBoot      { $true }
        Mock Invoke-Command          {
            @{
                Volumes    = @(New-FakeVolume -MountPoint 'C:')
                Tpm        = New-FakeTpm
                SecureBoot = $true
            }
        }
    }

    It 'returns rows from both hosts' {
        $rows = @(Get-BitLockerStatus -ComputerName '.', 'REMOTE01')
        $rows.Count | Should -Be 2
    }

    It 'local row has ComputerName=.' {
        $rows = @(Get-BitLockerStatus -ComputerName '.', 'REMOTE01')
        ($rows | Where-Object { $_.ComputerName -eq '.' }) | Should -Not -BeNullOrEmpty
    }

    It 'remote row has ComputerName=REMOTE01' {
        $rows = @(Get-BitLockerStatus -ComputerName '.', 'REMOTE01')
        ($rows | Where-Object { $_.ComputerName -eq 'REMOTE01' }) | Should -Not -BeNullOrEmpty
    }
}

# ===========================================================================
# T12: CSV roundtrip — -OutputPath writes file with expected columns
# ===========================================================================
Describe 'Get-BitLockerStatus — CSV roundtrip' {
    BeforeAll {
        Mock Get-GBLSBitLockerVolume { @(New-FakeVolume) }
        Mock Get-GBLSTpm             { New-FakeTpm }
        Mock Get-GBLSSecureBoot      { $true }
    }

    It 'creates the CSV file at -OutputPath' {
        $csvPath = Join-Path $TestDrive 'bitlocker.csv'
        Get-BitLockerStatus -OutputPath $csvPath | Out-Null
        Test-Path -LiteralPath $csvPath | Should -Be $true
    }

    It 'CSV contains a Status column' {
        $csvPath = Join-Path $TestDrive 'bl-status.csv'
        Get-BitLockerStatus -OutputPath $csvPath | Out-Null
        $imported = Import-Csv -LiteralPath $csvPath
        $imported[0].PSObject.Properties.Name | Should -Contain 'Status'
    }

    It 'CSV contains a Reasons column' {
        $csvPath = Join-Path $TestDrive 'bl-reasons.csv'
        Get-BitLockerStatus -OutputPath $csvPath | Out-Null
        $imported = Import-Csv -LiteralPath $csvPath
        $imported[0].PSObject.Properties.Name | Should -Contain 'Reasons'
    }

    It 'CSV contains a ComputerName column' {
        $csvPath = Join-Path $TestDrive 'bl-cn.csv'
        Get-BitLockerStatus -OutputPath $csvPath | Out-Null
        $imported = Import-Csv -LiteralPath $csvPath
        $imported[0].PSObject.Properties.Name | Should -Contain 'ComputerName'
    }

    It 'CSV contains a MountPoint column' {
        $csvPath = Join-Path $TestDrive 'bl-mp.csv'
        Get-BitLockerStatus -OutputPath $csvPath | Out-Null
        $imported = Import-Csv -LiteralPath $csvPath
        $imported[0].PSObject.Properties.Name | Should -Contain 'MountPoint'
    }
}

# ===========================================================================
# T13: KeyProtectorTypes joined with semicolons
# ===========================================================================
Describe 'Get-BitLockerStatus — KeyProtectorTypes semicolon-joined' {
    BeforeAll {
        Mock Get-GBLSBitLockerVolume {
            @(New-FakeVolume -KeyProtector @(
                [PSCustomObject]@{ KeyProtectorType = 'Tpm' },
                [PSCustomObject]@{ KeyProtectorType = 'RecoveryPassword' },
                [PSCustomObject]@{ KeyProtectorType = 'ExternalKey' }
            ))
        }
        Mock Get-GBLSTpm        { New-FakeTpm }
        Mock Get-GBLSSecureBoot { $true }
    }

    It 'KeyProtectorTypes contains semicolon-joined values' {
        $rows = @(Get-BitLockerStatus)
        $rows[0].KeyProtectorTypes | Should -Be 'Tpm;RecoveryPassword;ExternalKey'
    }
}
