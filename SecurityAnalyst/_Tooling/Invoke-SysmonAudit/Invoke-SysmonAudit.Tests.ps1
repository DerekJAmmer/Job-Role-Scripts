#requires -Version 7.2

BeforeAll {
    . (Join-Path $PSScriptRoot 'Invoke-SysmonAudit.ps1')
}

# ---------------------------------------------------------------------------
# Get-SADSysmonService
# ---------------------------------------------------------------------------

Describe 'Get-SADSysmonService' {

    Context 'when Sysmon64 service exists' {
        BeforeAll {
            Mock Get-Service {
                [pscustomobject]@{ Name = 'Sysmon64'; Status = 'Running'; BinaryPathName = 'C:\Windows\Sysmon64.exe' }
            } -ParameterFilter { $Name -contains 'Sysmon64' -or $Name -contains 'Sysmon' }
        }

        It 'returns the service object' {
            $result = Get-SADSysmonService
            $result | Should -Not -BeNullOrEmpty
            $result.Name | Should -Be 'Sysmon64'
        }
    }

    Context 'when no Sysmon service exists' {
        BeforeAll {
            Mock Get-Service { return $null }
        }

        It 'returns null' {
            $result = Get-SADSysmonService
            $result | Should -BeNullOrEmpty
        }
    }
}

# ---------------------------------------------------------------------------
# Test-SADSysmonInstalled
# ---------------------------------------------------------------------------

Describe 'Test-SADSysmonInstalled' {

    Context 'with null service' {
        It 'returns Fail status' {
            $result = Test-SADSysmonInstalled -Service $null
            $result.Status | Should -Be 'Fail'
        }

        It 'remediation mentions Install Sysmon' {
            $result = Test-SADSysmonInstalled -Service $null
            $result.Remediation | Should -Match 'Install Sysmon'
        }
    }

    Context 'with a valid service object' {
        BeforeAll {
            $script:fakeSvcInstalled = [pscustomobject]@{ Name = 'Sysmon64'; Status = 'Running'; BinaryPathName = 'C:\Windows\Sysmon64.exe' }
        }

        It 'returns Pass status' {
            $result = Test-SADSysmonInstalled -Service $script:fakeSvcInstalled
            $result.Status | Should -Be 'Pass'
        }

        It 'Check field is Sysmon Installed' {
            $result = Test-SADSysmonInstalled -Service $script:fakeSvcInstalled
            $result.Check | Should -Be 'Sysmon Installed'
        }
    }
}

# ---------------------------------------------------------------------------
# Test-SADSysmonRunning
# ---------------------------------------------------------------------------

Describe 'Test-SADSysmonRunning' {

    Context 'service status Running' {
        BeforeAll {
            $script:runningSvc = [pscustomobject]@{ Name = 'Sysmon64'; Status = 'Running'; BinaryPathName = 'C:\Windows\Sysmon64.exe' }
        }

        It 'returns Pass' {
            $result = Test-SADSysmonRunning -Service $script:runningSvc
            $result.Status | Should -Be 'Pass'
        }
    }

    Context 'service status Stopped' {
        BeforeAll {
            $script:stoppedSvc = [pscustomobject]@{ Name = 'Sysmon64'; Status = 'Stopped'; BinaryPathName = 'C:\Windows\Sysmon64.exe' }
        }

        It 'returns Fail' {
            $result = Test-SADSysmonRunning -Service $script:stoppedSvc
            $result.Status | Should -Be 'Fail'
        }

        It 'remediation mentions Start-Service' {
            $result = Test-SADSysmonRunning -Service $script:stoppedSvc
            $result.Remediation | Should -Match 'Start-Service'
        }
    }

    Context 'null service' {
        It 'returns Fail' {
            $result = Test-SADSysmonRunning -Service $null
            $result.Status | Should -Be 'Fail'
        }
    }
}

# ---------------------------------------------------------------------------
# Test-SADSysmonDriver
# ---------------------------------------------------------------------------

Describe 'Test-SADSysmonDriver' {

    Context 'driver found and Running' {
        BeforeAll {
            Mock Get-CimInstance {
                [pscustomobject]@{ Name = 'SysmonDrv'; State = 'Running' }
            }
        }

        It 'returns Pass' {
            $result = Test-SADSysmonDriver
            $result.Status | Should -Be 'Pass'
        }
    }

    Context 'driver found but Stopped' {
        BeforeAll {
            Mock Get-CimInstance {
                [pscustomobject]@{ Name = 'SysmonDrv'; State = 'Stopped' }
            }
        }

        It 'returns Fail' {
            $result = Test-SADSysmonDriver
            $result.Status | Should -Be 'Fail'
        }

        It 'Detail mentions the driver state' {
            $result = Test-SADSysmonDriver
            $result.Detail | Should -Match 'Stopped'
        }
    }

    Context 'driver not found (CimInstance returns null)' {
        BeforeAll {
            Mock Get-CimInstance { return $null }
        }

        It 'returns Fail' {
            $result = Test-SADSysmonDriver
            $result.Status | Should -Be 'Fail'
        }
    }
}

# ---------------------------------------------------------------------------
# Test-SADSysmonSignature
# ---------------------------------------------------------------------------

Describe 'Test-SADSysmonSignature' {

    Context 'null service' {
        It 'returns Skipped' {
            $result = Test-SADSysmonSignature -Service $null
            $result.Status | Should -Be 'Skipped'
        }
    }

    Context 'valid Microsoft signature' {
        BeforeAll {
            $script:fakeSvcValidSig = [pscustomobject]@{
                Name           = 'Sysmon64'
                Status         = 'Running'
                BinaryPathName = '"C:\Windows\Sysmon64.exe"'
            }

            Mock Test-Path { return $true }
            Mock Get-AuthenticodeSignature {
                [pscustomobject]@{
                    Status             = 'Valid'
                    SignerCertificate  = [pscustomobject]@{ Subject = 'CN=Microsoft Windows, O=Microsoft Corporation' }
                }
            }
        }

        It 'returns Pass' {
            $result = Test-SADSysmonSignature -Service $script:fakeSvcValidSig
            $result.Status | Should -Be 'Pass'
        }

        It 'Detail mentions signer' {
            $result = Test-SADSysmonSignature -Service $script:fakeSvcValidSig
            $result.Detail | Should -Match 'Microsoft'
        }
    }

    Context 'binary is not signed' {
        BeforeAll {
            $script:fakeSvcNotSigned = [pscustomobject]@{
                Name           = 'Sysmon64'
                Status         = 'Running'
                BinaryPathName = 'C:\Windows\Sysmon64.exe'
            }

            Mock Test-Path { return $true }
            Mock Get-AuthenticodeSignature {
                [pscustomobject]@{
                    Status            = 'NotSigned'
                    SignerCertificate = $null
                }
            }
        }

        It 'returns Fail' {
            $result = Test-SADSysmonSignature -Service $script:fakeSvcNotSigned
            $result.Status | Should -Be 'Fail'
        }

        It 'Detail mentions NotSigned' {
            $result = Test-SADSysmonSignature -Service $script:fakeSvcNotSigned
            $result.Detail | Should -Match 'NotSigned'
        }
    }

    Context 'valid signature but unexpected signer' {
        BeforeAll {
            $script:fakeSvcBadSigner = [pscustomobject]@{
                Name           = 'Sysmon64'
                Status         = 'Running'
                BinaryPathName = 'C:\Windows\Sysmon64.exe'
            }

            Mock Test-Path { return $true }
            Mock Get-AuthenticodeSignature {
                [pscustomobject]@{
                    Status            = 'Valid'
                    SignerCertificate = [pscustomobject]@{ Subject = 'CN=Evil Corp' }
                }
            }
        }

        It 'returns Fail' {
            $result = Test-SADSysmonSignature -Service $script:fakeSvcBadSigner
            $result.Status | Should -Be 'Fail'
        }

        It 'Remediation mentions unexpected signer' {
            $result = Test-SADSysmonSignature -Service $script:fakeSvcBadSigner
            $result.Remediation | Should -Match 'unexpected signer'
        }
    }
}

# ---------------------------------------------------------------------------
# Test-SADSysmonConfig
# ---------------------------------------------------------------------------

Describe 'Test-SADSysmonConfig' {

    BeforeAll {
        $script:fakeSvcConfig = [pscustomobject]@{
            Name           = 'Sysmon64'
            Status         = 'Running'
            BinaryPathName = 'C:\Windows\Sysmon64.exe'
        }
    }

    Context 'no baseline provided' {
        It 'returns Skipped' {
            $result = Test-SADSysmonConfig -Service $script:fakeSvcConfig
            $result.Status | Should -Be 'Skipped'
        }
    }

    Context 'ExpectedConfigHash matches active config' {
        BeforeAll {
            $script:knownHash = 'AABBCCDD' * 8  # 64 hex chars

            # Registry path exists and returns the config file path
            Mock Test-Path { return $true }
            Mock Get-ItemProperty {
                [pscustomobject]@{ ConfigFile = 'C:\Windows\SysmonConfig.xml' }
            }
            Mock Get-FileHash {
                [pscustomobject]@{ Hash = $script:knownHash.ToUpperInvariant() }
            }
        }

        It 'returns Pass' {
            $result = Test-SADSysmonConfig -Service $script:fakeSvcConfig -ExpectedConfigHash $script:knownHash
            $result.Status | Should -Be 'Pass'
        }
    }

    Context 'ExpectedConfigHash does not match active config' {
        BeforeAll {
            $script:expectedHash = 'AABBCCDD' * 8
            $script:activeHash   = 'DEADBEEF' * 8

            Mock Test-Path { return $true }
            Mock Get-ItemProperty {
                [pscustomobject]@{ ConfigFile = 'C:\Windows\SysmonConfig.xml' }
            }
            Mock Get-FileHash {
                [pscustomobject]@{ Hash = $script:activeHash.ToUpperInvariant() }
            }
        }

        It 'returns Fail' {
            $result = Test-SADSysmonConfig -Service $script:fakeSvcConfig -ExpectedConfigHash $script:expectedHash
            $result.Status | Should -Be 'Fail'
        }

        It 'Detail mentions both hashes' {
            $result = Test-SADSysmonConfig -Service $script:fakeSvcConfig -ExpectedConfigHash $script:expectedHash
            $result.Detail | Should -Match 'Expected'
            $result.Detail | Should -Match 'Actual'
        }
    }

    Context 'BaselineConfigPath provided — hashes match' {
        BeforeAll {
            $script:sharedHash = 'CAFEBABE' * 8

            Mock Test-Path { return $true }
            Mock Get-ItemProperty {
                [pscustomobject]@{ ConfigFile = 'C:\Windows\SysmonConfig.xml' }
            }
            # Both calls to Get-FileHash return the same hash (baseline & active)
            Mock Get-FileHash {
                [pscustomobject]@{ Hash = $script:sharedHash.ToUpperInvariant() }
            }
        }

        It 'returns Pass when baseline hash equals active hash' {
            $result = Test-SADSysmonConfig -Service $script:fakeSvcConfig -BaselineConfigPath 'C:\Baseline\sysmon.xml'
            $result.Status | Should -Be 'Pass'
        }
    }

    Context 'BaselineConfigPath does not exist' {
        BeforeAll {
            Mock Test-Path { return $false }
        }

        It 'returns Fail' {
            $result = Test-SADSysmonConfig -Service $script:fakeSvcConfig -BaselineConfigPath 'C:\NoSuchFile.xml'
            $result.Status | Should -Be 'Fail'
        }
    }
}

# ---------------------------------------------------------------------------
# Invoke-SysmonAudit (smoke test)
# ---------------------------------------------------------------------------

Describe 'Invoke-SysmonAudit smoke test' {

    BeforeAll {
        # Stub all underlying helpers so the orchestrator can run cleanly
        Mock Get-Service {
            [pscustomobject]@{
                Name           = 'Sysmon64'
                Status         = 'Running'
                BinaryPathName = 'C:\Windows\Sysmon64.exe'
            }
        }

        Mock Get-CimInstance {
            [pscustomobject]@{ Name = 'SysmonDrv'; State = 'Running' }
        }

        Mock Test-Path { return $true }

        Mock Get-AuthenticodeSignature {
            [pscustomobject]@{
                Status            = 'Valid'
                SignerCertificate = [pscustomobject]@{ Subject = 'CN=Sysinternals' }
            }
        }

        # Config check — no baseline supplied so this will be Skipped
    }

    It 'returns an object with Results containing exactly 5 checks' {
        $summary = Invoke-SysmonAudit -Quiet
        @($summary.Results).Count | Should -Be 5
    }

    It 'returned object has PassCount property' {
        $summary = Invoke-SysmonAudit -Quiet
        $summary.PSObject.Properties.Name | Should -Contain 'PassCount'
    }

    It 'returned object has FailCount property' {
        $summary = Invoke-SysmonAudit -Quiet
        $summary.PSObject.Properties.Name | Should -Contain 'FailCount'
    }

    It 'returned object has SkipCount property' {
        $summary = Invoke-SysmonAudit -Quiet
        $summary.PSObject.Properties.Name | Should -Contain 'SkipCount'
    }

    It 'PassCount + FailCount + SkipCount equals 5' {
        $summary = Invoke-SysmonAudit -Quiet
        ($summary.PassCount + $summary.FailCount + $summary.SkipCount) | Should -Be 5
    }

    It 'HostName matches env:COMPUTERNAME' {
        $summary = Invoke-SysmonAudit -Quiet
        $summary.HostName | Should -Be $env:COMPUTERNAME
    }
}
