#requires -Version 7.2

BeforeAll {
    . (Join-Path $PSScriptRoot 'Get-PendingReboot.ps1')
}

# ---------------------------------------------------------------------------
# Helper: reset all registry mocks to "nothing pending" baseline
# ---------------------------------------------------------------------------

# Each Describe/Context sets up its own mocks; tests are isolated by scope.

# ---------------------------------------------------------------------------
# Test-PRRebootCondition — individual conditions
# ---------------------------------------------------------------------------

Describe 'Test-PRRebootCondition — condition 1: Component Based Servicing' {
    BeforeAll {
        Mock Test-Path { $true  } -ParameterFilter { $LiteralPath -like '*Component Based Servicing*' }
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*WindowsUpdate*' }
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*SMS*' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ PendingFileRenameOperations = $null; ComputerName = 'SAME' }
        }
    }

    It 'sets RebootRequired=$true and adds "Component Based Servicing" to Reasons' {
        $result = Test-PRRebootCondition
        $result.RebootRequired | Should -Be $true
        $result.Reasons        | Should -Contain 'Component Based Servicing'
    }
}

Describe 'Test-PRRebootCondition — condition 2: Windows Update' {
    BeforeAll {
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*Component Based Servicing*' }
        Mock Test-Path { $true  } -ParameterFilter { $LiteralPath -like '*WindowsUpdate*' }
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*SMS*' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ PendingFileRenameOperations = $null; ComputerName = 'SAME' }
        }
    }

    It 'sets RebootRequired=$true and adds "Windows Update" to Reasons' {
        $result = Test-PRRebootCondition
        $result.RebootRequired | Should -Be $true
        $result.Reasons        | Should -Contain 'Windows Update'
    }
}

Describe 'Test-PRRebootCondition — condition 3: Pending File Rename' {
    BeforeAll {
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*Component Based Servicing*' }
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*WindowsUpdate*' }
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*SMS*' }
        # Session Manager key returns a non-null PendingFileRenameOperations
        Mock Get-ItemProperty {
            [PSCustomObject]@{ PendingFileRenameOperations = @('\??\C:\Temp\foo'); ComputerName = 'SAME' }
        } -ParameterFilter { $LiteralPath -like '*Session Manager*' }
        # Computer name keys return matching names (no rename pending)
        Mock Get-ItemProperty {
            [PSCustomObject]@{ ComputerName = 'SAME' }
        } -ParameterFilter { $LiteralPath -like '*ActiveComputerName*' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ ComputerName = 'SAME' }
        } -ParameterFilter { $LiteralPath -like '*ComputerName\ComputerName*' }
    }

    It 'sets RebootRequired=$true and adds "Pending File Rename" to Reasons' {
        $result = Test-PRRebootCondition
        $result.RebootRequired | Should -Be $true
        $result.Reasons        | Should -Contain 'Pending File Rename'
    }
}

Describe 'Test-PRRebootCondition — condition 4: SCCM Client' {
    BeforeAll {
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*Component Based Servicing*' }
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*WindowsUpdate*' }
        Mock Test-Path { $true  } -ParameterFilter { $LiteralPath -like '*SMS*' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ PendingFileRenameOperations = $null; ComputerName = 'SAME' }
        }
    }

    It 'sets RebootRequired=$true and adds "SCCM Client" to Reasons' {
        $result = Test-PRRebootCondition
        $result.RebootRequired | Should -Be $true
        $result.Reasons        | Should -Contain 'SCCM Client'
    }
}

Describe 'Test-PRRebootCondition — condition 5: Computer Rename' {
    BeforeAll {
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*Component Based Servicing*' }
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*WindowsUpdate*' }
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*SMS*' }
        # Session Manager — no rename ops
        Mock Get-ItemProperty {
            [PSCustomObject]@{ PendingFileRenameOperations = $null }
        } -ParameterFilter { $LiteralPath -like '*Session Manager*' }
        # Active name is OLD, pending name is NEW → mismatch
        Mock Get-ItemProperty {
            [PSCustomObject]@{ ComputerName = 'OLD-NAME' }
        } -ParameterFilter { $LiteralPath -like '*ActiveComputerName*' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ ComputerName = 'NEW-NAME' }
        } -ParameterFilter { $LiteralPath -like '*ComputerName\ComputerName*' }
    }

    It 'sets RebootRequired=$true and adds "Computer Rename" to Reasons' {
        $result = Test-PRRebootCondition
        $result.RebootRequired | Should -Be $true
        $result.Reasons        | Should -Contain 'Computer Rename'
    }
}

Describe 'Test-PRRebootCondition — no conditions trip' {
    BeforeAll {
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*Component Based Servicing*' }
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*WindowsUpdate*' }
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*SMS*' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ PendingFileRenameOperations = $null }
        } -ParameterFilter { $LiteralPath -like '*Session Manager*' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ ComputerName = 'SAME-NAME' }
        } -ParameterFilter { $LiteralPath -like '*ActiveComputerName*' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ ComputerName = 'SAME-NAME' }
        } -ParameterFilter { $LiteralPath -like '*ComputerName\ComputerName*' }
    }

    It 'returns RebootRequired=$false when no conditions are met' {
        $result = Test-PRRebootCondition
        $result.RebootRequired | Should -Be $false
    }

    It 'returns an empty Reasons array when no conditions are met' {
        $result = Test-PRRebootCondition
        $result.Reasons.Count  | Should -Be 0
    }

    It 'returns Status=OK for a clean host' {
        $result = Test-PRRebootCondition
        $result.Status | Should -Be 'OK'
    }
}

# ---------------------------------------------------------------------------
# Get-PendingReboot — public function output shape
# ---------------------------------------------------------------------------

Describe 'Get-PendingReboot — output shape for local host' {
    BeforeAll {
        # All clear — nothing pending
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*Component Based Servicing*' }
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*WindowsUpdate*' }
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*SMS*' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ PendingFileRenameOperations = $null }
        } -ParameterFilter { $LiteralPath -like '*Session Manager*' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ ComputerName = 'SAME' }
        } -ParameterFilter { $LiteralPath -like '*ActiveComputerName*' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ ComputerName = 'SAME' }
        } -ParameterFilter { $LiteralPath -like '*ComputerName\ComputerName*' }
    }

    It 'returns exactly one object for the local machine' {
        $result = @(Get-PendingReboot)
        $result.Count | Should -Be 1
    }

    It 'result object has all required properties' {
        $result = Get-PendingReboot
        $result.PSObject.Properties.Name | Should -Contain 'ComputerName'
        $result.PSObject.Properties.Name | Should -Contain 'RebootRequired'
        $result.PSObject.Properties.Name | Should -Contain 'Reasons'
        $result.PSObject.Properties.Name | Should -Contain 'QueriedAt'
        $result.PSObject.Properties.Name | Should -Contain 'Status'
    }

    It 'QueriedAt is a DateTime' {
        $result = Get-PendingReboot
        $result.QueriedAt | Should -BeOfType [datetime]
    }
}

# ---------------------------------------------------------------------------
# Get-PendingReboot — unreachable remote host
# ---------------------------------------------------------------------------

Describe 'Get-PendingReboot — unreachable remote host' {
    BeforeAll {
        Mock Invoke-Command { throw [System.Management.Automation.RemoteException]::new('Connection refused') }
    }

    It 'does not throw when a remote host is unreachable' {
        { Get-PendingReboot -ComputerName 'FAKE-REMOTE-HOST-XYZ' } | Should -Not -Throw
    }

    It 'records the host with Status=Unreachable' {
        $result = @(Get-PendingReboot -ComputerName 'FAKE-REMOTE-HOST-XYZ')
        $result[0].Status | Should -Be 'Unreachable'
    }

    It 'sets ComputerName correctly on an unreachable result' {
        $result = @(Get-PendingReboot -ComputerName 'FAKE-REMOTE-HOST-XYZ')
        $result[0].ComputerName | Should -Be 'FAKE-REMOTE-HOST-XYZ'
    }
}

# ---------------------------------------------------------------------------
# Get-PendingReboot — JSON output
# ---------------------------------------------------------------------------

Describe 'Get-PendingReboot — JSON output' {
    BeforeAll {
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*Component Based Servicing*' }
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*WindowsUpdate*' }
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*SMS*' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ PendingFileRenameOperations = $null }
        } -ParameterFilter { $LiteralPath -like '*Session Manager*' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ ComputerName = 'SAME' }
        } -ParameterFilter { $LiteralPath -like '*ActiveComputerName*' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ ComputerName = 'SAME' }
        } -ParameterFilter { $LiteralPath -like '*ComputerName\ComputerName*' }
    }

    It 'writes a JSON file when -OutputPath is supplied' {
        $jsonPath = Join-Path $TestDrive 'reboot.json'
        Get-PendingReboot -OutputPath $jsonPath | Out-Null
        Test-Path -LiteralPath $jsonPath | Should -Be $true
    }

    It 'JSON file contains valid parseable content' {
        $jsonPath = Join-Path $TestDrive 'reboot2.json'
        Get-PendingReboot -OutputPath $jsonPath | Out-Null
        $parsed = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
        $parsed | Should -Not -BeNullOrEmpty
    }
}

# ===========================================================================
# NEW TESTS — added for refactor verification
# ===========================================================================

# ---------------------------------------------------------------------------
# NEW 1: Mixed batch — local + remote in one call
# ---------------------------------------------------------------------------

Describe 'Get-PendingReboot — mixed batch: localhost + REMOTE-SRV01' {
    BeforeAll {
        # CBS key trips for local checks (Test-PRRebootCondition calls Test-Path locally)
        Mock Test-Path { $true  } -ParameterFilter { $LiteralPath -like '*Component Based Servicing*' }
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*WindowsUpdate*' }
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*SMS*' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ PendingFileRenameOperations = $null; ComputerName = 'SAME' }
        }

        # Remote returns clean (no reboot needed)
        Mock Invoke-Command {
            [PSCustomObject]@{
                RebootRequired = $false
                Reasons        = @()
                QueriedAt      = (Get-Date)
            }
        }
    }

    It 'returns two result rows' {
        $results = @(Get-PendingReboot -ComputerName 'localhost', 'REMOTE-SRV01')
        $results.Count | Should -Be 2
    }

    It 'local row has RebootRequired=$true (CBS tripped)' {
        $results = @(Get-PendingReboot -ComputerName 'localhost', 'REMOTE-SRV01')
        $localRow = $results | Where-Object { $_.ComputerName -eq 'localhost' }
        $localRow.RebootRequired | Should -Be $true
    }

    It 'remote row has RebootRequired=$false (mocked clean)' {
        $results = @(Get-PendingReboot -ComputerName 'localhost', 'REMOTE-SRV01')
        $remoteRow = $results | Where-Object { $_.ComputerName -eq 'REMOTE-SRV01' }
        $remoteRow.RebootRequired | Should -Be $false
    }

    It 'Invoke-Command was called exactly once targeting REMOTE-SRV01' {
        Get-PendingReboot -ComputerName 'localhost', 'REMOTE-SRV01' | Out-Null
        Should -Invoke Invoke-Command -Times 1 -Exactly -ParameterFilter { $ComputerName -eq 'REMOTE-SRV01' }
    }
}

# ---------------------------------------------------------------------------
# NEW 2: FQDN local detection — WK01.corp.local routes locally
# ---------------------------------------------------------------------------

Describe 'Get-PendingReboot — FQDN that matches local machine is treated as local' {
    BeforeAll {
        # Force a predictable COMPUTERNAME for the duration of this Describe
        $script:OriginalComputerName = $env:COMPUTERNAME
        $env:COMPUTERNAME = 'WK01'

        # Re-dot-source so Test-PRIsLocalHost picks up the new env var value.
        # The script re-evaluates $env:COMPUTERNAME at call time, so no re-source needed —
        # the function reads $env:COMPUTERNAME dynamically.

        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*Component Based Servicing*' }
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*WindowsUpdate*' }
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*SMS*' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ PendingFileRenameOperations = $null; ComputerName = 'SAME' }
        }
        Mock Invoke-Command { throw 'Should not be called for local FQDN' }
    }

    AfterAll {
        $env:COMPUTERNAME = $script:OriginalComputerName
    }

    It 'does not call Invoke-Command when FQDN left-label matches local machine' {
        # wk01.corp.local should be detected as local when COMPUTERNAME=WK01
        Get-PendingReboot -ComputerName 'wk01.corp.local' | Out-Null
        Should -Invoke Invoke-Command -Times 0 -Exactly
    }
}

# ---------------------------------------------------------------------------
# NEW 3: Pin "localhost is local" — documented behavior, locked with a test
# ---------------------------------------------------------------------------

Describe 'Get-PendingReboot — "localhost" is always treated as local (documented behavior)' {
    BeforeAll {
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*Component Based Servicing*' }
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*WindowsUpdate*' }
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*SMS*' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ PendingFileRenameOperations = $null; ComputerName = 'SAME' }
        }
        Mock Invoke-Command { throw 'Should not be called for localhost' }
    }

    It 'does not call Invoke-Command for "localhost"' {
        Get-PendingReboot -ComputerName 'localhost' | Out-Null
        Should -Invoke Invoke-Command -Times 0 -Exactly
    }

    It 'local helper produces a result with the expected property set' {
        $result = Get-PendingReboot -ComputerName 'localhost'
        $result.PSObject.Properties.Name | Should -Contain 'ComputerName'
        $result.PSObject.Properties.Name | Should -Contain 'RebootRequired'
        $result.PSObject.Properties.Name | Should -Contain 'Reasons'
        $result.PSObject.Properties.Name | Should -Contain 'QueriedAt'
        $result.PSObject.Properties.Name | Should -Contain 'Status'
    }
}

# ---------------------------------------------------------------------------
# NEW 4: Refactor sanity — SCCM key produces 'SCCM Client' in both paths
# ---------------------------------------------------------------------------

Describe 'Get-PendingReboot — refactor sanity: SCCM key detected via unified body' {
    BeforeAll {
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*Component Based Servicing*' }
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*WindowsUpdate*' }
        Mock Test-Path { $true  } -ParameterFilter { $LiteralPath -like '*SMS*' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ PendingFileRenameOperations = $null; ComputerName = 'SAME' }
        }
    }

    It 'local call: Reasons contains "SCCM Client" when SMS key is present' {
        $result = Get-PendingReboot -ComputerName 'localhost'
        $result.Reasons | Should -Contain 'SCCM Client'
    }

    It 'local call: RebootRequired=$true when SCCM key is the only condition' {
        $result = Get-PendingReboot -ComputerName 'localhost'
        $result.RebootRequired | Should -Be $true
    }

    Context 'remote path — unified body is passed to Invoke-Command' {
        BeforeAll {
            # Simulate a remote that returns the SCCM result (as if the unified body ran there)
            Mock Invoke-Command {
                [PSCustomObject]@{
                    RebootRequired = $true
                    Reasons        = @('SCCM Client')
                    QueriedAt      = (Get-Date)
                }
            }
        }

        It 'remote row: Reasons contains "SCCM Client" from mocked unified body response' {
            $result = Get-PendingReboot -ComputerName 'REMOTE-SCCM-HOST'
            $result.Reasons | Should -Contain 'SCCM Client'
        }

        It 'remote row: RebootRequired=$true from mocked unified body response' {
            $result = Get-PendingReboot -ComputerName 'REMOTE-SCCM-HOST'
            $result.RebootRequired | Should -Be $true
        }
    }
}
