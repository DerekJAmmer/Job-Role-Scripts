#requires -Version 7.2

BeforeAll {
    . (Join-Path $PSScriptRoot 'Get-ServerInventory.ps1')
}

# ---------------------------------------------------------------------------
# Get-SIComputerInfo
# ---------------------------------------------------------------------------

Describe 'Get-SIComputerInfo' {
    BeforeAll {
        Mock Get-CimInstance {
            [PSCustomObject]@{
                Manufacturer = 'Dell Inc.'
                Model        = 'PowerEdge R740'
            }
        } -ParameterFilter { $ClassName -eq 'Win32_ComputerSystem' }

        Mock Get-CimInstance {
            [PSCustomObject]@{
                Caption     = 'Microsoft Windows Server 2022 Standard'
                Version     = '10.0.20348'
                BuildNumber = '20348'
                InstallDate = [datetime]'2023-01-15'
            }
        } -ParameterFilter { $ClassName -eq 'Win32_OperatingSystem' }
    }

    It 'returns expected shape with Manufacturer, Model, OSName, OSVersion, OSBuild, InstallDate' {
        $result = Get-SIComputerInfo
        $result.Manufacturer | Should -Be 'Dell Inc.'
        $result.Model        | Should -Be 'PowerEdge R740'
        $result.OSName       | Should -Be 'Microsoft Windows Server 2022 Standard'
        $result.OSVersion    | Should -Be '10.0.20348'
        $result.OSBuild      | Should -Be '20348'
        $result.InstallDate  | Should -Not -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# Get-SICpuInfo
# ---------------------------------------------------------------------------

Describe 'Get-SICpuInfo' {
    BeforeAll {
        Mock Get-CimInstance {
            [PSCustomObject]@{
                Name                    = '  Intel(R) Xeon(R) Gold 6226R  '
                NumberOfCores           = 16
                NumberOfLogicalProcessors = 32
            }
        } -ParameterFilter { $ClassName -eq 'Win32_Processor' }
    }

    It 'returns CpuName with whitespace trimmed, Cores, and LogicalProcessors' {
        $result = Get-SICpuInfo
        $result.CpuName           | Should -Be 'Intel(R) Xeon(R) Gold 6226R'
        $result.Cores             | Should -Be 16
        $result.LogicalProcessors | Should -Be 32
    }
}

# ---------------------------------------------------------------------------
# Get-SIMemoryInfo
# ---------------------------------------------------------------------------

Describe 'Get-SIMemoryInfo' {
    BeforeAll {
        # Win32_OperatingSystem values are in KB
        Mock Get-CimInstance {
            [PSCustomObject]@{
                TotalVisibleMemorySize = 16384 * 1024   # 16 GB in KB
                FreePhysicalMemory     = 8192  * 1024   # 8 GB in KB
            }
        } -ParameterFilter { $ClassName -eq 'Win32_OperatingSystem' }
    }

    It 'converts KB values to MB and returns TotalMemoryMB and FreeMemoryMB' {
        $result = Get-SIMemoryInfo
        $result.TotalMemoryMB | Should -Be 16384
        $result.FreeMemoryMB  | Should -Be 8192
    }
}

# ---------------------------------------------------------------------------
# Get-SIDiskInfo
# ---------------------------------------------------------------------------

Describe 'Get-SIDiskInfo' {
    BeforeAll {
        Mock Get-CimInstance {
            @(
                [PSCustomObject]@{ DeviceID = 'C:'; Size = 107374182400; FreeSpace = 53687091200 },  # 100 GB / 50 GB
                [PSCustomObject]@{ DeviceID = 'D:'; Size = 214748364800; FreeSpace = 21474836480 }   # 200 GB / 20 GB
            )
        } -ParameterFilter { $ClassName -eq 'Win32_LogicalDisk' }
    }

    It 'returns one row per drive with Drive, SizeGB, FreeGB, PctFree' {
        $result = @(Get-SIDiskInfo)
        $result.Count        | Should -Be 2
        $result[0].Drive     | Should -Be 'C:'
        $result[0].SizeGB    | Should -Be 100
        $result[0].FreeGB    | Should -Be 50
        $result[0].PctFree   | Should -Be 50
        $result[1].Drive     | Should -Be 'D:'
        $result[1].PctFree   | Should -Be 10
    }
}

# ---------------------------------------------------------------------------
# Get-SIUptime
# ---------------------------------------------------------------------------

Describe 'Get-SIUptime' {
    BeforeAll {
        $fakeBootTime = (Get-Date).AddDays(-5)
        Mock Get-CimInstance {
            [PSCustomObject]@{
                LastBootUpTime = $fakeBootTime
            }
        } -ParameterFilter { $ClassName -eq 'Win32_OperatingSystem' }
    }

    It 'returns LastBootTime and a positive Uptime TimeSpan' {
        $result = Get-SIUptime
        $result.LastBootTime           | Should -Not -BeNullOrEmpty
        $result.Uptime.TotalDays       | Should -BeGreaterThan 4
        $result.Uptime                 | Should -BeOfType [timespan]
    }
}

# ---------------------------------------------------------------------------
# Get-SIPendingReboot
# ---------------------------------------------------------------------------

Describe 'Get-SIPendingReboot' {
    Context 'CBS key exists' {
        BeforeAll {
            Mock Test-Path { $true  } -ParameterFilter { $LiteralPath -like '*RebootPending*' }
            Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*RebootRequired*' }
            Mock Get-ItemProperty { [PSCustomObject]@{ PendingFileRenameOperations = $null } }
        }

        It 'returns RebootRequired=$true and includes CBS reason' {
            $result = Get-SIPendingReboot
            $result.RebootRequired | Should -Be $true
            $result.Reasons        | Should -Contain 'CBS reboot pending'
        }
    }

    Context 'WindowsUpdate key exists' {
        BeforeAll {
            Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*RebootPending*' }
            Mock Test-Path { $true  } -ParameterFilter { $LiteralPath -like '*RebootRequired*' }
            Mock Get-ItemProperty { [PSCustomObject]@{ PendingFileRenameOperations = $null } }
        }

        It 'returns RebootRequired=$true and includes WU reason' {
            $result = Get-SIPendingReboot
            $result.RebootRequired | Should -Be $true
            $result.Reasons        | Should -Contain 'Windows Update reboot required'
        }
    }

    Context 'PendingFileRenameOperations is set' {
        BeforeAll {
            Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*RebootPending*' }
            Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*RebootRequired*' }
            Mock Get-ItemProperty { [PSCustomObject]@{ PendingFileRenameOperations = @('\??\C:\Temp\foo', '\??\C:\Temp\bar') } }
        }

        It 'returns RebootRequired=$true and includes PFRO reason' {
            $result = Get-SIPendingReboot
            $result.RebootRequired | Should -Be $true
            $result.Reasons        | Should -Contain 'PendingFileRenameOperations set'
        }
    }

    Context 'No reboot indicators present' {
        BeforeAll {
            Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*RebootPending*' }
            Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*RebootRequired*' }
            Mock Get-ItemProperty { [PSCustomObject]@{ PendingFileRenameOperations = $null } }
        }

        It 'returns RebootRequired=$false and empty Reasons' {
            $result = Get-SIPendingReboot
            $result.RebootRequired | Should -Be $false
            $result.Reasons.Count  | Should -Be 0
        }
    }
}

# ---------------------------------------------------------------------------
# Get-ServerInventory — public function
# ---------------------------------------------------------------------------

Describe 'Get-ServerInventory — unreachable host' {
    BeforeAll {
        Mock Test-Connection { $false }
    }

    It 'does not throw when a host is unreachable' {
        { Get-ServerInventory -ComputerName 'FAKE-HOST-XYZ' -OutputPath $TestDrive -Format Csv } |
            Should -Not -Throw
    }

    It 'records the host with Status Unreachable' {
        $result = @(Get-ServerInventory -ComputerName 'FAKE-HOST-XYZ' -OutputPath $TestDrive -Format Csv)
        $result.Count           | Should -Be 1
        $result[0].ComputerName | Should -Be 'FAKE-HOST-XYZ'
        $result[0].Status       | Should -Be 'Unreachable'
    }
}

Describe 'Get-ServerInventory — CSV output' {
    BeforeAll {
        Mock Test-Connection { $true }
        Mock Get-CimInstance {
            [PSCustomObject]@{ Manufacturer = 'TestCo'; Model = 'TestBox' }
        } -ParameterFilter { $ClassName -eq 'Win32_ComputerSystem' }
        Mock Get-CimInstance {
            [PSCustomObject]@{
                Caption = 'TestOS'; Version = '10.0.0'; BuildNumber = '0'
                InstallDate = [datetime]'2024-01-01'; LastBootUpTime = (Get-Date).AddDays(-1)
                TotalVisibleMemorySize = 8192 * 1024; FreePhysicalMemory = 4096 * 1024
            }
        } -ParameterFilter { $ClassName -eq 'Win32_OperatingSystem' }
        Mock Get-CimInstance {
            [PSCustomObject]@{ Name = 'TestCPU'; NumberOfCores = 4; NumberOfLogicalProcessors = 8 }
        } -ParameterFilter { $ClassName -eq 'Win32_Processor' }
        Mock Get-CimInstance {
            @([PSCustomObject]@{ DeviceID = 'C:'; Size = 107374182400; FreeSpace = 53687091200 })
        } -ParameterFilter { $ClassName -eq 'Win32_LogicalDisk' }
        Mock Test-Path { $false }
        Mock Get-ItemProperty { [PSCustomObject]@{ PendingFileRenameOperations = $null } }
    }

    It 'creates a CSV file at OutputPath when Format is Csv' {
        Get-ServerInventory -ComputerName $env:COMPUTERNAME -OutputPath $TestDrive -Format Csv |
            Out-Null

        $csvFiles = @(Get-ChildItem -Path $TestDrive -Filter '*.csv')
        $csvFiles.Count | Should -BeGreaterThan 0
    }

    It 'CSV file is parseable and contains the inventoried host' {
        $csvFiles = @(Get-ChildItem -Path $TestDrive -Filter '*.csv')
        $rows     = @(Import-Csv -LiteralPath $csvFiles[0].FullName)
        $rows.Count | Should -BeGreaterThan 0
        $rows[0].ComputerName | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-ServerInventory — HTML output' {
    BeforeAll {
        Mock Test-Connection { $true }
        Mock Get-CimInstance {
            [PSCustomObject]@{ Manufacturer = 'TestCo'; Model = 'TestBox' }
        } -ParameterFilter { $ClassName -eq 'Win32_ComputerSystem' }
        Mock Get-CimInstance {
            [PSCustomObject]@{
                Caption = 'TestOS'; Version = '10.0.0'; BuildNumber = '0'
                InstallDate = [datetime]'2024-01-01'; LastBootUpTime = (Get-Date).AddDays(-1)
                TotalVisibleMemorySize = 8192 * 1024; FreePhysicalMemory = 4096 * 1024
            }
        } -ParameterFilter { $ClassName -eq 'Win32_OperatingSystem' }
        Mock Get-CimInstance {
            [PSCustomObject]@{ Name = 'TestCPU'; NumberOfCores = 4; NumberOfLogicalProcessors = 8 }
        } -ParameterFilter { $ClassName -eq 'Win32_Processor' }
        Mock Get-CimInstance {
            @([PSCustomObject]@{ DeviceID = 'C:'; Size = 107374182400; FreeSpace = 53687091200 })
        } -ParameterFilter { $ClassName -eq 'Win32_LogicalDisk' }
        Mock Test-Path { $false }
        Mock Get-ItemProperty { [PSCustomObject]@{ PendingFileRenameOperations = $null } }
    }

    It 'creates an HTML file at OutputPath when Format is Html' {
        Get-ServerInventory -ComputerName $env:COMPUTERNAME -OutputPath $TestDrive -Format Html |
            Out-Null

        $htmlFiles = @(Get-ChildItem -Path $TestDrive -Filter '*.html')
        $htmlFiles.Count | Should -BeGreaterThan 0
    }

    It 'HTML file contains the table and summary header' {
        $htmlFiles = @(Get-ChildItem -Path $TestDrive -Filter '*.html')
        $content   = Get-Content -LiteralPath $htmlFiles[0].FullName -Raw
        $content   | Should -Match '<table'
        $content   | Should -Match 'Hosts queried'
    }

    It 'creates both CSV and HTML when Format is Both' {
        $bothDir = Join-Path $TestDrive 'both'
        New-Item -ItemType Directory -Path $bothDir -Force | Out-Null

        Get-ServerInventory -ComputerName $env:COMPUTERNAME -OutputPath $bothDir -Format Both |
            Out-Null

        $csvFiles  = @(Get-ChildItem -Path $bothDir -Filter '*.csv')
        $htmlFiles = @(Get-ChildItem -Path $bothDir -Filter '*.html')
        $csvFiles.Count  | Should -BeGreaterThan 0
        $htmlFiles.Count | Should -BeGreaterThan 0
    }
}

# ---------------------------------------------------------------------------
# Local-host detection — Test-SIIsLocalHost (and shared-helper routing)
# ---------------------------------------------------------------------------

Describe 'Test-SIIsLocalHost — private helper' {
    It "returns `$true for 'localhost'" {
        Test-SIIsLocalHost -Name 'localhost' | Should -Be $true
    }

    It "returns `$true for '.'" {
        Test-SIIsLocalHost -Name '.' | Should -Be $true
    }

    It "returns `$true for `$env:COMPUTERNAME" {
        Test-SIIsLocalHost -Name $env:COMPUTERNAME | Should -Be $true
    }

    It "returns `$true for an FQDN matching the local machine" {
        $fqdn = "$($env:COMPUTERNAME).corp.local"
        Test-SIIsLocalHost -Name $fqdn | Should -Be $true
    }

    It "returns `$false for a distinct remote host name" {
        Test-SIIsLocalHost -Name 'OTHER-SRV' | Should -Be $false
    }
}

Describe 'Get-ServerInventory — local-host detection routing' {
    # Shared mocks for all three routing tests
    BeforeAll {
        Mock Test-Connection { $true }
        Mock Get-CimInstance {
            [PSCustomObject]@{ Manufacturer = 'TestCo'; Model = 'TestBox' }
        } -ParameterFilter { $ClassName -eq 'Win32_ComputerSystem' }
        Mock Get-CimInstance {
            [PSCustomObject]@{
                Caption = 'TestOS'; Version = '10.0.0'; BuildNumber = '0'
                InstallDate = [datetime]'2024-01-01'; LastBootUpTime = (Get-Date).AddDays(-1)
                TotalVisibleMemorySize = 8192 * 1024; FreePhysicalMemory = 4096 * 1024
            }
        } -ParameterFilter { $ClassName -eq 'Win32_OperatingSystem' }
        Mock Get-CimInstance {
            [PSCustomObject]@{ Name = 'TestCPU'; NumberOfCores = 4; NumberOfLogicalProcessors = 8 }
        } -ParameterFilter { $ClassName -eq 'Win32_Processor' }
        Mock Get-CimInstance {
            @([PSCustomObject]@{ DeviceID = 'C:'; Size = 107374182400; FreeSpace = 53687091200 })
        } -ParameterFilter { $ClassName -eq 'Win32_LogicalDisk' }
        Mock Test-Path { $false }
        Mock Get-ItemProperty { [PSCustomObject]@{ PendingFileRenameOperations = $null } }
        Mock Invoke-Command { throw 'Invoke-Command must not be called for a local host' }
    }

    It "'localhost' is treated as local — reboot probe runs without Invoke-Command" {
        # Should -Not -Throw proves Invoke-Command was not called (mock throws if reached)
        { Get-ServerInventory -ComputerName 'localhost' -OutputPath $TestDrive -Format Csv } |
            Should -Not -Throw
    }

    It "FQDN of local machine is treated as local — reboot probe runs without Invoke-Command" {
        $fqdn = "$($env:COMPUTERNAME).corp.local"
        { Get-ServerInventory -ComputerName $fqdn -OutputPath $TestDrive -Format Csv } |
            Should -Not -Throw
    }

    It "a distinct remote name skips the local reboot probe — RebootRequired is null in output" {
        # Get-ServerInventory only runs the reboot probe locally; for remote hosts
        # the probe is intentionally skipped (Get-SIPendingReboot is not called),
        # so RebootRequired must be $null in the result row.
        $result = @(Get-ServerInventory -ComputerName 'OTHER-SRV' -OutputPath $TestDrive -Format Csv)
        $result[0].RebootRequired | Should -BeNullOrEmpty
    }
}
