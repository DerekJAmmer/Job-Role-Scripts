#requires -Version 7.2

BeforeAll {
    . (Join-Path $PSScriptRoot 'Get-USBPolicyStatus.ps1')
}

# ===========================================================================
# T1: WriteProtect=1 → Restricted, Reason contains WriteProtect=1
# ===========================================================================
Describe 'Get-USBPolicyStatus — WriteProtect=1 restricts' {
    BeforeAll {
        Mock Get-GUPSStorageRegistry { 1 }
        Mock Get-GUPSDeviceInstallRestriction {
            [PSCustomObject]@{ DenyRemovableDevices = $null; DenyDeviceClasses = @() }
        }
        Mock Get-GUPSRecentUsbDevice { @() }
    }

    It 'Status is Restricted when WriteProtect=1' {
        $rows = @(Get-USBPolicyStatus -PolicyOnly)
        $policy = $rows | Where-Object { $_.RowType -eq 'Policy' }
        $policy.Status | Should -Be 'Restricted'
    }

    It 'Reason contains WriteProtect=1 text' {
        $rows = @(Get-USBPolicyStatus -PolicyOnly)
        $policy = $rows | Where-Object { $_.RowType -eq 'Policy' }
        $policy.Reason | Should -BeLike '*WriteProtect=1*'
    }
}

# ===========================================================================
# T2: DenyRemovableDevices=1 → Restricted
# ===========================================================================
Describe 'Get-USBPolicyStatus — DenyRemovableDevices=1 restricts' {
    BeforeAll {
        Mock Get-GUPSStorageRegistry { 0 }
        Mock Get-GUPSDeviceInstallRestriction {
            [PSCustomObject]@{ DenyRemovableDevices = 1; DenyDeviceClasses = @() }
        }
        Mock Get-GUPSRecentUsbDevice { @() }
    }

    It 'Status is Restricted when DenyRemovableDevices=1' {
        $rows = @(Get-USBPolicyStatus -PolicyOnly)
        $policy = $rows | Where-Object { $_.RowType -eq 'Policy' }
        $policy.Status | Should -Be 'Restricted'
    }

    It 'Reason contains DenyRemovableDevices=1 text' {
        $rows = @(Get-USBPolicyStatus -PolicyOnly)
        $policy = $rows | Where-Object { $_.RowType -eq 'Policy' }
        $policy.Reason | Should -BeLike '*DenyRemovableDevices=1*'
    }
}

# ===========================================================================
# T3: DenyDeviceClasses contains USB storage GUID → Restricted, Reason cites GUID
# ===========================================================================
Describe 'Get-USBPolicyStatus — DenyDeviceClasses USB GUID restricts' {
    BeforeAll {
        Mock Get-GUPSStorageRegistry { 0 }
        Mock Get-GUPSDeviceInstallRestriction {
            [PSCustomObject]@{
                DenyRemovableDevices = $null
                DenyDeviceClasses    = @('{53f56307-b6bf-11d0-94f2-00a0c91efb8b}')
            }
        }
        Mock Get-GUPSRecentUsbDevice { @() }
    }

    It 'Status is Restricted when DenyDeviceClasses contains USB disk GUID' {
        $rows = @(Get-USBPolicyStatus -PolicyOnly)
        $policy = $rows | Where-Object { $_.RowType -eq 'Policy' }
        $policy.Status | Should -Be 'Restricted'
    }

    It 'Reason cites the matched GUID' {
        $rows = @(Get-USBPolicyStatus -PolicyOnly)
        $policy = $rows | Where-Object { $_.RowType -eq 'Policy' }
        $policy.Reason | Should -BeLike '*53f56307*'
    }
}

# ===========================================================================
# T4: WriteProtect=0, no install restrictions → Unrestricted
# ===========================================================================
Describe 'Get-USBPolicyStatus — permissive policy is Unrestricted' {
    BeforeAll {
        Mock Get-GUPSStorageRegistry { 0 }
        Mock Get-GUPSDeviceInstallRestriction {
            [PSCustomObject]@{ DenyRemovableDevices = $null; DenyDeviceClasses = @() }
        }
        Mock Get-GUPSRecentUsbDevice { @() }
    }

    It 'Status is Unrestricted when WriteProtect=0 and no other restrictions' {
        $rows = @(Get-USBPolicyStatus -PolicyOnly)
        $policy = $rows | Where-Object { $_.RowType -eq 'Policy' }
        $policy.Status | Should -Be 'Unrestricted'
    }
}

# ===========================================================================
# T5: All helpers return $null/empty → Status=Unknown, Reason contains 'Unable to read'
# ===========================================================================
Describe 'Get-USBPolicyStatus — all helpers fail → Unknown' {
    BeforeAll {
        Mock Get-GUPSStorageRegistry { $null }
        Mock Get-GUPSDeviceInstallRestriction {
            [PSCustomObject]@{ DenyRemovableDevices = $null; DenyDeviceClasses = @() }
        }
        Mock Get-GUPSRecentUsbDevice { @() }
        # Ensure the registry path check also returns false.
        Mock Test-Path { $false }
    }

    It 'Status is Unknown when all policy reads fail' {
        $rows = @(Get-USBPolicyStatus -PolicyOnly)
        $policy = $rows | Where-Object { $_.RowType -eq 'Policy' }
        $policy.Status | Should -Be 'Unknown'
    }

    It 'Reason contains Unable to read text' {
        $rows = @(Get-USBPolicyStatus -PolicyOnly)
        $policy = $rows | Where-Object { $_.RowType -eq 'Policy' }
        $policy.Reason | Should -BeLike '*Unable to read*'
    }
}

# ===========================================================================
# T6: USBSTOR empty → no Device rows, Policy row still emitted
# ===========================================================================
Describe 'Get-USBPolicyStatus — empty USBSTOR still emits Policy row' {
    BeforeAll {
        Mock Get-GUPSStorageRegistry { 0 }
        Mock Get-GUPSDeviceInstallRestriction {
            [PSCustomObject]@{ DenyRemovableDevices = $null; DenyDeviceClasses = @() }
        }
        Mock Get-GUPSRecentUsbDevice { @() }
    }

    It 'emits exactly 1 row (Policy) when USBSTOR returns no devices' {
        $rows = @(Get-USBPolicyStatus)
        $rows.Count | Should -Be 1
    }

    It 'the single row is RowType=Policy' {
        $rows = @(Get-USBPolicyStatus)
        $rows[0].RowType | Should -Be 'Policy'
    }
}

# ===========================================================================
# T7: USBSTOR populated with 3 devices → 3 Device rows + 1 Policy row = 4 total, newest-first
# ===========================================================================
Describe 'Get-USBPolicyStatus — 3 devices emits 4 rows ordered newest-first' {
    BeforeAll {
        Mock Get-GUPSStorageRegistry { 0 }
        Mock Get-GUPSDeviceInstallRestriction {
            [PSCustomObject]@{ DenyRemovableDevices = $null; DenyDeviceClasses = @() }
        }
        Mock Get-GUPSRecentUsbDevice {
            @(
                [PSCustomObject]@{
                    FriendlyName  = 'SanDisk USB Drive'
                    DeviceId      = 'Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\0000001'
                    Service       = 'disk'
                    LastConnected = [datetime]::Parse('2026-04-15T10:00:00')
                },
                [PSCustomObject]@{
                    FriendlyName  = 'Kingston DataTraveler'
                    DeviceId      = 'Disk&Ven_Kingston&Prod_DT50&Rev_1.00\0000002'
                    Service       = 'disk'
                    LastConnected = [datetime]::Parse('2026-04-10T08:00:00')
                },
                [PSCustomObject]@{
                    FriendlyName  = 'Generic USB Drive'
                    DeviceId      = 'Disk&Ven_Generic&Prod_Flash&Rev_1.00\0000003'
                    Service       = 'disk'
                    LastConnected = [datetime]::Parse('2026-04-01T06:00:00')
                }
            )
        }
    }

    It 'emits 4 total rows (1 Policy + 3 Device)' {
        $rows = @(Get-USBPolicyStatus)
        $rows.Count | Should -Be 4
    }

    It 'first row is RowType=Policy' {
        $rows = @(Get-USBPolicyStatus)
        $rows[0].RowType | Should -Be 'Policy'
    }

    It 'remaining 3 rows are RowType=Device' {
        $rows = @(Get-USBPolicyStatus)
        $deviceRows = @($rows | Where-Object { $_.RowType -eq 'Device' })
        $deviceRows.Count | Should -Be 3
    }

    It 'Device rows are ordered newest LastConnected first' {
        $rows = @(Get-USBPolicyStatus)
        $deviceRows = @($rows | Where-Object { $_.RowType -eq 'Device' })
        $deviceRows[0].LastConnected | Should -BeGreaterThan $deviceRows[1].LastConnected
        $deviceRows[1].LastConnected | Should -BeGreaterThan $deviceRows[2].LastConnected
    }
}

# ===========================================================================
# T8: -PolicyOnly suppresses Device rows
# ===========================================================================
Describe 'Get-USBPolicyStatus — -PolicyOnly suppresses Device rows' {
    BeforeAll {
        Mock Get-GUPSStorageRegistry { 1 }
        Mock Get-GUPSDeviceInstallRestriction {
            [PSCustomObject]@{ DenyRemovableDevices = $null; DenyDeviceClasses = @() }
        }
        Mock Get-GUPSRecentUsbDevice {
            @(
                [PSCustomObject]@{
                    FriendlyName  = 'SanDisk USB Drive'
                    DeviceId      = 'Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\0000001'
                    Service       = 'disk'
                    LastConnected = [datetime]::Parse('2026-04-15T10:00:00')
                }
            )
        }
    }

    It 'only 1 row is emitted when -PolicyOnly is set' {
        $rows = @(Get-USBPolicyStatus -PolicyOnly)
        $rows.Count | Should -Be 1
    }

    It 'the single row is RowType=Policy when -PolicyOnly is set' {
        $rows = @(Get-USBPolicyStatus -PolicyOnly)
        $rows[0].RowType | Should -Be 'Policy'
    }
}

# ===========================================================================
# T9: -MaxDevices is forwarded to the helper
# ===========================================================================
Describe 'Get-USBPolicyStatus — -MaxDevices forwarded to helper' {
    BeforeAll {
        Mock Get-GUPSStorageRegistry { 0 }
        Mock Get-GUPSDeviceInstallRestriction {
            [PSCustomObject]@{ DenyRemovableDevices = $null; DenyDeviceClasses = @() }
        }
        Mock Get-GUPSRecentUsbDevice { @() }
    }

    It 'passes -MaxDevices 5 to Get-GUPSRecentUsbDevice' {
        Get-USBPolicyStatus -MaxDevices 5 | Out-Null
        Should -Invoke Get-GUPSRecentUsbDevice -Times 1 -ParameterFilter {
            $MaxDevices -eq 5
        }
    }
}

# ===========================================================================
# T10: CSV roundtrip contains both RowType values
# ===========================================================================
Describe 'Get-USBPolicyStatus — CSV roundtrip contains both RowType values' {
    BeforeAll {
        Mock Get-GUPSStorageRegistry { 1 }
        Mock Get-GUPSDeviceInstallRestriction {
            [PSCustomObject]@{ DenyRemovableDevices = $null; DenyDeviceClasses = @() }
        }
        Mock Get-GUPSRecentUsbDevice {
            @(
                [PSCustomObject]@{
                    FriendlyName  = 'SanDisk USB Drive'
                    DeviceId      = 'Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\0000001'
                    Service       = 'disk'
                    LastConnected = [datetime]::Parse('2026-04-15T10:00:00')
                }
            )
        }
    }

    It 'CSV file is created at OutputPath' {
        $csvPath = Join-Path $TestDrive 'usb-report.csv'
        Get-USBPolicyStatus -OutputPath $csvPath | Out-Null
        Test-Path -LiteralPath $csvPath | Should -Be $true
    }

    It 'CSV contains a Policy row' {
        $csvPath = Join-Path $TestDrive 'usb-policy-row.csv'
        Get-USBPolicyStatus -OutputPath $csvPath | Out-Null
        $rows = Import-Csv -LiteralPath $csvPath
        ($rows | Where-Object { $_.RowType -eq 'Policy' }) | Should -Not -BeNullOrEmpty
    }

    It 'CSV contains a Device row' {
        $csvPath = Join-Path $TestDrive 'usb-device-row.csv'
        Get-USBPolicyStatus -OutputPath $csvPath | Out-Null
        $rows = Import-Csv -LiteralPath $csvPath
        ($rows | Where-Object { $_.RowType -eq 'Device' }) | Should -Not -BeNullOrEmpty
    }
}

# ===========================================================================
# T11: Policy row has policy columns; Device rows have device columns populated
# ===========================================================================
Describe 'Get-USBPolicyStatus — column population per RowType' {
    BeforeAll {
        Mock Get-GUPSStorageRegistry { 1 }
        Mock Get-GUPSDeviceInstallRestriction {
            [PSCustomObject]@{ DenyRemovableDevices = 1; DenyDeviceClasses = @() }
        }
        Mock Get-GUPSRecentUsbDevice {
            @(
                [PSCustomObject]@{
                    FriendlyName  = 'Test USB'
                    DeviceId      = 'Disk&Ven_Test&Prod_USB&Rev_1.00\0000001'
                    Service       = 'disk'
                    LastConnected = [datetime]::Parse('2026-04-15T10:00:00')
                }
            )
        }
    }

    It 'Policy row has WriteProtect populated' {
        $rows = @(Get-USBPolicyStatus)
        $policy = $rows | Where-Object { $_.RowType -eq 'Policy' }
        $policy.WriteProtect | Should -Be 1
    }

    It 'Policy row has DenyRemovableDevices populated' {
        $rows = @(Get-USBPolicyStatus)
        $policy = $rows | Where-Object { $_.RowType -eq 'Policy' }
        $policy.DenyRemovableDevices | Should -Be 1
    }

    It 'Device row has FriendlyName populated' {
        $rows = @(Get-USBPolicyStatus)
        $device = $rows | Where-Object { $_.RowType -eq 'Device' }
        $device.FriendlyName | Should -Be 'Test USB'
    }

    It 'Device row has DeviceId populated' {
        $rows = @(Get-USBPolicyStatus)
        $device = $rows | Where-Object { $_.RowType -eq 'Device' }
        $device.DeviceId | Should -Not -BeNullOrEmpty
    }

    It 'Device row has WriteProtect as null' {
        $rows = @(Get-USBPolicyStatus)
        $device = $rows | Where-Object { $_.RowType -eq 'Device' }
        $device.WriteProtect | Should -BeNullOrEmpty
    }
}

# ===========================================================================
# T12: Devices with $null LastConnected sort to the end
# ===========================================================================
Describe 'Get-USBPolicyStatus — null LastConnected sorts last' {
    BeforeAll {
        Mock Get-GUPSStorageRegistry { 0 }
        Mock Get-GUPSDeviceInstallRestriction {
            [PSCustomObject]@{ DenyRemovableDevices = $null; DenyDeviceClasses = @() }
        }
        # Mock returns devices already in the order the real helper would produce:
        # dated entries first (newest-first), $null LastConnected entries last.
        Mock Get-GUPSRecentUsbDevice {
            @(
                [PSCustomObject]@{
                    FriendlyName  = 'Dated Device'
                    DeviceId      = 'DatedDevice'
                    Service       = 'disk'
                    LastConnected = [datetime]::Parse('2026-04-15T10:00:00')
                },
                [PSCustomObject]@{
                    FriendlyName  = 'Null Date Device'
                    DeviceId      = 'NullDevice'
                    Service       = 'disk'
                    LastConnected = $null
                }
            )
        }
    }

    It 'device with $null LastConnected appears after device with a timestamp' {
        $rows = @(Get-USBPolicyStatus)
        $deviceRows = @($rows | Where-Object { $_.RowType -eq 'Device' })
        $deviceRows[0].DeviceId | Should -Be 'DatedDevice'
        $deviceRows[1].DeviceId | Should -Be 'NullDevice'
    }
}

# ===========================================================================
# T13: WriteProtect=1 AND DenyRemovableDevices=1 → combined Reason
# ===========================================================================
Describe 'Get-USBPolicyStatus — multiple restriction signals combine in Reason' {
    BeforeAll {
        Mock Get-GUPSStorageRegistry { 1 }
        Mock Get-GUPSDeviceInstallRestriction {
            [PSCustomObject]@{ DenyRemovableDevices = 1; DenyDeviceClasses = @() }
        }
        Mock Get-GUPSRecentUsbDevice { @() }
    }

    It 'Status is Restricted when both WriteProtect=1 and DenyRemovableDevices=1' {
        $rows = @(Get-USBPolicyStatus -PolicyOnly)
        $policy = $rows | Where-Object { $_.RowType -eq 'Policy' }
        $policy.Status | Should -Be 'Restricted'
    }

    It 'Reason contains WriteProtect=1 portion' {
        $rows = @(Get-USBPolicyStatus -PolicyOnly)
        $policy = $rows | Where-Object { $_.RowType -eq 'Policy' }
        $policy.Reason | Should -BeLike '*WriteProtect=1*'
    }

    It 'Reason contains DenyRemovableDevices=1 portion' {
        $rows = @(Get-USBPolicyStatus -PolicyOnly)
        $policy = $rows | Where-Object { $_.RowType -eq 'Policy' }
        $policy.Reason | Should -BeLike '*DenyRemovableDevices=1*'
    }

    It 'Reason joins both messages with a semicolon separator' {
        $rows = @(Get-USBPolicyStatus -PolicyOnly)
        $policy = $rows | Where-Object { $_.RowType -eq 'Policy' }
        $policy.Reason | Should -BeLike '*;*'
    }
}
