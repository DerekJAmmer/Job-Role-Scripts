#requires -Version 7.2
<#
.SYNOPSIS
    Report whether USB removable storage is restricted by policy and enumerate recent USB device history.

.DESCRIPTION
    Get-USBPolicyStatus checks three policy surfaces that control USB removable storage access:

      1. HKLM:\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies — WriteProtect value (blocks writes).
      2. HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions — DenyRemovableDevices and
         DenyDeviceClasses values (blocks installation of device classes by GUID).
      3. HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR — enumerates devices that have been connected.

    Emits one Policy row (RowType='Policy') summarising the restriction state, followed by one Device row
    (RowType='Device') per recently connected USB storage device, unless -PolicyOnly is specified.

    This script is read-only: it never writes to the registry, installs devices, or modifies event logs.

.PARAMETER MaxDevices
    Maximum number of recent USB devices to enumerate from USBSTOR. Default: 50.

.PARAMETER PolicyOnly
    When specified, only the Policy row is emitted; device history rows are suppressed.

.PARAMETER OutputPath
    When supplied, all result rows are exported as a CSV file (UTF-8, no type information).

.OUTPUTS
    PSCustomObject with properties:
      RowType              — 'Policy' or 'Device'
      FriendlyName         — device friendly name (Device rows) or $null (Policy row)
      DeviceId             — USBSTOR registry key leaf name (Device rows) or $null (Policy row)
      Service              — driver service name (Device rows) or $null (Policy row)
      LastConnected        — DateTime of last arrival, or $null if unavailable
      WriteProtect         — int value from StorageDevicePolicies (Policy row only)
      DenyRemovableDevices — int value from DeviceInstall\Restrictions (Policy row only)
      DenyDeviceClasses    — semicolon-joined GUID list from DenyDeviceClasses subkey (Policy row only)
      Status               — Restricted | Unrestricted | Unknown (Policy row); '' (Device rows)
      Reason               — explanation of Status (Policy row); '' (Device rows)

.EXAMPLE
    Get-USBPolicyStatus
    # Emit one Policy row and up to 50 Device rows.

.EXAMPLE
    Get-USBPolicyStatus -PolicyOnly
    # Emit only the Policy row; skip device history.

.EXAMPLE
    Get-USBPolicyStatus -MaxDevices 10 -OutputPath .\usb-report.csv
    # Cap device history to 10 entries and export all rows to CSV.
#>

# ---------------------------------------------------------------------------
# USB removable storage class GUIDs checked in DenyDeviceClasses.
# {53f56307-...} = Disk drives   {53f5630d-...} = Volume (removable storage)
# ---------------------------------------------------------------------------
$script:GUPSUsbStorageGuids = @(
    '{53f56307-b6bf-11d0-94f2-00a0c91efb8b}',   # Disk drives
    '{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}'    # Volume / removable storage
)

# ---------------------------------------------------------------------------
# Private helper: Get-GUPSStorageRegistry
# Reads StorageDevicePolicies\WriteProtect. Returns $null on any failure.
# ---------------------------------------------------------------------------
function Get-GUPSStorageRegistry {
    <#
    .SYNOPSIS
        Read WriteProtect from StorageDevicePolicies; return $null on missing key or error.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param()

    try {
        $val = Get-ItemPropertyValue `
            -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies' `
            -Name 'WriteProtect' `
            -ErrorAction Stop
        return $val
    }
    catch {
        Write-Verbose "Get-GUPSStorageRegistry: $($_.Exception.Message)"
        return $null
    }
}

# ---------------------------------------------------------------------------
# Private helper: Get-GUPSDeviceInstallRestriction
# Reads DeviceInstall\Restrictions and its DenyDeviceClasses subkey.
# Returns a PSCustomObject; never throws.
# ---------------------------------------------------------------------------
function Get-GUPSDeviceInstallRestriction {
    <#
    .SYNOPSIS
        Read DenyRemovableDevices and DenyDeviceClasses from DeviceInstall\Restrictions.
        Returns safe defaults on any error.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $defaultResult = [PSCustomObject]@{
        DenyRemovableDevices = $null
        DenyDeviceClasses    = @()
    }

    try {
        $rootPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'

        # If root key doesn't exist, return defaults.
        if (-not (Test-Path -LiteralPath $rootPath)) {
            return $defaultResult
        }

        # Read DenyRemovableDevices value (may not exist).
        $denyRemovable = $null
        try {
            $denyRemovable = Get-ItemPropertyValue `
                -LiteralPath $rootPath `
                -Name 'DenyRemovableDevices' `
                -ErrorAction Stop
        }
        catch {
            # Value absent — leave $null.
        }

        # Enumerate DenyDeviceClasses subkey values.
        $denyGuids = @()
        $subkeyPath = "$rootPath\DenyDeviceClasses"
        if (Test-Path -LiteralPath $subkeyPath) {
            try {
                $subkey = Get-Item -LiteralPath $subkeyPath -ErrorAction Stop
                $skipNames = @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')
                $denyGuids = @(
                    $subkey.Property |
                        Where-Object { $_ -notin $skipNames } |
                        ForEach-Object {
                            (Get-ItemPropertyValue -LiteralPath $subkeyPath -Name $_ -ErrorAction SilentlyContinue)
                        } |
                        Where-Object { $_ }
                )
            }
            catch {
                Write-Verbose "Get-GUPSDeviceInstallRestriction DenyDeviceClasses: $($_.Exception.Message)"
            }
        }

        return [PSCustomObject]@{
            DenyRemovableDevices = $denyRemovable
            DenyDeviceClasses    = $denyGuids
        }
    }
    catch {
        Write-Verbose "Get-GUPSDeviceInstallRestriction: $($_.Exception.Message)"
        return $defaultResult
    }
}

# ---------------------------------------------------------------------------
# Private helper: Get-GUPSRecentUsbDevice
# Enumerates USBSTOR device instances. Returns array; never throws.
# ---------------------------------------------------------------------------
function Get-GUPSRecentUsbDevice {
    <#
    .SYNOPSIS
        Enumerate recent USB storage devices from HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR.
        Returns an array of PSCustomObjects ordered by LastConnected descending ($null entries last).
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [int]$MaxDevices = 50
    )

    try {
        $usbStorPath = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
        if (-not (Test-Path -LiteralPath $usbStorPath)) {
            return @()
        }

        $devices = [System.Collections.Generic.List[object]]::new()

        # Each child key is a device class (e.g. Disk&Ven_SanDisk&...).
        $deviceClasses = @(Get-ChildItem -LiteralPath $usbStorPath -ErrorAction SilentlyContinue)
        foreach ($class in $deviceClasses) {
            # Each grandchild is a device instance (serial number etc.).
            $instances = @(Get-ChildItem -LiteralPath $class.PSPath -ErrorAction SilentlyContinue)
            foreach ($instance in $instances) {
                $instancePath = $instance.PSPath

                # Read FriendlyName — may be absent.
                $friendlyName = $null
                try {
                    $friendlyName = Get-ItemPropertyValue `
                        -LiteralPath $instancePath `
                        -Name 'FriendlyName' `
                        -ErrorAction Stop
                }
                catch { }

                # Read Service driver name — may be absent.
                $service = $null
                try {
                    $service = Get-ItemPropertyValue `
                        -LiteralPath $instancePath `
                        -Name 'Service' `
                        -ErrorAction Stop
                }
                catch { }

                # Read last-connected timestamp from well-known property GUID.
                $lastConnected = $null
                try {
                    $tsPropPath = "$instancePath\Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0064"
                    $rawTs = Get-ItemProperty `
                        -Path $tsPropPath `
                        -Name '(default)' `
                        -ErrorAction Stop
                    if ($null -ne $rawTs.'(default)') {
                        $lastConnected = [datetime]$rawTs.'(default)'
                    }
                }
                catch { }

                $devices.Add([PSCustomObject]@{
                    FriendlyName  = $friendlyName
                    DeviceId      = $instance.PSChildName
                    Service       = $service
                    LastConnected = $lastConnected
                })
            }
        }

        # Sort: dated entries newest-first, $null LastConnected entries last.
        $sorted = @(
            @($devices | Where-Object { $null -ne $_.LastConnected } |
                Sort-Object -Property LastConnected -Descending) +
            @($devices | Where-Object { $null -eq $_.LastConnected })
        )

        # Cap to MaxDevices.
        if ($sorted.Count -gt $MaxDevices) {
            $sorted = $sorted[0..($MaxDevices - 1)]
        }

        return $sorted
    }
    catch {
        Write-Verbose "Get-GUPSRecentUsbDevice: $($_.Exception.Message)"
        return @()
    }
}

# ---------------------------------------------------------------------------
# Public function: Get-USBPolicyStatus
# ---------------------------------------------------------------------------
function Get-USBPolicyStatus {
    <#
    .SYNOPSIS
        Report USB removable storage policy restriction status and recent device history.

    .DESCRIPTION
        Checks StorageDevicePolicies, DeviceInstall restrictions, and the USBSTOR registry hive
        to produce a Policy row summarising USB restriction posture, plus optional Device rows for
        recently connected USB storage devices.

        Read-only — does not write to the registry, install devices, or modify event logs.

    .PARAMETER MaxDevices
        Maximum number of recent USB devices to enumerate. Default: 50.

    .PARAMETER PolicyOnly
        Suppress device history rows; emit only the Policy row.

    .PARAMETER OutputPath
        Optional CSV export path (UTF-8, no type information).

    .EXAMPLE
        Get-USBPolicyStatus

    .EXAMPLE
        Get-USBPolicyStatus -PolicyOnly -OutputPath .\usb-policy.csv
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$MaxDevices = 50,

        [Parameter()]
        [switch]$PolicyOnly,

        [Parameter()]
        [string]$OutputPath
    )

    $results = [System.Collections.Generic.List[object]]::new()

    # ------------------------------------------------------------------
    # Collect data from all three helpers (each handles exceptions internally).
    # ------------------------------------------------------------------
    $writeProtect    = Get-GUPSStorageRegistry
    $installRestrict = Get-GUPSDeviceInstallRestriction
    $recentDevices   = if (-not $PolicyOnly) {
        Get-GUPSRecentUsbDevice -MaxDevices $MaxDevices
    }
    else {
        @()
    }

    # ------------------------------------------------------------------
    # Compute Policy row Status and Reason.
    # ------------------------------------------------------------------
    $reasonParts = [System.Collections.Generic.List[string]]::new()

    $writeProtectRestricted    = ($null -ne $writeProtect) -and ($writeProtect -eq 1)
    $denyRemovableRestricted   = ($null -ne $installRestrict.DenyRemovableDevices) -and
                                 ($installRestrict.DenyRemovableDevices -eq 1)

    if ($writeProtectRestricted) {
        $reasonParts.Add('WriteProtect=1 (writes blocked)')
    }
    if ($denyRemovableRestricted) {
        $reasonParts.Add('DenyRemovableDevices=1')
    }

    # Check DenyDeviceClasses for USB storage GUIDs (case-insensitive).
    $matchedGuids = @(
        $installRestrict.DenyDeviceClasses | Where-Object {
            $lower = $_.ToLower()
            $script:GUPSUsbStorageGuids | Where-Object { $_.ToLower() -eq $lower }
        }
    )
    foreach ($guid in $matchedGuids) {
        $reasonParts.Add("DenyDeviceClasses contains $guid")
    }

    # Determine overall Status.
    $status = if ($reasonParts.Count -gt 0) {
        'Restricted'
    }
    elseif ($null -eq $writeProtect -and $null -eq $installRestrict.DenyRemovableDevices -and
            $installRestrict.DenyDeviceClasses.Count -eq 0) {
        # Distinguish between "all helpers failed with exceptions" vs "keys present but permissive".
        # If both registry reads returned $null AND DenyDeviceClasses is empty, we can't tell.
        # Use Unknown only when StorageDevicePolicies key itself is also inaccessible.
        $storagePolicyExists = Test-Path `
            -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies' `
            -ErrorAction SilentlyContinue
        if (-not $storagePolicyExists -and $null -eq $installRestrict.DenyRemovableDevices) {
            'Unknown'
        }
        else {
            'Unrestricted'
        }
    }
    else {
        'Unrestricted'
    }

    $reason = if ($reasonParts.Count -gt 0) {
        $reasonParts -join '; '
    }
    elseif ($status -eq 'Unknown') {
        'Unable to read policy keys'
    }
    else {
        ''
    }

    # ------------------------------------------------------------------
    # Emit Policy row.
    # ------------------------------------------------------------------
    $policyRow = [PSCustomObject]@{
        RowType              = 'Policy'
        FriendlyName         = $null
        DeviceId             = $null
        Service              = $null
        LastConnected        = $null
        WriteProtect         = $writeProtect
        DenyRemovableDevices = $installRestrict.DenyRemovableDevices
        DenyDeviceClasses    = if ($installRestrict.DenyDeviceClasses.Count -gt 0) {
            $installRestrict.DenyDeviceClasses -join ';'
        }
        else {
            ''
        }
        Status               = $status
        Reason               = $reason
    }
    $results.Add($policyRow)
    Write-Output $policyRow

    # ------------------------------------------------------------------
    # Emit Device rows (unless -PolicyOnly).
    # ------------------------------------------------------------------
    if (-not $PolicyOnly) {
        foreach ($dev in $recentDevices) {
            $deviceRow = [PSCustomObject]@{
                RowType              = 'Device'
                FriendlyName         = $dev.FriendlyName
                DeviceId             = $dev.DeviceId
                Service              = $dev.Service
                LastConnected        = $dev.LastConnected
                WriteProtect         = $null
                DenyRemovableDevices = $null
                DenyDeviceClasses    = $null
                Status               = ''
                Reason               = ''
            }
            $results.Add($deviceRow)
            Write-Output $deviceRow
        }
    }

    # ------------------------------------------------------------------
    # Optional CSV export.
    # ------------------------------------------------------------------
    if ($OutputPath) {
        $results | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Verbose "Results exported to: $OutputPath"
    }
}
