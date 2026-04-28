# Control Mapping — Get-USBPolicyStatus

## MITRE ATT&CK

| Technique | ID | How this script relates |
|-----------|----|------------------------|
| Replication Through Removable Media | T1091 | Adversaries copy malware to/from USB drives to propagate through air-gapped or segmented networks. Detecting the absence of USB restrictions reveals whether this vector is open. |
| Exfiltration Over Physical Medium — USB | T1052.001 | Data can be silently copied to a USB drive and removed from the premises. WriteProtect and DenyRemovableDevices controls directly mitigate this tactic; this script reports their state. |

## NIST SP 800-53

| Control | Title | Mapping |
|---------|-------|---------|
| AC-19 | Access Control for Mobile Devices | Requires organisations to establish usage restrictions and implementation guidance for mobile devices (including removable media). WriteProtect and device-install restrictions are direct AC-19 controls. |
| MP-7 | Media Use | Restricts the use of removable storage on systems based on organisational policy. DenyRemovableDevices and DenyDeviceClasses GPO settings implement MP-7. USBSTOR history provides evidence of past media use for audit purposes. |

## CIS Windows 11 Benchmark

| CIS Section | Recommendation | Registry check |
|-------------|---------------|----------------|
| 18.9.x | Prevent installation of removable devices | `DenyRemovableDevices` under `DeviceInstall\Restrictions` |
| 18.9.x | Prevent installation of devices using drivers that match device setup class GUIDs | `DenyDeviceClasses` subkey with USB storage class GUIDs |

CIS section numbers within 18.9 vary by benchmark version; consult the current CIS Windows 11
Benchmark PDF for exact numbering.

## Summary

| Check performed | Controls addressed |
|----------------|-------------------|
| `WriteProtect=1` in StorageDevicePolicies | T1052.001, MP-7 |
| `DenyRemovableDevices=1` in DeviceInstall\Restrictions | T1091, T1052.001, AC-19, MP-7, CIS 18.9.x |
| USB storage GUIDs in DenyDeviceClasses | T1091, T1052.001, AC-19, MP-7, CIS 18.9.x |
| USBSTOR device enumeration (history) | T1091, T1052.001 — evidence of past media use |
