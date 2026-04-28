# Control Mapping — Get-BitLockerStatus

## NIST SP 800-53 Rev 5

| Control | Title                        | Script Check                                                                         |
|---------|------------------------------|--------------------------------------------------------------------------------------|
| SC-28   | Protection of Information at Rest | Verifies `ProtectionStatus=On` and `EncryptionPercentage=100` — confirms data-at-rest encryption is active and complete for all fixed volumes. |
| SC-12   | Cryptographic Key Establishment and Management | Reports `KeyProtectorTypes` (e.g. `Tpm;RecoveryPassword`) — confirms that encryption keys are protected by hardware (TPM) and that a recovery path exists. |

## CIS Windows 11 Benchmark — Section 18.9.11 (BitLocker Drive Encryption)

| CIS Control      | Description                                              | Script Check                                                           |
|------------------|----------------------------------------------------------|------------------------------------------------------------------------|
| 18.9.11.x (OS)   | Require device encryption for operating system drives    | `ProtectionStatus=On`, `EncryptionPercentage=100`, `VolumeType=OperatingSystem` |
| 18.9.11.x (Data) | Require encryption for fixed data drives                 | Same conditions applied to `VolumeType=Data` volumes                  |
| 18.9.11.x (TPM)  | Require TPM startup for BitLocker                        | `TpmPresent=true` and `TpmReady=true`                                  |
| 18.9.11.x (SB)   | Require Secure Boot for integrity validation             | `SecureBootEnabled=true`; non-UEFI machines are flagged as NonCompliant |

## Notes

- The `Reasons` field in each output row maps directly to failed checks above, enabling
  point-in-time audit evidence without manual interpretation.
- `SecureBootEnabled=$null` indicates a non-UEFI or legacy BIOS machine; such hosts are marked
  NonCompliant because UEFI + Secure Boot is a CIS and STIG requirement for BitLocker integrity.
- `Status=Unknown` rows indicate that the BitLocker module (`BitLocker` RSAT feature) is not
  installed on the target — remediation requires installing the module before posture can be
  assessed.
