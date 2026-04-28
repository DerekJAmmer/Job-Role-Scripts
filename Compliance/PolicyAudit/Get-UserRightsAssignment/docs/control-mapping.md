# Control Mapping — Get-UserRightsAssignment

Maps each covered Windows privilege right to the relevant CIS Windows 11 section (2.2.x)
and NIST SP 800-53 controls (AC-3 Access Enforcement, AC-6 Least Privilege).

---

## NIST SP 800-53 Controls

| Control | Name              | Relevance |
|---------|-------------------|-----------|
| AC-3    | Access Enforcement | Ensures access to resources is enforced in accordance with applicable policy. User-rights assignments directly implement OS-level access enforcement. |
| AC-6    | Least Privilege    | Requires that subjects are granted only the access required to perform their functions. Auditing user-rights assignments verifies that privileges are not over-granted. |

---

## Privilege-to-CIS and NIST Mapping

| Privilege | CIS 2.2.x Section | NIST Controls | Notes |
|-----------|-------------------|---------------|-------|
| `SeDebugPrivilege` | 2.2.11 | AC-3, AC-6 | Debug programs — should be restricted to Administrators only. Attackers use this to inject into LSASS. |
| `SeBackupPrivilege` | 2.2.5 | AC-3, AC-6 | Back up files and directories — grants ability to read any file regardless of ACL. |
| `SeRestorePrivilege` | 2.2.38 | AC-3, AC-6 | Restore files and directories — grants ability to write any file regardless of ACL. |
| `SeRemoteShutdownPrivilege` | 2.2.34 | AC-6 | Force shutdown from a remote system — limit to Administrators. |
| `SeAssignPrimaryTokenPrivilege` | 2.2.4 | AC-3, AC-6 | Replace a process-level token — service accounts only (LOCAL SERVICE, NETWORK SERVICE). |
| `SeImpersonatePrivilege` | 2.2.29 | AC-3, AC-6 | Impersonate a client after authentication — Administrators and service identities only. Potato-family exploits abuse this right. |
| `SeLoadDriverPrivilege` | 2.2.31 | AC-3, AC-6 | Load and unload device drivers — must be restricted to Administrators to prevent unsigned driver loading. |
| `SeShutdownPrivilege` | 2.2.39 | AC-6 | Shut down the system — Administrators and Users on workstations; Administrators only on servers per CIS Server benchmark. |
| `SeTakeOwnershipPrivilege` | 2.2.44 | AC-3, AC-6 | Take ownership of files or other objects — Administrators only; over-granting allows data exfiltration. |
| `SeManageVolumePrivilege` | 2.2.32 | AC-3, AC-6 | Perform volume maintenance tasks — Administrators only; misuse can expose unallocated disk data. |

---

## References

- CIS Microsoft Windows 11 Benchmark v3.0, Section 2.2 (User Rights Assignment)
- NIST SP 800-53 Rev 5, AC-3 (Access Enforcement), AC-6 (Least Privilege)
- MITRE ATT&CK: T1134 (Access Token Manipulation), T1068 (Exploitation for Privilege Escalation)
