# Control Mapping — Get-PendingReboot

## NIST SP 800-53 Rev 5

### CM-3 — Configuration Change Control

**Rationale:** CM-3 requires that organizations identify, document, and review changes to information systems before implementation. A pending reboot often represents a staged but not yet applied change — a patch, a software install, a computer rename, or a CBS component update. Running `Get-PendingReboot` before and after change windows lets administrators confirm that staged changes have been properly applied (reboot completed) or flag hosts that are still awaiting a reboot before the change can take effect. This supports the CM-3 requirement to track and verify configuration changes across managed systems.

**Specific control statements addressed:**

- **CM-3a** — Determine the types of changes to the system that are configuration-controlled. Pending reboots signal that a configuration-controlled change (patch, software install, rename) is in a staged-but-incomplete state.
- **CM-3b** — Review proposed configuration-controlled changes and approve or disapprove. Knowing which hosts have pending reboots informs approval decisions for maintenance windows.
- **CM-3f** — Coordinate and provide oversight for configuration change control activities. Reboot status reporting provides the visibility needed for change coordinators to confirm that changes have landed across the fleet.
