# Lateral Movement (ATT&CK TA0008)

Scripts for detecting attacker movement between hosts — suspicious remote execution, service creation, and scheduled-task planting.

## Scripts

- **Invoke-RemoteExecHunt** — hunt 4688 parent/child anomalies (Office spawning PowerShell, services.exe → whoami), 4698 task creation events, and 7045 service install events. *(planned)*

See `SecurityAnalyst/README.md` for the full matrix.
