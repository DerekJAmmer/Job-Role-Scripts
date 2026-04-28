# Control mapping — Invoke-ScheduledReboot

## NIST 800-53 CM-3 — Configuration Change Control

CM-3 requires organizations to document, approve, and track changes to information systems
before those changes are implemented. Scheduled reboots — even routine maintenance ones —
constitute a configuration change event: they alter system availability and may expose
or surface previously pending software updates.

`Invoke-ScheduledReboot` supports CM-3 in the following ways:

- **Change window discipline**: the `$When` parameter is enforced to be at least 5 minutes
  in the future, preventing unplanned immediate reboots and ensuring operators must declare
  an explicit change window before registering any task.
- **Audit trail via task name**: the task name `AutopilotReboot_yyyyMMdd_HHmm` is
  deterministic and human-readable. It appears in the remote host's Task Scheduler history
  and in Windows Event Log, giving auditors a searchable record of when the change was
  authorized and when it executed.
- **Pre-check gate**: the optional pre-check phase (reachability, uptime, active sessions)
  mirrors a lightweight impact assessment — a CM-3 requirement before approving changes.
- **-WhatIf support**: operators can preview the full scope of a reboot schedule without
  making any change, supporting the CM-3 review-before-approve step.
- **JSON output**: `-OutputPath` produces a machine-readable record of every host's
  outcome, suitable for attaching to a change ticket or ITSM record.

## Applicable control families

| Control | Relevance |
|---------|-----------|
| CM-3    | Configuration Change Control — primary mapping (see above). |
| AU-2    | Audit Events — Task Scheduler history provides the event record. |
| SI-2    | Flaw Remediation — scheduled reboots often complete patch application. |
