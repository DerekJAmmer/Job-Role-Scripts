# Control Mapping — Backup-GPO

## NIST 800-53 Rev 5: CM-2 — Baseline Configuration

**Control statement:** Develop, document, and maintain under configuration control a current baseline configuration of the information system.

**How this script satisfies CM-2:**

`Backup-GPO` captures a point-in-time export of every Group Policy Object in the domain and stores it in a timestamped folder under `-BackupRoot`. Because GPOs define a large portion of the Windows security baseline (password policy, audit settings, software restriction, firewall rules, etc.), retaining versioned GPO backups directly fulfills the "maintain under configuration control" requirement. The `-CompareToPrevious` flag enables automated drift detection between successive snapshots, making unauthorized or accidental policy changes visible without manual review. The JSON summary (`-OutputPath`) provides a machine-readable artifact suitable for ingestion into a SIEM or compliance platform.

| CM-2 Enhancement | Coverage |
|---|---|
| CM-2(1) Reviews and Updates | Each run produces a new timestamped snapshot; scheduled execution creates an audit trail of GPO state over time. |
| CM-2(2) Automation Support | The `-OutputPath` JSON summary integrates with downstream automation (SIEM ingest, alerting on `Changed`/`Added`/`Removed` statuses). |
| CM-2(3) Retention of Previous Configurations | All prior backups are preserved under `-BackupRoot`; nothing is overwritten or deleted by this script. |
