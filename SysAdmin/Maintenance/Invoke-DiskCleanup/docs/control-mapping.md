# Control Mapping — Invoke-DiskCleanup

## NIST SP 800-53 Rev 5 — SI-12: Information Management and Retention

**Control text (summary):** The organization manages and retains information
within the system and information output from the system in accordance with
applicable laws, directives, policies, regulations, standards, and operational
requirements.

### Rationale

Temporary files, stale IIS logs, Windows error reports, and old CBS logs are
examples of system-generated output that accumulates over time. Retaining this
data beyond its useful life:

- Increases attack surface (leftover creds, tokens, or sensitive filenames in
  temp directories).
- May violate data-minimization policies if the files contain personal or
  sensitive information.
- Consumes disk space that could cause availability issues.

`Invoke-DiskCleanup` supports SI-12 by:

1. Removing temporary files from known locations on a schedule or on demand.
2. Enforcing an age threshold for log files (`-OldLogDays`) so data is
   retained only as long as operationally necessary.
3. Producing a JSON report for each run, providing an audit trail of what was
   deleted, when, and from which directories.

### Related controls

| Control     | Relationship |
|-------------|--------------|
| AU-11       | Audit record retention — logs older than policy period should be removed after archiving |
| CM-6        | Configuration settings — default targets align with CIS hardening guidance |
| SI-3        | Malware protection — removing temp files reduces attacker staging opportunities |
