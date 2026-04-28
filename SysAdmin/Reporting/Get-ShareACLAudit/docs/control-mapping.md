# Control Mapping — Get-ShareACLAudit

## NIST 800-53 Rev 5

### AC-3 — Access Enforcement

The system must enforce approved authorizations for accessing resources.
`Get-ShareACLAudit` supports this control by enumerating every ACL entry
that grants broad rights (`Modify`, `Write`, `FullControl`) to widely-scoped
identities (`Everyone`, `BUILTIN\Users`, etc.).  Findings give administrators
evidence to remediate grants that exceed approved authorizations.

### AC-6 — Least Privilege

Users and processes should be granted only the access rights they need.
Over-permissive share ACLs — particularly those granting write or full-control
access to domain-wide or built-in groups — violate the least-privilege
principle.  Regular output from this script can feed a periodic least-privilege
review cycle, helping teams identify and tighten unnecessary grants before they
become a security incident.

---

Both controls are addressed by the script's read-only enumeration capability.
Remediation actions (removing or tightening ACL entries) must be performed
separately and are deliberately outside the scope of this tool.
