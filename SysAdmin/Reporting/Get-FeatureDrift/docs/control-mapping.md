# Control Mapping — Get-FeatureDrift

## NIST SP 800-53 Rev 5

### CM-2 — Baseline Configuration

**Control:** The organization develops, documents, and maintains a baseline configuration of the information system.

**Rationale:** `Get-FeatureDrift` directly operationalizes CM-2 by providing a machine-readable baseline manifest (the JSON file) and a repeatable mechanism to verify that the live system matches it. Each run produces a `Missing` list (features that should be installed but are not) and an `Extra` list (features installed outside the approved baseline), giving administrators an audit-ready record of configuration state. Running the script on a schedule closes the feedback loop between the documented baseline and the actual system.

---

### CM-8 — System Component Inventory

**Control:** The organization develops and documents an inventory of system components that accurately reflects the current system, includes all components within the authorization boundary, and is available for review.

**Rationale:** In Software mode, `Get-FeatureDrift` walks both the 64-bit and Wow6432Node Uninstall registry hives to enumerate every installed application with a DisplayName. Comparing this enumeration against a baseline manifest identifies unauthorized or unexpected software (Extra) and confirms presence of mandated tools (Missing). This supports continuous inventory accuracy required by CM-8 and feeds into asset management processes without requiring a separate inventory agent.
