# Control Mapping — Get-SoftwareInventoryCVE

## NIST SP 800-53 Rev 5

### SI-5 — Security Alerts, Advisories, and Directives
This tool automates the consumption of NVD vulnerability advisories for all
installed software on a host. By querying CVE data per package and recording
CVSS scores, it gives security teams a machine-readable view of which
advisories are relevant to their environment — directly supporting the SI-5
requirement to receive and act on security alerts.

### RA-5 — Vulnerability Scanning
Enumerating installed software and correlating each package against the NVD
CVE database is a lightweight form of vulnerability scanning that does not
require a credentialed scanner. The CSV output can feed into risk registers,
patch management workflows, or SIEM ingestion pipelines, satisfying RA-5's
requirement to scan for vulnerabilities in systems and hosted applications.

## CIS Controls for Windows 11

### CIS Control 2.3 — Ensure Software Inventory Is Current
Collecting the installed software list (via winget or the registry) and
exporting it to a dated CSV satisfies the CIS requirement to maintain an
accurate, up-to-date software inventory. Repeating the scan on a schedule
(e.g., via Task Scheduler) keeps the inventory current per CIS guidance.

## Mapping Summary

| Control | Family | How This Tool Helps |
|---|---|---|
| SI-5 | System & Info Integrity | Pulls NVD advisories per installed package; CSV surfaces actionable CVEs |
| RA-5 | Risk Assessment | Provides CVE IDs and CVSS scores for patch prioritisation |
| CIS 2.3 | Software Inventory | Exports timestamped software inventory from winget or registry |
