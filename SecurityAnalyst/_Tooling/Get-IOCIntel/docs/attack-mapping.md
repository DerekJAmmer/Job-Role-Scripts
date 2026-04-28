# ATT&CK mapping — Get-IOCIntel

This is enrichment tooling, not a detector. It augments IOCs you already have with reputation context from public threat intel sources.

| Activity | ATT&CK | Why it maps |
|---|---|---|
| Querying threat-intel APIs for IOC reputation | T1598 (Phishing for Information) — defensive mirror | The same OSINT-style enrichment that adversaries use for recon, used here defensively to assess whether an indicator from your environment matches known-bad infrastructure. |
| Cross-referencing file hashes against AV verdicts | DS0022 (File) detection support | VirusTotal verdicts feed directly into triage decisions. |
| IP reputation lookup | DS0029 (Network Traffic) detection support | AbuseIPDB scores help prioritize active connections flagged by Invoke-IOCSweep. |

## NIST 800-53

- **SI-4** — Threat-intel enrichment is part of monitoring "for unauthorized use of the information system."
- **SI-5** — Security alerts and advisories: this is how you check whether your IOCs match known advisories.
- **IR-4** — Incident handling: enrichment is a routine first-pass step before deeper investigation.
