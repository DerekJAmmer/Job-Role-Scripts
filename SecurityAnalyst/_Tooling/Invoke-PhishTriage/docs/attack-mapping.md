# ATT&CK mapping — Invoke-PhishTriage

This script supports analyst triage of phishing reports — the front door for most intrusions.

| Activity | ATT&CK | Why it maps |
|---|---|---|
| Suspicious sender domain analysis | T1566 (Phishing) | Identifies the social-engineering vector before clicks happen. |
| Spearphishing attachment hashing + executable extension flags | T1566.001 (Spearphishing Attachment) | Surfaces malicious payloads (docm/xlsm/iso) for IOC enrichment via Get-IOCIntel. |
| URL extraction + shortener detection | T1566.002 (Spearphishing Link) | Shorteners hide destination domains; flagging them is the first defense. |
| SPF / DKIM / DMARC verdict surfacing | T1656 (Impersonation) defensive mirror | Auth failure is the strongest single signal of a spoof. |

## NIST 800-53

- **SI-3** — Malicious code protection: triaging emails before delivery to the user is part of layered AV defense.
- **SI-4** — Information system monitoring: phishing reports feed the monitoring loop.
- **IR-4** — Incident handling: phishing triage is one of the most common incident-response workflows.
