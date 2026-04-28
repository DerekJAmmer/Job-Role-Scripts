# Windows Useful Scripts — Portfolio Plan

## What this is

A collection of Windows-focused scripts built around the roles I'm targeting: Security Analyst, Sysadmin, Cloud Admin, etc. The goal is practical, working scripts — not demos. Each one does something I'd actually use on the job.

Scripts map to frameworks (CIS, NIST, MITRE ATT&CK, DISA STIG) where it makes sense, but that's secondary to them actually working.

### How it's organized

- One folder per role (e.g. `/SecurityAnalyst/`, `/SysAdmin/`)
- Shared utilities in `/Common/`
- Language picks: PowerShell 7+ for anything Windows/AD/Azure; Python for parsing, cross-platform, and network/security tooling; Batch only when PowerShell isn't available
- Each script comes with a README, usage examples, and a test file (Pester or pytest)
- Destructive actions need `-WhatIf` or `--dry-run` to do anything
- No creds in source — use env vars or `SecretManagement`

Difficulty: 🟢 easy  🟡 medium  🔴 hard

---

## Role 1 — Windows System Administrator
**Language: PowerShell**

1. 🟢 **Bulk AD user provisioning from CSV** — create/update/disable users, set OU, group membership, licenses
2. 🟢 **Server inventory report** — CPU/RAM/disk/OS/uptime/pending-reboot, HTML + CSV across a server list
3. 🟡 **Scheduled reboot orchestrator** — batched maintenance-window reboots with pre-checks and post-reboot validation
4. 🟡 **Stale AD object cleaner** — users/computers with no logon in N days, stage to disabled OU, report before delete
5. 🟡 **GPO backup + diff tool** — export all GPOs, compare to last snapshot, flag changes
6. 🟡 **DFS / file-share permission auditor** — recursive ACL export, find "Everyone" / Domain Users grants
7. 🔴 **AD health check suite** — replication, FSMO roles, SYSVOL, DNS SRV, Kerberos — dashboard output
8. 🟡 **Windows Update compliance reporter** — WSUS/Intune/WUfB query, missing-patch CSV, email digest
9. 🟢 **Disk-cleanup automation** — temp/log/IIS-log/WinSxS cleanup with threshold triggers
10. 🔴 **Service dependency mapper** — walk service dependencies and startup failures; generate restart runbooks

---

## Role 2 — Windows Server Administrator
**Language: PowerShell** (IIS, DNS, DHCP, Hyper-V, Failover Clustering)

1. 🟡 **IIS site inventory & hardening check** — bindings, TLS versions, security headers, anonymous auth (CIS-aligned)
2. 🟡 **DNS/DHCP scope audit & backup** — export scopes/records, flag exhaustion, versioned backup
3. 🟡 **Hyper-V VM health + checkpoint cleaner** — integration services, stuck checkpoints, resource overcommit
4. 🔴 **Failover-cluster validation runner + report** — schedule `Test-Cluster`, diff against baseline
5. 🟡 **Certificate expiry scanner** — machine store + IIS + LDAPS + WinRM; 30/60/90-day warnings
6. 🟡 **Print server migration helper** — export/import print queues, drivers, ports between servers
7. 🟢 **Feature/role drift detector** — compare installed Windows features to a golden JSON manifest
8. 🟡 **Scheduled task auditor** — all tasks across servers, creator, last run, signed-script check
9. 🔴 **Server build automation (DSC or PS template)** — post-OS unattend: roles, firewall, join-domain
10. 🟡 **Event log forwarder setup** — configure WEF subscriptions + verify collector ingestion

---

## Role 3 — Desktop Support Engineer
**Language: PowerShell**; small Batch helpers for PE

1. 🟢 **New-hire laptop baseline** — rename, join domain/Entra, install apps via winget, map drives/printers
2. 🟢 **Account-lockout investigator** — pull 4740 events from DCs, trace source workstation/IP, optional unlock
3. 🟢 **Remote app uninstaller** — find by DisplayName, silent removal, MSI+EXE
4. 🟡 **Printer troubleshooter** — clear spooler, reinstall driver, reconnect queue, export diagnostic bundle
5. 🟢 **Profile cleanup / orphaned profile remover** — safe deletion with whitelist + age threshold
6. 🟡 **Outlook / M365 quick fixes** — OST reset, cached-cred clear, Teams cache purge (parameterized)
7. 🟢 **Network quick-check pack** — DNS, gateway, proxy, VPN, DHCP lease; one summary output
8. 🟡 **Self-service BitLocker recovery key fetcher** (AD/Entra) — helpdesk GUI (WinForms/WPF)
9. 🟢 **Driver + Windows Update force-trigger with logs** — reliability history snapshot included
10. 🟡 **Endpoint support bundle collector** — logs, msinfo32, dxdiag, event logs; zipped hostname+date

---

## Role 4 — Cloud Administrator (Azure / Entra ID)
**Language: PowerShell (Az + Microsoft.Graph)**; Python (Azure SDK) for integrations

1. 🟡 **Entra ID user lifecycle runbook** — JML via Graph, group + license automation
2. 🟡 **Azure resource tag compliance enforcer** — find untagged, apply from policy, report drift
3. 🔴 **Cost-anomaly detector** — Cost Management API, flag resources exceeding rolling average (Python)
4. 🟡 **Conditional Access policy backup + diff** — nightly JSON export, compare, alert on change
5. 🟡 **Orphaned resource sweeper** — unused disks, NICs, public IPs, snapshots; staged deletion
6. 🟡 **Azure Automation Runbook: VM start/stop scheduler** — tag-driven, timezone-aware
7. 🔴 **Key Vault secret rotation helper** — rotate on schedule, update consumer app settings
8. 🟡 **Log Analytics KQL query pack + runner** — frequently used queries parameterized
9. 🟡 **MFA / passwordless coverage report** — users lacking strong auth methods, audit-exportable
10. 🟢 **Subscription & RBAC inventory** — who has what where; flag Owner-at-subscription

---

## Role 5 — Security Analyst (Blue Team / SOC)
**Language: PowerShell (endpoint/IR) + Python (parsing, enrichment, APIs)**
Frameworks: MITRE ATT&CK, NIST 800-53 (AU, IR, SI)

1. 🟡 **Windows event-log hunt pack** — 4624/4625 anomalies, 4688 parent-child, 4698 tasks, 7045 services; mapped to ATT&CK
2. 🟡 **IOC sweeper** — hash/IP/domain list swept across endpoints (PS remoting) + DNS/proxy logs
3. 🔴 **Sysmon config auditor + deployer** — validate against SwiftOnSecurity/Olaf Hartong, deploy, verify
4. 🟡 **PowerShell ScriptBlock log parser (Python)** — decode 4104 events, extract IOCs, flag obfuscation
5. 🟡 **Persistence auditor** — Run keys, tasks, services, WMI subs, startup folders — diff vs baseline (ATT&CK TA0003)
6. 🟡 **Browser / credential artifact collector** (authorized IR only) — history, saved-cred presence, LSASS protection state
7. 🟡 **Threat-intel enrichment CLI (Python)** — VT/AbuseIPDB/OTX lookup, cache, CSV/JSON output
8. 🔴 **Mini SIEM-lite** — ingest Winlogbeat-style JSON to SQLite, Sigma-ish YAML rules — capstone piece
9. 🟡 **Phishing email triage** — parse `.eml`/`.msg` headers, URLs, attachments (Python)
10. 🟢 **Quick-triage one-liner pack** — netstat, autoruns-style, process tree, recent files — Markdown report

---

## Role 6 — Penetration Tester (Offensive / Ethical)
**Language: PowerShell (on-host) + Python (tooling)**
All scripts for authorized engagements, CTF, or home lab only.

1. 🟢 **Host recon collector** — OS, patches, users, shares, services, firewall, AV
2. 🟡 **Local privesc checklist runner** — unquoted service paths, weak ACLs, AlwaysInstallElevated, token privileges
3. 🟡 **AD recon script** — domain, trusts, GPOs, Kerberoastable SPNs, AS-REP-roastable users
4. 🟡 **SMB/share enumerator (Python)** — guest access, readable shares, keyword hits (password, config)
5. 🟡 **Password-spray safety harness** — rate-limited, lockout-aware
6. 🟢 **Hash + ticket format converter** — reshape output for Hashcat/John
7. 🟡 **Post-exploitation data triage** (lab) — parse artifacts to structured output
8. 🟡 **AMSI / ETW bypass detector** (defender perspective) — lab detection coverage test
9. 🟡 **Report generator** — structured JSON findings → Markdown/HTML pentest report (CVSS, evidence)
10. 🟢 **CTF helper lib (Python)** — decoders, shell spawners, listener launchers

---

## Role 7 — Compliance Officer / Auditor
**Language: PowerShell (gathering) + Python (reporting/mapping)**
Frameworks: CIS, DISA STIG, NIST 800-53 / 800-171

1. 🟡 **CIS Windows 10/11 benchmark auditor** — password/audit policy, SMB signing, LAPS, etc.; HTML report
2. 🟡 **Local audit policy exporter** — `auditpol /get` wrapper, compare to CIS JSON baseline
3. 🟡 **User rights assignment auditor** — `secedit` export, parse, baseline compare
4. 🔴 **NIST 800-171 control mapper** — CIS findings + inventory → 800-171 gap report (Python + docx template)
5. 🟡 **Account/password policy reporter** — domain + local, FGPP, last-set ages
6. 🟡 **Logging coverage auditor** — Sysmon, PS transcription, ScriptBlock, WEF → compliance matrix
7. 🟢 **Installed software inventory with CVE lookup** — winget/WMI → NVD API
8. 🟡 **Evidence collector for audit** — screenshot + config export bundled per control ID
9. 🟡 **BitLocker / TPM / Secure Boot posture report** across fleet
10. 🟢 **USB / removable-media policy checker** — GPO + registry + recent device history (ATT&CK T1091)

---

## Role 8 — Network Administrator
**Language: PowerShell (Windows networking) + Python (Netmiko/NAPALM)**

1. 🟡 **Subnet sweep + inventory** — ping + rDNS + NetBIOS + top-N port, CSV output
2. 🟡 **DHCP lease utilization tracker** — scope stats, trend, threshold alerts
3. 🟡 **DNS record auditor** — orphaned A records, scavenging state, duplicate PTRs
4. 🔴 **Multi-vendor config backup (Netmiko)** — Cisco/Juniper/Arista; git-commit diffs on change
5. 🟡 **Firewall rule exporter + analyzer** — Defender Firewall inventory, unused-rule detection
6. 🟡 **VPN / RRAS session reporter** — active sessions, duration, throughput outliers
7. 🟢 **Bandwidth snapshot** — perfmon per-interface → rolling HTML chart
8. 🟡 **Port-scanner CLI (Python)** — async + banner grab (lab use)
9. 🟡 **Wi-Fi profile auditor** — exported XMLs, insecure auth (WEP/WPA2-PSK legacy)
10. 🟢 **Network quick-diag bundle** — tracert/pathping/nslookup/Test-NetConnection across targets

---

## Role 9 — Operations Engineer / SRE-adjacent
**Language: PowerShell + Python**

1. 🟡 **Service uptime + SLO reporter** — probe HTTP/TCP, error-budget burn
2. 🟡 **Runbook-as-code launcher** — YAML runbooks, PS/Python executor, logging + approval gate
3. 🔴 **Deployment smoke-test harness** — post-deploy checks (service, endpoint, DB, log error rate)
4. 🟡 **Log shipper lite** — tail + forward Event Logs/files to syslog/HTTP (Python)
5. 🟡 **Prometheus/Grafana exporter for Windows** — custom metrics via textfile collector
6. 🟢 **On-call paging simulator** — test Opsgenie/PagerDuty with canned alerts
7. 🟡 **Capacity forecaster** — disk/CPU trend → days-until-full (pandas linear regression)
8. 🟡 **Chaos toy** — safely kill test service, observe recovery, report MTTR (lab)
9. 🟢 **Change-freeze guard** — gate blocking deployments during freeze windows
10. 🟡 **Secrets-in-code scanner pre-commit hook** — regex + entropy with line numbers

---

## Role 10 — Backup & Recovery Specialist
**Language: PowerShell (VSS, Windows Backup, Azure Backup); Python where cross-platform**

1. 🟡 **VSS shadow-copy creator + validator** — `diskshadow`/`vssadmin` wrapper, writer-state verification
2. 🟡 **Backup job status aggregator** — Veeam/WSB/Azure Backup → HTML dashboard
3. 🔴 **Automated restore-test harness** — restore random set to sandbox, hash-compare, success log (capstone)
4. 🟡 **File-system integrity baseline + drift** — hash critical paths, detect changes (doubles as IR tool)
5. 🟡 **Retention policy enforcer** — prune per GFS, audit log
6. 🟡 **Azure Recovery Services Vault reporter** — protected items, last successful restore, RPO compliance
7. 🟢 **Pre-backup app-consistency hooks** — quiesce SQL/Exchange/Hyper-V via VSS writers
8. 🟡 **Ransomware-resilience check** — immutable storage? offline copy age? MFA on backup admin?
9. 🟢 **DR runbook executor** — step-by-step failover with manual gates and timing log
10. 🟡 **Backup-size forecaster** — ingest history → storage growth prediction

---

## Capstone picks (1–2 for resume highlight)
- **Mini SIEM-lite** (Security Analyst #8)
- **CIS/STIG auditor with HTML report** (Compliance #1)
- **Automated restore-test harness** (Backup #3)
- **Entra ID JML runbook** (Cloud #1)
- **Pentest report generator** (Pentester #9)

---

## Framework tags per script

Each script README carries a small frontmatter block like this:

```yaml
role: SecurityAnalyst
language: PowerShell
difficulty: intermediate
frameworks:
  mitre_attack: [T1059.001, T1053.005]
  nist_800_53: [AU-6, SI-4]
  cis_windows11: [18.9.27.1]
  stig: [WN11-AU-000500]
```

Makes it easy to generate a coverage matrix across the whole repo later.
