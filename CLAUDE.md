# CLAUDE.md — UsefulScripts

## Project
A portfolio of practical, working Windows-focused scripts across 10 IT/security roles (SecurityAnalyst, SysAdmin, WindowsServerAdmin, DesktopSupport, CloudAdmin, Pentester, Compliance, NetworkAdmin, OpsEngineer, BackupRecovery). Scripts are real, job-ready tools — not demos. Each maps to relevant frameworks (MITRE ATT&CK, CIS, NIST 800-53, DISA STIG) where applicable.

## Structure
- One folder per role (e.g. `/SecurityAnalyst/`, `/SysAdmin/`)
- `/Common/` for shared utilities across roles
- Within each role folder: subfolders by tactic/category
- Each script has: `README.md` (with YAML frontmatter), the script, a test file (Pester or pytest), optional `samples/`, and `docs/attack-mapping.md`

### SecurityAnalyst layout (most active role)
```
SecurityAnalyst/
├── _SHARED/        # SA.Common PS module + sa_common Python pkg
├── _Tooling/       # cross-tactic tools (SIEM-lite, threat-intel CLI, phishing triage)
├── InitialAccess/
├── Execution/
├── Persistence/
├── LateralMovement/
├── Discovery/
└── Triage/
```

## Conventions
- **PowerShell 7+** for Windows/AD/Azure; **Python** for parsing, network, APIs; **Batch** only when PS unavailable
- State-changing actions gated behind `-WhatIf` (PS) / `--dry-run` (Py)
- No credentials in source — use env vars or `SecretManagement`
- Script README frontmatter:
  ```yaml
  role: SecurityAnalyst
  language: PowerShell
  difficulty: intermediate   # easy / intermediate / hard
  frameworks:
    mitre_attack: [T1059.001]
    nist_800_53: [AU-6]
    cis_windows11: []
    stig: []
  ```
- Difficulty scale: easy / medium / hard (symbols in PORTFOLIO_PLAN.md: 🟢/🟡/🔴)

## Workflow
**Always follow this three-phase cycle:**
1. **Plan** — lay out approach, ask clarifying questions before writing any code
2. **Implement** — build from the agreed plan
3. **Verify** — test, lint, confirm behavior matches spec

Do not skip straight to implementation. If requirements are ambiguous, ask first.

## CI
- PSScriptAnalyzer + Pester via `.github/workflows/powershell.yml` (windows-latest)
- ruff + pytest via `.github/workflows/python.yml` (ubuntu-latest)
- `PSScriptAnalyzerSettings.psd1` at repo root controls PS linting rules

## Memory

Project knowledge base: `C:\ClaudeVault\wiki\projects\{project-name}\`

Read at session start (in order):
1. `roadmap.md` — current goals & north star
2. `docs.md` — architecture & key files
3. `deps.md` — setup & dependencies
4. `devlog.md` — recent work log

Session hygiene:
- After significant work, append a dated bullet to `devlog.md`:
    - `YYYY-MM-DD: concise note about what was done`
- If `devlog.md` exceeds ~40 entries, compress the oldest 20 into `devlog-archive.md` (one line each), then remove them from `devlog.md`
- Keep all files within their size limits — summarize rather than append
- Update `roadmap.md` and `docs.md` when architecture or goals change
