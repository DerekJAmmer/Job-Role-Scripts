# Triage

First-response scripts — the stuff you run in the first few minutes when something looks off.

## Scripts

- **Invoke-QuickTriage** — one-command snapshot of a suspect host: processes, listeners, persistence, Defender, drop-site files. Outputs a Markdown report you can scroll through or hand off. *(in-progress)*
- **Invoke-IOCSweep** — sweep a hash/IP/domain list across endpoints and DNS/proxy logs. *(planned)*
- **Get-ArtifactCollect** — collect browser history, saved-cred presence (not the creds themselves), and LSASS protection state. Authorized IR only. *(planned)*

See `SecurityAnalyst/README.md` for the full matrix.
