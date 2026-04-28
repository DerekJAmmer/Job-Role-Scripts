# ATT&CK mapping — Invoke-ScriptBlockParse

| Detection | ATT&CK | Why it matters |
|---|---|---|
| base64_literal / decoded payload | T1027 (Obfuscated Files or Information), T1027.010 (Command Obfuscation) | Base64 encoding the payload is the most common way to hide a PowerShell command from casual inspection. `-EncodedCommand` and inline `[Convert]::FromBase64String(...)` both show up here. |
| char_cast / string_concat / hex_chars | T1027 (Obfuscation) | These are string-hiding tricks that evade simple keyword-based AV. `[char]105` for `i`, etc. Often layered on top of a b64 payload. |
| iex / Invoke-Expression | T1059.001 (PowerShell) | IEX is how the decoded payload gets executed. It's the final step in almost every PS-based stager. |
| download (WebClient, DownloadString, etc.) | T1059.001 (PowerShell), T1105 (Ingress Tool Transfer) | Pulling a second-stage payload from the network. Frequently seen in macro-to-PS-to-download chains. |
| amsi_bypass | T1562.001 (Impair Defenses: Disable or Modify Tools) | AMSI patches in PowerShell are a well-known evasion technique. Any reference to AmsiUtils or amsiInitFailed is worth investigating. |
| reflective_load | T1620 (Reflective Code Loading), T1055 (Process Injection) | Loading a .NET assembly or native DLL from memory without touching disk — a common final stage in PS-based attacks. |

## NIST 800-53

- **AU-6** — Audit review. This is exactly what the 4104 log was designed for — reviewing what PowerShell actually executed, not just what was typed.
- **SI-4** — System monitoring. Detecting obfuscated or download-triggering scripts at the log level maps to continuous monitoring for malicious activity.
- **SI-3** — Malicious code protection. Obfuscation pattern detection supplements signature-based AV where encoding defeats simple matches.
