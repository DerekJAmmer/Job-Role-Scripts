---
role: SysAdmin
language: PowerShell
difficulty: easy
frameworks:
  mitre_attack: []
  nist_800_53: [CM-2, CM-8]
  cis_windows11: []
  stig: []
---

# Get-FeatureDrift

Compares installed Windows features or software against a JSON baseline manifest and reports what is missing, what is extra, and how closely the host matches the expected state.

## What it does

For each target host the script:

1. Reads a JSON baseline that lists the expected features or software titles.
2. Queries the host for what is actually installed.
3. Computes two lists:
   - **Missing** — items in the baseline that are not on the host.
   - **Extra** — items on the host that are not in the baseline.
4. Calculates a **MatchPercent** score: `(baseline items found / total baseline items) × 100`.
5. Emits a `PSCustomObject` per host and optionally writes the full result set to JSON.

## Baseline manifest schema

The baseline is a JSON file with three top-level keys:

| Key | Type | Description |
|-----|------|-------------|
| `name` | string | Human-readable label for this baseline (shown in output as `BaselineName`). |
| `features` | string[] | Windows feature names to expect in Features mode. |
| `software` | string[] | Application DisplayNames to expect in Software mode. |

Both `features` and `software` are optional. If omitted, they default to an empty array, which causes `MatchPercent` to be 0 and `Missing` to be empty (nothing to require means nothing can be missing).

### Example baseline

```json
{
  "name": "DC-Standard-2022",
  "features": ["AD-Domain-Services", "DNS", "RSAT-AD-Tools"],
  "software": []
}
```

A ready-to-edit example is shipped at `samples/baseline-example.json`.

## Feature name sources

- **Server (Features mode):** `Get-WindowsFeature` — use the `Name` property, e.g. `AD-Domain-Services`.
- **Client fallback (Features mode):** `Get-WindowsOptionalFeature` — use the `FeatureName` property, e.g. `Microsoft-Hyper-V`.
- **Software mode:** The `DisplayName` field from `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*` and its `Wow6432Node` equivalent. Match the exact string shown in Programs and Features.

## Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-BaselinePath` | string | Yes | — | Path to the JSON baseline manifest. |
| `-ComputerName` | string[] | No | `localhost` | One or more hosts to evaluate. |
| `-Mode` | string | No | `Features` | `Features` or `Software`. |
| `-OutputPath` | string | No | — | Write results to this path as UTF-8 JSON. |

## Output object

Each host produces one `PSCustomObject`:

| Property | Type | Description |
|----------|------|-------------|
| `ComputerName` | string | Target host name. |
| `Mode` | string | `Features` or `Software`. |
| `Missing` | string[] | Baseline items not found on the host. |
| `Extra` | string[] | Installed items not in the baseline. |
| `MatchPercent` | decimal | Percentage of baseline items present. |
| `BaselineName` | string | The `name` field from the baseline JSON. |

## Usage examples

**Features mode against local host:**

```powershell
Get-FeatureDrift -BaselinePath .\samples\baseline-example.json
```

**Software mode against multiple remote hosts with JSON output:**

```powershell
Get-FeatureDrift -BaselinePath .\workstation-sw-baseline.json `
                 -ComputerName WS01,WS02,WS03 `
                 -Mode Software `
                 -OutputPath .\software-drift-report.json
```

## Collectors

- **`Get-FDInstalledFeature`** — Tries `Get-WindowsFeature` (requires ServerManager module, available on Windows Server). If that throws, falls back to `Get-WindowsOptionalFeature -Online` (available on Windows client via DISM).
- **`Get-FDInstalledSoftware`** — Walks both the 64-bit and `Wow6432Node` Uninstall registry keys and returns all `DisplayName` values.

## Framework mapping

See `docs/control-mapping.md` for rationale against NIST SP 800-53 CM-2 (Baseline Configuration) and CM-8 (System Component Inventory).
