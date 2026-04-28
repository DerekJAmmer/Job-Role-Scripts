---
name: Get-ServerInventory
role: SysAdmin
tactic_folder: Inventory
language: PowerShell
difficulty: easy
status: complete
entry_point: Get-ServerInventory.ps1
requires:
  PowerShell: 7.2+
  Modules: []
  Privileges: non-elevated for local; WinRM + admin rights for remote CIM
frameworks:
  nist_800_53: [CM-8]
  cis_windows11: []
inputs:
  - ComputerName: string[] (default local machine)
  - OutputPath: string (default current directory)
  - Format: Csv | Html | Both (default Both)
outputs:
  - CSV file: ServerInventory-<yyyyMMdd-HHmm>.csv
  - HTML file: ServerInventory-<yyyyMMdd-HHmm>.html
  - PSCustomObject[]: one row per host, returned to pipeline
---

# Get-ServerInventory

You need to know what's running on a set of servers — OS version, hardware
specs, free disk space, uptime, whether a reboot is waiting. This script
pulls that data via CIM and writes a CSV and/or HTML report so you have a
record you can share, diff against later, or paste into a ticket.

Run it before patching a batch of machines, after onboarding new servers, or
any time you want a quick hardware/OS baseline without clicking through every
machine manually.

Unreachable hosts are recorded in the output as `Status='Unreachable'` rather
than aborting the whole run.

## What it collects

| Field | Source |
|---|---|
| Manufacturer, Model | Win32_ComputerSystem |
| OS name, version, build, install date | Win32_OperatingSystem |
| CPU name, cores, logical processors | Win32_Processor |
| Total and free memory (MB) | Win32_OperatingSystem |
| Fixed drives — size, free, % free | Win32_LogicalDisk (DriveType=3) |
| Last boot time, uptime in days | Win32_OperatingSystem |
| Pending reboot flag + reasons | Registry (CBS, WU, PFRO keys) |

## Usage

```powershell
# Inventory the local machine — writes CSV + HTML to the current directory
Get-ServerInventory

# Three servers, HTML only, custom output folder
Get-ServerInventory -ComputerName SRV01,SRV02,SRV03 -OutputPath C:\Reports -Format Html

# Just a CSV
Get-ServerInventory -ComputerName SRV01 -OutputPath C:\Reports -Format Csv

# Capture output in a variable and also write both files
$rows = Get-ServerInventory -ComputerName SRV01,SRV02 -OutputPath C:\Reports
```

## Output

Two files land in `-OutputPath`:

- `ServerInventory-<timestamp>.csv` — all fields, one row per host.
  Good for diffing, importing into Excel, or feeding other scripts.
- `ServerInventory-<timestamp>.html` — same data as a styled table with a
  summary header showing how many hosts were queried and how many responded.
  No external dependencies, no JavaScript — just HTML and embedded CSS.

The function also returns the rows as `PSCustomObject[]` to the pipeline.

## Running the tests

```powershell
Invoke-Pester .\Get-ServerInventory.Tests.ps1 -Output Detailed
```

All tests mock CIM and registry calls so they run without elevated privileges
and without touching real hardware.

## Known gaps

- **Pending reboot check is local only.** The registry check runs only when
  the target host matches `$env:COMPUTERNAME`. Remote hosts skip this field.
  A future version could use `Invoke-Command` to run it remotely.
- **Remote CIM requires WinRM.** Hosts where WinRM is not enabled or
  firewalled will show as `Unreachable` even if they are online.
- **Disk summary is a single string in CSV.** Multi-disk hosts pack all
  drives into one field (`C: 50GB free/100GB (50%); D: 20GB free/200GB (10%)`).
  The HTML table shows the same. A future version could write one row per disk.
