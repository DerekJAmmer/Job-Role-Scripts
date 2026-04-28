# Control Mapping — Get-ServerInventory

## NIST SP 800-53 Rev 5: CM-8 — System Component Inventory

### What the control says

CM-8 requires organizations to develop and document an inventory of system
components that accurately reflects the system, includes all components within
the system boundary, and is kept current. The inventory must contain the
information necessary to achieve accountability, no more, no less.

### Why this script maps to CM-8

`Get-ServerInventory` automates the data collection side of CM-8. Each run
produces a timestamped snapshot of every queried host: hardware make and model,
OS version and build, CPU, memory, disk layout, uptime, and whether a reboot
is pending. Written to CSV and HTML, those snapshots become the inventory
records CM-8 calls for.

Running the script on a schedule (weekly, monthly, before/after patching) gives
you the version history CM-8 expects — you can diff two CSVs to spot changes
to any field: a new OS build after an unexpected update, a drive that lost 50%
free space since last check, a host that stopped responding.

### Specific CM-8 requirements this script supports

| CM-8 requirement | How the script helps |
|---|---|
| Inventory reflects the current state of the system | CIM queries run live against each host at execution time |
| Inventory is at a level of granularity deemed necessary | Collects hardware, OS, CPU, memory, storage, and uptime — typical baseline fields for a Windows server inventory |
| Inventory is kept current | Each run is timestamped; schedule it to build a continuous record |
| Inventory supports accountability | CSV output is durable, diffable, and importable into ticketing or CMDB tools |

### What this script does not cover

CM-8 also requires keeping the inventory current through automated discovery
and updating it when changes occur. This script is a point-in-time collector.
A full CM-8 program would schedule it on a recurring basis and integrate the
output into a CMDB or configuration management platform.
