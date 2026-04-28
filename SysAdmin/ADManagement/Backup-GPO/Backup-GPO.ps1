#requires -Version 7.2
<#
.SYNOPSIS
    Export all Group Policy Objects to a timestamped backup folder with optional change comparison.

.DESCRIPTION
    Backup-GPO enumerates every GPO in the domain, backs each one up using the
    GroupPolicy module, and writes per-GPO XML and HTML reports.  All output
    goes to a timestamped subfolder (yyyy-MM-dd_HHmm) created under
    -BackupRoot; Active Directory itself is never modified.

    When -CompareToPrevious is specified, the function locates the most recent
    prior backup folder under -BackupRoot and compares XML report hashes to
    classify each GPO as Unchanged, Changed, Added, or Removed.

    State-changing operations (folder creation, file writes) are gated behind
    ShouldProcess, so -WhatIf works end-to-end.

.PARAMETER BackupRoot
    Parent directory under which the timestamped backup subfolder is created.
    Created automatically if it does not exist.

.PARAMETER CompareToPrevious
    When set, compare the new backup against the most recent prior backup
    folder found under -BackupRoot.

.PARAMETER OutputPath
    Optional path to write a JSON summary file containing the backup results
    and (when applicable) the comparison results.

.EXAMPLE
    Backup-GPO -BackupRoot C:\GPOBackups -WhatIf
    # Preview what would be created. Nothing is written.

.EXAMPLE
    Backup-GPO -BackupRoot C:\GPOBackups -CompareToPrevious -OutputPath C:\GPOBackups\summary.json
    # Back up all GPOs, compare with the previous backup, write a JSON summary.
#>

# ---------------------------------------------------------------------------
# Private helpers — each wraps the real GroupPolicy cmdlet.
# Pester mocks these helpers, so tests never need the GroupPolicy module.
# ---------------------------------------------------------------------------

function Invoke-PBGGetGPO {
    <#
    .SYNOPSIS
        Private wrapper around Get-GPO -All. Throws when GroupPolicy module is absent.
    #>
    [CmdletBinding()]
    param()
    $cmd = Get-Command 'Get-GPO' -Module GroupPolicy -ErrorAction SilentlyContinue
    if (-not $cmd) {
        throw 'GroupPolicy module not loaded — install RSAT.GroupPolicy or import the module.'
    }
    & $cmd -All
}

function Invoke-PBGBackupGPO {
    <#
    .SYNOPSIS
        Private wrapper around the GroupPolicy\Backup-GPO cmdlet.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [guid]$Guid,

        [Parameter(Mandatory)]
        [string]$Path
    )
    $cmd = Get-Command 'Backup-GPO' -Module GroupPolicy -ErrorAction SilentlyContinue
    if (-not $cmd) {
        throw 'GroupPolicy module not loaded — install RSAT.GroupPolicy or import the module.'
    }
    & $cmd -Guid $Guid -Path $Path
}

function Invoke-PBGGetGPOReport {
    <#
    .SYNOPSIS
        Private wrapper around Get-GPOReport.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [guid]$Guid,

        [Parameter(Mandatory)]
        [ValidateSet('Xml', 'Html')]
        [string]$ReportType,

        [Parameter(Mandatory)]
        [string]$Path
    )
    $cmd = Get-Command 'Get-GPOReport' -Module GroupPolicy -ErrorAction SilentlyContinue
    if (-not $cmd) {
        throw 'GroupPolicy module not loaded — install RSAT.GroupPolicy or import the module.'
    }
    & $cmd -Guid $Guid -ReportType $ReportType -Path $Path
}

# ---------------------------------------------------------------------------
# Private helper — sanitize a GPO display name into a safe file-system name.
# ---------------------------------------------------------------------------
function ConvertTo-PBGSafeFileName {
    <#
    .SYNOPSIS
        Replace file-system-unsafe characters with underscores.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )
    # Replace characters that are illegal in Windows file names.
    $Name -replace '[/\\:*?"<>|]', '_'
}

# ---------------------------------------------------------------------------
# Public function: Backup-GPO
# ---------------------------------------------------------------------------
<#
.SYNOPSIS
    Export all Group Policy Objects to a timestamped backup folder.

.DESCRIPTION
    Backup-GPO enumerates every GPO in the domain, backs each one up using the
    GroupPolicy module, and writes per-GPO XML and HTML reports.  All output
    goes to a timestamped subfolder (yyyy-MM-dd_HHmm) created under
    -BackupRoot; Active Directory itself is never modified.

.PARAMETER BackupRoot
    Parent directory under which the timestamped backup subfolder is created.

.PARAMETER CompareToPrevious
    Compare the new backup against the most recent prior backup folder.

.PARAMETER OutputPath
    Optional path to write a JSON summary file.

.EXAMPLE
    Backup-GPO -BackupRoot C:\GPOBackups -WhatIf

.EXAMPLE
    Backup-GPO -BackupRoot C:\GPOBackups -CompareToPrevious -OutputPath C:\GPOBackups\summary.json
#>
function Backup-GPO {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$BackupRoot,

        [Parameter()]
        [switch]$CompareToPrevious,

        [Parameter()]
        [string]$OutputPath
    )

    # ------------------------------------------------------------------
    # 1. Validate / create BackupRoot
    # ------------------------------------------------------------------
    if (Test-Path -LiteralPath $BackupRoot -PathType Leaf) {
        throw "BackupRoot '$BackupRoot' exists but is a file, not a directory."
    }

    if (-not (Test-Path -LiteralPath $BackupRoot -PathType Container)) {
        if ($PSCmdlet.ShouldProcess($BackupRoot, 'Create backup root directory')) {
            $null = New-Item -Path $BackupRoot -ItemType Directory -Force
        }
    }

    # ------------------------------------------------------------------
    # 2. Compute timestamped subfolder
    # ------------------------------------------------------------------
    $timestamp = Get-Date -Format 'yyyy-MM-dd_HHmm'
    $folder    = Join-Path $BackupRoot $timestamp

    if ($PSCmdlet.ShouldProcess($folder, 'Create timestamped backup subfolder')) {
        $null = New-Item -Path $folder -ItemType Directory -Force
    }

    # ------------------------------------------------------------------
    # 3. Enumerate GPOs
    # ------------------------------------------------------------------
    $gpos = Invoke-PBGGetGPO   # throws if module absent; let it propagate

    # ------------------------------------------------------------------
    # 4. Back up each GPO
    # ------------------------------------------------------------------
    $backupResults = [System.Collections.Generic.List[object]]::new()

    foreach ($g in $gpos) {
        $safeName = ConvertTo-PBGSafeFileName -Name $g.DisplayName
        $xmlPath  = Join-Path $folder "$safeName.xml"
        $htmlPath = Join-Path $folder "$safeName.html"

        if (-not $PSCmdlet.ShouldProcess($g.DisplayName, 'Backup GPO and write reports')) {
            $backupResults.Add([PSCustomObject]@{
                DisplayName = $g.DisplayName
                Id          = $g.Id
                Status      = 'WhatIf'
                Reason      = ''
            })
            continue
        }

        try {
            Invoke-PBGBackupGPO  -Guid $g.Id -Path $folder
            Invoke-PBGGetGPOReport -Guid $g.Id -ReportType Xml  -Path $xmlPath
            Invoke-PBGGetGPOReport -Guid $g.Id -ReportType Html -Path $htmlPath

            $backupResults.Add([PSCustomObject]@{
                DisplayName = $g.DisplayName
                Id          = $g.Id
                Status      = 'Success'
                Reason      = ''
            })
        }
        catch {
            $backupResults.Add([PSCustomObject]@{
                DisplayName = $g.DisplayName
                Id          = $g.Id
                Status      = 'Failed'
                Reason      = $_.Exception.Message
            })
            Write-Warning "GPO '$($g.DisplayName)': $($_.Exception.Message)"
        }
    }

    # ------------------------------------------------------------------
    # 5. Optional comparison against previous backup
    # ------------------------------------------------------------------
    $comparison    = $null
    $compareSkipped = $false

    if ($CompareToPrevious) {
        # List all timestamped sibling folders, exclude the one we just created.
        $priorFolders = @(
            Get-ChildItem -LiteralPath $BackupRoot -Directory |
                Where-Object { $_.Name -ne $timestamp } |
                Sort-Object -Property Name
        )

        if ($priorFolders.Count -eq 0) {
            $compareSkipped = $true
            Write-Verbose 'No prior backup folder found; skipping comparison.'
        }
        else {
            $priorFolder = $priorFolders[-1].FullName
            Write-Verbose "Comparing against prior folder: $priorFolder"

            $comparison = [System.Collections.Generic.List[object]]::new()

            # Gather XML file names from both folders.
            $currentXmls = @(Get-ChildItem -LiteralPath $folder    -Filter '*.xml' -File |
                              ForEach-Object { $_.Name })
            $priorXmls   = @(Get-ChildItem -LiteralPath $priorFolder -Filter '*.xml' -File |
                              ForEach-Object { $_.Name })

            $allNames = ($currentXmls + $priorXmls) | Sort-Object -Unique

            foreach ($xmlName in $allNames) {
                $inCurrent = $xmlName -in $currentXmls
                $inPrior   = $xmlName -in $priorXmls
                $gpoName   = [System.IO.Path]::GetFileNameWithoutExtension($xmlName)

                if ($inCurrent -and $inPrior) {
                    $currentHash = (Get-FileHash -LiteralPath (Join-Path $folder     $xmlName) -Algorithm SHA256).Hash
                    $priorHash   = (Get-FileHash -LiteralPath (Join-Path $priorFolder $xmlName) -Algorithm SHA256).Hash
                    $diffStatus  = if ($currentHash -eq $priorHash) { 'Unchanged' } else { 'Changed' }
                    $comparison.Add([PSCustomObject]@{ DisplayName = $gpoName; Status = $diffStatus })
                }
                elseif ($inCurrent -and -not $inPrior) {
                    $comparison.Add([PSCustomObject]@{ DisplayName = $gpoName; Status = 'Added' })
                }
                else {
                    $comparison.Add([PSCustomObject]@{ DisplayName = $gpoName; Status = 'Removed' })
                }
            }
        }
    }

    # ------------------------------------------------------------------
    # 6. Emit results to pipeline; write JSON summary if requested
    # ------------------------------------------------------------------
    $backupResults | ForEach-Object { Write-Output $_ }

    if ($OutputPath) {
        $summary = [ordered]@{
            BackupFolder    = $folder
            Timestamp       = (Get-Date -Format 'o')
            BackupResults   = @($backupResults)
            Comparison      = if ($comparison) { @($comparison) } else { $null }
            CompareSkipped  = $compareSkipped
        }

        $json = $summary | ConvertTo-Json -Depth 5

        if ($PSCmdlet.ShouldProcess($OutputPath, 'Write JSON summary')) {
            Set-Content -LiteralPath $OutputPath -Value $json -Encoding UTF8
            Write-Verbose "JSON summary written to: $OutputPath"
        }
    }
}
