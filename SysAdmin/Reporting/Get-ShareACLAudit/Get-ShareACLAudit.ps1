#requires -Version 7.2
<#
.SYNOPSIS
    Walk one or more paths recursively and flag ACL grants that combine a risky
    principal with a risky file-system right.

.DESCRIPTION
    Get-ShareACLAudit enumerates every directory under each input path (up to
    MaxDepth levels deep, including the root itself) and inspects the Windows
    ACL on each directory.  Any access rule whose IdentityReference matches a
    risky principal AND whose FileSystemRights overlap a risky right produces a
    finding row in the pipeline output.

    The script is strictly read-only.  It never modifies ACLs, permissions, or
    any file-system object.

    Both Allow AND Deny rules are reported.  A Deny rule for a risky principal
    may indicate misconfiguration (e.g. a blanket Deny that was meant to
    compensate for an overly-permissive Allow) and operators should be aware of
    it regardless of its type.

    Access-denied errors on individual directories are non-fatal: the function
    emits a warning and continues with the next directory so that a partial audit
    is always returned rather than an aborted one.

.PARAMETER Path
    One or more root paths (local or UNC) to audit.  Each path is validated with
    Test-Path before enumeration begins; missing paths produce a warning and are
    skipped.

.PARAMETER MaxDepth
    Maximum recursion depth when enumerating subdirectories.  Default: 5.

.PARAMETER RiskyPrincipals
    Array of identity strings to flag.  Case-insensitive exact match against the
    IdentityReference.Value of each access rule.
    Default: Everyone, BUILTIN\Users, NT AUTHORITY\Authenticated Users, Domain Users.

.PARAMETER RiskyRights
    Array of right-name strings to flag.  The function checks whether any token
    in the comma-separated FileSystemRights string matches an entry in this list.
    Default: Modify, Write, FullControl.

.PARAMETER OutputPath
    Optional.  When supplied, all findings are also written to this path as a
    UTF-8 CSV via Export-Csv.

.EXAMPLE
    Get-ShareACLAudit -Path '\\fileserver\shares'
    # Audit a single UNC root with all defaults.

.EXAMPLE
    Get-ShareACLAudit -Path 'D:\Data','E:\Dept' -MaxDepth 3 -OutputPath .\findings.csv
    # Audit two roots to depth 3 and save findings to CSV.

.EXAMPLE
    Get-ShareACLAudit -Path 'C:\Shares' -RiskyPrincipals 'Domain Users','Everyone' -RiskyRights 'Write','FullControl'
    # Override risky principal and right lists.
#>

# ---------------------------------------------------------------------------
# Private helpers — wrapped so Pester tests can mock them cleanly without
# needing the real Get-Acl / Get-ChildItem calls.
# ---------------------------------------------------------------------------

function Get-GSAAcl {
    <#
    .SYNOPSIS
        Thin wrapper around Get-Acl so Pester can mock it per Describe block.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    Get-Acl -LiteralPath $Path
}

function Get-GSAChildItem {
    <#
    .SYNOPSIS
        Thin wrapper around Get-ChildItem so Pester can inject a synthetic tree.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LiteralPath,

        [switch]$Directory,
        [switch]$Recurse,
        [int]$Depth,
        [string]$ErrorAction = 'SilentlyContinue'
    )
    Get-ChildItem -LiteralPath $LiteralPath -Directory:$Directory -Recurse:$Recurse `
        -Depth $Depth -ErrorAction $ErrorAction
}

# ---------------------------------------------------------------------------
# Public function: Get-ShareACLAudit
# ---------------------------------------------------------------------------

function Get-ShareACLAudit {
    <#
    .SYNOPSIS
        Enumerate directory ACLs under one or more paths and flag risky grants.

    .DESCRIPTION
        Walks each input path recursively (up to MaxDepth) including the root,
        checks each directory ACL, and emits a finding row for every access rule
        that matches both a risky principal and a risky file-system right.

        The script is read-only and never modifies any ACL or file-system object.

    .PARAMETER Path
        One or more paths to audit.

    .PARAMETER MaxDepth
        Recursion depth for subdirectory enumeration.  Default: 5.

    .PARAMETER RiskyPrincipals
        Identity strings to consider risky.  Case-insensitive exact match.

    .PARAMETER RiskyRights
        Right names to consider risky.  Matched against the comma-split of
        FileSystemRights.ToString().

    .PARAMETER OutputPath
        Optional CSV output path.

    .EXAMPLE
        Get-ShareACLAudit -Path '\\srv\share'

    .EXAMPLE
        Get-ShareACLAudit -Path 'C:\Data' -OutputPath .\report.csv
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string[]]$Path,

        [Parameter()]
        [int]$MaxDepth = 5,

        [Parameter()]
        [string[]]$RiskyPrincipals = @(
            'Everyone',
            'BUILTIN\Users',
            'NT AUTHORITY\Authenticated Users',
            'Domain Users'
        ),

        [Parameter()]
        [string[]]$RiskyRights = @('Modify', 'Write', 'FullControl'),

        [Parameter()]
        [string]$OutputPath
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    foreach ($p in $Path) {

        # ----------------------------------------------------------------
        # 1. Validate root path.
        # ----------------------------------------------------------------
        if ([string]::IsNullOrWhiteSpace($p)) { continue }

        if (-not (Test-Path -LiteralPath $p)) {
            Write-Warning "Path not found, skipping: '$p'"
            continue
        }

        # ----------------------------------------------------------------
        # 2. Build directory list: root itself + recursive children.
        # ----------------------------------------------------------------
        $rootItem = [PSCustomObject]@{ FullName = $p }

        $children = @(Get-GSAChildItem -LiteralPath $p -Directory -Recurse -Depth $MaxDepth -ErrorAction SilentlyContinue)

        $dirs = @($rootItem) + $children

        # ----------------------------------------------------------------
        # 3. Inspect each directory.
        # ----------------------------------------------------------------
        foreach ($dir in $dirs) {
            $acl = $null
            try {
                $acl = Get-GSAAcl -Path $dir.FullName
            }
            catch {
                Write-Warning "Cannot read ACL for '$($dir.FullName)': $($_.Exception.Message)"
                continue
            }

            foreach ($rule in $acl.Access) {

                $principal = $rule.IdentityReference.Value

                # Case-insensitive exact match against risky principals.
                $principalIsRisky = $RiskyPrincipals |
                    Where-Object { $_ -ieq $principal } |
                    Select-Object -First 1

                if (-not $principalIsRisky) { continue }

                # Split the FileSystemRights string and check for overlap.
                $rightsTokens = $rule.FileSystemRights.ToString() -split ',\s*'
                $rightIsRisky = $false
                foreach ($token in $rightsTokens) {
                    if ($RiskyRights -icontains $token.Trim()) {
                        $rightIsRisky = $true
                        break
                    }
                }

                if (-not $rightIsRisky) { continue }

                $finding = [PSCustomObject]@{
                    Path              = $dir.FullName
                    Principal         = $principal
                    Rights            = $rule.FileSystemRights.ToString()
                    AccessControlType = $rule.AccessControlType.ToString()
                    IsInherited       = $rule.IsInherited
                }

                $findings.Add($finding)
                Write-Output $finding
            }
        }
    }

    # ----------------------------------------------------------------
    # 4. Optional CSV export.
    # ----------------------------------------------------------------
    if ($OutputPath -and $findings.Count -gt 0) {
        $findings | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Verbose "Findings written to: $OutputPath"
    }
}
