#requires -Version 7.2
<#
.SYNOPSIS
    Bulk-create Active Directory users from a CSV file.

.DESCRIPTION
    New-ADUserBulk reads a CSV, validates required columns, and creates each
    user in Active Directory. Existing users are skipped. A random initial
    password is generated per user. All AD-modifying calls are gated behind
    -WhatIf / ShouldProcess so you can preview before committing.

    Run with -WhatIf first against any live directory. By default, initial
    passwords are redacted in the CSV report (use -IncludePlainTextPasswords
    to override). Pipeline output always carries the plain-text password.

.PARAMETER CsvPath
    Path to the input CSV file. Required columns: SamAccountName,
    UserPrincipalName. Optional columns: GivenName, Surname, OU, Groups,
    Department, Title.

.PARAMETER DefaultOU
    Fallback distinguished name to use when a row's OU column is blank.
    If neither the row OU nor DefaultOU is set, that row is marked Failed.

.PARAMETER PasswordLength
    Length of the generated random password. Must be at least 8. Default: 16.

.PARAMETER OutputPath
    Optional path to write the result report as a CSV file. Passwords are
    redacted in this file unless -IncludePlainTextPasswords is set.

.PARAMETER IncludePlainTextPasswords
    When set together with -OutputPath, writes plain-text initial passwords
    into the CSV report and applies restrictive ACLs to the output file.
    Off by default — passwords are blanked in the CSV report.

.EXAMPLE
    New-ADUserBulk -CsvPath .\users.csv -WhatIf
    # Preview what would be created. Nothing is written to AD.

.EXAMPLE
    New-ADUserBulk -CsvPath .\users.csv -DefaultOU 'OU=Staff,DC=corp,DC=local' -OutputPath .\report.csv
    # Create users, fall back to Staff OU for rows without an OU, write report (passwords redacted).

.EXAMPLE
    New-ADUserBulk -CsvPath .\users.csv -OutputPath .\report.csv -IncludePlainTextPasswords
    # Write the CSV report with plain-text passwords (ACL hardening applied automatically).
#>

# ---------------------------------------------------------------------------
# Stub gate — makes AD cmdlets mockable when the module is not installed.
# Pester's Mock requires the command to exist in scope before mocking.
# ---------------------------------------------------------------------------
if (-not (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
    function Get-ADUser {
        <#
        .SYNOPSIS
            Stub — replaced at runtime by the ActiveDirectory module.
        #>
        [CmdletBinding()]
        param(
            [string]$Filter,
            [string]$Identity
        )
        throw 'ActiveDirectory module not loaded — install RSAT or import the module.'
    }
    function New-ADUser {
        <#
        .SYNOPSIS
            Stub — replaced at runtime by the ActiveDirectory module.
        #>
        [CmdletBinding(SupportsShouldProcess = $true)]
        param(
            [string]$Name,
            [string]$SamAccountName,
            [string]$UserPrincipalName,
            [string]$GivenName,
            [string]$Surname,
            [string]$Path,
            [string]$Department,
            [string]$Title,
            [securestring]$AccountPassword,
            [switch]$Enabled
        )
        throw 'ActiveDirectory module not loaded — install RSAT or import the module.'
    }
    function Add-ADGroupMember {
        <#
        .SYNOPSIS
            Stub — replaced at runtime by the ActiveDirectory module.
        #>
        [CmdletBinding(SupportsShouldProcess = $true)]
        param(
            [string]$Identity,
            [string[]]$Members
        )
        throw 'ActiveDirectory module not loaded — install RSAT or import the module.'
    }
}

# ---------------------------------------------------------------------------
# Helper: Get-NABRandomPassword
# Generates a cryptographically random password with all four character classes.
# ---------------------------------------------------------------------------
function Get-NABRandomPassword {
    <#
    .SYNOPSIS
        Generate a random password with mixed character classes.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(8, 128)]
        [int]$Length
    )

    $upper   = [char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    $lower   = [char[]]'abcdefghijklmnopqrstuvwxyz'
    $digits  = [char[]]'0123456789'
    $symbols = [char[]]'!@#$%^&*()-_=+'
    $all     = $upper + $lower + $digits + $symbols

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $buf = [byte[]]::new(1)

    function Invoke-PickChar ([char[]]$set) {
        do {
            $rng.GetBytes($buf)
        } while ($buf[0] -ge (256 - (256 % $set.Length)))   # rejection sampling
        return $set[$buf[0] % $set.Length]
    }

    # Guarantee at least one of each class in the first 4 positions.
    $chars = [System.Collections.Generic.List[char]]::new()
    $chars.Add((Invoke-PickChar $upper))
    $chars.Add((Invoke-PickChar $lower))
    $chars.Add((Invoke-PickChar $digits))
    $chars.Add((Invoke-PickChar $symbols))

    # Fill remaining positions from the full alphabet.
    for ($i = 4; $i -lt $Length; $i++) {
        $chars.Add((Invoke-PickChar $all))
    }

    # Fisher-Yates shuffle.
    for ($i = $chars.Count - 1; $i -gt 0; $i--) {
        $rng.GetBytes($buf)
        $j         = $buf[0] % ($i + 1)
        $tmp       = $chars[$i]
        $chars[$i] = $chars[$j]
        $chars[$j] = $tmp
    }

    $rng.Dispose()
    return -join $chars
}

# ---------------------------------------------------------------------------
# Helper: Test-NABRequiredColumn
# Validates that a CSV data set contains the required column names.
# ---------------------------------------------------------------------------
function Test-NABRequiredColumn {
    <#
    .SYNOPSIS
        Validate that a CSV header row contains required columns.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$CsvRows
    )

    if ($CsvRows.Count -eq 0) {
        throw 'CSV file is empty or contains only a header row.'
    }

    $headers  = $CsvRows[0].PSObject.Properties.Name
    $required = @('SamAccountName', 'UserPrincipalName')

    foreach ($col in $required) {
        if ($col -notin $headers) {
            throw "CSV is missing required column: '$col'."
        }
    }
}

# ---------------------------------------------------------------------------
# Public function: New-ADUserBulk
# ---------------------------------------------------------------------------
function New-ADUserBulk {
    <#
    .SYNOPSIS
        Bulk-create Active Directory users from a CSV file.

    .DESCRIPTION
        Reads a CSV file, validates required columns, then creates each user in
        Active Directory. Existing users are skipped. Random initial passwords
        are generated per user. All state-changing AD calls are gated with
        ShouldProcess so -WhatIf works end-to-end.

        Pipeline objects always carry the plain-text InitialPassword. The CSV
        report (when -OutputPath is set) redacts passwords by default; use
        -IncludePlainTextPasswords to include them (ACL hardening is applied).

        Status values: Created, Skipped, Failed, WhatIf, Partial (created but
        one or more group-add operations failed).

    .PARAMETER CsvPath
        Path to the input CSV. Required columns: SamAccountName, UserPrincipalName.

    .PARAMETER DefaultOU
        Fallback OU distinguished name when a row's OU column is blank.

    .PARAMETER PasswordLength
        Length of generated passwords (min 8, default 16).

    .PARAMETER OutputPath
        Optional path to write the result report as a CSV. Passwords are
        redacted in the CSV unless -IncludePlainTextPasswords is also set.

    .PARAMETER IncludePlainTextPasswords
        Include plain-text initial passwords in the exported CSV report.
        Off by default. When enabled, ACL hardening (current-user FullControl,
        inheritance disabled) is applied to the output file.

    .EXAMPLE
        New-ADUserBulk -CsvPath .\users.csv -WhatIf

    .EXAMPLE
        New-ADUserBulk -CsvPath .\users.csv -OutputPath .\report.csv -IncludePlainTextPasswords
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$CsvPath,

        [Parameter()]
        [string]$DefaultOU = '',

        [Parameter()]
        [ValidateRange(8, 128)]
        [int]$PasswordLength = 16,

        [Parameter()]
        [string]$OutputPath,

        [Parameter()]
        [switch]$IncludePlainTextPasswords
    )

    # Validate CSV path.
    if (-not (Test-Path -LiteralPath $CsvPath)) {
        throw "CsvPath not found: '$CsvPath'."
    }

    $rows = @(Import-Csv -LiteralPath $CsvPath)
    Test-NABRequiredColumn -CsvRows $rows

    $report = [System.Collections.Generic.List[object]]::new()

    foreach ($row in $rows) {
        $sam = $row.SamAccountName.Trim()
        $upn = $row.UserPrincipalName.Trim()
        $ou  = if ($row.PSObject.Properties['OU'] -and $row.OU.Trim()) {
                   $row.OU.Trim()
               }
               elseif ($DefaultOU) {
                   $DefaultOU
               }
               else {
                   $null
               }

        $entry = [PSCustomObject]@{
            SamAccountName  = $sam
            UPN             = $upn
            OU              = $ou
            Status          = ''
            InitialPassword = ''
            Reason          = ''
        }

        # OU resolution check — must have an OU before we can do anything.
        if (-not $ou) {
            $entry.Status = 'Failed'
            $entry.Reason = 'NoOU: no OU in row and no -DefaultOU supplied.'
            $report.Add($entry)
            Write-Warning "Row '$sam': no OU specified and -DefaultOU not set. Skipping."
            continue
        }

        # Check for existing user — use -Identity to avoid filter injection.
        try {
            $existing = Get-ADUser -Identity $sam -ErrorAction Stop
        }
        catch {
            $existing = $null
        }

        if ($existing) {
            $entry.Status = 'Skipped'
            $entry.Reason = 'AlreadyExists'
            $report.Add($entry)
            Write-Verbose "Skipped '$sam': user already exists."
            continue
        }

        # WhatIf / ShouldProcess gate for user creation.
        $target = "$sam ($upn)"
        $action = 'Create AD user'

        if (-not $PSCmdlet.ShouldProcess($target, $action)) {
            $entry.Status = 'WhatIf'
            $report.Add($entry)
            continue
        }

        # Generate password — use NetworkCredential to avoid ConvertTo-SecureString -AsPlainText.
        $plainPassword  = Get-NABRandomPassword -Length $PasswordLength
        $securePassword = [System.Net.NetworkCredential]::new('', $plainPassword).SecurePassword

        # Build New-ADUser parameter table.
        $adParams = @{
            SamAccountName    = $sam
            UserPrincipalName = $upn
            Name              = "$($row.GivenName) $($row.Surname)".Trim()
            Path              = $ou
            AccountPassword   = $securePassword
            Enabled           = $true
        }

        # Name cannot be empty for New-ADUser; fall back to SamAccountName.
        if ([string]::IsNullOrWhiteSpace($adParams['Name'])) { $adParams['Name'] = $sam }

        if ($row.PSObject.Properties['GivenName'] -and $row.GivenName) {
            $adParams['GivenName'] = $row.GivenName
        }
        if ($row.PSObject.Properties['Surname'] -and $row.Surname) {
            $adParams['Surname'] = $row.Surname
        }
        if ($row.PSObject.Properties['Department'] -and $row.Department) {
            $adParams['Department'] = $row.Department
        }
        if ($row.PSObject.Properties['Title'] -and $row.Title) {
            $adParams['Title'] = $row.Title
        }

        # Create the user.
        try {
            New-ADUser @adParams
            $entry.Status          = 'Created'
            $entry.InitialPassword = $plainPassword
        }
        catch {
            $entry.Status = 'Failed'
            $entry.Reason = $_.Exception.Message
            $report.Add($entry)
            Write-Warning "Failed to create '$sam': $($_.Exception.Message)"
            continue
        }

        # Add group memberships (semicolon-delimited).
        $groupReasons = [System.Collections.Generic.List[string]]::new()

        if ($row.PSObject.Properties['Groups'] -and $row.Groups.Trim()) {
            $groups = $row.Groups -split ';' |
                      Where-Object { $_.Trim() } |
                      ForEach-Object { $_.Trim() }

            foreach ($group in $groups) {
                try {
                    if ($PSCmdlet.ShouldProcess("$sam -> $group", 'Add to group')) {
                        Add-ADGroupMember -Identity $group -Members $sam
                    }
                }
                catch {
                    $groupReasons.Add("GroupFailed[$group]: $($_.Exception.Message)")
                    Write-Warning "Failed to add '$sam' to group '$group': $($_.Exception.Message)"
                }
            }
        }

        if ($groupReasons.Count -gt 0) {
            $entry.Reason = $groupReasons -join '; '
            # Created but one or more group-adds failed → Partial.
            if ($entry.Status -eq 'Created') {
                $entry.Status = 'Partial'
            }
        }

        $report.Add($entry)
    }

    # Emit all results to the pipeline (always includes InitialPassword in-memory).
    $report | ForEach-Object { Write-Output $_ }

    # Write CSV report if -OutputPath is given.
    if ($OutputPath) {
        if ($IncludePlainTextPasswords) {
            # Write to a temp file under the same directory (so Move-Item is a same-volume rename),
            # apply ACL hardening to the temp file, THEN atomically move it to $OutputPath.
            # This avoids a window where the credential file exists with inherited permissions.
            $finalPath = $OutputPath
            $outputDir = Split-Path -LiteralPath $finalPath
            if ([string]::IsNullOrEmpty($outputDir)) { $outputDir = '.' }
            $tempPath  = Join-Path $outputDir ('.' + [Guid]::NewGuid().ToString('N') + '.tmp')

            try {
                $report | Export-Csv -LiteralPath $tempPath -NoTypeInformation -Encoding UTF8

                try {
                    $acl = Get-Acl -LiteralPath $tempPath
                    $acl.SetAccessRuleProtection($true, $false)
                    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().User
                    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                        $currentUser,
                        [System.Security.AccessControl.FileSystemRights]::FullControl,
                        [System.Security.AccessControl.AccessControlType]::Allow
                    )
                    $acl.AddAccessRule($rule)
                    Set-Acl -LiteralPath $tempPath -AclObject $acl
                }
                catch {
                    Write-Warning "ACL hardening failed for '$tempPath': $($_.Exception.Message). Secure the file manually."
                }

                Move-Item -LiteralPath $tempPath -Destination $finalPath -Force
                Write-Warning "Plain-text initial passwords are in '$finalPath'. Restrict ACLs and delete promptly after secure handoff."
            }
            catch {
                # Cleanup temp on any export failure.
                if (Test-Path -LiteralPath $tempPath) {
                    Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
                }
                throw
            }
        }
        else {
            $redactedRows = $report | ForEach-Object {
                [PSCustomObject]@{
                    SamAccountName  = $_.SamAccountName
                    UPN             = $_.UPN
                    OU              = $_.OU
                    Status          = $_.Status
                    InitialPassword = ''
                    Reason          = $_.Reason
                }
            }
            $redactedRows | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
            Write-Warning "Plain-text initial passwords were redacted from the CSV report. Re-run with -IncludePlainTextPasswords to include them, and protect the file accordingly."
        }

        Write-Verbose "Report written to: $OutputPath"
    }
}
