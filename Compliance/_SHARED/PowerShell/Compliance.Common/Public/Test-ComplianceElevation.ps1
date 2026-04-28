function Test-ComplianceElevation {
    <#
    .SYNOPSIS
        Returns $true if the current PowerShell session is elevated (Administrator).

    .DESCRIPTION
        Cross-platform-aware check. On Windows, queries the WindowsPrincipal for the
        Administrator role. On non-Windows, returns $true (scripts that require
        elevation should treat this as 'not applicable, proceed').

    .PARAMETER ThrowIfNotElevated
        If set, throws a terminating error when the session is not elevated.

    .EXAMPLE
        if (-not (Test-ComplianceElevation)) { Write-Warning 'Some checks will be skipped.' }

    .EXAMPLE
        Test-ComplianceElevation -ThrowIfNotElevated
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [switch]$ThrowIfNotElevated
    )

    $isElevated = $true
    if ($IsWindows -or $PSVersionTable.Platform -eq 'Win32NT' -or -not $PSVersionTable.Platform) {
        $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
        $isElevated = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    if (-not $isElevated -and $ThrowIfNotElevated) {
        throw 'This operation requires an elevated PowerShell session (Run as Administrator).'
    }

    return $isElevated
}
