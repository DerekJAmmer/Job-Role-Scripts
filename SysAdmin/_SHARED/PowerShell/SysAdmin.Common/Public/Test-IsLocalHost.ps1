function Test-IsLocalHost {
    <#
    .SYNOPSIS
        Returns $true if the supplied name refers to the local machine.

    .DESCRIPTION
        Recognises '.', 'localhost', the bare NetBIOS name ($env:COMPUTERNAME),
        and any FQDN whose leftmost label matches the local NetBIOS name
        (e.g. 'WK01.corp.local' when running on WK01).

        An empty or whitespace-only name is treated as local (same convention
        as PowerShell remoting's implicit localhost).

    .PARAMETER Name
        The computer name to test. May be a NetBIOS name, FQDN, 'localhost',
        '.', or an empty string.

    .EXAMPLE
        Test-IsLocalHost -Name 'localhost'
        # Returns $true

    .EXAMPLE
        Test-IsLocalHost -Name 'WK01.corp.local'
        # Returns $true when $env:COMPUTERNAME is 'WK01'

    .EXAMPLE
        Test-IsLocalHost -Name 'OTHER-SRV'
        # Returns $false
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Name)) { return $true }
    $lower    = $Name.ToLower()
    $compName = $env:COMPUTERNAME.ToLower()
    if ($lower -in @('.', 'localhost', $compName)) { return $true }
    # FQDN whose left-most label matches the local short name.
    if ($lower.StartsWith("$compName.")) { return $true }
    return $false
}
