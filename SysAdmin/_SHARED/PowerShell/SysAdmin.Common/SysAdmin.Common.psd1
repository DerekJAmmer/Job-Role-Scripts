@{
    RootModule        = 'SysAdmin.Common.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'c1e7a9f2-3b8d-4d11-9b2e-7f0e2a4c6d80'
    Author            = 'UsefulScripts Portfolio'
    Description       = 'Shared helpers for SysAdmin role scripts (logging, elevation, report emit).'
    PowerShellVersion = '7.2'
    FunctionsToExport = @('Write-SysAdminReport', 'Test-SysAdminElevation', 'Test-IsLocalHost')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags         = @('sysadmin', 'windows', 'ad', 'ops')
            ProjectUri   = ''
            ReleaseNotes = 'Initial M0 skeleton.'
        }
    }
}
