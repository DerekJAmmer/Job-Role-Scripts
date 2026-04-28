@{
    RootModule        = 'SA.Common.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'b4d6e4a2-1f4f-4e2e-9a8e-0c0f7b5f1a11'
    Author            = 'UsefulScripts Portfolio'
    Description       = 'Shared helpers for SecurityAnalyst role scripts (logging, elevation, report emit, ATT&CK mapping).'
    PowerShellVersion = '7.2'
    FunctionsToExport = @('Write-SAReport', 'Test-SAElevation')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags         = @('security', 'soc', 'blueteam', 'attack')
            ProjectUri   = ''
            ReleaseNotes = 'Initial M0 skeleton.'
        }
    }
}
