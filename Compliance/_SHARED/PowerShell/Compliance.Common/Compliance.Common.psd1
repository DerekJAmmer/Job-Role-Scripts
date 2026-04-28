@{
    RootModule        = 'Compliance.Common.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '592f30e5-12da-4abb-a258-8eb0a9d2a7a4'
    Author            = 'UsefulScripts Portfolio'
    Description       = 'Shared utilities for Compliance/Auditor role scripts (reporting, elevation checks, baseline helpers).'
    PowerShellVersion = '7.2'
    FunctionsToExport = @('Write-ComplianceReport', 'Test-ComplianceElevation')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags         = @('compliance', 'audit', 'windows', 'nist', 'cis', 'stig')
            ProjectUri   = ''
            ReleaseNotes = 'Initial M0 skeleton.'
        }
    }
}
