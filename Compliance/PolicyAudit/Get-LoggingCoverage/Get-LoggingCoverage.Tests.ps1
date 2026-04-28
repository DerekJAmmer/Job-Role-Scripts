#requires -Version 7.2

BeforeAll {
    . (Join-Path $PSScriptRoot 'Get-LoggingCoverage.ps1')

    # ---------------------------------------------------------------------------
    # Helper: build a synthetic service object for Sysmon / Wecsvc mocking.
    # 'Get-' prefix avoids PSUseShouldProcessForStateChangingFunctions lint rule.
    # ---------------------------------------------------------------------------
    function Get-MockService {
        <#
        .SYNOPSIS
            Return a synthetic service PSObject for use in Pester mocks.
        #>
        param(
            [string]$DisplayName = 'MockSvc',
            [string]$Status      = 'Running'
        )
        [PSCustomObject]@{
            DisplayName = $DisplayName
            Status      = $Status
        }
    }

    # ---------------------------------------------------------------------------
    # Helper: standard "all enabled" mock wiring.
    # Encapsulated so individual describes can call it in their BeforeAll.
    # ---------------------------------------------------------------------------
    function Set-AllEnabledMocks {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pester fixture builder — pure function, no state change.')]
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Pester fixture builder — plural reflects multi-mock semantic.')]
        param()

        Mock Get-GLCRegistryValue {
            param($Path, $Name)
            switch ($Name) {
                'EnableScriptBlockLogging' { return 1 }
                'EnableModuleLogging'      { return 1 }
                'EnableTranscripting'      { return 1 }
                'OutputDirectory'          { return 'C:\Transcripts' }
            }
            return $null
        }
        Mock Test-Path    { return $true }
        Mock Get-Item     {
            $fakeItem = [PSCustomObject]@{ Property = @('*') }
            return $fakeItem
        }
        Mock Get-GLCService {
            param($Name)
            if ($Name -like 'Sysmon*') { return (Get-MockService -DisplayName 'Sysmon64' -Status 'Running') }
            if ($Name -eq 'Wecsvc')    { return (Get-MockService -DisplayName 'Windows Event Collector' -Status 'Running') }
            return $null
        }
        Mock Invoke-GLCWecutil { return "Subscription1`nSubscription2" }
    }
}

# ===========================================================================
# T1: All controls Enabled — 7 data rows + rollup = 8 total; rollup 100%
# ===========================================================================
Describe 'Get-LoggingCoverage — all Enabled' {
    BeforeAll {
        Set-AllEnabledMocks
    }

    It 'returns at least 8 rows (7 data + 1 rollup)' {
        $result = @(Get-LoggingCoverage)
        $result.Count | Should -BeGreaterOrEqual 8
    }

    It 'all non-rollup rows have Status=Enabled' {
        $result = @(Get-LoggingCoverage)
        $data   = $result | Where-Object { $_.Control -ne '__OverallScore' }
        $data | ForEach-Object { $_.Status | Should -Be 'Enabled' }
    }

    It 'rollup row Status is 100%' {
        $result  = @(Get-LoggingCoverage)
        $rollup  = $result | Where-Object { $_.Control -eq '__OverallScore' }
        $rollup.Status | Should -Be '100%'
    }
}

# ===========================================================================
# T2: All Disabled — every explicit-value check returns 0 / Stopped / empty
# ===========================================================================
Describe 'Get-LoggingCoverage — all Disabled' {
    BeforeAll {
        Mock Get-GLCRegistryValue {
            param($Path, $Name)
            switch ($Name) {
                'EnableScriptBlockLogging' { return 0 }
                'EnableModuleLogging'      { return 0 }
                'EnableTranscripting'      { return 0 }
                'OutputDirectory'          { return 0 }
            }
            return 0
        }
        Mock Get-GLCService {
            param($Name)
            if ($Name -like 'Sysmon*') { return (Get-MockService -DisplayName 'Sysmon64' -Status 'Stopped') }
            if ($Name -eq 'Wecsvc')    { return (Get-MockService -DisplayName 'Windows Event Collector' -Status 'Stopped') }
            return $null
        }
        Mock Invoke-GLCWecutil { return '' }
    }

    It 'non-rollup rows are Disabled (none Enabled)' {
        $result  = @(Get-LoggingCoverage)
        $data    = $result | Where-Object { $_.Control -ne '__OverallScore' }
        $enabled = @($data | Where-Object { $_.Status -eq 'Enabled' })
        $enabled.Count | Should -Be 0
    }

    It 'rollup row Status is 0%' {
        $result = @(Get-LoggingCoverage)
        $rollup = $result | Where-Object { $_.Control -eq '__OverallScore' }
        $rollup.Status | Should -Be '0%'
    }
}

# ===========================================================================
# T3: All Missing — registry returns $null, services return $null
# ===========================================================================
Describe 'Get-LoggingCoverage — all Missing' {
    BeforeAll {
        Mock Get-GLCRegistryValue { return $null }
        Mock Test-Path            { return $false }
        Mock Get-GLCService       { return $null }
        Mock Invoke-GLCWecutil    { return '' }
    }

    It 'ScriptBlock Logging row is Missing' {
        $result = @(Get-LoggingCoverage)
        $row    = $result | Where-Object { $_.Setting -eq 'EnableScriptBlockLogging' }
        $row.Status | Should -Be 'Missing'
    }

    It 'Module Logging row is Missing' {
        $result = @(Get-LoggingCoverage)
        $row    = $result | Where-Object { $_.Setting -eq 'EnableModuleLogging' }
        $row.Status | Should -Be 'Missing'
    }

    It 'Sysmon row is Missing' {
        $result = @(Get-LoggingCoverage)
        $row    = $result | Where-Object { $_.Setting -eq 'Sysmon Service' }
        $row.Status | Should -Be 'Missing'
    }

    It 'Wecsvc row is Missing' {
        $result = @(Get-LoggingCoverage)
        $row    = $result | Where-Object { $_.Setting -eq 'Wecsvc Service' }
        $row.Status | Should -Be 'Missing'
    }
}

# ===========================================================================
# T4: ScriptBlock Enabled, Module Disabled — statuses are independent
# ===========================================================================
Describe 'Get-LoggingCoverage — ScriptBlock Enabled, Module Disabled' {
    BeforeAll {
        Mock Get-GLCRegistryValue {
            param($Path, $Name)
            switch ($Name) {
                'EnableScriptBlockLogging' { return 1 }
                'EnableModuleLogging'      { return 0 }
                'EnableTranscripting'      { return 0 }
                'OutputDirectory'          { return $null }
            }
            return $null
        }
        Mock Test-Path         { return $false }
        Mock Get-GLCService    { return $null }
        Mock Invoke-GLCWecutil { return '' }
    }

    It 'ScriptBlock Logging row is Enabled' {
        $result = @(Get-LoggingCoverage)
        $row    = $result | Where-Object { $_.Setting -eq 'EnableScriptBlockLogging' }
        $row.Status | Should -Be 'Enabled'
    }

    It 'Module Logging row is Disabled' {
        $result = @(Get-LoggingCoverage)
        $row    = $result | Where-Object { $_.Setting -eq 'EnableModuleLogging' }
        $row.Status | Should -Be 'Disabled'
    }
}

# ===========================================================================
# T5: Transcription emits 2 rows with correct values
# ===========================================================================
Describe 'Get-LoggingCoverage — Transcription splits into 2 rows' {
    BeforeAll {
        Mock Get-GLCRegistryValue {
            param($Path, $Name)
            switch ($Name) {
                'EnableTranscripting' { return 1 }
                'OutputDirectory'     { return 'C:\Transcripts' }
                default               { return $null }
            }
        }
        Mock Test-Path         { return $false }
        Mock Get-GLCService    { return $null }
        Mock Invoke-GLCWecutil { return '' }
    }

    It 'Transcription EnableTranscripting row has Status=Enabled and Value=1' {
        $result = @(Get-LoggingCoverage)
        $row    = $result | Where-Object {
            $_.Control -eq 'PowerShell Transcription' -and $_.Setting -eq 'EnableTranscripting'
        }
        $row.Status | Should -Be 'Enabled'
        $row.Value  | Should -Be 1
    }

    It 'Transcription OutputDirectory row has Value=C:\Transcripts' {
        $result = @(Get-LoggingCoverage)
        $row    = $result | Where-Object {
            $_.Control -eq 'PowerShell Transcription' -and $_.Setting -eq 'OutputDirectory'
        }
        $row.Value | Should -Be 'C:\Transcripts'
    }

    It 'Transcription emits exactly 2 rows for the Transcription control' {
        $result = @(Get-LoggingCoverage)
        $rows   = @($result | Where-Object { $_.Control -eq 'PowerShell Transcription' })
        $rows.Count | Should -Be 2
    }
}

# ===========================================================================
# T6: Sysmon running — Status=Enabled, Value contains 'Running'
# ===========================================================================
Describe 'Get-LoggingCoverage — Sysmon running' {
    BeforeAll {
        Mock Get-GLCRegistryValue { return $null }
        Mock Test-Path            { return $false }
        Mock Get-GLCService {
            param($Name)
            if ($Name -like 'Sysmon*') {
                return (Get-MockService -DisplayName 'Sysmon64' -Status 'Running')
            }
            return $null
        }
        Mock Invoke-GLCWecutil { return '' }
    }

    It 'Sysmon Service row Status is Enabled' {
        $result = @(Get-LoggingCoverage)
        $row    = $result | Where-Object { $_.Setting -eq 'Sysmon Service' }
        $row.Status | Should -Be 'Enabled'
    }

    It 'Sysmon Service row Value contains Running' {
        $result = @(Get-LoggingCoverage)
        $row    = $result | Where-Object { $_.Setting -eq 'Sysmon Service' }
        $row.Value | Should -Match 'Running'
    }
}

# ===========================================================================
# T7: Sysmon stopped — Status=Disabled
# ===========================================================================
Describe 'Get-LoggingCoverage — Sysmon stopped' {
    BeforeAll {
        Mock Get-GLCRegistryValue { return $null }
        Mock Test-Path            { return $false }
        Mock Get-GLCService {
            param($Name)
            if ($Name -like 'Sysmon*') {
                return (Get-MockService -DisplayName 'Sysmon64' -Status 'Stopped')
            }
            return $null
        }
        Mock Invoke-GLCWecutil { return '' }
    }

    It 'Sysmon Service row Status is Disabled when service is stopped' {
        $result = @(Get-LoggingCoverage)
        $row    = $result | Where-Object { $_.Setting -eq 'Sysmon Service' }
        $row.Status | Should -Be 'Disabled'
    }
}

# ===========================================================================
# T8: Sysmon missing — Status=Missing, Value=NotInstalled
# ===========================================================================
Describe 'Get-LoggingCoverage — Sysmon missing' {
    BeforeAll {
        Mock Get-GLCRegistryValue { return $null }
        Mock Test-Path            { return $false }
        Mock Get-GLCService       { return $null }
        Mock Invoke-GLCWecutil    { return '' }
    }

    It 'Sysmon Service row Status is Missing when service not found' {
        $result = @(Get-LoggingCoverage)
        $row    = $result | Where-Object { $_.Setting -eq 'Sysmon Service' }
        $row.Status | Should -Be 'Missing'
    }

    It 'Sysmon Service row Value is NotInstalled when service not found' {
        $result = @(Get-LoggingCoverage)
        $row    = $result | Where-Object { $_.Setting -eq 'Sysmon Service' }
        $row.Value | Should -Be 'NotInstalled'
    }
}

# ===========================================================================
# T9: Wecsvc running + 2 subscriptions — both WEF rows Enabled
# ===========================================================================
Describe 'Get-LoggingCoverage — Wecsvc running with 2 subscriptions' {
    BeforeAll {
        Mock Get-GLCRegistryValue { return $null }
        Mock Test-Path            { return $false }
        Mock Get-GLCService {
            param($Name)
            if ($Name -like 'Sysmon*') { return $null }
            if ($Name -eq 'Wecsvc') {
                return (Get-MockService -DisplayName 'Windows Event Collector' -Status 'Running')
            }
            return $null
        }
        Mock Invoke-GLCWecutil { return "Subscription1`nSubscription2" }
    }

    It 'Wecsvc Service row is Enabled' {
        $result = @(Get-LoggingCoverage)
        $row    = $result | Where-Object { $_.Setting -eq 'Wecsvc Service' }
        $row.Status | Should -Be 'Enabled'
    }

    It 'WEF Subscriptions row is Enabled with count 2' {
        $result = @(Get-LoggingCoverage)
        $row    = $result | Where-Object { $_.Setting -eq 'WEF Subscriptions' }
        $row.Status | Should -Be 'Enabled'
        $row.Value  | Should -Be '2'
    }
}

# ===========================================================================
# T10: Wecsvc running but 0 subscriptions — service Enabled, subs Disabled
# ===========================================================================
Describe 'Get-LoggingCoverage — Wecsvc running, no subscriptions' {
    BeforeAll {
        Mock Get-GLCRegistryValue { return $null }
        Mock Test-Path            { return $false }
        Mock Get-GLCService {
            param($Name)
            if ($Name -like 'Sysmon*') { return $null }
            if ($Name -eq 'Wecsvc') {
                return (Get-MockService -DisplayName 'Windows Event Collector' -Status 'Running')
            }
            return $null
        }
        Mock Invoke-GLCWecutil { return '' }
    }

    It 'Wecsvc Service row is Enabled' {
        $result = @(Get-LoggingCoverage)
        $row    = $result | Where-Object { $_.Setting -eq 'Wecsvc Service' }
        $row.Status | Should -Be 'Enabled'
    }

    It 'WEF Subscriptions row is Disabled with Value=None' {
        $result = @(Get-LoggingCoverage)
        $row    = $result | Where-Object { $_.Setting -eq 'WEF Subscriptions' }
        $row.Status | Should -Be 'Disabled'
        $row.Value  | Should -Be 'None'
    }
}

# ===========================================================================
# T11: Wecsvc stopped + 0 subscriptions — both Disabled
# ===========================================================================
Describe 'Get-LoggingCoverage — Wecsvc stopped, no subscriptions' {
    BeforeAll {
        Mock Get-GLCRegistryValue { return $null }
        Mock Test-Path            { return $false }
        Mock Get-GLCService {
            param($Name)
            if ($Name -like 'Sysmon*') { return $null }
            if ($Name -eq 'Wecsvc') {
                return (Get-MockService -DisplayName 'Windows Event Collector' -Status 'Stopped')
            }
            return $null
        }
        Mock Invoke-GLCWecutil { return '' }
    }

    It 'Wecsvc Service row is Disabled when service is stopped' {
        $result = @(Get-LoggingCoverage)
        $row    = $result | Where-Object { $_.Setting -eq 'Wecsvc Service' }
        $row.Status | Should -Be 'Disabled'
    }

    It 'WEF Subscriptions row is Disabled when no subscriptions' {
        $result = @(Get-LoggingCoverage)
        $row    = $result | Where-Object { $_.Setting -eq 'WEF Subscriptions' }
        $row.Status | Should -Be 'Disabled'
    }
}

# ===========================================================================
# T12: Invoke-GLCWecutil throws — WEF Subscriptions row Status=Unknown + warning
# ===========================================================================
Describe 'Get-LoggingCoverage — Invoke-GLCWecutil throws' {
    BeforeAll {
        Mock Get-GLCRegistryValue { return $null }
        Mock Test-Path            { return $false }
        Mock Get-GLCService {
            param($Name)
            if ($Name -eq 'Wecsvc') {
                return (Get-MockService -DisplayName 'Windows Event Collector' -Status 'Running')
            }
            return $null
        }
        Mock Invoke-GLCWecutil { throw 'wecutil access denied' }
    }

    It 'WEF Subscriptions row Status is Unknown when wecutil throws' {
        $result = @(Get-LoggingCoverage)
        $row    = $result | Where-Object { $_.Setting -eq 'WEF Subscriptions' }
        $row.Status | Should -Be 'Unknown'
    }

    It 'emits a warning when wecutil throws' {
        $warnings = @()
        Get-LoggingCoverage -WarningVariable warnings | Out-Null
        ($warnings | Where-Object { $_ -match 'Invoke-GLCWecutil' }) | Should -Not -BeNullOrEmpty
    }
}

# ===========================================================================
# T13: -OutputPath writes CSV including the rollup row
# ===========================================================================
Describe 'Get-LoggingCoverage — OutputPath writes CSV' {
    BeforeAll {
        Set-AllEnabledMocks
    }

    It 'creates the CSV file at -OutputPath' {
        $csvPath = Join-Path $TestDrive 'logging.csv'
        Get-LoggingCoverage -OutputPath $csvPath | Out-Null
        Test-Path -LiteralPath $csvPath | Should -Be $true
    }

    It 'CSV contains the __OverallScore rollup row' {
        $csvPath = Join-Path $TestDrive 'logging-rollup.csv'
        Get-LoggingCoverage -OutputPath $csvPath | Out-Null
        $imported = Import-Csv -LiteralPath $csvPath
        ($imported | Where-Object { $_.Control -eq '__OverallScore' }) | Should -Not -BeNullOrEmpty
    }

    It 'CSV contains expected columns: Control, Setting, Value, Status' {
        $csvPath = Join-Path $TestDrive 'logging-cols.csv'
        Get-LoggingCoverage -OutputPath $csvPath | Out-Null
        $imported = Import-Csv -LiteralPath $csvPath
        $cols = $imported[0].PSObject.Properties.Name
        $cols | Should -Contain 'Control'
        $cols | Should -Contain 'Setting'
        $cols | Should -Contain 'Value'
        $cols | Should -Contain 'Status'
    }
}

# ===========================================================================
# T14: Rollup math — 3 Enabled out of 7 checks = 43%
# ===========================================================================
Describe 'Get-LoggingCoverage — rollup math 3 of 7' {
    BeforeAll {
        # SBL=Enabled(1), ModuleLog=Disabled(0), Transcription Enable=Disabled(0),
        # Transcription Dir=Disabled(0), Sysmon=Enabled(1),
        # Wecsvc=Enabled(1), WEF Subs=Disabled(0) => 3/7 = 43%
        Mock Get-GLCRegistryValue {
            param($Path, $Name)
            switch ($Name) {
                'EnableScriptBlockLogging' { return 1 }   # Enabled
                'EnableModuleLogging'      { return 0 }   # Disabled
                'EnableTranscripting'      { return 0 }   # Disabled
                'OutputDirectory'          { return 0 }   # Disabled
            }
            return $null
        }
        Mock Test-Path { return $false }
        Mock Get-GLCService {
            param($Name)
            if ($Name -like 'Sysmon*') {
                return (Get-MockService -DisplayName 'Sysmon64' -Status 'Running')  # Enabled
            }
            if ($Name -eq 'Wecsvc') {
                return (Get-MockService -DisplayName 'Windows Event Collector' -Status 'Running')  # Enabled
            }
            return $null
        }
        Mock Invoke-GLCWecutil { return '' }   # Disabled (0 subs)
    }

    It 'rollup Value is 3 / 7' {
        $result = @(Get-LoggingCoverage)
        $rollup = $result | Where-Object { $_.Control -eq '__OverallScore' }
        $rollup.Value | Should -Be '3 / 7'
    }

    It 'rollup Status is 43%' {
        $result = @(Get-LoggingCoverage)
        $rollup = $result | Where-Object { $_.Control -eq '__OverallScore' }
        $rollup.Status | Should -Be '43%'
    }
}

# ===========================================================================
# T15: Rollup row is the last row in the result set
# ===========================================================================
Describe 'Get-LoggingCoverage — rollup is the last row' {
    BeforeAll {
        Set-AllEnabledMocks
    }

    It '__OverallScore row is the last row emitted' {
        $result = @(Get-LoggingCoverage)
        $result[-1].Control | Should -Be '__OverallScore'
    }
}

# ===========================================================================
# T16: Module logging Enabled but ModuleNames empty — Value mentions 'ModuleNames empty'
# ===========================================================================
Describe 'Get-LoggingCoverage — Module logging Enabled but ModuleNames empty' {
    BeforeAll {
        Mock Get-GLCRegistryValue {
            param($Path, $Name)
            switch ($Name) {
                'EnableModuleLogging'      { return 1 }
                'EnableScriptBlockLogging' { return $null }
                'EnableTranscripting'      { return $null }
                'OutputDirectory'          { return $null }
            }
            return $null
        }
        # The ModuleNames subkey exists but has no properties.
        Mock Test-Path {
            param($LiteralPath)
            return $true
        }
        Mock Get-Item {
            [PSCustomObject]@{ Property = @() }
        }
        Mock Get-GLCService    { return $null }
        Mock Invoke-GLCWecutil { return '' }
    }

    It 'Module Logging row Status is still Enabled' {
        $result = @(Get-LoggingCoverage)
        $row    = $result | Where-Object { $_.Setting -eq 'EnableModuleLogging' }
        $row.Status | Should -Be 'Enabled'
    }

    It 'Module Logging row Value mentions ModuleNames empty' {
        $result = @(Get-LoggingCoverage)
        $row    = $result | Where-Object { $_.Setting -eq 'EnableModuleLogging' }
        $row.Value | Should -Match 'ModuleNames empty'
    }
}
