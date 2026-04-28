BeforeAll {
    $modulePath = Join-Path $PSScriptRoot 'Compliance.Common.psd1'
    Import-Module $modulePath -Force
}

AfterAll {
    Remove-Module Compliance.Common -ErrorAction SilentlyContinue
}

Describe 'Compliance.Common module' {
    It 'exports Write-ComplianceReport and Test-ComplianceElevation' {
        $exports = (Get-Module Compliance.Common).ExportedFunctions.Keys
        $exports | Should -Contain 'Write-ComplianceReport'
        $exports | Should -Contain 'Test-ComplianceElevation'
    }

    It 'Test-ComplianceElevation returns a boolean' {
        (Test-ComplianceElevation) | Should -BeOfType ([bool])
    }
}

Describe 'Write-ComplianceReport' {
    It 'writes JSON when given a .json OutFile' {
        $tmp = Join-Path $TestDrive 'out.json'
        $data = [pscustomobject]@{ Id = 1; Control = 'IA-5' },
                [pscustomobject]@{ Id = 2; Control = 'AU-2' }
        $data | Write-ComplianceReport -OutFile $tmp -InformationAction SilentlyContinue
        Test-Path $tmp | Should -BeTrue
        $round = Get-Content $tmp -Raw | ConvertFrom-Json
        $round.Count | Should -Be 2
    }

    It 'writes CSV when given a .csv OutFile' {
        $tmp = Join-Path $TestDrive 'out.csv'
        $data = [pscustomobject]@{ Control = 'AU-2'; Status = 'Pass' }
        $data | Write-ComplianceReport -OutFile $tmp -InformationAction SilentlyContinue
        (Get-Content $tmp | Select-Object -First 1) | Should -Match 'Control.*Status'
    }

    It 'throws on unsupported extension' {
        $tmp = Join-Path $TestDrive 'out.xyz'
        $data = [pscustomobject]@{ A = 1 }
        { $data | Write-ComplianceReport -OutFile $tmp -InformationAction SilentlyContinue } |
            Should -Throw -ExpectedMessage '*Unsupported output extension*'
    }

    It 'HTML-encodes a script-tag title — raw <script> tag must not appear in the output' {
        $tmp  = Join-Path $TestDrive 'xss-test.html'
        $data = [pscustomobject]@{ Host = 'srv1'; Status = 'OK' }
        $data | Write-ComplianceReport -OutFile $tmp -Title '<script>alert(1)</script>' -InformationAction SilentlyContinue
        $html = Get-Content $tmp -Raw
        $html | Should -Not -Match ([regex]::Escape('<script>alert(1)</script>'))
        $html | Should -Match ([regex]::Escape('&lt;script&gt;'))
    }

    It 'plain title passes through unescaped in HTML output' {
        $tmp  = Join-Path $TestDrive 'plain-title.html'
        $data = [pscustomobject]@{ Host = 'srv1'; Status = 'OK' }
        $data | Write-ComplianceReport -OutFile $tmp -Title 'Compliance Audit Report' -InformationAction SilentlyContinue
        $html = Get-Content $tmp -Raw
        $html | Should -Match 'Compliance Audit Report'
    }

    It 'emits no-findings message and returns when collection is empty' {
        $tmp = Join-Path $TestDrive 'empty.json'
        $result = @() | Write-ComplianceReport -OutFile $tmp -InformationAction SilentlyContinue
        Test-Path $tmp | Should -BeFalse
        $result | Should -BeNullOrEmpty
    }
}
