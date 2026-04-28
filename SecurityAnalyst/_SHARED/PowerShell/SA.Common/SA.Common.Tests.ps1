BeforeAll {
    $modulePath = Join-Path $PSScriptRoot 'SA.Common.psd1'
    Import-Module $modulePath -Force
}

AfterAll {
    Remove-Module SA.Common -ErrorAction SilentlyContinue
}

Describe 'SA.Common module' {
    It 'exports Write-SAReport and Test-SAElevation' {
        $exports = (Get-Module SA.Common).ExportedFunctions.Keys
        $exports | Should -Contain 'Write-SAReport'
        $exports | Should -Contain 'Test-SAElevation'
    }

    It 'Test-SAElevation returns a boolean' {
        (Test-SAElevation) | Should -BeOfType ([bool])
    }
}

Describe 'Write-SAReport' {
    It 'writes JSON when given a .json OutFile' {
        $tmp = Join-Path $TestDrive 'out.json'
        $data = [pscustomobject]@{ Id = 1; Msg = 'hi' },
                [pscustomobject]@{ Id = 2; Msg = 'there' }
        $data | Write-SAReport -OutFile $tmp -InformationAction SilentlyContinue
        Test-Path $tmp | Should -BeTrue
        $round = Get-Content $tmp -Raw | ConvertFrom-Json
        $round.Count | Should -Be 2
    }

    It 'writes CSV when given a .csv OutFile' {
        $tmp = Join-Path $TestDrive 'out.csv'
        $data = [pscustomobject]@{ A = 1; B = 'x' }
        $data | Write-SAReport -OutFile $tmp -InformationAction SilentlyContinue
        (Get-Content $tmp | Select-Object -First 1) | Should -Match 'A.*B'
    }

    It 'throws on unsupported extension' {
        $tmp = Join-Path $TestDrive 'out.xyz'
        $data = [pscustomobject]@{ A = 1 }
        { $data | Write-SAReport -OutFile $tmp -InformationAction SilentlyContinue } |
            Should -Throw -ExpectedMessage '*Unsupported output extension*'
    }
}
