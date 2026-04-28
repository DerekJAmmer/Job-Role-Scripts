BeforeAll {
    $modulePath = Join-Path $PSScriptRoot 'SysAdmin.Common.psd1'
    Import-Module $modulePath -Force
}

AfterAll {
    Remove-Module SysAdmin.Common -ErrorAction SilentlyContinue
}

Describe 'SysAdmin.Common module' {
    It 'exports Write-SysAdminReport and Test-SysAdminElevation' {
        $exports = (Get-Module SysAdmin.Common).ExportedFunctions.Keys
        $exports | Should -Contain 'Write-SysAdminReport'
        $exports | Should -Contain 'Test-SysAdminElevation'
    }

    It 'exports Test-IsLocalHost' {
        $exports = (Get-Module SysAdmin.Common).ExportedFunctions.Keys
        $exports | Should -Contain 'Test-IsLocalHost'
    }

    It 'Test-SysAdminElevation returns a boolean' {
        (Test-SysAdminElevation) | Should -BeOfType ([bool])
    }
}

Describe 'Write-SysAdminReport' {
    It 'writes JSON when given a .json OutFile' {
        $tmp = Join-Path $TestDrive 'out.json'
        $data = [pscustomobject]@{ Id = 1; Msg = 'hi' },
                [pscustomobject]@{ Id = 2; Msg = 'there' }
        $data | Write-SysAdminReport -OutFile $tmp -InformationAction SilentlyContinue
        Test-Path $tmp | Should -BeTrue
        $round = Get-Content $tmp -Raw | ConvertFrom-Json
        $round.Count | Should -Be 2
    }

    It 'writes CSV when given a .csv OutFile' {
        $tmp = Join-Path $TestDrive 'out.csv'
        $data = [pscustomobject]@{ A = 1; B = 'x' }
        $data | Write-SysAdminReport -OutFile $tmp -InformationAction SilentlyContinue
        (Get-Content $tmp | Select-Object -First 1) | Should -Match 'A.*B'
    }

    It 'throws on unsupported extension' {
        $tmp = Join-Path $TestDrive 'out.xyz'
        $data = [pscustomobject]@{ A = 1 }
        { $data | Write-SysAdminReport -OutFile $tmp -InformationAction SilentlyContinue } |
            Should -Throw -ExpectedMessage '*Unsupported output extension*'
    }

    It 'HTML-encodes a script-tag title — raw <script> tag must not appear in the output' {
        $tmp  = Join-Path $TestDrive 'xss-test.html'
        $data = [pscustomobject]@{ Host = 'srv1'; Status = 'OK' }
        $data | Write-SysAdminReport -OutFile $tmp -Title '<script>alert(1)</script>' -InformationAction SilentlyContinue
        $html = Get-Content $tmp -Raw
        $html | Should -Not -Match ([regex]::Escape('<script>alert(1)</script>'))
        $html | Should -Match ([regex]::Escape('&lt;script&gt;'))
    }

    It 'plain title passes through unescaped in HTML output' {
        $tmp  = Join-Path $TestDrive 'plain-title.html'
        $data = [pscustomobject]@{ Host = 'srv1'; Status = 'OK' }
        $data | Write-SysAdminReport -OutFile $tmp -Title 'Server Inventory' -InformationAction SilentlyContinue
        $html = Get-Content $tmp -Raw
        $html | Should -Match 'Server Inventory'
    }
}

Describe 'Test-IsLocalHost' {
    It "returns `$true for '.'" {
        Test-IsLocalHost -Name '.' | Should -Be $true
    }

    It "returns `$true for 'localhost'" {
        Test-IsLocalHost -Name 'localhost' | Should -Be $true
    }

    It "returns `$true for `$env:COMPUTERNAME (bare NetBIOS name)" {
        Test-IsLocalHost -Name $env:COMPUTERNAME | Should -Be $true
    }

    It "returns `$true for an FQDN whose leftmost label matches `$env:COMPUTERNAME" {
        $fqdn = "$($env:COMPUTERNAME).corp.local"
        Test-IsLocalHost -Name $fqdn | Should -Be $true
    }

    It "returns `$false for a distinct remote host name" {
        Test-IsLocalHost -Name 'OTHER-SRV' | Should -Be $false
    }

    It "returns `$true for an empty string" {
        Test-IsLocalHost -Name '' | Should -Be $true
    }
}
