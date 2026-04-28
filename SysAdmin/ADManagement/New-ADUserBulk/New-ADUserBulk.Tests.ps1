#requires -Version 7.2

BeforeAll {
    . (Join-Path $PSScriptRoot 'New-ADUserBulk.ps1')

    # Helper: write a CSV to TestDrive and return the path.
    function Export-TestCsv {
        param(
            [string]$Name = 'users.csv',
            [string]$Content
        )
        $path = Join-Path $TestDrive $Name
        Set-Content -Path $path -Value $Content -Encoding UTF8
        return $path
    }

    # Full valid header for convenience.
    $script:validHeader = 'GivenName,Surname,SamAccountName,UserPrincipalName,OU,Groups,Department,Title'
}

# ---------------------------------------------------------------------------
# T1: Throws on missing CsvPath
# ---------------------------------------------------------------------------
Describe 'New-ADUserBulk — missing CsvPath' {
    It 'throws when the CSV file does not exist' {
        { New-ADUserBulk -CsvPath 'C:\NoSuchFile_xyz.csv' } | Should -Throw
    }
}

# ---------------------------------------------------------------------------
# T2-T3: Header validation
# ---------------------------------------------------------------------------
Describe 'New-ADUserBulk — header validation' {
    It 'throws when SamAccountName column is missing' {
        $csv = Export-TestCsv -Name 'no-sam.csv' -Content @"
GivenName,Surname,UserPrincipalName,OU,Groups,Department,Title
Alice,Smith,alice@corp.local,OU=Staff,DC=corp,DC=local,,IT,Engineer
"@
        { New-ADUserBulk -CsvPath $csv } | Should -Throw -ExpectedMessage "*SamAccountName*"
    }

    It 'throws when UserPrincipalName column is missing' {
        $csv = Export-TestCsv -Name 'no-upn.csv' -Content @"
GivenName,Surname,SamAccountName,OU,Groups,Department,Title
Alice,Smith,asmith,OU=Staff,DC=corp,DC=local,,IT,Engineer
"@
        { New-ADUserBulk -CsvPath $csv } | Should -Throw -ExpectedMessage "*UserPrincipalName*"
    }

    It 'does not throw when both required columns are present' {
        Mock Get-ADUser { return $null }
        Mock New-ADUser { }
        $csv = Export-TestCsv -Name 'valid-header.csv' -Content @"
$script:validHeader
Alice,Smith,asmith,alice@corp.local,OU=Staff DC=corp DC=local,,IT,Engineer
"@
        { New-ADUserBulk -CsvPath $csv -DefaultOU 'OU=Staff,DC=corp,DC=local' -WhatIf } | Should -Not -Throw
    }
}

# ---------------------------------------------------------------------------
# T4: Existing user → Skipped, New-ADUser not called
# ---------------------------------------------------------------------------
Describe 'New-ADUserBulk — existing user skipped' {
    BeforeAll {
        Mock Get-ADUser { return [PSCustomObject]@{ SamAccountName = 'asmith' } }
        Mock New-ADUser { }
    }

    It 'records Status=Skipped when user already exists' {
        $csv = Export-TestCsv -Name 'existing.csv' -Content @"
$script:validHeader
Alice,Smith,asmith,alice@corp.local,OU=Staff DC=corp DC=local,,IT,Engineer
"@
        $result = @(New-ADUserBulk -CsvPath $csv)
        $result[0].Status | Should -Be 'Skipped'
    }

    It 'records Reason=AlreadyExists when user already exists' {
        $csv = Export-TestCsv -Name 'existing2.csv' -Content @"
$script:validHeader
Alice,Smith,asmith,alice@corp.local,OU=Staff DC=corp DC=local,,IT,Engineer
"@
        $result = @(New-ADUserBulk -CsvPath $csv)
        $result[0].Reason | Should -Be 'AlreadyExists'
    }

    It 'does not call New-ADUser when user already exists' {
        $csv = Export-TestCsv -Name 'existing3.csv' -Content @"
$script:validHeader
Alice,Smith,asmith,alice@corp.local,OU=Staff DC=corp DC=local,,IT,Engineer
"@
        New-ADUserBulk -CsvPath $csv | Out-Null
        Should -Invoke New-ADUser -Times 0 -Exactly
    }
}

# ---------------------------------------------------------------------------
# T5: Happy path — new user created
# ---------------------------------------------------------------------------
Describe 'New-ADUserBulk — happy path new user' {
    BeforeAll {
        Mock Get-ADUser { return $null }
        Mock New-ADUser { }
        Mock Add-ADGroupMember { }
    }

    It 'calls New-ADUser exactly once for a new user' {
        $csv = Export-TestCsv -Name 'new-user.csv' -Content @"
$script:validHeader
Bob,Jones,bjones,bob@corp.local,OU=Staff DC=corp DC=local,,HR,Analyst
"@
        New-ADUserBulk -CsvPath $csv | Out-Null
        Should -Invoke New-ADUser -Times 1 -Exactly -ParameterFilter { $SamAccountName -eq 'bjones' }
    }

    It 'records Status=Created for a successfully created user' {
        $csv = Export-TestCsv -Name 'new-user2.csv' -Content @"
$script:validHeader
Bob,Jones,bjones,bob@corp.local,OU=Staff DC=corp DC=local,,HR,Analyst
"@
        $result = @(New-ADUserBulk -CsvPath $csv)
        $result[0].Status | Should -Be 'Created'
    }
}

# ---------------------------------------------------------------------------
# T6: Group membership — two groups → Add-ADGroupMember called twice
# ---------------------------------------------------------------------------
Describe 'New-ADUserBulk — group membership' {
    BeforeAll {
        Mock Get-ADUser { return $null }
        Mock New-ADUser { }
        Mock Add-ADGroupMember { }
    }

    It 'calls Add-ADGroupMember once per group in semicolon-delimited Groups column' {
        $csv = Export-TestCsv -Name 'groups.csv' -Content @"
$script:validHeader
Carol,White,cwhite,carol@corp.local,OU=Staff DC=corp DC=local,G1;G2,IT,Admin
"@
        New-ADUserBulk -CsvPath $csv | Out-Null
        Should -Invoke Add-ADGroupMember -Times 2 -Exactly
    }
}

# ---------------------------------------------------------------------------
# T7: Empty Groups column → Add-ADGroupMember not called
# ---------------------------------------------------------------------------
Describe 'New-ADUserBulk — empty groups column' {
    BeforeAll {
        Mock Get-ADUser { return $null }
        Mock New-ADUser { }
        Mock Add-ADGroupMember { }
    }

    It 'does not call Add-ADGroupMember when Groups column is empty' {
        $csv = Export-TestCsv -Name 'no-groups.csv' -Content @"
$script:validHeader
Dave,Black,dblack,dave@corp.local,OU=Staff DC=corp DC=local,,Finance,Analyst
"@
        New-ADUserBulk -CsvPath $csv | Out-Null
        Should -Invoke Add-ADGroupMember -Times 0 -Exactly
    }
}

# ---------------------------------------------------------------------------
# T8: New-ADUser throws → Status=Failed, processing continues
# ---------------------------------------------------------------------------
Describe 'New-ADUserBulk — New-ADUser failure' {
    BeforeAll {
        Mock Get-ADUser { return $null }
        Mock New-ADUser { throw 'Simulated AD error' }
        Mock Add-ADGroupMember { }
    }

    It 'records Status=Failed when New-ADUser throws' {
        $csv = Export-TestCsv -Name 'fail.csv' -Content @"
$script:validHeader
Eve,Green,egreen,eve@corp.local,OU=Staff DC=corp DC=local,,Ops,Engineer
"@
        $result = @(New-ADUserBulk -CsvPath $csv)
        $result[0].Status | Should -Be 'Failed'
    }

    It 'includes the error message in Reason when New-ADUser throws' {
        $csv = Export-TestCsv -Name 'fail2.csv' -Content @"
$script:validHeader
Eve,Green,egreen,eve@corp.local,OU=Staff DC=corp DC=local,,Ops,Engineer
"@
        $result = @(New-ADUserBulk -CsvPath $csv)
        $result[0].Reason | Should -Match 'Simulated AD error'
    }

    It 'continues processing the next row after a failure' {
        Mock Get-ADUser { return $null }
        Mock New-ADUser {
            if ($SamAccountName -eq 'fail1') { throw 'Simulated AD error' }
        }
        $csv = Export-TestCsv -Name 'fail-continue.csv' -Content @"
$script:validHeader
Eve,Green,fail1,fail1@corp.local,OU=Staff DC=corp DC=local,,Ops,Engineer
Frank,Blue,frank2,frank2@corp.local,OU=Staff DC=corp DC=local,,Ops,Admin
"@
        $result = @(New-ADUserBulk -CsvPath $csv)
        $result.Count | Should -Be 2
        $result[1].Status | Should -Be 'Created'
    }
}

# ---------------------------------------------------------------------------
# T9: -WhatIf mode → Status=WhatIf, New-ADUser not called
# ---------------------------------------------------------------------------
Describe 'New-ADUserBulk — WhatIf mode' {
    BeforeAll {
        Mock Get-ADUser { return $null }
        Mock New-ADUser { }
        Mock Add-ADGroupMember { }
    }

    It 'records Status=WhatIf when -WhatIf is supplied' {
        $csv = Export-TestCsv -Name 'whatif.csv' -Content @"
$script:validHeader
Grace,Hall,ghall,grace@corp.local,OU=Staff DC=corp DC=local,,Legal,Counsel
"@
        $result = @(New-ADUserBulk -CsvPath $csv -WhatIf)
        $result[0].Status | Should -Be 'WhatIf'
    }

    It 'does not call New-ADUser when -WhatIf is supplied' {
        $csv = Export-TestCsv -Name 'whatif2.csv' -Content @"
$script:validHeader
Grace,Hall,ghall,grace@corp.local,OU=Staff DC=corp DC=local,,Legal,Counsel
"@
        New-ADUserBulk -CsvPath $csv -WhatIf | Out-Null
        Should -Invoke New-ADUser -Times 0 -Exactly
    }
}

# ---------------------------------------------------------------------------
# T10: OU resolution — row OU empty + DefaultOU set → uses DefaultOU
# ---------------------------------------------------------------------------
Describe 'New-ADUserBulk — OU resolution: DefaultOU fallback' {
    BeforeAll {
        Mock Get-ADUser { return $null }
        Mock New-ADUser { }
    }

    It 'uses DefaultOU when row OU column is empty' {
        $csv = Export-TestCsv -Name 'ou-default.csv' -Content @"
$script:validHeader
Henry,Ford,hford,henry@corp.local,,,Marketing,Director
"@
        $result = @(New-ADUserBulk -CsvPath $csv -DefaultOU 'OU=Marketing,DC=corp,DC=local')
        $result[0].OU | Should -Be 'OU=Marketing,DC=corp,DC=local'
    }
}

# ---------------------------------------------------------------------------
# T11: OU resolution — row OU empty + DefaultOU empty → Status=Failed
# ---------------------------------------------------------------------------
Describe 'New-ADUserBulk — OU resolution: no OU anywhere' {
    BeforeAll {
        Mock Get-ADUser { return $null }
        Mock New-ADUser { }
    }

    It 'records Status=Failed with Reason containing NoOU when no OU is available' {
        $csv = Export-TestCsv -Name 'no-ou.csv' -Content @"
$script:validHeader
Ida,Lake,ilake,ida@corp.local,,,Sales,Rep
"@
        $result = @(New-ADUserBulk -CsvPath $csv)
        $result[0].Status | Should -Be 'Failed'
        $result[0].Reason | Should -Match 'NoOU'
    }
}

# ---------------------------------------------------------------------------
# T12: OU resolution — row OU set → uses row OU even if DefaultOU set
# ---------------------------------------------------------------------------
Describe 'New-ADUserBulk — OU resolution: row OU takes precedence' {
    BeforeAll {
        Mock Get-ADUser { return $null }
        Mock New-ADUser { }
    }

    It 'uses the row OU column when both row OU and DefaultOU are supplied' {
        $csv = Export-TestCsv -Name 'ou-row.csv' -Content @"
$script:validHeader
Jack,Moss,jmoss,jack@corp.local,OU=Exec DC=corp DC=local,,Exec,VP
"@
        $result = @(New-ADUserBulk -CsvPath $csv -DefaultOU 'OU=Staff,DC=corp,DC=local')
        $result[0].OU | Should -Be 'OU=Exec DC=corp DC=local'
    }
}

# ---------------------------------------------------------------------------
# T13-T15: Get-NABRandomPassword
# ---------------------------------------------------------------------------
Describe 'Get-NABRandomPassword' {
    It 'returns a string of the requested length' {
        $pw = Get-NABRandomPassword -Length 20
        $pw.Length | Should -Be 20
    }

    It 'contains at least one uppercase letter' {
        $pw = Get-NABRandomPassword -Length 16
        $pw -cmatch '[A-Z]' | Should -Be $true
    }

    It 'contains at least one lowercase letter' {
        $pw = Get-NABRandomPassword -Length 16
        $pw -cmatch '[a-z]' | Should -Be $true
    }

    It 'contains at least one digit' {
        $pw = Get-NABRandomPassword -Length 16
        $pw -match '[0-9]' | Should -Be $true
    }

    It 'contains at least one symbol' {
        $pw = Get-NABRandomPassword -Length 16
        $pw -match '[!@#$%^&*()\-_=+]' | Should -Be $true
    }

    It 'returns different values on successive calls' {
        $pw1 = Get-NABRandomPassword -Length 16
        $pw2 = Get-NABRandomPassword -Length 16
        $pw1 | Should -Not -Be $pw2
    }
}

# ---------------------------------------------------------------------------
# T16: Output CSV written when -OutputPath is given
# ---------------------------------------------------------------------------
Describe 'New-ADUserBulk — OutputPath' {
    BeforeAll {
        Mock Get-ADUser { return $null }
        Mock New-ADUser { }
    }

    It 'writes a CSV file to -OutputPath when the parameter is supplied' {
        $csv    = Export-TestCsv -Name 'out-source.csv' -Content @"
$script:validHeader
Karl,Stone,kstone,karl@corp.local,OU=Staff DC=corp DC=local,,IT,Admin
"@
        $report = Join-Path $TestDrive 'report.csv'
        New-ADUserBulk -CsvPath $csv -OutputPath $report | Out-Null
        Test-Path -LiteralPath $report | Should -Be $true
    }
}

# ---------------------------------------------------------------------------
# T17: Multi-row — 1 created, 1 skipped, 1 failed
# ---------------------------------------------------------------------------
Describe 'New-ADUserBulk — multi-row processing' {
    BeforeAll {
        Mock Get-ADUser {
            if ($Identity -eq 'existing') { return [PSCustomObject]@{ SamAccountName = 'existing' } }
            return $null
        }
        Mock New-ADUser {
            if ($SamAccountName -eq 'willfail') { throw 'AD creation error' }
        }
        Mock Add-ADGroupMember { }
    }

    It 'processes all three rows and returns three result objects' {
        $csv = Export-TestCsv -Name 'multi.csv' -Content @"
$script:validHeader
New,User,newuser,new@corp.local,OU=Staff DC=corp DC=local,,IT,Admin
Old,User,existing,old@corp.local,OU=Staff DC=corp DC=local,,IT,Analyst
Bad,User,willfail,bad@corp.local,OU=Staff DC=corp DC=local,,IT,Dev
"@
        $result = @(New-ADUserBulk -CsvPath $csv)
        $result.Count | Should -Be 3
    }

    It 'first row is Created in multi-row scenario' {
        $csv = Export-TestCsv -Name 'multi2.csv' -Content @"
$script:validHeader
New,User,newuser,new@corp.local,OU=Staff DC=corp DC=local,,IT,Admin
Old,User,existing,old@corp.local,OU=Staff DC=corp DC=local,,IT,Analyst
Bad,User,willfail,bad@corp.local,OU=Staff DC=corp DC=local,,IT,Dev
"@
        $result = @(New-ADUserBulk -CsvPath $csv)
        $result[0].Status | Should -Be 'Created'
    }

    It 'second row is Skipped in multi-row scenario' {
        $csv = Export-TestCsv -Name 'multi3.csv' -Content @"
$script:validHeader
New,User,newuser,new@corp.local,OU=Staff DC=corp DC=local,,IT,Admin
Old,User,existing,old@corp.local,OU=Staff DC=corp DC=local,,IT,Analyst
Bad,User,willfail,bad@corp.local,OU=Staff DC=corp DC=local,,IT,Dev
"@
        $result = @(New-ADUserBulk -CsvPath $csv)
        $result[1].Status | Should -Be 'Skipped'
    }

    It 'third row is Failed in multi-row scenario' {
        $csv = Export-TestCsv -Name 'multi4.csv' -Content @"
$script:validHeader
New,User,newuser,new@corp.local,OU=Staff DC=corp DC=local,,IT,Admin
Old,User,existing,old@corp.local,OU=Staff DC=corp DC=local,,IT,Analyst
Bad,User,willfail,bad@corp.local,OU=Staff DC=corp DC=local,,IT,Dev
"@
        $result = @(New-ADUserBulk -CsvPath $csv)
        $result[2].Status | Should -Be 'Failed'
    }
}

# ---------------------------------------------------------------------------
# T18: InitialPassword only populated for Created rows
# ---------------------------------------------------------------------------
Describe 'New-ADUserBulk — InitialPassword field' {
    BeforeAll {
        Mock Get-ADUser {
            if ($Identity -eq 'skipme') { return [PSCustomObject]@{ SamAccountName = 'skipme' } }
            return $null
        }
        Mock New-ADUser { }
    }

    It 'InitialPassword is populated for Created rows' {
        $csv = Export-TestCsv -Name 'pw-created.csv' -Content @"
$script:validHeader
Laura,Day,lday,laura@corp.local,OU=Staff DC=corp DC=local,,IT,Admin
"@
        $result = @(New-ADUserBulk -CsvPath $csv)
        $result[0].InitialPassword | Should -Not -BeNullOrEmpty
    }

    It 'InitialPassword is empty for Skipped rows' {
        $csv = Export-TestCsv -Name 'pw-skipped.csv' -Content @"
$script:validHeader
Old,User,skipme,old@corp.local,OU=Staff DC=corp DC=local,,IT,Analyst
"@
        $result = @(New-ADUserBulk -CsvPath $csv)
        $result[0].InitialPassword | Should -BeNullOrEmpty
    }

    It 'InitialPassword is empty for Failed rows (no OU)' {
        $csv = Export-TestCsv -Name 'pw-failed.csv' -Content @"
$script:validHeader
Bad,User,baduser,bad@corp.local,,,IT,Dev
"@
        $result = @(New-ADUserBulk -CsvPath $csv)
        $result[0].InitialPassword | Should -BeNullOrEmpty
    }
}

# ===========================================================================
# NEW TESTS — Changes introduced in this revision
# ===========================================================================

# ---------------------------------------------------------------------------
# N1: Get-ADUser called with -Identity (filter injection fix)
# ---------------------------------------------------------------------------
Describe 'New-ADUserBulk — Get-ADUser uses -Identity not -Filter' {
    BeforeAll {
        Mock Get-ADUser { return $null }
        Mock New-ADUser { }
    }

    It 'invokes Get-ADUser with -Identity matching the SamAccountName' {
        $csv = Export-TestCsv -Name 'identity-check.csv' -Content @"
$script:validHeader
Alice,Smith,asmith,alice@corp.local,OU=Staff DC=corp DC=local,,IT,Engineer
"@
        New-ADUserBulk -CsvPath $csv | Out-Null
        Should -Invoke Get-ADUser -ParameterFilter { $Identity -eq 'asmith' }
    }
}

# ---------------------------------------------------------------------------
# N2: SAM with single quote — no filter injection, user created
# ---------------------------------------------------------------------------
Describe "New-ADUserBulk — SAM with single quote (o'connor)" {
    BeforeAll {
        Mock Get-ADUser { throw 'not found' }
        Mock New-ADUser { }
    }

    It "does not throw on existence-check for SAM containing a single quote" {
        $csv = Export-TestCsv -Name 'singlequote.csv' -Content @"
$script:validHeader
Owen,Connor,o'connor,oconnor@corp.local,OU=Staff DC=corp DC=local,,IT,Analyst
"@
        { New-ADUserBulk -CsvPath $csv } | Should -Not -Throw
    }

    It "calls New-ADUser with the quoted SAM account name" {
        $csv = Export-TestCsv -Name 'singlequote2.csv' -Content @"
$script:validHeader
Owen,Connor,o'connor,oconnor@corp.local,OU=Staff DC=corp DC=local,,IT,Analyst
"@
        New-ADUserBulk -CsvPath $csv | Out-Null
        Should -Invoke New-ADUser -Times 1 -Exactly -ParameterFilter { $SamAccountName -eq "o'connor" }
    }
}

# ---------------------------------------------------------------------------
# N3: Group-add partial failure → Status=Partial
# ---------------------------------------------------------------------------
Describe 'New-ADUserBulk — group-add partial failure' {
    BeforeAll {
        Mock Get-ADUser { return $null }
        Mock New-ADUser { }
        Mock Add-ADGroupMember -ParameterFilter { $Identity -eq 'BadGroup' } { throw 'no such group' }
        Mock Add-ADGroupMember -ParameterFilter { $Identity -eq 'GoodGroup' } { }
    }

    It 'sets Status=Partial when one group-add fails but user was created' {
        $csv = Export-TestCsv -Name 'partial.csv' -Content @"
$script:validHeader
Alice,Smith,asmith,alice@corp.local,OU=Staff DC=corp DC=local,GoodGroup;BadGroup,IT,Engineer
"@
        $result = @(New-ADUserBulk -CsvPath $csv)
        $result[0].Status | Should -Be 'Partial'
    }

    It 'still calls New-ADUser once even when a group-add fails' {
        $csv = Export-TestCsv -Name 'partial2.csv' -Content @"
$script:validHeader
Alice,Smith,asmith,alice@corp.local,OU=Staff DC=corp DC=local,GoodGroup;BadGroup,IT,Engineer
"@
        New-ADUserBulk -CsvPath $csv | Out-Null
        Should -Invoke New-ADUser -Times 1 -Exactly
    }

    It 'calls Add-ADGroupMember twice (once per group)' {
        $csv = Export-TestCsv -Name 'partial3.csv' -Content @"
$script:validHeader
Alice,Smith,asmith,alice@corp.local,OU=Staff DC=corp DC=local,GoodGroup;BadGroup,IT,Engineer
"@
        New-ADUserBulk -CsvPath $csv | Out-Null
        Should -Invoke Add-ADGroupMember -Times 2 -Exactly
    }

    It 'includes the failed group name in Reason' {
        $csv = Export-TestCsv -Name 'partial4.csv' -Content @"
$script:validHeader
Alice,Smith,asmith,alice@corp.local,OU=Staff DC=corp DC=local,GoodGroup;BadGroup,IT,Engineer
"@
        $result = @(New-ADUserBulk -CsvPath $csv)
        $result[0].Reason | Should -Match 'BadGroup'
    }
}

# ---------------------------------------------------------------------------
# N4: Empty GivenName and Surname → Name falls back to SamAccountName
# ---------------------------------------------------------------------------
Describe 'New-ADUserBulk — empty name fallback to SamAccountName' {
    BeforeAll {
        Mock Get-ADUser { return $null }
        Mock New-ADUser { }
    }

    It 'calls New-ADUser with Name equal to SamAccountName when GivenName and Surname are both empty' {
        $csv = Export-TestCsv -Name 'noname.csv' -Content @"
$script:validHeader
,,asmith,asmith@corp.local,OU=Staff DC=corp DC=local,,IT,Admin
"@
        New-ADUserBulk -CsvPath $csv | Out-Null
        Should -Invoke New-ADUser -Times 1 -Exactly -ParameterFilter { $Name -eq 'asmith' }
    }
}

# ---------------------------------------------------------------------------
# N5: OutputPath without -IncludePlainTextPasswords → passwords redacted in CSV
# ---------------------------------------------------------------------------
Describe 'New-ADUserBulk — OutputPath redacts passwords by default' {
    BeforeAll {
        Mock Get-ADUser { return $null }
        Mock New-ADUser { }
        Mock Set-Acl { }
    }

    It 'InitialPassword column is empty in the exported CSV when -IncludePlainTextPasswords is not set' {
        $csv    = Export-TestCsv -Name 'redact-source.csv' -Content @"
$script:validHeader
Alice,Smith,asmith,alice@corp.local,OU=Staff DC=corp DC=local,,IT,Engineer
"@
        $report = Join-Path $TestDrive 'redact-report.csv'
        New-ADUserBulk -CsvPath $csv -OutputPath $report -WarningAction SilentlyContinue | Out-Null
        $imported = Import-Csv -Path $report
        $imported[0].InitialPassword | Should -BeNullOrEmpty
    }

    It 'emits a warning about redaction when -IncludePlainTextPasswords is not set' {
        $csv    = Export-TestCsv -Name 'redact-warn-source.csv' -Content @"
$script:validHeader
Alice,Smith,asmith,alice@corp.local,OU=Staff DC=corp DC=local,,IT,Engineer
"@
        $report = Join-Path $TestDrive 'redact-warn-report.csv'
        $warns  = @()
        New-ADUserBulk -CsvPath $csv -OutputPath $report -WarningVariable warns -WarningAction SilentlyContinue | Out-Null
        $warns | Where-Object { $_ -match 'redacted' } | Should -Not -BeNullOrEmpty
    }

    It 'does not call Set-Acl when -IncludePlainTextPasswords is not set' {
        $csv    = Export-TestCsv -Name 'redact-acl-source.csv' -Content @"
$script:validHeader
Alice,Smith,asmith,alice@corp.local,OU=Staff DC=corp DC=local,,IT,Engineer
"@
        $report = Join-Path $TestDrive 'redact-acl-report.csv'
        New-ADUserBulk -CsvPath $csv -OutputPath $report -WarningAction SilentlyContinue | Out-Null
        Should -Invoke Set-Acl -Times 0 -Exactly
    }
}

# ---------------------------------------------------------------------------
# N6: OutputPath with -IncludePlainTextPasswords → passwords present in CSV
# ---------------------------------------------------------------------------
Describe 'New-ADUserBulk — OutputPath with -IncludePlainTextPasswords' {
    BeforeAll {
        Mock Get-ADUser { return $null }
        Mock New-ADUser { }
        Mock Set-Acl { }
    }

    It 'InitialPassword column is non-empty in CSV when -IncludePlainTextPasswords is set' {
        $csv    = Export-TestCsv -Name 'plain-source.csv' -Content @"
$script:validHeader
Alice,Smith,asmith,alice@corp.local,OU=Staff DC=corp DC=local,,IT,Engineer
"@
        $report = Join-Path $TestDrive 'plain-report.csv'
        New-ADUserBulk -CsvPath $csv -OutputPath $report -IncludePlainTextPasswords -WarningAction SilentlyContinue | Out-Null
        $imported = Import-Csv -Path $report
        $imported[0].InitialPassword | Should -Not -BeNullOrEmpty
    }

    It 'emits a warning about plain-text passwords in the file' {
        $csv    = Export-TestCsv -Name 'plain-warn-source.csv' -Content @"
$script:validHeader
Alice,Smith,asmith,alice@corp.local,OU=Staff DC=corp DC=local,,IT,Engineer
"@
        $report = Join-Path $TestDrive 'plain-warn-report.csv'
        $warns  = @()
        New-ADUserBulk -CsvPath $csv -OutputPath $report -IncludePlainTextPasswords -WarningVariable warns -WarningAction SilentlyContinue | Out-Null
        $warns | Where-Object { $_ -match 'Plain-text initial passwords are in' } | Should -Not -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# N7: ACL hardening — Set-Acl called once with -IncludePlainTextPasswords
# ---------------------------------------------------------------------------
Describe 'New-ADUserBulk — ACL hardening with -IncludePlainTextPasswords' {
    BeforeAll {
        Mock Get-ADUser { return $null }
        Mock New-ADUser { }
        Mock Set-Acl { }
    }

    It 'calls Set-Acl exactly once when -OutputPath and -IncludePlainTextPasswords are both set' {
        $csv    = Export-TestCsv -Name 'acl-on-source.csv' -Content @"
$script:validHeader
Alice,Smith,asmith,alice@corp.local,OU=Staff DC=corp DC=local,,IT,Engineer
"@
        $report = Join-Path $TestDrive 'acl-on-report.csv'
        New-ADUserBulk -CsvPath $csv -OutputPath $report -IncludePlainTextPasswords -WarningAction SilentlyContinue | Out-Null
        Should -Invoke Set-Acl -Times 1 -Exactly
    }
}

# ---------------------------------------------------------------------------
# N8: ACL hardening failure tolerance — function still completes
# ---------------------------------------------------------------------------
Describe 'New-ADUserBulk — ACL hardening failure is non-fatal' {
    BeforeAll {
        Mock Get-ADUser { return $null }
        Mock New-ADUser { }
        Mock Set-Acl { throw 'denied' }
    }

    It 'does not throw when Set-Acl fails' {
        $csv    = Export-TestCsv -Name 'acl-fail-source.csv' -Content @"
$script:validHeader
Alice,Smith,asmith,alice@corp.local,OU=Staff DC=corp DC=local,,IT,Engineer
"@
        $report = Join-Path $TestDrive 'acl-fail-report.csv'
        { New-ADUserBulk -CsvPath $csv -OutputPath $report -IncludePlainTextPasswords -WarningAction SilentlyContinue } | Should -Not -Throw
    }

    It 'still writes the CSV when Set-Acl fails' {
        $csv    = Export-TestCsv -Name 'acl-fail-csv-source.csv' -Content @"
$script:validHeader
Alice,Smith,asmith,alice@corp.local,OU=Staff DC=corp DC=local,,IT,Engineer
"@
        $report = Join-Path $TestDrive 'acl-fail-csv-report.csv'
        New-ADUserBulk -CsvPath $csv -OutputPath $report -IncludePlainTextPasswords -WarningAction SilentlyContinue | Out-Null
        Test-Path -LiteralPath $report | Should -Be $true
    }

    It 'emits a warning when Set-Acl fails' {
        $csv    = Export-TestCsv -Name 'acl-fail-warn-source.csv' -Content @"
$script:validHeader
Alice,Smith,asmith,alice@corp.local,OU=Staff DC=corp DC=local,,IT,Engineer
"@
        $report = Join-Path $TestDrive 'acl-fail-warn-report.csv'
        $warns  = @()
        New-ADUserBulk -CsvPath $csv -OutputPath $report -IncludePlainTextPasswords -WarningVariable warns -WarningAction SilentlyContinue | Out-Null
        $warns | Where-Object { $_ -match 'ACL hardening failed' } | Should -Not -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# N9: Pipeline always carries InitialPassword regardless of -IncludePlainTextPasswords
# ---------------------------------------------------------------------------
Describe 'New-ADUserBulk — pipeline InitialPassword unaffected by -IncludePlainTextPasswords' {
    BeforeAll {
        Mock Get-ADUser { return $null }
        Mock New-ADUser { }
        Mock Set-Acl { }
    }

    It 'pipeline object has non-empty InitialPassword when -IncludePlainTextPasswords is not set' {
        $csv    = Export-TestCsv -Name 'pipe-no-flag.csv' -Content @"
$script:validHeader
Alice,Smith,asmith,alice@corp.local,OU=Staff DC=corp DC=local,,IT,Engineer
"@
        $report = Join-Path $TestDrive 'pipe-no-flag-report.csv'
        $result = @(New-ADUserBulk -CsvPath $csv -OutputPath $report -WarningAction SilentlyContinue)
        $result[0].InitialPassword | Should -Not -BeNullOrEmpty
    }

    It 'pipeline object has non-empty InitialPassword when -IncludePlainTextPasswords is set' {
        $csv    = Export-TestCsv -Name 'pipe-with-flag.csv' -Content @"
$script:validHeader
Alice,Smith,asmith,alice@corp.local,OU=Staff DC=corp DC=local,,IT,Engineer
"@
        $report = Join-Path $TestDrive 'pipe-with-flag-report.csv'
        $result = @(New-ADUserBulk -CsvPath $csv -OutputPath $report -IncludePlainTextPasswords -WarningAction SilentlyContinue)
        $result[0].InitialPassword | Should -Not -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# N10: Status=Created (not Partial) when ALL group-adds succeed
# ---------------------------------------------------------------------------
Describe 'New-ADUserBulk — Status stays Created when all group-adds succeed' {
    BeforeAll {
        Mock Get-ADUser { return $null }
        Mock New-ADUser { }
        Mock Add-ADGroupMember { }
    }

    It 'Status is Created (not Partial) when all group-adds succeed' {
        $csv = Export-TestCsv -Name 'all-groups-ok.csv' -Content @"
$script:validHeader
Alice,Smith,asmith,alice@corp.local,OU=Staff DC=corp DC=local,GroupA;GroupB,IT,Engineer
"@
        $result = @(New-ADUserBulk -CsvPath $csv)
        $result[0].Status | Should -Be 'Created'
    }
}

# ---------------------------------------------------------------------------
# N11: Atomic write — Move-Item called with a .tmp source and $OutputPath dest
# ---------------------------------------------------------------------------
Describe 'New-ADUserBulk — atomic write: temp file renamed to OutputPath' {
    BeforeAll {
        Mock Get-ADUser { return $null }
        Mock New-ADUser { }
        Mock Set-Acl { }

        # Capture Move-Item call arguments; create the destination so downstream
        # assertions (e.g. Test-Path) remain consistent.
        $script:moveItemCalls = [System.Collections.Generic.List[hashtable]]::new()
        Mock Move-Item {
            $script:moveItemCalls.Add(@{ Source = $LiteralPath; Destination = $Destination })
            # Actually create the destination file so the rest of the test can verify it.
            if (Test-Path -LiteralPath $LiteralPath) {
                Copy-Item -LiteralPath $LiteralPath -Destination $Destination -Force
                Remove-Item -LiteralPath $LiteralPath -Force -ErrorAction SilentlyContinue
            }
        }
    }

    It 'calls Move-Item exactly once when -OutputPath and -IncludePlainTextPasswords are both set' {
        $script:moveItemCalls.Clear()
        $csv    = Export-TestCsv -Name 'atomic-source.csv' -Content @"
$script:validHeader
Alice,Smith,asmith,alice@corp.local,OU=Staff DC=corp DC=local,,IT,Engineer
"@
        $report = Join-Path $TestDrive 'atomic-report.csv'
        New-ADUserBulk -CsvPath $csv -OutputPath $report -IncludePlainTextPasswords -WarningAction SilentlyContinue | Out-Null
        Should -Invoke Move-Item -Times 1 -Exactly
    }

    It 'Move-Item destination is the requested OutputPath' {
        $script:moveItemCalls.Clear()
        $csv    = Export-TestCsv -Name 'atomic-dest-source.csv' -Content @"
$script:validHeader
Alice,Smith,asmith,alice@corp.local,OU=Staff DC=corp DC=local,,IT,Engineer
"@
        $report = Join-Path $TestDrive 'atomic-dest-report.csv'
        New-ADUserBulk -CsvPath $csv -OutputPath $report -IncludePlainTextPasswords -WarningAction SilentlyContinue | Out-Null
        $script:moveItemCalls[0].Destination | Should -Be $report
    }

    It 'Move-Item source is a .tmp file (never the final OutputPath)' {
        $script:moveItemCalls.Clear()
        $csv    = Export-TestCsv -Name 'atomic-src-source.csv' -Content @"
$script:validHeader
Alice,Smith,asmith,alice@corp.local,OU=Staff DC=corp DC=local,,IT,Engineer
"@
        $report = Join-Path $TestDrive 'atomic-src-report.csv'
        New-ADUserBulk -CsvPath $csv -OutputPath $report -IncludePlainTextPasswords -WarningAction SilentlyContinue | Out-Null
        $script:moveItemCalls[0].Source | Should -Match '\.tmp$'
    }
}
