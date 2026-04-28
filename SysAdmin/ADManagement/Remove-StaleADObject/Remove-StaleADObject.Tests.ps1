#requires -Version 7.2

BeforeAll {
    . (Join-Path $PSScriptRoot 'Remove-StaleADObject.ps1')

    # Helper: build a fake stale user object.
    function New-StaleUser {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pester fixture builder — pure function, no state change.')]
        param(
            [string]$Sam,
            [datetime]$LastLogon,
            [bool]$Enabled = $true
        )
        [PSCustomObject]@{
            SamAccountName    = $Sam
            DistinguishedName = "CN=$Sam,OU=Staff,DC=corp,DC=local"
            LastLogonDate     = $LastLogon
            Enabled           = $Enabled
        }
    }

    # Helper: build a fake stale computer object.
    function New-StaleComputer {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pester fixture builder — pure function, no state change.')]
        param(
            [string]$Name,
            [datetime]$LastLogon,
            [bool]$Enabled = $true
        )
        [PSCustomObject]@{
            SamAccountName    = $Name
            DistinguishedName = "CN=$Name,OU=Computers,DC=corp,DC=local"
            LastLogonDate     = $LastLogon
            Enabled           = $Enabled
        }
    }

    $script:QuarantineOU = 'OU=Quarantine,DC=corp,DC=local'
    $script:StaleDate    = (Get-Date).AddDays(-120)
    $script:FreshDate    = (Get-Date).AddDays(-10)
}

# ---------------------------------------------------------------------------
# T1: User mode — 2 stale users, both processed
# ---------------------------------------------------------------------------
Describe 'Remove-StaleADObject — User mode: 2 stale users' {
    BeforeAll {
        $u1 = New-StaleUser -Sam 'alice' -LastLogon $script:StaleDate
        $u2 = New-StaleUser -Sam 'bob'   -LastLogon $script:StaleDate
        Mock Get-ADUser      { @($u1, $u2) }
        Mock Disable-ADAccount { }
        Mock Move-ADObject   { }
    }

    It 'calls Disable-ADAccount twice for 2 stale users' {
        Remove-StaleADObject -Confirm:$false -Mode User -QuarantineOU $script:QuarantineOU | Out-Null
        Should -Invoke Disable-ADAccount -Times 2 -Exactly
    }

    It 'calls Move-ADObject twice for 2 stale users' {
        Remove-StaleADObject -Confirm:$false -Mode User -QuarantineOU $script:QuarantineOU | Out-Null
        Should -Invoke Move-ADObject -Times 2 -Exactly
    }

    It 'returns 2 result rows for 2 stale users' {
        $result = @(Remove-StaleADObject -Confirm:$false -Mode User -QuarantineOU $script:QuarantineOU)
        $result.Count | Should -Be 2
    }

    It 'rows have Action=Disable+Move' {
        $result = @(Remove-StaleADObject -Confirm:$false -Mode User -QuarantineOU $script:QuarantineOU)
        $result | ForEach-Object { $_.Action | Should -Be 'Disable+Move' }
    }
}

# ---------------------------------------------------------------------------
# T2: Computer mode — 2 stale computers, both processed
# ---------------------------------------------------------------------------
Describe 'Remove-StaleADObject — Computer mode: 2 stale computers' {
    BeforeAll {
        $c1 = New-StaleComputer -Name 'PC01' -LastLogon $script:StaleDate
        $c2 = New-StaleComputer -Name 'PC02' -LastLogon $script:StaleDate
        Mock Get-ADComputer  { @($c1, $c2) }
        Mock Disable-ADAccount { }
        Mock Move-ADObject   { }
    }

    It 'calls Disable-ADAccount twice for 2 stale computers' {
        Remove-StaleADObject -Confirm:$false -Mode Computer -QuarantineOU $script:QuarantineOU | Out-Null
        Should -Invoke Disable-ADAccount -Times 2 -Exactly
    }

    It 'calls Move-ADObject twice for 2 stale computers' {
        Remove-StaleADObject -Confirm:$false -Mode Computer -QuarantineOU $script:QuarantineOU | Out-Null
        Should -Invoke Move-ADObject -Times 2 -Exactly
    }

    It 'result rows have ObjectType=Computer' {
        $result = @(Remove-StaleADObject -Confirm:$false -Mode Computer -QuarantineOU $script:QuarantineOU)
        $result | ForEach-Object { $_.ObjectType | Should -Be 'Computer' }
    }
}

# ---------------------------------------------------------------------------
# T3: Both mode — 1 user + 1 computer, 2 rows
# ---------------------------------------------------------------------------
Describe 'Remove-StaleADObject — Both mode: 1 user + 1 computer' {
    BeforeAll {
        $u = New-StaleUser     -Sam 'alice' -LastLogon $script:StaleDate
        $c = New-StaleComputer -Name 'PC01' -LastLogon $script:StaleDate
        Mock Get-ADUser     { @($u) }
        Mock Get-ADComputer { @($c) }
        Mock Disable-ADAccount { }
        Mock Move-ADObject  { }
    }

    It 'returns 2 rows when 1 user and 1 computer are stale' {
        $result = @(Remove-StaleADObject -Confirm:$false -Mode Both -QuarantineOU $script:QuarantineOU)
        $result.Count | Should -Be 2
    }

    It 'first row ObjectType is User' {
        $result = @(Remove-StaleADObject -Confirm:$false -Mode Both -QuarantineOU $script:QuarantineOU)
        $result[0].ObjectType | Should -Be 'User'
    }

    It 'second row ObjectType is Computer' {
        $result = @(Remove-StaleADObject -Confirm:$false -Mode Both -QuarantineOU $script:QuarantineOU)
        $result[1].ObjectType | Should -Be 'Computer'
    }
}

# ---------------------------------------------------------------------------
# T4: No stale users found — empty pipeline, no error
# ---------------------------------------------------------------------------
Describe 'Remove-StaleADObject — no stale objects found' {
    BeforeAll {
        Mock Get-ADUser     { @() }
        Mock Get-ADComputer { @() }
        Mock Disable-ADAccount { }
        Mock Move-ADObject  { }
    }

    It 'returns empty pipeline when no stale objects exist' {
        $result = @(Remove-StaleADObject -Confirm:$false -Mode Both -QuarantineOU $script:QuarantineOU)
        $result.Count | Should -Be 0
    }

    It 'does not call Disable-ADAccount when no stale objects exist' {
        Remove-StaleADObject -Confirm:$false -Mode Both -QuarantineOU $script:QuarantineOU | Out-Null
        Should -Invoke Disable-ADAccount -Times 0 -Exactly
    }
}

# ---------------------------------------------------------------------------
# T5: Already-disabled skipped by default
# ---------------------------------------------------------------------------
Describe 'Remove-StaleADObject — already-disabled skipped by default' {
    BeforeAll {
        $disabled = New-StaleUser -Sam 'ghost' -LastLogon $script:StaleDate -Enabled $false
        Mock Get-ADUser { @($disabled) }
        Mock Disable-ADAccount { }
        Mock Move-ADObject { }
    }

    It 'does not call Disable-ADAccount for already-disabled user' {
        Remove-StaleADObject -Confirm:$false -Mode User -QuarantineOU $script:QuarantineOU | Out-Null
        Should -Invoke Disable-ADAccount -Times 0 -Exactly
    }

    It 'row Action is Skipped:AlreadyDisabled' {
        $result = @(Remove-StaleADObject -Confirm:$false -Mode User -QuarantineOU $script:QuarantineOU)
        $result[0].Action | Should -Be 'Skipped:AlreadyDisabled'
    }
}

# ---------------------------------------------------------------------------
# T6: Already-disabled processed when -IncludeDisabled is set
# ---------------------------------------------------------------------------
Describe 'Remove-StaleADObject — already-disabled processed with -IncludeDisabled' {
    BeforeAll {
        $disabled = New-StaleUser -Sam 'ghost' -LastLogon $script:StaleDate -Enabled $false
        Mock Get-ADUser { @($disabled) }
        Mock Disable-ADAccount { }
        Mock Move-ADObject { }
    }

    It 'calls Disable-ADAccount for already-disabled user when -IncludeDisabled is set' {
        Remove-StaleADObject -Confirm:$false -Mode User -QuarantineOU $script:QuarantineOU -IncludeDisabled | Out-Null
        Should -Invoke Disable-ADAccount -Times 1 -Exactly
    }

    It 'row Action is Disable+Move when -IncludeDisabled is set' {
        $result = @(Remove-StaleADObject -Confirm:$false -Mode User -QuarantineOU $script:QuarantineOU -IncludeDisabled)
        $result[0].Action | Should -Be 'Disable+Move'
    }
}

# ---------------------------------------------------------------------------
# T7: -WhatIf — no AD calls, row action = WhatIf, QuarantineOU not required
# ---------------------------------------------------------------------------
Describe 'Remove-StaleADObject — WhatIf mode' {
    BeforeAll {
        $u = New-StaleUser -Sam 'alice' -LastLogon $script:StaleDate
        Mock Get-ADUser { @($u) }
        Mock Disable-ADAccount { }
        Mock Move-ADObject { }
    }

    It 'does not call Disable-ADAccount when -WhatIf is specified' {
        Remove-StaleADObject -Mode User -WhatIf | Out-Null
        Should -Invoke Disable-ADAccount -Times 0 -Exactly
    }

    It 'does not call Move-ADObject when -WhatIf is specified' {
        Remove-StaleADObject -Mode User -WhatIf | Out-Null
        Should -Invoke Move-ADObject -Times 0 -Exactly
    }

    It 'row Action is WhatIf when -WhatIf is specified' {
        $result = @(Remove-StaleADObject -Mode User -WhatIf)
        $result[0].Action | Should -Be 'WhatIf'
    }

    It 'does not throw when -QuarantineOU is omitted and -WhatIf is specified' {
        { Remove-StaleADObject -Mode User -WhatIf } | Should -Not -Throw
    }
}

# ---------------------------------------------------------------------------
# T8: Missing QuarantineOU without -WhatIf → throws exact message
# ---------------------------------------------------------------------------
Describe 'Remove-StaleADObject — QuarantineOU required for real action' {
    It 'throws with exact message when QuarantineOU is not supplied' {
        {
            Remove-StaleADObject -Mode User -StaleDays 90
        } | Should -Throw '-QuarantineOU is required unless -WhatIf is used.'
    }
}

# ---------------------------------------------------------------------------
# T9: Cutoff math — included vs. excluded based on StaleDays
# ---------------------------------------------------------------------------
Describe 'Remove-StaleADObject — cutoff math' {
    BeforeAll {
        Mock Disable-ADAccount { }
        Mock Move-ADObject { }
    }

    It 'includes user with LastLogonDate 100 days ago when StaleDays=90' {
        $stale = New-StaleUser -Sam 'old' -LastLogon (Get-Date).AddDays(-100)
        Mock Get-ADUser { @($stale) }
        $result = @(Remove-StaleADObject -Confirm:$false -Mode User -StaleDays 90 -QuarantineOU $script:QuarantineOU)
        $result.Count | Should -Be 1
    }

    It 'excludes user with LastLogonDate 100 days ago when StaleDays=110' {
        $fresh = New-StaleUser -Sam 'recent' -LastLogon (Get-Date).AddDays(-100)
        Mock Get-ADUser { @($fresh) }
        $result = @(Remove-StaleADObject -Confirm:$false -Mode User -StaleDays 110 -QuarantineOU $script:QuarantineOU)
        $result.Count | Should -Be 0
    }
}

# ---------------------------------------------------------------------------
# T10-T12: StaleDays boundary validation
# ---------------------------------------------------------------------------
Describe 'Remove-StaleADObject — StaleDays boundaries' {
    BeforeAll {
        Mock Get-ADUser     { @() }
        Mock Get-ADComputer { @() }
    }

    It 'accepts -StaleDays 30 (lower boundary)' {
        { Remove-StaleADObject -Mode User -StaleDays 30 -WhatIf } | Should -Not -Throw
    }

    It 'rejects -StaleDays 29 (below lower boundary)' {
        { Remove-StaleADObject -Mode User -StaleDays 29 -WhatIf } | Should -Throw
    }

    It 'accepts -StaleDays 730 (upper boundary)' {
        { Remove-StaleADObject -Mode User -StaleDays 730 -WhatIf } | Should -Not -Throw
    }

    It 'rejects -StaleDays 731 (above upper boundary)' {
        { Remove-StaleADObject -Mode User -StaleDays 731 -WhatIf } | Should -Throw
    }
}

# ---------------------------------------------------------------------------
# T13: Invalid -Mode value → ValidateSet throws
# ---------------------------------------------------------------------------
Describe 'Remove-StaleADObject — invalid Mode value' {
    It 'throws when -Mode is an invalid value' {
        { Remove-StaleADObject -Mode 'Service' -WhatIf } | Should -Throw
    }
}

# ---------------------------------------------------------------------------
# T14: Disable-ADAccount throws → row.Action=Failed, continues to next
# ---------------------------------------------------------------------------
Describe 'Remove-StaleADObject — Disable-ADAccount failure' {
    BeforeAll {
        $u1 = New-StaleUser -Sam 'alice' -LastLogon $script:StaleDate
        $u2 = New-StaleUser -Sam 'bob'   -LastLogon $script:StaleDate
        Mock Get-ADUser { @($u1, $u2) }
        Mock Disable-ADAccount -ParameterFilter { $Identity -like '*alice*' } { throw 'Simulated disable error' }
        Mock Disable-ADAccount -ParameterFilter { $Identity -like '*bob*'   } { }
        Mock Move-ADObject { }
    }

    It 'row Action is Failed when Disable-ADAccount throws' {
        $result = @(Remove-StaleADObject -Confirm:$false -Mode User -QuarantineOU $script:QuarantineOU -WarningAction SilentlyContinue)
        ($result | Where-Object { $_.SamAccountName -eq 'alice' }).Action | Should -Be 'Failed'
    }

    It 'row Reason contains the error message when Disable-ADAccount throws' {
        $result = @(Remove-StaleADObject -Confirm:$false -Mode User -QuarantineOU $script:QuarantineOU -WarningAction SilentlyContinue)
        ($result | Where-Object { $_.SamAccountName -eq 'alice' }).Reason | Should -Match 'Simulated disable error'
    }

    It 'continues to process next object after Disable-ADAccount failure' {
        $result = @(Remove-StaleADObject -Confirm:$false -Mode User -QuarantineOU $script:QuarantineOU -WarningAction SilentlyContinue)
        ($result | Where-Object { $_.SamAccountName -eq 'bob' }).Action | Should -Be 'Disable+Move'
    }
}

# ---------------------------------------------------------------------------
# T15: Move-ADObject throws → row.Action=Failed (Disable already succeeded)
# ---------------------------------------------------------------------------
Describe 'Remove-StaleADObject — Move-ADObject failure' {
    BeforeAll {
        $u = New-StaleUser -Sam 'alice' -LastLogon $script:StaleDate
        Mock Get-ADUser { @($u) }
        Mock Disable-ADAccount { }
        Mock Move-ADObject { throw 'Simulated move error' }
    }

    It 'row Action is Failed when Move-ADObject throws' {
        $result = @(Remove-StaleADObject -Confirm:$false -Mode User -QuarantineOU $script:QuarantineOU -WarningAction SilentlyContinue)
        $result[0].Action | Should -Be 'Failed'
    }

    It 'row Reason contains the move error message' {
        $result = @(Remove-StaleADObject -Confirm:$false -Mode User -QuarantineOU $script:QuarantineOU -WarningAction SilentlyContinue)
        $result[0].Reason | Should -Match 'Simulated move error'
    }

    It 'Disable-ADAccount is still called before Move-ADObject fails' {
        Remove-StaleADObject -Confirm:$false -Mode User -QuarantineOU $script:QuarantineOU -WarningAction SilentlyContinue | Out-Null
        Should -Invoke Disable-ADAccount -Times 1 -Exactly
    }
}

# ---------------------------------------------------------------------------
# T16: -OutputPath — CSV is written with expected columns
# ---------------------------------------------------------------------------
Describe 'Remove-StaleADObject — OutputPath writes CSV' {
    BeforeAll {
        $u = New-StaleUser -Sam 'alice' -LastLogon $script:StaleDate
        Mock Get-ADUser { @($u) }
        Mock Disable-ADAccount { }
        Mock Move-ADObject { }
    }

    It 'creates a CSV file at the -OutputPath' {
        $outPath = Join-Path $TestDrive 'stale-report.csv'
        Remove-StaleADObject -Confirm:$false -Mode User -QuarantineOU $script:QuarantineOU -OutputPath $outPath | Out-Null
        Test-Path -LiteralPath $outPath | Should -Be $true
    }

    It 'CSV contains the ObjectType column' {
        $outPath = Join-Path $TestDrive 'stale-cols.csv'
        Remove-StaleADObject -Confirm:$false -Mode User -QuarantineOU $script:QuarantineOU -OutputPath $outPath | Out-Null
        $imported = Import-Csv -LiteralPath $outPath
        $imported[0].PSObject.Properties.Name | Should -Contain 'ObjectType'
    }

    It 'CSV contains the Action column' {
        $outPath = Join-Path $TestDrive 'stale-action.csv'
        Remove-StaleADObject -Confirm:$false -Mode User -QuarantineOU $script:QuarantineOU -OutputPath $outPath | Out-Null
        $imported = Import-Csv -LiteralPath $outPath
        $imported[0].PSObject.Properties.Name | Should -Contain 'Action'
    }

    It 'CSV row Action value is Disable+Move' {
        $outPath = Join-Path $TestDrive 'stale-val.csv'
        Remove-StaleADObject -Confirm:$false -Mode User -QuarantineOU $script:QuarantineOU -OutputPath $outPath | Out-Null
        $imported = Import-Csv -LiteralPath $outPath
        $imported[0].Action | Should -Be 'Disable+Move'
    }
}

# ---------------------------------------------------------------------------
# T18: Mixed result — 3 stale users, #2 throws on Disable → 3 rows
# ---------------------------------------------------------------------------
Describe 'Remove-StaleADObject — mixed results: 3 users, middle one fails' {
    BeforeAll {
        $u1 = New-StaleUser -Sam 'user1' -LastLogon $script:StaleDate
        $u2 = New-StaleUser -Sam 'user2' -LastLogon $script:StaleDate
        $u3 = New-StaleUser -Sam 'user3' -LastLogon $script:StaleDate
        Mock Get-ADUser { @($u1, $u2, $u3) }
        Mock Disable-ADAccount -ParameterFilter { $Identity -like '*user2*' } { throw 'Disable error on user2' }
        Mock Disable-ADAccount -ParameterFilter { $Identity -notlike '*user2*' } { }
        Mock Move-ADObject { }
    }

    It 'returns 3 rows when 3 stale users exist' {
        $result = @(Remove-StaleADObject -Confirm:$false -Mode User -QuarantineOU $script:QuarantineOU -WarningAction SilentlyContinue)
        $result.Count | Should -Be 3
    }

    It 'user1 row Action is Disable+Move' {
        $result = @(Remove-StaleADObject -Confirm:$false -Mode User -QuarantineOU $script:QuarantineOU -WarningAction SilentlyContinue)
        ($result | Where-Object { $_.SamAccountName -eq 'user1' }).Action | Should -Be 'Disable+Move'
    }

    It 'user2 row Action is Failed' {
        $result = @(Remove-StaleADObject -Confirm:$false -Mode User -QuarantineOU $script:QuarantineOU -WarningAction SilentlyContinue)
        ($result | Where-Object { $_.SamAccountName -eq 'user2' }).Action | Should -Be 'Failed'
    }

    It 'user3 row Action is Disable+Move' {
        $result = @(Remove-StaleADObject -Confirm:$false -Mode User -QuarantineOU $script:QuarantineOU -WarningAction SilentlyContinue)
        ($result | Where-Object { $_.SamAccountName -eq 'user3' }).Action | Should -Be 'Disable+Move'
    }
}

# ---------------------------------------------------------------------------
# T19: Both mode totals — 2 users + 3 computers → 5 rows, users first
# ---------------------------------------------------------------------------
Describe 'Remove-StaleADObject — Both mode totals: 2 users + 3 computers' {
    BeforeAll {
        $u1 = New-StaleUser     -Sam  'user1' -LastLogon $script:StaleDate
        $u2 = New-StaleUser     -Sam  'user2' -LastLogon $script:StaleDate
        $c1 = New-StaleComputer -Name 'PC01'  -LastLogon $script:StaleDate
        $c2 = New-StaleComputer -Name 'PC02'  -LastLogon $script:StaleDate
        $c3 = New-StaleComputer -Name 'PC03'  -LastLogon $script:StaleDate
        Mock Get-ADUser     { @($u1, $u2) }
        Mock Get-ADComputer { @($c1, $c2, $c3) }
        Mock Disable-ADAccount { }
        Mock Move-ADObject  { }
    }

    It 'returns 5 rows (2 users + 3 computers)' {
        $result = @(Remove-StaleADObject -Confirm:$false -Mode Both -QuarantineOU $script:QuarantineOU)
        $result.Count | Should -Be 5
    }

    It 'first two rows are User type' {
        $result = @(Remove-StaleADObject -Confirm:$false -Mode Both -QuarantineOU $script:QuarantineOU)
        $result[0].ObjectType | Should -Be 'User'
        $result[1].ObjectType | Should -Be 'User'
    }

    It 'last three rows are Computer type' {
        $result = @(Remove-StaleADObject -Confirm:$false -Mode Both -QuarantineOU $script:QuarantineOU)
        $result[2].ObjectType | Should -Be 'Computer'
        $result[3].ObjectType | Should -Be 'Computer'
        $result[4].ObjectType | Should -Be 'Computer'
    }
}
