#requires -Version 7.2

BeforeAll {
    . (Join-Path $PSScriptRoot 'Get-ShareACLAudit.ps1')

    # -----------------------------------------------------------------------
    # Helper: build a synthetic access rule object.
    # -----------------------------------------------------------------------
    function New-AccessRule {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pester fixture builder — pure function, no state change.')]
        param(
            [string]$Identity,
            [string]$Rights,
            [string]$AccessControlType = 'Allow',
            [bool]$IsInherited = $false
        )
        [PSCustomObject]@{
            IdentityReference  = [PSCustomObject]@{ Value = $Identity }
            FileSystemRights   = $Rights
            AccessControlType  = $AccessControlType
            IsInherited        = $IsInherited
        }
    }

    # -----------------------------------------------------------------------
    # Helper: build a synthetic ACL object.
    # -----------------------------------------------------------------------
    function New-MockAcl {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pester fixture builder — pure function, no state change.')]
        param([object[]]$Access)
        [PSCustomObject]@{ Access = $Access }
    }

    # -----------------------------------------------------------------------
    # Helper: build a synthetic directory-info-like object.
    # -----------------------------------------------------------------------
    function New-MockDir {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pester fixture builder — pure function, no state change.')]
        param([string]$FullName)
        [PSCustomObject]@{ FullName = $FullName }
    }
}

# ---------------------------------------------------------------------------
# T01: Single risky grant — Everyone Modify on root.
# ---------------------------------------------------------------------------
Describe 'T01 — Single risky grant: Everyone Modify on root' {
    BeforeAll {
        $testRoot = 'TestDrive:\ShareRoot'
        New-Item -Path $testRoot -ItemType Directory -Force | Out-Null

        Mock Get-GSAChildItem { @() }
        Mock Get-GSAAcl {
            New-MockAcl -Access @(
                New-AccessRule -Identity 'Everyone' -Rights 'Modify'
            )
        }
    }

    It 'produces exactly 1 finding' {
        $result = @(Get-ShareACLAudit -Path $testRoot)
        $result.Count | Should -Be 1
    }

    It 'finding Principal is Everyone' {
        $result = @(Get-ShareACLAudit -Path $testRoot)
        $result[0].Principal | Should -Be 'Everyone'
    }

    It 'finding Rights is Modify' {
        $result = @(Get-ShareACLAudit -Path $testRoot)
        $result[0].Rights | Should -Be 'Modify'
    }

    It 'finding Path is the root path' {
        $result = @(Get-ShareACLAudit -Path $testRoot)
        $result[0].Path | Should -Be $testRoot
    }
}

# ---------------------------------------------------------------------------
# T02: Non-risky principal (CORP\Alice with FullControl) — 0 findings.
# ---------------------------------------------------------------------------
Describe 'T02 — Non-risky principal CORP\Alice is ignored' {
    BeforeAll {
        $testRoot = 'TestDrive:\T02Root'
        New-Item -Path $testRoot -ItemType Directory -Force | Out-Null

        Mock Get-GSAChildItem { @() }
        Mock Get-GSAAcl {
            New-MockAcl -Access @(
                New-AccessRule -Identity 'CORP\Alice' -Rights 'FullControl'
            )
        }
    }

    It 'produces 0 findings when the principal is not in RiskyPrincipals' {
        $result = @(Get-ShareACLAudit -Path $testRoot)
        $result.Count | Should -Be 0
    }
}

# ---------------------------------------------------------------------------
# T03: Non-risky right (Everyone Read) — 0 findings.
# ---------------------------------------------------------------------------
Describe 'T03 — Non-risky right Read is ignored' {
    BeforeAll {
        $testRoot = 'TestDrive:\T03Root'
        New-Item -Path $testRoot -ItemType Directory -Force | Out-Null

        Mock Get-GSAChildItem { @() }
        Mock Get-GSAAcl {
            New-MockAcl -Access @(
                New-AccessRule -Identity 'Everyone' -Rights 'Read'
            )
        }
    }

    It 'produces 0 findings when the right is not in RiskyRights' {
        $result = @(Get-ShareACLAudit -Path $testRoot)
        $result.Count | Should -Be 0
    }
}

# ---------------------------------------------------------------------------
# T04: Two risky grants on same path — 2 findings.
# ---------------------------------------------------------------------------
Describe 'T04 — Two risky grants on the same path' {
    BeforeAll {
        $testRoot = 'TestDrive:\T04Root'
        New-Item -Path $testRoot -ItemType Directory -Force | Out-Null

        Mock Get-GSAChildItem { @() }
        Mock Get-GSAAcl {
            New-MockAcl -Access @(
                New-AccessRule -Identity 'Everyone' -Rights 'Modify'
                New-AccessRule -Identity 'NT AUTHORITY\Authenticated Users' -Rights 'Write'
            )
        }
    }

    It 'produces exactly 2 findings' {
        $result = @(Get-ShareACLAudit -Path $testRoot)
        $result.Count | Should -Be 2
    }
}

# ---------------------------------------------------------------------------
# T05: Recursion respects MaxDepth — Get-GSAChildItem called with -Depth 2.
# ---------------------------------------------------------------------------
Describe 'T05 — Recursion respects custom MaxDepth' {
    BeforeAll {
        $testRoot = 'TestDrive:\T05Root'
        New-Item -Path $testRoot -ItemType Directory -Force | Out-Null

        Mock Get-GSAChildItem {
            @(
                New-MockDir "$testRoot\Sub1"
                New-MockDir "$testRoot\Sub1\Sub2"
                New-MockDir "$testRoot\Sub1\Sub2\Sub3"
            )
        }
        Mock Get-GSAAcl {
            New-MockAcl -Access @()
        }
    }

    It 'calls Get-GSAChildItem with -Depth 2 when -MaxDepth 2 is specified' {
        Get-ShareACLAudit -Path $testRoot -MaxDepth 2 | Out-Null
        Should -Invoke Get-GSAChildItem -Times 1 -Exactly -ParameterFilter { $Depth -eq 2 }
    }
}

# ---------------------------------------------------------------------------
# T06: Default MaxDepth is 5.
# ---------------------------------------------------------------------------
Describe 'T06 — Default MaxDepth is 5' {
    BeforeAll {
        $testRoot = 'TestDrive:\T06Root'
        New-Item -Path $testRoot -ItemType Directory -Force | Out-Null

        Mock Get-GSAChildItem { @() }
        Mock Get-GSAAcl { New-MockAcl -Access @() }
    }

    It 'calls Get-GSAChildItem with -Depth 5 when no -MaxDepth is supplied' {
        Get-ShareACLAudit -Path $testRoot | Out-Null
        Should -Invoke Get-GSAChildItem -Times 1 -Exactly -ParameterFilter { $Depth -eq 5 }
    }
}

# ---------------------------------------------------------------------------
# T07: Get-GSAAcl throws — warning emitted, processing continues.
# ---------------------------------------------------------------------------
Describe 'T07 — Get-GSAAcl throws: warning emitted, other dirs still produce findings' {
    BeforeAll {
        $testRoot = 'TestDrive:\T07Root'
        New-Item -Path $testRoot -ItemType Directory -Force | Out-Null

        $script:aclCallCount = 0
        Mock Get-GSAChildItem {
            @( New-MockDir "$testRoot\GoodSub" )
        }
        Mock Get-GSAAcl {
            $script:aclCallCount++
            # First call (root) throws; second call (GoodSub) succeeds.
            if ($script:aclCallCount -eq 1) {
                throw 'Access denied'
            }
            New-MockAcl -Access @(
                New-AccessRule -Identity 'Everyone' -Rights 'FullControl'
            )
        }
    }

    It 'emits a warning when Get-GSAAcl throws' {
        $script:aclCallCount = 0
        $warns = @()
        Get-ShareACLAudit -Path $testRoot -WarningVariable warns -WarningAction SilentlyContinue | Out-Null
        $warns | Where-Object { $_ -match 'Cannot read ACL' } | Should -Not -BeNullOrEmpty
    }

    It 'still produces findings from dirs where Get-GSAAcl succeeds' {
        $script:aclCallCount = 0
        $result = @(Get-ShareACLAudit -Path $testRoot -WarningAction SilentlyContinue)
        $result.Count | Should -Be 1
    }
}

# ---------------------------------------------------------------------------
# T08: Path doesn't exist — warning, no findings, no throw.
# ---------------------------------------------------------------------------
Describe 'T08 — Non-existent path: warning, no findings, no throw' {
    It 'does not throw when the path does not exist' {
        { Get-ShareACLAudit -Path 'C:\NoSuchPath_xyz_audit' -WarningAction SilentlyContinue } |
            Should -Not -Throw
    }

    It 'produces 0 findings when the path does not exist' {
        $result = @(Get-ShareACLAudit -Path 'C:\NoSuchPath_xyz_audit' -WarningAction SilentlyContinue)
        $result.Count | Should -Be 0
    }

    It 'emits a warning when the path does not exist' {
        $warns = @()
        Get-ShareACLAudit -Path 'C:\NoSuchPath_xyz_audit' -WarningVariable warns -WarningAction SilentlyContinue | Out-Null
        $warns | Where-Object { $_ -match 'not found' } | Should -Not -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# T09: Multiple roots — 1 finding per root → 2 total.
# ---------------------------------------------------------------------------
Describe 'T09 — Multiple roots produce combined findings' {
    BeforeAll {
        $root1 = 'TestDrive:\T09Root1'
        $root2 = 'TestDrive:\T09Root2'
        New-Item -Path $root1 -ItemType Directory -Force | Out-Null
        New-Item -Path $root2 -ItemType Directory -Force | Out-Null

        Mock Get-GSAChildItem { @() }
        Mock Get-GSAAcl {
            New-MockAcl -Access @(
                New-AccessRule -Identity 'Everyone' -Rights 'Modify'
            )
        }
    }

    It 'produces 2 findings when each root has 1 risky grant' {
        $result = @(Get-ShareACLAudit -Path $root1, $root2)
        $result.Count | Should -Be 2
    }
}

# ---------------------------------------------------------------------------
# T10: OutputPath produces a CSV with expected columns.
# ---------------------------------------------------------------------------
Describe 'T10 — OutputPath produces a CSV with expected columns' {
    BeforeAll {
        $testRoot = 'TestDrive:\T10Root'
        New-Item -Path $testRoot -ItemType Directory -Force | Out-Null

        Mock Get-GSAChildItem { @() }
        Mock Get-GSAAcl {
            New-MockAcl -Access @(
                New-AccessRule -Identity 'Everyone' -Rights 'FullControl'
            )
        }
    }

    It 'creates a CSV file at OutputPath' {
        $csvPath = Join-Path $TestDrive 'T10-findings.csv'
        Get-ShareACLAudit -Path $testRoot -OutputPath $csvPath
        Test-Path -LiteralPath $csvPath | Should -Be $true
    }

    It 'CSV contains the expected columns' {
        $csvPath = Join-Path $TestDrive 'T10-cols.csv'
        Get-ShareACLAudit -Path $testRoot -OutputPath $csvPath
        $row = Import-Csv -LiteralPath $csvPath | Select-Object -First 1
        $cols = $row.PSObject.Properties.Name
        $cols | Should -Contain 'Path'
        $cols | Should -Contain 'Principal'
        $cols | Should -Contain 'Rights'
        $cols | Should -Contain 'AccessControlType'
        $cols | Should -Contain 'IsInherited'
    }
}

# ---------------------------------------------------------------------------
# T11: Deny rule for risky principal is still flagged.
# ---------------------------------------------------------------------------
Describe 'T11 — Deny rule for a risky principal is reported' {
    BeforeAll {
        $testRoot = 'TestDrive:\T11Root'
        New-Item -Path $testRoot -ItemType Directory -Force | Out-Null

        Mock Get-GSAChildItem { @() }
        Mock Get-GSAAcl {
            New-MockAcl -Access @(
                New-AccessRule -Identity 'Everyone' -Rights 'Modify' -AccessControlType 'Deny'
            )
        }
    }

    It 'produces a finding for a Deny rule matching a risky principal and right' {
        $result = @(Get-ShareACLAudit -Path $testRoot)
        $result.Count | Should -Be 1
    }

    It 'finding AccessControlType is Deny' {
        $result = @(Get-ShareACLAudit -Path $testRoot)
        $result[0].AccessControlType | Should -Be 'Deny'
    }
}

# ---------------------------------------------------------------------------
# T12: Inherited flag preserved in finding row.
# ---------------------------------------------------------------------------
Describe 'T12 — IsInherited flag is preserved in finding row' {
    BeforeAll {
        $testRoot = 'TestDrive:\T12Root'
        New-Item -Path $testRoot -ItemType Directory -Force | Out-Null

        Mock Get-GSAChildItem { @() }
        Mock Get-GSAAcl {
            New-MockAcl -Access @(
                New-AccessRule -Identity 'Everyone' -Rights 'Modify' -IsInherited $true
            )
        }
    }

    It 'finding IsInherited is true when the rule is inherited' {
        $result = @(Get-ShareACLAudit -Path $testRoot)
        $result[0].IsInherited | Should -Be $true
    }
}

# ---------------------------------------------------------------------------
# T13: Custom RiskyPrincipals — only the custom list is matched.
# ---------------------------------------------------------------------------
Describe 'T13 — Custom RiskyPrincipals overrides defaults' {
    BeforeAll {
        $testRoot = 'TestDrive:\T13Root'
        New-Item -Path $testRoot -ItemType Directory -Force | Out-Null

        Mock Get-GSAChildItem { @() }
        Mock Get-GSAAcl {
            New-MockAcl -Access @(
                New-AccessRule -Identity 'Domain Admins' -Rights 'Modify'
                New-AccessRule -Identity 'Everyone' -Rights 'Modify'
            )
        }
    }

    It 'flags Domain Admins when it is in custom RiskyPrincipals' {
        $result = @(Get-ShareACLAudit -Path $testRoot -RiskyPrincipals @('Domain Admins'))
        $result | Where-Object { $_.Principal -eq 'Domain Admins' } | Should -Not -BeNullOrEmpty
    }

    It 'does not flag Everyone when it is not in custom RiskyPrincipals' {
        $result = @(Get-ShareACLAudit -Path $testRoot -RiskyPrincipals @('Domain Admins'))
        $result | Where-Object { $_.Principal -eq 'Everyone' } | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# T14: Custom RiskyRights — Read is now flagged.
# ---------------------------------------------------------------------------
Describe 'T14 — Custom RiskyRights: Read grants are flagged' {
    BeforeAll {
        $testRoot = 'TestDrive:\T14Root'
        New-Item -Path $testRoot -ItemType Directory -Force | Out-Null

        Mock Get-GSAChildItem { @() }
        Mock Get-GSAAcl {
            New-MockAcl -Access @(
                New-AccessRule -Identity 'Everyone' -Rights 'Read'
            )
        }
    }

    It 'flags a Read grant when Read is in custom RiskyRights' {
        $result = @(Get-ShareACLAudit -Path $testRoot -RiskyRights @('Read'))
        $result.Count | Should -Be 1
    }
}

# ---------------------------------------------------------------------------
# T15: Flags-style rights string 'Modify, Synchronize' matches 'Modify'.
# ---------------------------------------------------------------------------
Describe 'T15 — Flags-style rights string with extra tokens still matches' {
    BeforeAll {
        $testRoot = 'TestDrive:\T15Root'
        New-Item -Path $testRoot -ItemType Directory -Force | Out-Null

        Mock Get-GSAChildItem { @() }
        Mock Get-GSAAcl {
            New-MockAcl -Access @(
                New-AccessRule -Identity 'Everyone' -Rights 'Modify, Synchronize'
            )
        }
    }

    It 'produces a finding when FileSystemRights contains Modify among other tokens' {
        $result = @(Get-ShareACLAudit -Path $testRoot)
        $result.Count | Should -Be 1
    }
}

# ---------------------------------------------------------------------------
# T16: Empty Path array — no findings, no error.
# ---------------------------------------------------------------------------
Describe 'T16 — Empty Path array: no findings, no error' {
    It 'does not throw when an empty array is passed' {
        { Get-ShareACLAudit -Path @('') -WarningAction SilentlyContinue } | Should -Not -Throw
    }

    It 'returns 0 findings for an empty-string path' {
        $result = @(Get-ShareACLAudit -Path @('') -WarningAction SilentlyContinue)
        $result.Count | Should -Be 0
    }
}

# ---------------------------------------------------------------------------
# T17: Root with no subdirs but a risky ACL still produces a root finding.
# ---------------------------------------------------------------------------
Describe 'T17 — Root with no subdirs but risky ACL still produces a root finding' {
    BeforeAll {
        $testRoot = 'TestDrive:\T17Root'
        New-Item -Path $testRoot -ItemType Directory -Force | Out-Null

        # No children returned — root only.
        Mock Get-GSAChildItem { @() }
        Mock Get-GSAAcl {
            New-MockAcl -Access @(
                New-AccessRule -Identity 'Everyone' -Rights 'FullControl'
            )
        }
    }

    It 'produces 1 finding for the root path even when no subdirs exist' {
        $result = @(Get-ShareACLAudit -Path $testRoot)
        $result.Count | Should -Be 1
    }

    It 'finding Path equals the root path' {
        $result = @(Get-ShareACLAudit -Path $testRoot)
        $result[0].Path | Should -Be $testRoot
    }
}
