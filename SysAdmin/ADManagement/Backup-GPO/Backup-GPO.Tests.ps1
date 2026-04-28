#requires -Version 7.2

BeforeAll {
    . (Join-Path $PSScriptRoot 'Backup-GPO.ps1')

    # Helper: build a synthetic GPO object.
    function New-TestGPO {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pester fixture builder — pure function, no state change.')]
        param(
            [string]$Name,
            [Guid]$Id = [Guid]::NewGuid()
        )
        [PSCustomObject]@{ DisplayName = $Name; Id = $Id }
    }
}

# ---------------------------------------------------------------------------
# T1: Happy path — 3 GPOs all back up successfully
# ---------------------------------------------------------------------------
Describe 'Backup-GPO — happy path 3 GPOs' {
    BeforeAll {
        Mock Invoke-PBGGetGPO {
            @(
                (New-TestGPO -Name 'Default Domain Policy'),
                (New-TestGPO -Name 'Default Domain Controllers Policy'),
                (New-TestGPO -Name 'Workstation Baseline')
            )
        }
        Mock Invoke-PBGBackupGPO    { }
        Mock Invoke-PBGGetGPOReport { }
    }

    It 'returns 3 result rows' {
        $result = @(Backup-GPO -BackupRoot (Join-Path $TestDrive 'happy'))
        $result.Count | Should -Be 3
    }

    It 'all rows have Status=Success' {
        $result = @(Backup-GPO -BackupRoot (Join-Path $TestDrive 'happy2'))
        $result | ForEach-Object { $_.Status | Should -Be 'Success' }
    }

    It 'creates the timestamped subfolder under BackupRoot' {
        $root   = Join-Path $TestDrive 'happy3'
        $null   = @(Backup-GPO -BackupRoot $root)
        $subDir = Get-ChildItem -LiteralPath $root -Directory
        $subDir.Count | Should -BeGreaterOrEqual 1
    }
}

# ---------------------------------------------------------------------------
# T2: One GPO throws on Invoke-PBGBackupGPO
# ---------------------------------------------------------------------------
Describe 'Backup-GPO — one GPO backup fails' {
    BeforeAll {
        $script:gpo1 = New-TestGPO -Name 'GPO-A'
        $script:gpo2 = New-TestGPO -Name 'GPO-B'
        $script:gpo3 = New-TestGPO -Name 'GPO-C'

        Mock Invoke-PBGGetGPO { @($script:gpo1, $script:gpo2, $script:gpo3) }
        Mock Invoke-PBGBackupGPO {
            param([guid]$Guid, [string]$Path)
            if ($Guid -eq $script:gpo2.Id) { throw 'Simulated backup failure' }
        }
        Mock Invoke-PBGGetGPOReport { }
    }

    It 'returns 3 rows total' {
        $result = @(Backup-GPO -BackupRoot (Join-Path $TestDrive 'fail-backup'))
        $result.Count | Should -Be 3
    }

    It 'the failing GPO row has Status=Failed' {
        $result = @(Backup-GPO -BackupRoot (Join-Path $TestDrive 'fail-backup2') -WarningAction SilentlyContinue)
        ($result | Where-Object { $_.DisplayName -eq 'GPO-B' }).Status | Should -Be 'Failed'
    }

    It 'the other two rows have Status=Success' {
        $result = @(Backup-GPO -BackupRoot (Join-Path $TestDrive 'fail-backup3') -WarningAction SilentlyContinue)
        $ok = $result | Where-Object { $_.Status -eq 'Success' }
        $ok.Count | Should -Be 2
    }
}

# ---------------------------------------------------------------------------
# T3: One GPO throws on Invoke-PBGGetGPOReport (XML)
# ---------------------------------------------------------------------------
Describe 'Backup-GPO — GPO report write fails' {
    BeforeAll {
        $script:rptGpo = New-TestGPO -Name 'ReportFail'

        Mock Invoke-PBGGetGPO       { @($script:rptGpo) }
        Mock Invoke-PBGBackupGPO    { }
        Mock Invoke-PBGGetGPOReport {
            param([guid]$Guid, [string]$ReportType, [string]$Path)
            if ($ReportType -eq 'Xml') { throw 'XML report write failed' }
        }
    }

    It 'the row has Status=Failed when the XML report throws' {
        $result = @(Backup-GPO -BackupRoot (Join-Path $TestDrive 'rpt-fail') -WarningAction SilentlyContinue)
        $result[0].Status | Should -Be 'Failed'
    }

    It 'the Reason contains the report error message' {
        $result = @(Backup-GPO -BackupRoot (Join-Path $TestDrive 'rpt-fail2') -WarningAction SilentlyContinue)
        $result[0].Reason | Should -Match 'XML report write failed'
    }
}

# ---------------------------------------------------------------------------
# T4: -WhatIf — helpers not called, rows are WhatIf, no folder created
# ---------------------------------------------------------------------------
Describe 'Backup-GPO — WhatIf mode' {
    BeforeAll {
        Mock Invoke-PBGGetGPO {
            @(
                (New-TestGPO -Name 'Policy-1'),
                (New-TestGPO -Name 'Policy-2')
            )
        }
        Mock Invoke-PBGBackupGPO    { }
        Mock Invoke-PBGGetGPOReport { }
    }

    It 'returns rows with Status=WhatIf' {
        $root   = Join-Path $TestDrive 'whatif'
        $result = @(Backup-GPO -BackupRoot $root -WhatIf)
        $result | ForEach-Object { $_.Status | Should -Be 'WhatIf' }
    }

    It 'does not call Invoke-PBGBackupGPO' {
        $root = Join-Path $TestDrive 'whatif2'
        Backup-GPO -BackupRoot $root -WhatIf | Out-Null
        Should -Invoke Invoke-PBGBackupGPO -Times 0 -Exactly
    }

    It 'does not create any subfolder on disk' {
        $root = Join-Path $TestDrive 'whatif3'
        $null = New-Item -Path $root -ItemType Directory -Force
        Backup-GPO -BackupRoot $root -WhatIf | Out-Null
        $dirs = @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue)
        $dirs.Count | Should -Be 0
    }
}

# ---------------------------------------------------------------------------
# T5: -OutputPath writes JSON with expected top-level keys
# ---------------------------------------------------------------------------
Describe 'Backup-GPO — OutputPath JSON summary' {
    BeforeAll {
        Mock Invoke-PBGGetGPO       { @((New-TestGPO -Name 'TestGPO')) }
        Mock Invoke-PBGBackupGPO    { }
        Mock Invoke-PBGGetGPOReport { }
    }

    It 'writes a file at the specified OutputPath' {
        $root    = Join-Path $TestDrive 'json-out'
        $outFile = Join-Path $TestDrive 'summary.json'
        Backup-GPO -BackupRoot $root -OutputPath $outFile | Out-Null
        Test-Path -LiteralPath $outFile | Should -Be $true
    }

    It 'JSON contains BackupFolder, Timestamp, BackupResults, Comparison, CompareSkipped keys' {
        $root    = Join-Path $TestDrive 'json-keys'
        $outFile = Join-Path $TestDrive 'summary-keys.json'
        Backup-GPO -BackupRoot $root -OutputPath $outFile | Out-Null
        $json = Get-Content -LiteralPath $outFile -Raw | ConvertFrom-Json
        $json.PSObject.Properties.Name | Should -Contain 'BackupFolder'
        $json.PSObject.Properties.Name | Should -Contain 'Timestamp'
        $json.PSObject.Properties.Name | Should -Contain 'BackupResults'
        $json.PSObject.Properties.Name | Should -Contain 'Comparison'
        $json.PSObject.Properties.Name | Should -Contain 'CompareSkipped'
    }
}

# ---------------------------------------------------------------------------
# T6: -CompareToPrevious with no prior folder — CompareSkipped=true
# ---------------------------------------------------------------------------
Describe 'Backup-GPO — CompareToPrevious no prior folder' {
    BeforeAll {
        Mock Invoke-PBGGetGPO       { @((New-TestGPO -Name 'GPO-X')) }
        Mock Invoke-PBGBackupGPO    { }
        Mock Invoke-PBGGetGPOReport { }
    }

    It 'CompareSkipped is true when no prior folder exists' {
        $root    = Join-Path $TestDrive 'cmp-noprior'
        $outFile = Join-Path $TestDrive 'cmp-noprior.json'
        Backup-GPO -BackupRoot $root -CompareToPrevious -OutputPath $outFile | Out-Null
        $json = Get-Content -LiteralPath $outFile -Raw | ConvertFrom-Json
        $json.CompareSkipped | Should -Be $true
    }

    It 'does not throw when no prior folder exists' {
        $root = Join-Path $TestDrive 'cmp-noprior2'
        { Backup-GPO -BackupRoot $root -CompareToPrevious } | Should -Not -Throw
    }
}

# ---------------------------------------------------------------------------
# T7: -CompareToPrevious detects Unchanged
# ---------------------------------------------------------------------------
Describe 'Backup-GPO — CompareToPrevious detects Unchanged' {
    BeforeAll {
        Mock Invoke-PBGGetGPO    { @((New-TestGPO -Name 'SameGPO')) }
        Mock Invoke-PBGBackupGPO { }
        # Write the current XML so the comparison logic finds a file in both folders.
        Mock Invoke-PBGGetGPOReport {
            param([guid]$Guid, [string]$ReportType, [string]$Path)
            if ($ReportType -eq 'Xml') {
                Set-Content -LiteralPath $Path -Value '<xml>identical</xml>' -Encoding UTF8
            }
        }

        # Seed a prior folder with a known XML file.
        $script:root7      = Join-Path $TestDrive 'cmp-unchanged'
        $script:priorDir7  = Join-Path $script:root7 '2020-01-01_0000'
        $null = New-Item -Path $script:priorDir7 -ItemType Directory -Force
        Set-Content -Path (Join-Path $script:priorDir7 'SameGPO.xml') -Value '<xml>identical</xml>' -Encoding UTF8

        # Make Get-FileHash return matching hashes for the current XML.
        Mock Get-FileHash {
            param([string]$LiteralPath, [string]$Algorithm)
            [PSCustomObject]@{ Hash = 'AABBCC'; Algorithm = $Algorithm; Path = $LiteralPath }
        }
    }

    It 'reports Unchanged for a GPO with identical XML in both folders' {
        $outFile = Join-Path $TestDrive 'unchanged.json'
        Backup-GPO -BackupRoot $script:root7 -CompareToPrevious -OutputPath $outFile | Out-Null
        $json = Get-Content -LiteralPath $outFile -Raw | ConvertFrom-Json
        $cmp  = $json.Comparison | Where-Object { $_.DisplayName -eq 'SameGPO' }
        $cmp.Status | Should -Be 'Unchanged'
    }
}

# ---------------------------------------------------------------------------
# T8: -CompareToPrevious detects Changed
# ---------------------------------------------------------------------------
Describe 'Backup-GPO — CompareToPrevious detects Changed' {
    BeforeAll {
        Mock Invoke-PBGGetGPO    { @((New-TestGPO -Name 'ChangedGPO')) }
        Mock Invoke-PBGBackupGPO { }
        # Write the current XML so the comparison logic finds a file in the current folder.
        Mock Invoke-PBGGetGPOReport {
            param([guid]$Guid, [string]$ReportType, [string]$Path)
            if ($ReportType -eq 'Xml') {
                Set-Content -LiteralPath $Path -Value '<xml>new</xml>' -Encoding UTF8
            }
        }

        $script:root8     = Join-Path $TestDrive 'cmp-changed'
        $script:priorDir8 = Join-Path $script:root8 '2020-01-01_0000'
        $null = New-Item -Path $script:priorDir8 -ItemType Directory -Force
        Set-Content -Path (Join-Path $script:priorDir8 'ChangedGPO.xml') -Value '<xml>old</xml>' -Encoding UTF8

        # Return different hashes for the two paths to simulate changed content.
        Mock Get-FileHash {
            param([string]$LiteralPath, [string]$Algorithm)
            $hash = if ($LiteralPath -like '*2020-01-01_0000*') { 'HASH_OLD' } else { 'HASH_NEW' }
            [PSCustomObject]@{ Hash = $hash; Algorithm = $Algorithm; Path = $LiteralPath }
        }
    }

    It 'reports Changed for a GPO with different XML content' {
        $outFile = Join-Path $TestDrive 'changed.json'
        Backup-GPO -BackupRoot $script:root8 -CompareToPrevious -OutputPath $outFile | Out-Null
        $json = Get-Content -LiteralPath $outFile -Raw | ConvertFrom-Json
        $cmp  = $json.Comparison | Where-Object { $_.DisplayName -eq 'ChangedGPO' }
        $cmp.Status | Should -Be 'Changed'
    }
}

# ---------------------------------------------------------------------------
# T9: -CompareToPrevious detects Added
# ---------------------------------------------------------------------------
Describe 'Backup-GPO — CompareToPrevious detects Added' {
    BeforeAll {
        Mock Invoke-PBGGetGPO       { @((New-TestGPO -Name 'NewGPO')) }
        Mock Invoke-PBGBackupGPO    { }
        # Write the current XML when GetGPOReport is called.
        Mock Invoke-PBGGetGPOReport {
            param([guid]$Guid, [string]$ReportType, [string]$Path)
            if ($ReportType -eq 'Xml') {
                Set-Content -LiteralPath $Path -Value '<xml>new</xml>' -Encoding UTF8
            }
        }

        $script:root9     = Join-Path $TestDrive 'cmp-added'
        $script:priorDir9 = Join-Path $script:root9 '2020-01-01_0000'
        $null = New-Item -Path $script:priorDir9 -ItemType Directory -Force
        # Prior folder has NO file for 'NewGPO', simulating an added GPO.
    }

    It 'reports Added for a GPO present in current but not in prior' {
        $outFile = Join-Path $TestDrive 'added.json'
        Backup-GPO -BackupRoot $script:root9 -CompareToPrevious -OutputPath $outFile | Out-Null
        $json = Get-Content -LiteralPath $outFile -Raw | ConvertFrom-Json
        $cmp  = $json.Comparison | Where-Object { $_.DisplayName -eq 'NewGPO' }
        $cmp.Status | Should -Be 'Added'
    }
}

# ---------------------------------------------------------------------------
# T10: -CompareToPrevious detects Removed
# ---------------------------------------------------------------------------
Describe 'Backup-GPO — CompareToPrevious detects Removed' {
    BeforeAll {
        # Current run backs up zero GPOs (the old GPO was deleted from AD).
        Mock Invoke-PBGGetGPO       { @() }
        Mock Invoke-PBGBackupGPO    { }
        Mock Invoke-PBGGetGPOReport { }

        $script:root10     = Join-Path $TestDrive 'cmp-removed'
        $script:priorDir10 = Join-Path $script:root10 '2020-01-01_0000'
        $null = New-Item -Path $script:priorDir10 -ItemType Directory -Force
        # Prior folder has 'OldGPO.xml'; current run produces nothing.
        Set-Content -Path (Join-Path $script:priorDir10 'OldGPO.xml') -Value '<xml>old</xml>' -Encoding UTF8
    }

    It 'reports Removed for a GPO present in prior but absent in current' {
        $outFile = Join-Path $TestDrive 'removed.json'
        Backup-GPO -BackupRoot $script:root10 -CompareToPrevious -OutputPath $outFile | Out-Null
        $json = Get-Content -LiteralPath $outFile -Raw | ConvertFrom-Json
        $cmp  = $json.Comparison | Where-Object { $_.DisplayName -eq 'OldGPO' }
        $cmp.Status | Should -Be 'Removed'
    }
}

# ---------------------------------------------------------------------------
# T11: -CompareToPrevious picks the most recent prior folder
# ---------------------------------------------------------------------------
Describe 'Backup-GPO — CompareToPrevious picks most recent prior' {
    BeforeAll {
        Mock Invoke-PBGGetGPO    { @((New-TestGPO -Name 'MultiPriorGPO')) }
        Mock Invoke-PBGBackupGPO { }
        # Write the current XML so comparison finds it in the current folder.
        Mock Invoke-PBGGetGPOReport {
            param([guid]$Guid, [string]$ReportType, [string]$Path)
            if ($ReportType -eq 'Xml') {
                Set-Content -LiteralPath $Path -Value '<xml>current</xml>' -Encoding UTF8
            }
        }

        $script:root11 = Join-Path $TestDrive 'cmp-multi'
        # Create two older folders; the second is more recent.
        $older  = Join-Path $script:root11 '2020-01-01_0000'
        $newer  = Join-Path $script:root11 '2020-06-01_1200'
        $null = New-Item -Path $older  -ItemType Directory -Force
        $null = New-Item -Path $newer  -ItemType Directory -Force

        # Place different XML in each prior folder; the newer folder's file has
        # a distinct marker so we can verify which one was chosen.
        Set-Content -Path (Join-Path $older  'MultiPriorGPO.xml') -Value '<xml>oldest</xml>' -Encoding UTF8
        Set-Content -Path (Join-Path $newer  'MultiPriorGPO.xml') -Value '<xml>newer</xml>'  -Encoding UTF8

        # Track which folder Get-FileHash was called with.
        $script:hashedPaths11 = [System.Collections.Generic.List[string]]::new()
        Mock Get-FileHash {
            param([string]$LiteralPath, [string]$Algorithm)
            $script:hashedPaths11.Add($LiteralPath)
            [PSCustomObject]@{ Hash = 'SAME'; Algorithm = $Algorithm; Path = $LiteralPath }
        }
    }

    It 'hashes the file from the more recent prior folder (not the oldest)' {
        $script:hashedPaths11.Clear()
        Backup-GPO -BackupRoot $script:root11 -CompareToPrevious | Out-Null
        # At least one of the hashed paths should be from the 2020-06-01_1200 folder.
        $usedNewer = $script:hashedPaths11 | Where-Object { $_ -like '*2020-06-01_1200*' }
        $usedNewer | Should -Not -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# T12: Invoke-PBGGetGPO throws — function re-throws
# ---------------------------------------------------------------------------
Describe 'Backup-GPO — GetGPO failure re-throws' {
    BeforeAll {
        Mock Invoke-PBGGetGPO { throw 'AD is unreachable' }
        Mock Invoke-PBGBackupGPO    { }
        Mock Invoke-PBGGetGPOReport { }
    }

    It 'throws when Invoke-PBGGetGPO throws' {
        { Backup-GPO -BackupRoot (Join-Path $TestDrive 'getgpo-throw') } | Should -Throw
    }
}

# ---------------------------------------------------------------------------
# T13: BackupRoot is a file — throws with clear message
# ---------------------------------------------------------------------------
Describe 'Backup-GPO — BackupRoot is a file' {
    It 'throws when BackupRoot points to an existing file' {
        $filePath = Join-Path $TestDrive 'iamafile.txt'
        Set-Content -Path $filePath -Value 'not a directory' -Encoding UTF8
        { Backup-GPO -BackupRoot $filePath } | Should -Throw -ExpectedMessage "*is a file*"
    }
}

# ---------------------------------------------------------------------------
# T14: GPO display name with special characters is sanitized
# ---------------------------------------------------------------------------
Describe 'Backup-GPO — special characters in GPO name are sanitized' {
    BeforeAll {
        $script:specialGpo = New-TestGPO -Name 'Policy/With:Special\Chars*Name'

        Mock Invoke-PBGGetGPO       { @($script:specialGpo) }
        Mock Invoke-PBGBackupGPO    { }

        $script:capturedPaths14 = [System.Collections.Generic.List[string]]::new()
        Mock Invoke-PBGGetGPOReport {
            param([guid]$Guid, [string]$ReportType, [string]$Path)
            $script:capturedPaths14.Add($Path)
        }
    }

    It 'replaces / \\ : * with underscores in the report file name' {
        $script:capturedPaths14.Clear()
        Backup-GPO -BackupRoot (Join-Path $TestDrive 'sanitize') | Out-Null
        $xmlPath = $script:capturedPaths14 | Where-Object { $_ -like '*.xml' }
        $xmlPath | Should -Not -BeNullOrEmpty
        $fileName = [System.IO.Path]::GetFileName($xmlPath)
        $fileName | Should -Match '^Policy_With_Special_Chars_Name\.xml$'
    }
}

# ---------------------------------------------------------------------------
# T15: Multiple runs create two separate timestamped folders
# ---------------------------------------------------------------------------
Describe 'Backup-GPO — multiple runs are idempotent (two separate folders)' {
    BeforeAll {
        Mock Invoke-PBGGetGPO {
            @(
                (New-TestGPO -Name 'Stable-1'),
                (New-TestGPO -Name 'Stable-2'),
                (New-TestGPO -Name 'Stable-3')
            )
        }
        Mock Invoke-PBGBackupGPO    { }
        Mock Invoke-PBGGetGPOReport { }
    }

    It 'produces two timestamped subfolders after two calls' {
        $root    = Join-Path $TestDrive 'idempotent'
        $null    = @(Backup-GPO -BackupRoot $root)
        # Sleep 1 minute would change the minute stamp, but in tests we just
        # need two distinct folder names. Manipulate by renaming the first folder.
        $first   = (Get-ChildItem -LiteralPath $root -Directory)[0]
        Rename-Item -LiteralPath $first.FullName -NewName '2020-01-01_0000'

        $null    = @(Backup-GPO -BackupRoot $root)
        $dirs    = @(Get-ChildItem -LiteralPath $root -Directory)
        $dirs.Count | Should -Be 2
    }

    It 'second run does not remove the first folder' {
        $root    = Join-Path $TestDrive 'idempotent2'
        $null    = @(Backup-GPO -BackupRoot $root)
        $first   = (Get-ChildItem -LiteralPath $root -Directory)[0]
        Rename-Item -LiteralPath $first.FullName -NewName '2020-01-01_0000'

        $null    = @(Backup-GPO -BackupRoot $root)
        $oldDir  = Join-Path $root '2020-01-01_0000'
        Test-Path -LiteralPath $oldDir -PathType Container | Should -Be $true
    }
}
