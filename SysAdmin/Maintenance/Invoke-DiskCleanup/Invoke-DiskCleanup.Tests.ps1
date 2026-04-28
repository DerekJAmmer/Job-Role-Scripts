#requires -Version 7.2

BeforeAll {
    . (Join-Path $PSScriptRoot 'Invoke-DiskCleanup.ps1')
}

# ---------------------------------------------------------------------------
# Get-DCUserTempFile
# ---------------------------------------------------------------------------

Describe 'Get-DCUserTempFile' {
    BeforeAll {
        $userTemp = Join-Path $TestDrive 'UserTemp'
        New-Item -ItemType Directory -Path $userTemp -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $userTemp 'file1.tmp') -Value 'data1'
        Set-Content -LiteralPath (Join-Path $userTemp 'file2.tmp') -Value 'data2'
    }

    It 'returns files from the root temp directory' {
        $files = @(Get-DCUserTempFile -Root (Join-Path $TestDrive 'UserTemp') -AllUsersRoot (Join-Path $TestDrive 'NoSuchDir'))
        $files.Count | Should -BeGreaterOrEqual 2
    }

    It 'returns empty array when root does not exist' {
        $files = @(Get-DCUserTempFile -Root (Join-Path $TestDrive 'NonExistent') -AllUsersRoot (Join-Path $TestDrive 'NonExistent2'))
        $files.Count | Should -Be 0
    }

    It 'includes files from user profile AppData Local Temp subdirs' {
        $allUsersRoot = Join-Path $TestDrive 'Users'
        $profileTemp  = Join-Path $allUsersRoot 'TestUser\AppData\Local\Temp'
        New-Item -ItemType Directory -Path $profileTemp -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $profileTemp 'profile-file.tmp') -Value 'x'

        $files = @(Get-DCUserTempFile -Root (Join-Path $TestDrive 'EmptyRoot') -AllUsersRoot $allUsersRoot)
        $fileNames = $files | ForEach-Object { $_.Name }
        $fileNames | Should -Contain 'profile-file.tmp'
    }
}

# ---------------------------------------------------------------------------
# Get-DCWindowsTempFile
# ---------------------------------------------------------------------------

Describe 'Get-DCWindowsTempFile' {
    BeforeAll {
        $winTemp = Join-Path $TestDrive 'WinTemp'
        New-Item -ItemType Directory -Path $winTemp -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $winTemp 'wt1.log') -Value 'log1'
        Set-Content -LiteralPath (Join-Path $winTemp 'wt2.log') -Value 'log2'
    }

    It 'returns files from the Windows Temp directory' {
        $files = @(Get-DCWindowsTempFile -Root (Join-Path $TestDrive 'WinTemp'))
        $files.Count | Should -Be 2
    }

    It 'returns empty array when root does not exist' {
        $files = @(Get-DCWindowsTempFile -Root (Join-Path $TestDrive 'NoSuchWinTemp'))
        $files.Count | Should -Be 0
    }
}

# ---------------------------------------------------------------------------
# Get-DCIISLogFile
# ---------------------------------------------------------------------------

Describe 'Get-DCIISLogFile' {
    It 'returns empty array when IIS log root does not exist' {
        $files = @(Get-DCIISLogFile -Root (Join-Path $TestDrive 'NoIIS'))
        $files.Count | Should -Be 0
    }

    It 'returns log files older than 7 days' {
        $iisRoot = Join-Path $TestDrive 'IISLogs\W3SVC1'
        New-Item -ItemType Directory -Path $iisRoot -Force | Out-Null

        $oldLog = Join-Path $iisRoot 'old.log'
        $newLog = Join-Path $iisRoot 'new.log'
        Set-Content -LiteralPath $oldLog -Value 'old'
        Set-Content -LiteralPath $newLog -Value 'new'
        (Get-Item -LiteralPath $oldLog).LastWriteTime = (Get-Date).AddDays(-30)
        (Get-Item -LiteralPath $newLog).LastWriteTime = (Get-Date).AddDays(-1)

        $files = @(Get-DCIISLogFile -Root (Join-Path $TestDrive 'IISLogs'))
        $fileNames = $files | ForEach-Object { $_.Name }
        $fileNames | Should -Contain 'old.log'
        $fileNames | Should -Not -Contain 'new.log'
    }

    It 'does not throw when IIS path is missing' {
        { Get-DCIISLogFile -Root (Join-Path $TestDrive 'AbsolutelyMissing') -ErrorAction Stop } |
            Should -Not -Throw
    }
}

# ---------------------------------------------------------------------------
# Get-DCOldLogFile
# ---------------------------------------------------------------------------

Describe 'Get-DCOldLogFile' {
    BeforeAll {
        $logsRoot = Join-Path $TestDrive 'WinLogs'
        New-Item -ItemType Directory -Path $logsRoot -Force | Out-Null

        $oldFile = Join-Path $logsRoot 'old-event.log'
        $newFile = Join-Path $logsRoot 'new-event.log'
        Set-Content -LiteralPath $oldFile -Value 'old'
        Set-Content -LiteralPath $newFile -Value 'new'
        (Get-Item -LiteralPath $oldFile).LastWriteTime = (Get-Date).AddDays(-60)
        (Get-Item -LiteralPath $newFile).LastWriteTime = (Get-Date).AddDays(-5)
    }

    It 'returns files older than OldLogDays' {
        $files = @(Get-DCOldLogFile -OldLogDays 30 `
            -WindowsLogsRoot (Join-Path $TestDrive 'WinLogs') `
            -CbsLogsRoot     (Join-Path $TestDrive 'NoCBS') `
            -WerRoot         (Join-Path $TestDrive 'NoWER'))
        $fileNames = $files | ForEach-Object { $_.Name }
        $fileNames | Should -Contain 'old-event.log'
    }

    It 'does not return files newer than OldLogDays' {
        $files = @(Get-DCOldLogFile -OldLogDays 30 `
            -WindowsLogsRoot (Join-Path $TestDrive 'WinLogs') `
            -CbsLogsRoot     (Join-Path $TestDrive 'NoCBS') `
            -WerRoot         (Join-Path $TestDrive 'NoWER'))
        $fileNames = $files | ForEach-Object { $_.Name }
        $fileNames | Should -Not -Contain 'new-event.log'
    }

    It 'respects a shorter OldLogDays value' {
        $files = @(Get-DCOldLogFile -OldLogDays 3 `
            -WindowsLogsRoot (Join-Path $TestDrive 'WinLogs') `
            -CbsLogsRoot     (Join-Path $TestDrive 'NoCBS') `
            -WerRoot         (Join-Path $TestDrive 'NoWER'))
        # Both files (5 days and 60 days old) should now be included
        $files.Count | Should -Be 2
    }

    It 'returns empty array when all roots are missing' {
        $files = @(Get-DCOldLogFile -OldLogDays 30 `
            -WindowsLogsRoot (Join-Path $TestDrive 'NoDir1') `
            -CbsLogsRoot     (Join-Path $TestDrive 'NoDir2') `
            -WerRoot         (Join-Path $TestDrive 'NoDir3'))
        $files.Count | Should -Be 0
    }

    It 'aggregates files from multiple roots' {
        $root1 = Join-Path $TestDrive 'MultiRoot1'
        $root2 = Join-Path $TestDrive 'MultiRoot2'
        New-Item -ItemType Directory -Path $root1 -Force | Out-Null
        New-Item -ItemType Directory -Path $root2 -Force | Out-Null

        $f1 = Join-Path $root1 'a.log'
        $f2 = Join-Path $root2 'b.log'
        Set-Content -LiteralPath $f1 -Value 'a'
        Set-Content -LiteralPath $f2 -Value 'b'
        (Get-Item -LiteralPath $f1).LastWriteTime = (Get-Date).AddDays(-40)
        (Get-Item -LiteralPath $f2).LastWriteTime = (Get-Date).AddDays(-40)

        $files = @(Get-DCOldLogFile -OldLogDays 30 `
            -WindowsLogsRoot $root1 `
            -CbsLogsRoot     $root2 `
            -WerRoot         (Join-Path $TestDrive 'NoWER3'))
        $files.Count | Should -Be 2
    }
}

# ---------------------------------------------------------------------------
# Invoke-DiskCleanup — MinFreeGB short-circuit
# ---------------------------------------------------------------------------

Describe 'Invoke-DiskCleanup MinFreeGB short-circuit' {
    It 'skips cleanup when drive free space meets the threshold' {
        # Mock 50 GB free; threshold is 20 GB — drive is above threshold, should skip
        Mock Get-PSDrive {
            [PSCustomObject]@{ Name = 'C'; Free = 50GB }
        }
        Mock Remove-Item { }

        $report = Invoke-DiskCleanup -MinFreeGB 20 -Confirm:$false

        $report.TotalReclaimedMB | Should -Be 0
        $report.Targets | ForEach-Object { $_.Skipped | Should -Be 'AboveThreshold' }
        Should -Invoke Remove-Item -Times 0
    }

    It 'proceeds with cleanup when drive free space is below the threshold' {
        # Mock 5 GB free; threshold is 20 GB — drive is below threshold, should run
        Mock Get-PSDrive {
            [PSCustomObject]@{ Name = 'C'; Free = 5GB }
        }
        $report = Invoke-DiskCleanup -MinFreeGB 20 -Targets @('WindowsTemp') -Confirm:$false

        $report.Targets.Count | Should -Be 1
        $report.Targets[0].Skipped | Should -Not -Be 'AboveThreshold'
    }

    It 'always runs when MinFreeGB is 0 (default)' {
        Mock Get-PSDrive { }   # Should not be called at all

        $report = Invoke-DiskCleanup -MinFreeGB 0 -Targets @('WindowsTemp') -Confirm:$false
        $report.Targets | ForEach-Object { $_.Skipped | Should -Not -Be 'AboveThreshold' }
        Should -Invoke Get-PSDrive -Times 0
    }
}

# ---------------------------------------------------------------------------
# Invoke-DiskCleanup — ShouldProcess / WhatIf gating
# ---------------------------------------------------------------------------

Describe 'Invoke-DiskCleanup ShouldProcess gating' {
    BeforeAll {
        $fakeTemp = Join-Path $TestDrive 'FakeWinTemp'
        New-Item -ItemType Directory -Path $fakeTemp -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $fakeTemp 'deleteme.tmp') -Value 'junk'

        # Override the WindowsTemp collector to return our test file
        Mock Get-DCWindowsTempFile {
            Get-ChildItem -Path (Join-Path $TestDrive 'FakeWinTemp') -File
        }
        Mock Remove-Item { }
    }

    It 'calls Remove-Item when Confirm:$false is passed' {
        Invoke-DiskCleanup -Targets WindowsTemp -Confirm:$false | Out-Null
        Should -Invoke Remove-Item -Times 1 -ParameterFilter { $Path -like '*deleteme.tmp' }
    }

    It 'does not call Remove-Item when -WhatIf is passed' {
        Invoke-DiskCleanup -Targets WindowsTemp -WhatIf | Out-Null
        Should -Invoke Remove-Item -Times 0
    }
}

# ---------------------------------------------------------------------------
# Invoke-DiskCleanup — report shape and JSON output
# ---------------------------------------------------------------------------

Describe 'Invoke-DiskCleanup report output' {
    BeforeAll {
        # Mock all collectors to avoid hitting real system paths in test runs
        Mock Get-DCUserTempFile    { @() }
        Mock Get-DCWindowsTempFile { @() }
        Mock Get-DCIISLogFile      { @() }
        Mock Get-DCOldLogFile      { @() }
    }

    It 'emits a report with the expected top-level properties' {
        $report = Invoke-DiskCleanup -Targets WindowsTemp -Confirm:$false
        $report.Host             | Should -Not -BeNullOrEmpty
        $report.Started          | Should -BeOfType [datetime]
        $report.Finished         | Should -BeOfType [datetime]
        $report.Targets          | Should -Not -BeNullOrEmpty
        $report.TotalReclaimedMB | Should -BeOfType [double]
    }

    It 'writes a parseable JSON file when -OutputPath is given' {
        $outFile = Join-Path $TestDrive 'report.json'
        Invoke-DiskCleanup -Targets WindowsTemp -Confirm:$false -OutputPath $outFile | Out-Null
        Test-Path -LiteralPath $outFile | Should -BeTrue
        $parsed = Get-Content -LiteralPath $outFile -Raw | ConvertFrom-Json
        $parsed | Should -Not -BeNullOrEmpty
        $parsed.Host | Should -Not -BeNullOrEmpty
    }

    It 'report Targets array contains one entry per requested target' {
        $report = Invoke-DiskCleanup -Targets @('UserTemp', 'WindowsTemp') -Confirm:$false
        $report.Targets.Count | Should -Be 2
        ($report.Targets | ForEach-Object { $_.Name }) | Should -Contain 'UserTemp'
        ($report.Targets | ForEach-Object { $_.Name }) | Should -Contain 'WindowsTemp'
    }
}
