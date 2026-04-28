#requires -Version 7.2

BeforeAll {
    . (Join-Path $PSScriptRoot 'Invoke-IOCSweep.ps1')
}

# ---------------------------------------------------------------------------
# Read-ISIocFile
# ---------------------------------------------------------------------------

Describe 'Read-ISIocFile' {
    BeforeAll {
        # Build a JSON file with mixed valid types
        $jsonContent = @'
[
  { "type": "sha256",  "value": "AABBCCDD1122334455667788990011AABBCCDD1122334455667788990011AABB" },
  { "type": "ip",      "value": "10.0.0.1" },
  { "type": "process", "value": "mimi.exe" },
  { "type": "domain",  "value": "evil.com" }
]
'@
        $jsonFile = Join-Path $TestDrive 'iocs.json'
        Set-Content -LiteralPath $jsonFile -Value $jsonContent -Encoding UTF8

        # Build a CSV equivalent
        $csvFile = Join-Path $TestDrive 'iocs.csv'
        @"
type,value
sha256,AABBCCDD1122334455667788990011AABBCCDD1122334455667788990011AABB
ip,10.0.0.1
process,mimi.exe
domain,evil.com
"@ | Set-Content -LiteralPath $csvFile -Encoding UTF8

        # A file with an unsupported type mixed in
        $mixedJson = @'
[
  { "type": "sha256",  "value": "AABBCCDD1122334455667788990011AABBCCDD1122334455667788990011AABB" },
  { "type": "registry","value": "HKLM\\bad\\key" }
]
'@
        $mixedFile = Join-Path $TestDrive 'mixed.json'
        Set-Content -LiteralPath $mixedFile -Value $mixedJson -Encoding UTF8
    }

    It 'parses JSON — returns 4 items with correct types' {
        $iocs = @(Read-ISIocFile -Path (Join-Path $TestDrive 'iocs.json'))
        $iocs.Count | Should -Be 4
        $iocs[0].Type  | Should -Be 'sha256'
        $iocs[1].Type  | Should -Be 'ip'
        $iocs[2].Type  | Should -Be 'process'
        $iocs[3].Type  | Should -Be 'domain'
    }

    It 'parses CSV — returns 4 items' {
        $iocs = @(Read-ISIocFile -Path (Join-Path $TestDrive 'iocs.csv'))
        $iocs.Count | Should -Be 4
    }

    It 'CSV items have Type and Value properties' {
        $iocs = @(Read-ISIocFile -Path (Join-Path $TestDrive 'iocs.csv'))
        $iocs[0].Type  | Should -Be 'sha256'
        $iocs[3].Value | Should -Be 'evil.com'
    }

    It 'throws on missing file' {
        { Read-ISIocFile -Path (Join-Path $TestDrive 'no-such-file.json') } | Should -Throw
    }

    It 'throws on unsupported extension' {
        $txtFile = Join-Path $TestDrive 'iocs.txt'
        Set-Content -LiteralPath $txtFile -Value 'type,value' -Encoding UTF8
        { Read-ISIocFile -Path $txtFile } | Should -Throw
    }

    It 'skips unsupported type with a warning, does not throw' {
        $iocs = @(Read-ISIocFile -Path (Join-Path $TestDrive 'mixed.json') -WarningAction SilentlyContinue)
        # Only the sha256 entry is valid — registry is skipped
        $iocs.Count | Should -Be 1
        $iocs[0].Type | Should -Be 'sha256'
    }

    It 'trims whitespace and lowercases the type field' {
        $spaceJson = '[{"type":" SHA256 ","value":"AABBCCDD1122334455667788990011AABBCCDD1122334455667788990011AABB"}]'
        $spaceFile = Join-Path $TestDrive 'spaced.json'
        Set-Content -LiteralPath $spaceFile -Value $spaceJson -Encoding UTF8
        $iocs = @(Read-ISIocFile -Path $spaceFile)
        $iocs.Count     | Should -Be 1
        $iocs[0].Type   | Should -Be 'sha256'
    }
}

# ---------------------------------------------------------------------------
# Find-ISConnectionMatches
# ---------------------------------------------------------------------------

Describe 'Find-ISConnectionMatches' {
    It 'returns one finding for the matching IP, skips the other' {
        $fakeConns = @(
            [pscustomobject]@{ RemoteAddress = '1.2.3.4'; RemotePort = 443; State = 'Established';
                                LocalAddress = '192.168.1.1'; LocalPort = 54321; OwningProcess = 1234 },
            [pscustomobject]@{ RemoteAddress = '9.9.9.9'; RemotePort = 80;  State = 'Established';
                                LocalAddress = '192.168.1.1'; LocalPort = 54322; OwningProcess = 5678 }
        )
        Mock Get-NetTCPConnection { $fakeConns }

        $results = @(Find-ISConnectionMatches -IpIocs @('1.2.3.4'))
        $results.Count       | Should -Be 1
        $results[0].Category | Should -Be 'NetConnection'
        $results[0].Ioc      | Should -Be '1.2.3.4'
        $results[0].Subject  | Should -Be '1.2.3.4:443'
    }

    It 'returns empty list when no IPs are supplied' {
        $results = @(Find-ISConnectionMatches -IpIocs @())
        $results.Count | Should -Be 0
    }
}

# ---------------------------------------------------------------------------
# Find-ISProcessMatches
# ---------------------------------------------------------------------------

Describe 'Find-ISProcessMatches' {
    It 'matches mimi.exe IOC against process named mimi (strips .exe, case-insensitive)' {
        $fakeProcs = @(
            [pscustomobject]@{ ProcessName = 'mimi';      Id = 100; Path = 'C:\Temp\mimi.exe';   StartTime = $null },
            [pscustomobject]@{ ProcessName = 'notepad';   Id = 200; Path = 'C:\Windows\notepad.exe'; StartTime = $null }
        )
        Mock Get-Process { $fakeProcs }

        $results = @(Find-ISProcessMatches -ProcessIocs @('mimi.exe'))
        $results.Count       | Should -Be 1
        $results[0].Category | Should -Be 'Process'
        $results[0].Ioc      | Should -Be 'mimi'
    }

    It 'is case-insensitive — MIMI.EXE matches process mimi' {
        $fakeProcs = @(
            [pscustomobject]@{ ProcessName = 'mimi'; Id = 100; Path = 'C:\Temp\mimi.exe'; StartTime = $null }
        )
        Mock Get-Process { $fakeProcs }

        $results = @(Find-ISProcessMatches -ProcessIocs @('MIMI.EXE'))
        $results.Count | Should -Be 1
    }

    It 'returns empty list when no process IOCs are supplied' {
        $results = @(Find-ISProcessMatches -ProcessIocs @())
        $results.Count | Should -Be 0
    }
}

# ---------------------------------------------------------------------------
# Find-ISDnsMatches
# ---------------------------------------------------------------------------

Describe 'Find-ISDnsMatches' {
    It 'matches exact domain in Entry field' {
        $fakeCache = @(
            [pscustomobject]@{ Entry = 'evil.com';     Name = 'evil.com';     Data = '1.2.3.4'; Type = 'A'; Status = 'Success'; TimeToLive = 300 }
        )
        Mock Get-DnsClientCache { $fakeCache }

        $results = @(Find-ISDnsMatches -DomainIocs @('evil.com'))
        $results.Count       | Should -Be 1
        $results[0].Category | Should -Be 'Dns'
        $results[0].Ioc      | Should -Be 'evil.com'
    }

    It 'matches subdomain — evil.com IOC matches sub.evil.com cache entry' {
        $fakeCache = @(
            [pscustomobject]@{ Entry = 'sub.evil.com'; Name = 'sub.evil.com'; Data = '1.2.3.4'; Type = 'A'; Status = 'Success'; TimeToLive = 300 }
        )
        Mock Get-DnsClientCache { $fakeCache }

        $results = @(Find-ISDnsMatches -DomainIocs @('evil.com'))
        $results.Count       | Should -Be 1
        $results[0].Subject  | Should -Be 'sub.evil.com'
    }

    It 'does not match unrelated domain' {
        $fakeCache = @(
            [pscustomobject]@{ Entry = 'goodsite.com'; Name = 'goodsite.com'; Data = '5.6.7.8'; Type = 'A'; Status = 'Success'; TimeToLive = 300 }
        )
        Mock Get-DnsClientCache { $fakeCache }

        $results = @(Find-ISDnsMatches -DomainIocs @('evil.com'))
        $results.Count | Should -Be 0
    }

    It 'returns empty list when no domain IOCs are supplied' {
        $results = @(Find-ISDnsMatches -DomainIocs @())
        $results.Count | Should -Be 0
    }
}

# ---------------------------------------------------------------------------
# Find-ISHashMatches
# ---------------------------------------------------------------------------

Describe 'Find-ISHashMatches' {
    It 'finds a file whose hash is in the IOC list' {
        # Write two small files into TestDrive
        $fileA = Join-Path $TestDrive 'match.exe'
        $fileB = Join-Path $TestDrive 'nope.exe'
        Set-Content -LiteralPath $fileA -Value 'MATCH_CONTENT' -Encoding UTF8
        Set-Content -LiteralPath $fileB -Value 'DIFFERENT'     -Encoding UTF8

        $hashA = (Get-FileHash -LiteralPath $fileA -Algorithm SHA256).Hash

        $results = @(Find-ISHashMatches -HashIocs @($hashA) -Roots @($TestDrive))
        $results.Count       | Should -Be 1
        $results[0].Category | Should -Be 'HashMatch'
        $results[0].Subject  | Should -Be $fileA
    }

    It 'returns empty list when no hashes match' {
        $fileC = Join-Path $TestDrive 'clean.exe'
        Set-Content -LiteralPath $fileC -Value 'CLEAN_CONTENT' -Encoding UTF8

        $results = @(Find-ISHashMatches -HashIocs @('0000000000000000000000000000000000000000000000000000000000000000') -Roots @($TestDrive))
        $results.Count | Should -Be 0
    }

    It 'returns empty list when no hash IOCs are supplied' {
        $results = @(Find-ISHashMatches -HashIocs @() -Roots @($TestDrive))
        $results.Count | Should -Be 0
    }
}

# ---------------------------------------------------------------------------
# Invoke-IOCSweep (smoke test)
# ---------------------------------------------------------------------------

Describe 'Invoke-IOCSweep (smoke)' -Tag 'Integration' {
    It 'returns a summary object, writes a parseable JSON report, IocCounts matches input' {
        # Write a small JSON IOC file — only sha256 entries so all four checks
        # can be skipped cleanly and the result is deterministic.
        $iocJson = @'
[
  { "type": "sha256",  "value": "AABBCCDD1122334455667788990011AABBCCDD1122334455667788990011AABB" },
  { "type": "ip",      "value": "10.99.99.1" },
  { "type": "process", "value": "definitely-not-running.exe" },
  { "type": "domain",  "value": "not-a-real-domain-xyzzy.com" }
]
'@
        $iocFile  = Join-Path $TestDrive 'smoke-iocs.json'
        $outFile  = Join-Path $TestDrive 'out.json'
        Set-Content -LiteralPath $iocFile -Value $iocJson -Encoding UTF8

        # Skip all four surfaces so the test doesn't hit the network/filesystem
        $result = Invoke-IOCSweep `
            -IocFile    $iocFile `
            -OutputPath $outFile `
            -Skip       Hash, Connection, Process, Dns `
            -ErrorAction Stop

        # Summary object shape
        $result           | Should -Not -BeNullOrEmpty
        $result.HostName  | Should -Not -BeNullOrEmpty
        $result.FindingCount | Should -BeOfType [int]
        $result.OutputPath   | Should -Not -BeNullOrEmpty

        # JSON report was written and is parseable
        Test-Path $outFile | Should -BeTrue
        $parsed = Get-Content -LiteralPath $outFile -Raw | ConvertFrom-Json
        $parsed | Should -Not -BeNullOrEmpty

        # IocCounts in the JSON match the 4-entry input
        $parsed.IocCounts.sha256  | Should -Be 1
        $parsed.IocCounts.ip      | Should -Be 1
        $parsed.IocCounts.process | Should -Be 1
        $parsed.IocCounts.domain  | Should -Be 1
    }
}
