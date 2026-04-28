#requires -Version 7.2

<#
    Pester tests for Invoke-RemoteExecHunt.ps1

    Get-WinEvent is mocked throughout so these run without real event logs.
    Each detector gets: a "clean" test (no findings) and a "hit" test (≥1 finding).
#>

BeforeAll {
    . "$PSScriptRoot/Invoke-RemoteExecHunt.ps1"

    # Build a minimal fake EventLogRecord-like object from XML text.
    function New-FakeEvent {
        param(
            [int]$Id,
            [datetime]$TimeCreated,
            [string]$XmlBody   # everything inside <EventData>
        )
        $fullXml = @"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>$Id</EventID>
    <TimeCreated SystemTime="$($TimeCreated.ToString('o'))"/>
  </System>
  <EventData>
$XmlBody
  </EventData>
</Event>
"@
        $obj = [pscustomobject]@{
            Id          = $Id
            TimeCreated = $TimeCreated
            _xml        = $fullXml
        }
        # ToXml() is called by every collector
        $obj | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $this._xml }
        return $obj
    }

    $script:Now = Get-Date
}

# ---------------------------------------------------------------------------
# Read-REHEvents
# ---------------------------------------------------------------------------

Describe 'Read-REHEvents' {
    It 'returns empty array when Get-WinEvent says no events found' {
        Mock Get-WinEvent { throw [System.Exception]'No events were found' }
        $result = Read-REHEvents -LogName 'Security' -EventIds @(4697) `
                      -StartTime $Now.AddHours(-1) -EndTime $Now -MaxEvents 100
        $result | Should -HaveCount 0
    }

    It 'returns empty array when log does not exist' {
        Mock Get-WinEvent { throw [System.Exception]'The specified channel could not be found' }
        $result = Read-REHEvents -LogName 'NonExistent/Log' -EventIds @(91) `
                      -StartTime $Now.AddHours(-1) -EndTime $Now -MaxEvents 100
        $result | Should -HaveCount 0
    }

    It 'returns events when Get-WinEvent succeeds' {
        $fake = New-FakeEvent -Id 4697 -TimeCreated $Now -XmlBody ''
        Mock Get-WinEvent { return @($fake) }
        $result = Read-REHEvents -LogName 'Security' -EventIds @(4697) `
                      -StartTime $Now.AddHours(-1) -EndTime $Now -MaxEvents 100
        $result | Should -HaveCount 1
    }
}

# ---------------------------------------------------------------------------
# ServiceInstall (4697)
# ---------------------------------------------------------------------------

Describe 'Get-REHServiceInstalls' {
    BeforeEach { $script:REHSignerCache = @{} }

    It 'returns no findings when there are no events' {
        Mock Get-WinEvent { throw 'No events were found' }
        $findings, $count = Get-REHServiceInstalls -StartTime $Now.AddHours(-1) -EndTime $Now -MaxEvents 100
        $findings | Should -HaveCount 0
    }

    It 'returns no findings for a Microsoft-signed service' {
        $xml = @'
    <Data Name="SubjectUserName">SYSTEM</Data>
    <Data Name="SubjectDomainName">NT AUTHORITY</Data>
    <Data Name="ServiceName">WinDefend</Data>
    <Data Name="ServiceFileName">C:\Windows\System32\MsMpEng.exe</Data>
'@
        $fake = New-FakeEvent -Id 4697 -TimeCreated $Now -XmlBody $xml
        Mock Get-WinEvent { return @($fake) }
        Mock Test-Path { $true }
        Mock Get-AuthenticodeSignature {
            [pscustomobject]@{
                Status            = 'Valid'
                SignerCertificate = [pscustomobject]@{ Subject = 'CN=Microsoft Windows, O=Microsoft Corporation' }
            }
        }
        $findings, $count = Get-REHServiceInstalls -StartTime $Now.AddHours(-1) -EndTime $Now -MaxEvents 100
        $findings | Should -HaveCount 0
    }

    It 'returns a finding for an unsigned service binary' {
        $xml = @'
    <Data Name="SubjectUserName">Administrator</Data>
    <Data Name="SubjectDomainName">CONTOSO</Data>
    <Data Name="ServiceName">PSEXESVC</Data>
    <Data Name="ServiceFileName">C:\Windows\PSEXESVC.exe</Data>
'@
        $fake = New-FakeEvent -Id 4697 -TimeCreated $Now -XmlBody $xml
        Mock Get-WinEvent { return @($fake) }
        Mock Get-AuthenticodeSignature { [pscustomobject]@{ Status = 'UnknownError'; SignerCertificate = $null } }
        Mock Test-Path { $true }
        $findings, $count = Get-REHServiceInstalls -StartTime $Now.AddHours(-1) -EndTime $Now -MaxEvents 100
        $findings | Should -HaveCount 1
        $findings[0].Detection | Should -Be 'ServiceInstall'
        $findings[0].Detail    | Should -Match 'PSEXESVC'
    }
}

# ---------------------------------------------------------------------------
# RemoteTaskCreate (4698 / 4702)
# ---------------------------------------------------------------------------

Describe 'Get-REHRemoteTaskCreates' {
    It 'returns no findings when there are no events' {
        Mock Get-WinEvent { throw 'No events were found' }
        $findings, $count = Get-REHRemoteTaskCreates -StartTime $Now.AddHours(-1) -EndTime $Now -MaxEvents 100
        $findings | Should -HaveCount 0
    }

    It 'returns no findings for a benign task (no LOLBin in command)' {
        $xml = @'
    <Data Name="SubjectUserName">bob</Data>
    <Data Name="SubjectDomainName">CONTOSO</Data>
    <Data Name="TaskName">\Microsoft\Windows\UpdateOrchestrator\Schedule Scan</Data>
    <Data Name="TaskContent"><Task><Actions><Exec><Command>UsoClient.exe</Command></Exec></Actions></Task></Data>
'@
        $fake = New-FakeEvent -Id 4698 -TimeCreated $Now -XmlBody $xml
        Mock Get-WinEvent { return @($fake) }
        $findings, $count = Get-REHRemoteTaskCreates -StartTime $Now.AddHours(-1) -EndTime $Now -MaxEvents 100
        $findings | Should -HaveCount 0
    }

    It 'returns a finding when task action contains powershell' {
        # Real 4698 events store TaskContent as escaped XML text, not child nodes
        $xml = @'
    <Data Name="SubjectUserName">attacker</Data>
    <Data Name="SubjectDomainName">EVIL</Data>
    <Data Name="TaskName">\Updater</Data>
    <Data Name="TaskContent">powershell.exe -enc AABBCC</Data>
'@
        $fake = New-FakeEvent -Id 4698 -TimeCreated $Now -XmlBody $xml
        Mock Get-WinEvent { return @($fake) }
        $findings, $count = Get-REHRemoteTaskCreates -StartTime $Now.AddHours(-1) -EndTime $Now -MaxEvents 100
        $findings | Should -HaveCount 1
        $findings[0].Detection | Should -Be 'RemoteTaskCreate'
        $findings[0].Detail    | Should -Match 'Created'
    }

    It 'flags 4702 (task modified) as Modified in Detail' {
        $xml = @'
    <Data Name="SubjectUserName">attacker</Data>
    <Data Name="SubjectDomainName">EVIL</Data>
    <Data Name="TaskName">\Backdoor</Data>
    <Data Name="TaskContent">cmd.exe /c whoami</Data>
'@
        $fake = New-FakeEvent -Id 4702 -TimeCreated $Now -XmlBody $xml
        Mock Get-WinEvent { return @($fake) }
        $findings, $count = Get-REHRemoteTaskCreates -StartTime $Now.AddHours(-1) -EndTime $Now -MaxEvents 100
        $findings | Should -HaveCount 1
        $findings[0].Detail | Should -Match 'Modified'
    }
}

# ---------------------------------------------------------------------------
# WMIExecution (5857 / 5860 / 5861)
# ---------------------------------------------------------------------------

Describe 'Get-REHWMIExecution' {
    It 'returns no findings when there are no events' {
        Mock Get-WinEvent { throw 'No events were found' }
        $findings, $count = Get-REHWMIExecution -StartTime $Now.AddHours(-1) -EndTime $Now -MaxEvents 100
        $findings | Should -HaveCount 0
    }

    It 'does not flag 5857 for a standard namespace' {
        $xml = @'
    <Data Name="ProviderName">CIMWin32</Data>
    <Data Name="NamespaceName">root/cimv2</Data>
'@
        $fake = New-FakeEvent -Id 5857 -TimeCreated $Now -XmlBody $xml
        Mock Get-WinEvent { return @($fake) }
        $findings, $count = Get-REHWMIExecution -StartTime $Now.AddHours(-1) -EndTime $Now -MaxEvents 100
        $findings | Should -HaveCount 0
    }

    It 'flags 5857 for a non-standard namespace' {
        $xml = @'
    <Data Name="ProviderName">EvilProvider</Data>
    <Data Name="NamespaceName">root/evil</Data>
'@
        $fake = New-FakeEvent -Id 5857 -TimeCreated $Now -XmlBody $xml
        Mock Get-WinEvent { return @($fake) }
        $findings, $count = Get-REHWMIExecution -StartTime $Now.AddHours(-1) -EndTime $Now -MaxEvents 100
        $findings | Should -HaveCount 1
        $findings[0].Detection | Should -Be 'WMIExecution'
    }

    It 'always flags 5860 (temporary subscription)' {
        $xml = @'
    <Data Name="CONSUMER">ActiveScriptEventConsumer.Name="Backdoor"</Data>
    <Data Name="QUERY">SELECT * FROM __InstanceCreationEvent</Data>
'@
        $fake = New-FakeEvent -Id 5860 -TimeCreated $Now -XmlBody $xml
        Mock Get-WinEvent { return @($fake) }
        $findings, $count = Get-REHWMIExecution -StartTime $Now.AddHours(-1) -EndTime $Now -MaxEvents 100
        $findings | Should -HaveCount 1
        $findings[0].Subject | Should -Match 'Temporary'
    }

    It 'always flags 5861 (permanent subscription)' {
        $xml = @'
    <Data Name="CONSUMER">CommandLineEventConsumer.Name="Persist"</Data>
    <Data Name="QUERY">SELECT * FROM __InstanceModificationEvent</Data>
'@
        $fake = New-FakeEvent -Id 5861 -TimeCreated $Now -XmlBody $xml
        Mock Get-WinEvent { return @($fake) }
        $findings, $count = Get-REHWMIExecution -StartTime $Now.AddHours(-1) -EndTime $Now -MaxEvents 100
        $findings | Should -HaveCount 1
        $findings[0].Subject | Should -Match 'Permanent'
    }
}

# ---------------------------------------------------------------------------
# PSRemoting (WinRM/Operational 91)
# ---------------------------------------------------------------------------

Describe 'Get-REHPSRemoting' {
    It 'returns no findings when there are no events' {
        Mock Get-WinEvent { throw 'No events were found' }
        $findings, $count = Get-REHPSRemoting -StartTime $Now.AddHours(-1) -EndTime $Now -MaxEvents 100
        $findings | Should -HaveCount 0
    }

    It 'returns a finding for any WinRM session' {
        $xml = @'
    <Data Name="userName">CONTOSO\bob</Data>
    <Data Name="clientIp">192.168.1.50</Data>
    <Data Name="resourceUri">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</Data>
'@
        $fake = New-FakeEvent -Id 91 -TimeCreated $Now -XmlBody $xml
        Mock Get-WinEvent { return @($fake) }
        $findings, $count = Get-REHPSRemoting -StartTime $Now.AddHours(-1) -EndTime $Now -MaxEvents 100
        $findings | Should -HaveCount 1
        $findings[0].Detection | Should -Be 'PSRemoting'
        $findings[0].Detail    | Should -Match '192.168.1.50'
    }

    It 'suppresses findings for IPs on the allow list' {
        $xml = @'
    <Data Name="userName">CONTOSO\monitoring</Data>
    <Data Name="clientIp">10.0.0.50</Data>
    <Data Name="resourceUri">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</Data>
'@
        $fake = New-FakeEvent -Id 91 -TimeCreated $Now -XmlBody $xml
        Mock Get-WinEvent { return @($fake) }
        $findings, $count = Get-REHPSRemoting -StartTime $Now.AddHours(-1) -EndTime $Now `
                                -MaxEvents 100 -AllowedSourceIPs @('10.0.0.50')
        $findings | Should -HaveCount 0
    }

    It 'only suppresses matching IPs, not others' {
        $xml1 = @'
    <Data Name="userName">CONTOSO\monitoring</Data>
    <Data Name="clientIp">10.0.0.50</Data>
    <Data Name="resourceUri">wsman/shell</Data>
'@
        $xml2 = @'
    <Data Name="userName">CONTOSO\attacker</Data>
    <Data Name="clientIp">203.0.113.99</Data>
    <Data Name="resourceUri">wsman/shell</Data>
'@
        $fakeAllowed  = New-FakeEvent -Id 91 -TimeCreated $Now -XmlBody $xml1
        $fakeSuspect  = New-FakeEvent -Id 91 -TimeCreated $Now.AddSeconds(5) -XmlBody $xml2
        Mock Get-WinEvent { return @($fakeAllowed, $fakeSuspect) }
        $findings, $count = Get-REHPSRemoting -StartTime $Now.AddHours(-1) -EndTime $Now `
                                -MaxEvents 100 -AllowedSourceIPs @('10.0.0.50')
        $findings | Should -HaveCount 1
        $findings[0].Detail | Should -Match '203.0.113.99'
    }
}

# ---------------------------------------------------------------------------
# Invoke-RemoteExecHunt (integration)
# ---------------------------------------------------------------------------

Describe 'Invoke-RemoteExecHunt' {
    BeforeEach {
        # Default: all collectors return no events
        Mock Get-WinEvent { throw 'No events were found' }
    }

    It 'writes a Markdown file and returns a summary object' {
        $tmp = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.md'
        $result = Invoke-RemoteExecHunt -HoursBack 1 -OutFile $tmp
        $result.PSObject.Properties.Name | Should -Contain 'FindingCount'
        $result.PSObject.Properties.Name | Should -Contain 'EventsScanned'
        $result.PSObject.Properties.Name | Should -Contain 'OutFile'
        Test-Path $tmp | Should -BeTrue
        Remove-Item $tmp -ErrorAction SilentlyContinue
    }

    It 'skips a detection when named in -Skip' {
        # PSRemoting mock returns a real event; if skipped, no finding
        $xml = @'
    <Data Name="userName">bob</Data>
    <Data Name="clientIp">1.2.3.4</Data>
    <Data Name="resourceUri">wsman</Data>
'@
        $fake = New-FakeEvent -Id 91 -TimeCreated $Now -XmlBody $xml
        Mock Get-WinEvent -ParameterFilter {
            $FilterHashtable.LogName -eq 'Microsoft-Windows-WinRM/Operational'
        } { return @($fake) }

        $tmp    = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.md'
        $result = Invoke-RemoteExecHunt -HoursBack 1 -Skip PSRemoting -OutFile $tmp
        $result.FindingCount | Should -Be 0
        Remove-Item $tmp -ErrorAction SilentlyContinue
    }

    It 'report says no findings when everything is clean' {
        $tmp    = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.md'
        Invoke-RemoteExecHunt -HoursBack 1 -OutFile $tmp | Out-Null
        $content = Get-Content $tmp -Raw
        $content | Should -Match 'No suspicious remote execution'
        Remove-Item $tmp -ErrorAction SilentlyContinue
    }
}
