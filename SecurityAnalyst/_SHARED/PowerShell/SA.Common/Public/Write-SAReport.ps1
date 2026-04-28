function Write-SAReport {
    <#
    .SYNOPSIS
        Emit a collection of finding objects to the console and optionally a file.

    .DESCRIPTION
        Normalizes how SecurityAnalyst scripts surface results. By default, prints a
        formatted table to the host. When -OutFile is specified, infers format from
        the file extension (.json, .csv, .html) and writes a persistent report.

    .PARAMETER InputObject
        The objects to emit. Accepts pipeline input.

    .PARAMETER OutFile
        Optional path to write the report to. Extension drives format: .json | .csv | .html.

    .PARAMETER Title
        Optional title placed at the top of the HTML output.

    .EXAMPLE
        $findings | Write-SAReport -OutFile .\triage.json

    .EXAMPLE
        $findings | Write-SAReport -OutFile .\triage.html -Title 'QuickTriage on HOST1'
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$InputObject,

        [Parameter()]
        [string]$OutFile,

        [Parameter()]
        [string]$Title = 'SecurityAnalyst Report'
    )

    begin {
        $buffer = [System.Collections.Generic.List[object]]::new()
    }

    process {
        foreach ($item in $InputObject) {
            if ($null -ne $item) { $buffer.Add($item) }
        }
    }

    end {
        if ($buffer.Count -eq 0) {
            Write-Information 'No findings to report.' -InformationAction Continue
            return
        }

        $buffer | Format-Table -AutoSize | Out-String | Write-Information -InformationAction Continue

        if (-not $OutFile) { return }

        $ext = [System.IO.Path]::GetExtension($OutFile).ToLowerInvariant()
        switch ($ext) {
            '.json' {
                $buffer | ConvertTo-Json -Depth 6 | Set-Content -Path $OutFile -Encoding UTF8
            }
            '.csv' {
                $buffer | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
            }
            '.html' {
                $buffer | ConvertTo-Html -Title $Title -PreContent "<h1>$Title</h1>" |
                    Set-Content -Path $OutFile -Encoding UTF8
            }
            default {
                throw "Unsupported output extension '$ext'. Use .json, .csv, or .html."
            }
        }

        Write-Information "Report written to $OutFile" -InformationAction Continue
    }
}
