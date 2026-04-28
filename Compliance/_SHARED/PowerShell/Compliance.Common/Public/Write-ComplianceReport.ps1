function Write-ComplianceReport {
    <#
    .SYNOPSIS
        Emit a collection of compliance finding objects to the console and optionally a file.

    .DESCRIPTION
        Normalizes how Compliance scripts surface results. By default, prints a
        formatted table to the host. When -OutFile is specified, infers format from
        the file extension (.json, .csv, .html) and writes a persistent report.

        Note: ConvertTo-HtmlEncodedCompliance is inlined here to keep the module
        self-contained. If a shared cross-role helper library is introduced (Tasks
        18/19), this helper is a candidate for promotion.

    .PARAMETER InputObject
        The objects to emit. Accepts pipeline input.

    .PARAMETER OutFile
        Optional path to write the report to. Extension drives format: .json | .csv | .html.

    .PARAMETER Title
        Optional title placed at the top of the HTML output.

    .EXAMPLE
        $findings | Write-ComplianceReport -OutFile .\audit.json

    .EXAMPLE
        $findings | Write-ComplianceReport -OutFile .\audit.html -Title 'CIS Benchmark Audit — HOST1'
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$InputObject,

        [Parameter()]
        [string]$OutFile,

        [Parameter()]
        [string]$Title = 'Compliance Report'
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
                $buffer | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutFile -Encoding UTF8
            }
            '.csv' {
                $buffer | Export-Csv -LiteralPath $OutFile -NoTypeInformation -Encoding UTF8
            }
            '.html' {
                # HTML-encode $Title to prevent XSS when the title contains script tags.
                function ConvertTo-HtmlEncodedCompliance ([string]$Text) {
                    if ($null -eq $Text) { return '' }
                    return $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&#39;')
                }
                $encodedTitle = ConvertTo-HtmlEncodedCompliance $Title
                $buffer | ConvertTo-Html -Title $encodedTitle -PreContent "<h1>$encodedTitle</h1>" |
                    Set-Content -LiteralPath $OutFile -Encoding UTF8
            }
            default {
                throw "Unsupported output extension '$ext'. Use .json, .csv, or .html."
            }
        }

        Write-Information "Report written to $OutFile" -InformationAction Continue
    }
}
