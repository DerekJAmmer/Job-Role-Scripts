$ErrorActionPreference = 'Stop'

$publicDir = Join-Path $PSScriptRoot 'Public'

if (Test-Path $publicDir) {
    $publicFunctions = Get-ChildItem -Path $publicDir -Filter '*.ps1' -File
    foreach ($file in $publicFunctions) {
        . $file.FullName
    }
    Export-ModuleMember -Function $publicFunctions.BaseName
}
