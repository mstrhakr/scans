param([string]$OutputFile)

$ErrorActionPreference = 'Stop'
Import-Module Pester -RequiredVersion 4.10.1 -ErrorAction Stop

$root = Split-Path $PSScriptRoot -Parent
foreach ($file in Get-ChildItem -Path $root -Filter '*.ps1' -Recurse) {
	$tokens = $null
	$parseErrors = $null
	[void][System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$parseErrors)
	if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
}

$parameters = @{ Script = $PSScriptRoot; PassThru = $true }
if ($OutputFile) {
	$parameters.OutputFile = $OutputFile
	$parameters.OutputFormat = 'NUnitXml'
}
$result = Invoke-Pester @parameters
if ($result.TotalCount -eq 0 -or $result.FailedCount -gt 0) {
	throw "Test gate failed: $($result.FailedCount) failed out of $($result.TotalCount) tests."
}
