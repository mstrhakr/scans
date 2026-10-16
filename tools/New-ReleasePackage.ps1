param(
	[Parameter(Mandatory)][string]$Version,
	[Parameter(Mandatory)][string]$SourceCommit,
	[Parameter(Mandatory)][string]$OutputDirectory,
	[string]$SourceDirectory = (Split-Path $PSScriptRoot -Parent)
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Release.Common.ps1')
Assert-ReleaseVersion $Version
if ($SourceCommit -notmatch '^[a-f0-9]{40}$') { throw 'SourceCommit must be a full Git commit SHA.' }
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Package output directory must not already exist.' }
$root = $SourceDirectory
$sourcePath = if (Test-Path (Join-Path $root 'src\scans.ps1')) { 'src/scans.ps1' } else { 'scans.ps1' }
$source = Join-Path $root ($sourcePath -replace '/', '\')
New-Item -Path $OutputDirectory -ItemType Directory | Out-Null
$asset = Join-Path $OutputDirectory 'scans.ps1'
Copy-Item -LiteralPath $source -Destination $asset
$hash = (Get-FileHash -LiteralPath $asset -Algorithm SHA256).Hash.ToLowerInvariant()
$metadata = [ordered]@{
	schemaVersion = 1
	version = $Version
	sourceCommit = $SourceCommit
	sourcePath = $sourcePath
	sha256 = $hash
}
$metadata | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputDirectory 'release.json') -Encoding UTF8
"$hash  scans.ps1" | Set-Content -LiteralPath (Join-Path $OutputDirectory 'SHA256SUMS.txt') -Encoding ASCII
