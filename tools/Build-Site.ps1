param(
	[Parameter(Mandatory)][string]$CatalogPath,
	[Parameter(Mandatory)][string]$StableVersion,
	[Parameter(Mandatory)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Release.Common.ps1')
Assert-ReleaseVersion $StableVersion
$catalog = @(Get-Content -LiteralPath $CatalogPath -Raw | ConvertFrom-Json | ForEach-Object { $_ })
$versions = @()
foreach ($release in $catalog) {
	Assert-ReleaseVersion $release.version
	if ($versions -contains $release.version -or $release.sha256 -notmatch '^[a-fA-F0-9]{64}$' -or
		$release.url -cne "https://github.com/printmaster-org/scans/releases/download/$($release.version)/scans.ps1" -or
		$release.releaseUrl -cne "https://github.com/printmaster-org/scans/releases/tag/$($release.version)") {
		throw 'The release catalog contains duplicate versions or invalid release records.'
	}
	$versions += $release.version
}
if ($versions -cnotcontains $StableVersion) { throw "Stable version '$StableVersion' is not in the verified catalog." }
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Site output directory must not already exist.' }
$root = Split-Path $PSScriptRoot -Parent
New-Item -Path $OutputDirectory -ItemType Directory | Out-Null
Copy-Item -Path (Join-Path $root 'site\*') -Destination $OutputDirectory -Recurse
Copy-Item -LiteralPath (Join-Path $root 'scans.ps1') -Destination (Join-Path $OutputDirectory 'scans.ps1')
Copy-Item -Path (Join-Path $root 'img') -Destination $OutputDirectory -Recurse
$manifest = [ordered]@{
	schemaVersion = 1
	stable = $StableVersion
	releases = @($catalog | Sort-Object { [version]$_.version.Substring(1) } -Descending)
}
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'releases.json') -Encoding UTF8
'scans.printmaster.work' | Set-Content -LiteralPath (Join-Path $OutputDirectory 'CNAME') -Encoding ASCII
New-Item -Path (Join-Path $OutputDirectory '.nojekyll') -ItemType File | Out-Null
