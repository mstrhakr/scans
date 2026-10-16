param(
	[Parameter(Mandatory)][string]$OutputFile,
	[string]$Repository = 'printmaster-org/scans',
	[string]$SelectedVersion
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Release.Common.ps1')
if ($Repository -ine 'printmaster-org/scans') { throw 'Release publication is restricted to printmaster-org/scans.' }
if ($SelectedVersion) { Assert-ReleaseVersion $SelectedVersion }
$pages = gh api "repos/$Repository/releases?per_page=100" --paginate --slurp
if ($LASTEXITCODE -ne 0) { throw 'Could not list GitHub releases.' }
$releases = @($pages | ConvertFrom-Json | ForEach-Object { $_ } | ForEach-Object { $_ })
if ($SelectedVersion) {
	$selected = @($releases | Where-Object { $_.tag_name -ceq $SelectedVersion })
	if ($selected.Count -ne 1) {
		throw "Release '$SelectedVersion' was not found or is not visible to this workflow. A Git tag alone is not a published release. Prepare its draft, review it, then publish it in GitHub Releases before promoting."
	}
	if ($selected[0].draft) {
		throw "Release '$SelectedVersion' is still a draft. Review its notes and test its assets, then click Publish release in GitHub Releases. Publishing starts Pages promotion automatically; a manual promotion does not publish the draft."
	}
	if ($selected[0].prerelease) { throw "Release '$SelectedVersion' is a prerelease and cannot be promoted to stable." }
}
$catalog = @()
$work = Join-Path ([IO.Path]::GetTempPath()) ("scans-catalog-" + [guid]::NewGuid().ToString('N'))
New-Item -Path $work -ItemType Directory | Out-Null
try {
	foreach ($release in $releases) {
		if ($release.draft -or $release.prerelease -or $release.tag_name -match '^v?\d+\.\d+\.\d+\.\d+$') { continue }
		$version = $release.tag_name
		Assert-ReleaseVersion $version
		$directory = Join-Path $work $version
		New-Item -Path $directory -ItemType Directory | Out-Null
		gh release download $version --repo $Repository --dir $directory --pattern scans.ps1 --pattern release.json --pattern SHA256SUMS.txt
		if ($LASTEXITCODE -ne 0) { throw "Could not download all required assets for '$version'." }
		$asset = Join-Path $directory 'scans.ps1'
		$metadata = Get-Content -LiteralPath (Join-Path $directory 'release.json') -Raw | ConvertFrom-Json
		Assert-ReleaseMetadata -Metadata $metadata -Version $version -ScriptPath $asset
		$tagCommit = gh api "repos/$Repository/commits/$version" --jq .sha
		if ($LASTEXITCODE -ne 0 -or $tagCommit -cne $metadata.sourceCommit) { throw "Release '$version' points to a different source commit." }
		$source = Join-Path $directory 'source.ps1'
		Invoke-WebRequest -Uri "https://raw.githubusercontent.com/$Repository/$($metadata.sourceCommit)/$($metadata.sourcePath)" -OutFile $source
		if ((Get-FileHash $source -Algorithm SHA256).Hash -ine $metadata.sha256) { throw "Release '$version' differs from its tagged source." }
		$checksum = (Get-Content -LiteralPath (Join-Path $directory 'SHA256SUMS.txt') -Raw).Trim()
		if ($checksum -ine "$($metadata.sha256)  scans.ps1") { throw "Invalid SHA256SUMS.txt for '$version'." }
		$catalog += [ordered]@{
			version = $version
			url = "https://github.com/printmaster-org/scans/releases/download/$version/scans.ps1"
			sha256 = $metadata.sha256.ToLowerInvariant()
			sourceCommit = $metadata.sourceCommit
			publishedAt = $release.published_at
			releaseUrl = "https://github.com/printmaster-org/scans/releases/tag/$version"
		}
	}
	if ($catalog.Count -eq 0) { throw 'No published, verified SemVer releases are available. Publish the first prepared draft before deploying Pages.' }
	ConvertTo-Json -InputObject @($catalog) -Depth 5 | Set-Content -LiteralPath $OutputFile -Encoding UTF8
}
finally {
	Remove-Item -LiteralPath $work -Recurse -Force
}
