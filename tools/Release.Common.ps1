function Assert-ReleaseVersion {
	param([string]$Version)
	if ($Version -cnotmatch '^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$') {
		throw "Invalid release version '$Version'. Use stable SemVer, for example v2.1.0. Historical four-part tags are not renamed."
	}
}

function Assert-ReleaseMetadata {
	param($Metadata, [string]$Version, [string]$ScriptPath)
	Assert-ReleaseVersion $Version
	if ($Metadata.schemaVersion -ne 1 -or $Metadata.version -cne $Version -or
		$Metadata.sourceCommit -notmatch '^[a-f0-9]{40}$' -or
		$Metadata.sourcePath -cnotin @('scans.ps1', 'src/scans.ps1') -or
		$Metadata.sha256 -notmatch '^[a-fA-F0-9]{64}$') {
		throw "Invalid release metadata for '$Version'."
	}
	if ((Get-FileHash -LiteralPath $ScriptPath -Algorithm SHA256).Hash -ine $Metadata.sha256) {
		throw "Release '$Version' does not match its recorded SHA-256."
	}
}
