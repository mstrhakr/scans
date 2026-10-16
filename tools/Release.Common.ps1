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

function Assert-CommitCI {
	param(
		[Parameter(Mandatory)][string]$SourceCommit,
		[ValidateRange(1, 120)][int]$MaxAttempts = 40,
		[ValidateRange(0, 60)][int]$RetrySeconds = 15
	)
	if ($SourceCommit -cnotmatch '^[a-f0-9]{40}$') { throw 'CI verification requires a full commit SHA.' }
	$repository = 'printmaster-org/scans'
	for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
		$response = gh api "repos/$repository/actions/workflows/ci.yml/runs?event=push&branch=main&head_sha=$SourceCommit&per_page=100" --paginate --slurp
		if ($LASTEXITCODE -ne 0) { throw "Could not verify main CI for $SourceCommit." }
		$runs = @($response | ConvertFrom-Json | ForEach-Object { $_ } | ForEach-Object { $_.workflow_runs } |
			Where-Object { $_.head_sha -ceq $SourceCommit -and $_.event -eq 'push' -and $_.head_branch -eq 'main' } |
			Sort-Object { [long]$_.id } -Descending)
		if ($runs.Count -gt 0) {
			$run = $runs[0]
			if ($run.status -eq 'completed') {
				if ($run.conclusion -ne 'success') {
					throw "Main CI did not pass for $SourceCommit ($($run.conclusion)). See $($run.html_url)"
				}
				Write-Host "Reusing successful main CI: $($run.html_url)"
				return
			}
		}
		if ($attempt -lt $MaxAttempts) {
			Write-Host "Waiting for existing main CI for $SourceCommit ($attempt/$MaxAttempts); no tests are being started."
			Start-Sleep -Seconds $RetrySeconds
		}
	}
	throw "No completed successful main-push CI for $SourceCommit after waiting. Wait for CI and retry the workflow; never move an existing release tag to bypass this gate."
}
