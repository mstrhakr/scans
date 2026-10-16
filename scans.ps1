# Requires Windows PowerShell 5.1 or PowerShell 7 on Windows.
param([string]$Version)

function Get-ScanRelease {
	param($Manifest, [string]$RequestedVersion)

	if ($Manifest.schemaVersion -ne 1) { throw 'Unsupported or missing release manifest schema.' }
	$selectedVersion = if ($RequestedVersion) { $RequestedVersion } else { $Manifest.stable }
	if ($selectedVersion -cnotmatch '^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$') {
		throw 'The requested release must be a stable version such as v2.1.0.'
	}
	$matches = @($Manifest.releases | Where-Object { $_.version -ceq $selectedVersion })
	if ($matches.Count -ne 1) { throw "Release '$selectedVersion' is missing or duplicated in the manifest." }
	$release = $matches[0]
	$expectedUrl = "https://github.com/printmaster-org/scans/releases/download/$selectedVersion/scans.ps1"
	if ($release.url -cne $expectedUrl -or $release.sha256 -notmatch '^[a-fA-F0-9]{64}$') {
		throw "Release '$selectedVersion' has an invalid download URL or SHA-256."
	}
	return $release
}

function Invoke-ScanRelease {
	param([string]$RequestedVersion)

	if ($PSVersionTable.PSVersion -lt [version]'5.1' -or $env:OS -ne 'Windows_NT') {
		throw 'Scans requires Windows and Windows PowerShell 5.1 or PowerShell 7.'
	}
	[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
	$manifest = Invoke-RestMethod -Uri 'https://scans.printmaster.work/releases.json' -TimeoutSec 30 -ErrorAction Stop
	$release = Get-ScanRelease -Manifest $manifest -RequestedVersion $RequestedVersion
	$downloadDirectory = Join-Path ([IO.Path]::GetTempPath()) ("printmaster-scans-" + [guid]::NewGuid().ToString('N'))
	$downloadPath = Join-Path $downloadDirectory 'scans.ps1'
	[IO.Directory]::CreateDirectory($downloadDirectory) | Out-Null
	try {
		Invoke-WebRequest -Uri $release.url -OutFile $downloadPath -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
		$actualHash = (Get-FileHash -LiteralPath $downloadPath -Algorithm SHA256 -ErrorAction Stop).Hash
		if ($actualHash -ine $release.sha256) {
			throw "SHA-256 verification failed for $($release.version). Nothing was executed. Try again or contact the maintainer."
		}
		Start-ScanScript -Path $downloadPath -ReleaseVersion $release.version
	}
	finally {
		if (Test-Path -LiteralPath $downloadPath) { Remove-Item -LiteralPath $downloadPath -Force -ErrorAction Stop }
		[IO.Directory]::Delete($downloadDirectory)
	}
}

function Start-ScanScript {
	param([string]$Path, [string]$ReleaseVersion)
	# The child inherits elevation; waiting keeps the verified file available until setup exits.
	$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
	if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
		throw 'Open PowerShell or Terminal as Administrator, then run the Scans command again.'
	}
	Write-Host "Starting PrintMaster Scans $ReleaseVersion (SHA-256 verified)."
	$hostExecutable = if ($PSVersionTable.PSVersion.Major -ge 6) { 'pwsh.exe' } else { 'powershell.exe' }
	& (Join-Path $PSHOME $hostExecutable) -NoProfile -STA -File $Path
	if ($LASTEXITCODE -ne 0) { throw "Scans exited with code $LASTEXITCODE. Review the setup errors before trying again." }
}

try {
	Invoke-ScanRelease -RequestedVersion $Version
}
catch {
	Write-Error "Scans could not start: $($_.Exception.Message)" -ErrorAction Stop
}
