using module PowerShellGet
using module PackageManagement

param (
    [switch]$Verbose
)

$VerbosePreference = 'SilentlyContinue'
$ErrorActionPreference = 'SilentlyContinue'
$extras = @{}
if ($VerbosePreference -eq 'Continue' -or $Verbose) {
    $extras['Verbose'] = $true
}
$extras['ErrorAction'] = $ErrorActionPreference

function Get-CurrentVersion {
    # Make sure nuget is installed without user intervention
    if (-not (Get-PackageProvider -Name NuGet @extras)) {
        Install-PackageProvider -Name NuGet -Force -Confirm:$false @extras
    }

    # Trust the PowerShell Gallery repository
    if (-not (Get-PSRepository -Name PSGallery @extras)) {
        Register-PSRepository -Name PSGallery -SourceLocation https://www.powershellgallery.com/api/v2 -InstallationPolicy Trusted @extras
    }
    if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne 'Trusted') {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted @extras
    }
    
    # Return the current version number that is published to the PowerShell Gallery
    $currentVersion = (Find-Module -Name scans @extras | Sort-Object -Property Version -Descending | Select-Object -First 1).Version
    return $currentVersion
}

function Set-NewVersion {
    param (
        [string]$Version
    )

    # Increment the version number
    $versionParts = $Version.Split('.')
    $versionParts[3] = [int]$versionParts[3] + 1
    $newVersion = $versionParts -join '.'

    return $newVersion
}

function Update-ManifestVersion {
    param (
        [string]$manifestPath,
        [string]$newVersion
    )

    # Read the current module manifest
    $manifest = Get-Content -Path $manifestPath @extras

    # Update the version number in the manifest
    $versionLine = $manifest | Where-Object { $_ -match "ModuleVersion" }
    $newVersionLine = $versionLine -replace $versionLine.Split('=')[1].Trim().Trim("`'"), $newVersion
    $manifest = $manifest -replace $versionLine, $newVersionLine

    # Write the new manifest back to the file
    $manifest | Set-Content -Path $manifestPath @extras
}

$manifestPath = ".\scans.psd1"
$currentVersion = Get-CurrentVersion
$newVersion = Set-NewVersion -Version $currentVersion
Write-Verbose "New version: $newVersion"
Write-Verbose "Updating the module manifest"
Update-ManifestVersion -manifestPath $manifestPath -newVersion $newVersion

# Set the security protocol to TLS 1.2
Write-Verbose "Checking the security protocol"
if ([Net.ServicePointManager]::SecurityProtocol -ne [Net.SecurityProtocolType]::Tls12) {
    Write-Verbose "Setting the security protocol to TLS 1.2"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} else {
    Write-Verbose "Security protocol is already set to TLS 1.2"
}

# Publish the module to the PowerShell Gallery
Write-Verbose "Publishing the module to the PowerShell Gallery"
$ProgressPreference = 'SilentlyContinue'
Publish-Module -Path .\ -NuGetApiKey oy2chbuy6pf4wdvdjrfq56geccumwpoufgjzlxgw4hqd5u @extras

# Write the new manifest back to the file if the module was published successfully
Write-Verbose "Checking if the new version was published to the PowerShell Gallery successfully"
if (Get-CurrentVersion -eq $newVersion) {
    Write-Host "New version $newVersion published to the PowerShell Gallery successfully"
}
else {
    Write-Error "New version $newVersion was not published to the PowerShell Gallery successfully"
}