# Read the current module manifest
$manifest = Get-Content -Path .\scans.psd1

# Extract the current version number
$versionLine = $manifest | Where-Object { $_ -match "ModuleVersion" }
$version = $versionLine.Split('=')[1].Trim().Trim("'")

# Increment the version number
$versionParts = $version.Split('.')
$versionParts[3] = [int]$versionParts[3] + 1
$newVersion = $versionParts -join '.'
Write-Host "New version: $newVersion"

# Replace the old version number with the new one in the manifest
$newManifest = $manifest -replace "ModuleVersion = '$version'", "ModuleVersion = '$newVersion'"

# Write the new manifest back to the file
$newManifest | Set-Content -Path .\scans.psd1

Publish-Module -Path .\ -NuGetApiKey oy2chbuy6pf4wdvdjrfq56geccumwpoufgjzlxgw4hqd5u

Write-Host "Module published to the PowerShell Gallery"