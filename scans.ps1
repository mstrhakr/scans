# Setup variables and defaults
[string]$scanUser = 'scans'
[string]$scanPass = 'scans'
[string]$folderPath = 'C:\scans'
[string]$shareName = 'scans'
[string]$description = 'Scanning setup by Printer Source Plus.'
$ENV:details = 'Loading...'
$domainJoined = (Get-CimInstance -Class Win32_ComputerSystem).PartOfDomain

# Import the Scans module
$moduleName = "scans"
$latestRelease = (Find-Module -Name $moduleName -ErrorAction SilentlyContinue | Sort-Object -Property Version -Descending | Select-Object -First 1).Version
$installedModule = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue

if ($installedModule -and $installedModule.Version -eq $latestRelease) {
	Write-Host "Module '$moduleName' is already $latestRelease."
} else {
	if ($installedModule) {
		Uninstall-Module -Name $moduleName -Force -ErrorAction SilentlyContinue | Out-Null
	}
	Install-Module -Name $moduleName -AllowClobber -Force -SkipPublisherCheck -Scope CurrentUser -RequiredVersion $latestRelease -ErrorAction SilentlyContinue -Confirm:$false | Out-Null
	Import-Module $moduleName -ErrorAction SilentlyContinue | Out-Null
}
$installedModule = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue

# Add required assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Web

# Get user details
$userDetails = Show-ScanningSetupForm -scanUser $scanUser -scanPass $scanPass -folderPath $folderPath -shareName $shareName -description $description

# Extract user details
$scanUser = $userDetails.scanUser
$scanPass = $userDetails.scanPass
$folderPath = $userDetails.folderPath
$shareName = $userDetails.shareName
$description = $userDetails.description

# Show the loading screen
$loadingScreen = New-LoadingForm
$loadingScreen.Form.Show()
$loadingScreen.Form.Topmost = $true

# Setup the scanning user
Set-ScanUser -scanUser $scanUser -scanPass $scanPass -description $description
Hide-ScanUserFromLoginScreen -scanUser $scanUser

# Setup the scanning folder
New-ScanFolder -folderPath $folderPath

$users = @($Env:UserName, $scanUser, "Everyone")
if ($domainJoined) {
	$users += "Domain Users"
}

foreach ($user in $users) {
	Set-ScanFolderPermissions -folderPath $folderPath -username $user -setPermissions $true
}

Set-SmbShare -shareName $shareName -folderPath $folderPath -scanUser $scanUser

New-DesktopShortcut -shortcutPath "C:\Users\Public\Desktop\Scans.lnk"

Set-NetworkSettings -domainJoined $domainJoined -enableFileAndPrinterSharing $true -enablePasswordProtectedSharing $true

Update-ProgressBar $loadingScreen "Finished!"
$loadingScreen.Form.Close() | Out-Null

$finished = New-LoadingForm $true $details
$finished.Form.ShowDialog() | Out-Null
if ($finished.Form -eq [System.Windows.Forms.DialogResult]::OK) {
	$finished.Form.Close() | Out-Null
	Exit
}