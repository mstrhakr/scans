# Setup variables and defaults
param (
	[string]$scanUser = 'scans',
	[string]$folderPath = 'C:\Scans',
	[string]$shareName = 'scans',
	[string]$description = 'Scanning Setup by PSP.',
	[switch]$Verbose,
	[switch]$Quiet
)
$ENV:details = 'Loading...'
$domainJoined = (Get-CimInstance -Class Win32_ComputerSystem).PartOfDomain
<# $ProgressPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue' #>
$ErrorActionPreference = 'Continue'
$extras = @{}
if ($VerbosePreference -eq 'Continue' -or $Verbose -eq $true) {
	$extras['Verbose'] = $true
}
$extras['ErrorAction'] = $ErrorActionPreference

if ($Quiet) {
	$env:quiet = $true
} else {
	$env:quiet = $false
}

# Add required assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Web

#Create a form for the loading text
$loadingForm = New-Object System.Windows.Forms.Form
$loadingForm.Text = "Loading..."
$loadingForm.Size = New-Object System.Drawing.Size(300, 120)
$loadingForm.StartPosition = "CenterScreen"
$loadingForm.Topmost = $true
$loadingForm.FormBorderStyle = "FixedDialog"
$loadingForm.ControlBox = $false
$loadingForm.MaximizeBox = $false
$loadingForm.MinimizeBox = $false

#Create a label for the loading text
$loadingLabel = New-Object System.Windows.Forms.Label
$loadingLabel.Location = New-Object System.Drawing.Size(10, 10)
$loadingLabel.Size = New-Object System.Drawing.Size(280, 20)
$loadingLabel.Text = "Loading, please wait..."
$loadingForm.Controls.Add($loadingLabel)

#Create a progress bar
$loadingProgressBar = New-Object System.Windows.Forms.ProgressBar
$loadingProgressBar.Location = New-Object System.Drawing.Size(10, 40)
$loadingProgressBar.Size = New-Object System.Drawing.Size(270, 20)
$loadingProgressBar.Style = "Continuous"
$loadingProgressBar.Minimum = 0
$loadingProgressBar.Maximum = 110
$loadingProgressBar.Value = 0
$loadingForm.Controls.Add($loadingProgressBar)

if (!$Quiet) {
	try {
		# Show the loading form
		$loadingForm.Add_Shown({ $loadingForm.Activate() })
		$loadingForm.Show()
	}
	catch {
		Write-Error "Error occurred while showing the loading form: $_"
	}
}

function Update-LoadingBar {
	param (
		[System.Windows.Forms.Form]$form,
		[string]$text,
		[int]$value
	)
	if (!$Quiet) {
		try {
			$form.Controls[0].Text = $text
			$form.Controls[1].Value = $value
			$form.Refresh()
			Start-Sleep -Milliseconds 100
		}
		catch {
			Write-Error "Error occurred while updating the loading bar: $_"
		}
	}
}

try {

	try {
		# Check for required modules
		Update-LoadingBar $loadingForm "Checking for required modules..." 5

		try {
			# Check if the NuGet package provider is installed
			Write-Debug "Checking if the NuGet package provider is installed..."
			Update-LoadingBar $loadingForm "Checking if the NuGet package provider is installed..." 10
			if (-not (Get-PackageProvider -Name NuGet @extras)) {
				Write-Debug "Installing NuGet package provider..."
				Update-LoadingBar $loadingForm "Installing NuGet package provider..." 15
				Install-PackageProvider -Name NuGet -Force -Confirm:$false @extras
			}
		}
		catch {
			Write-Error "Error occurred while checking/installing the NuGet package provider: $_"
		}

		try {
			# Trust the PowerShell Gallery repository
			Write-Debug "Checking for the PSGallery repository..."
			Update-LoadingBar $loadingForm "Checking for the PSGallery repository..." 20
			if (-not (Get-PSRepository -Name PSGallery @extras)) {
				Update-LoadingBar $loadingForm "Registering the PSGallery repository..." 25
				Register-PSRepository -Name PSGallery -SourceLocation https://www.powershellgallery.com/api/v2 -InstallationPolicy Trusted @extras
			}
		}
		catch {
			Write-Error "Error occurred while checking/registering the PSGallery repository: $_"
		}

		try {
			# Set the PSGallery repository to trusted
			Write-Debug "Checking if the PSGallery repository is trusted..."
			Update-LoadingBar $loadingForm "Checking if the PSGallery repository is trusted..." 30
			if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne 'Trusted') {
				Update-LoadingBar $loadingForm "Setting the PSGallery repository to trusted..." 35
				Set-PSRepository -Name PSGallery -InstallationPolicy Trusted @extras
			}
		}
		catch {
			Write-Error "Error occurred while setting the PSGallery repository to trusted: $_"
		}

		try {
			# Check if the PackageManagement module is installed
			Write-Debug "Checking if the PackageManagement module is installed..."
			Update-LoadingBar $loadingForm "Checking if the PackageManagement module is installed..." 40
			if (-not (Get-Module -Name PackageManagement -ListAvailable)) {
				Write-Debug "Installing the PackageManagement module..."
				Update-LoadingBar $loadingForm "Installing the PackageManagement module..." 45
				Install-Module -Name PackageManagement -Force -Repository PSGallery -Confirm:$false @extras
			}
		}
		catch {
			Write-Error "Error occurred while checking/installing the PackageManagement module: $_"
		}

		try {
			Write-Debug "Importing the PackageManagement module..."
			Update-LoadingBar $loadingForm "Importing the PackageManagement module..." 50
			Import-Module -Name PackageManagement -Force @extras
		}
		catch {
			Write-Error "Error occurred while importing the PackageManagement module: $_"
		}

		try {
			# Check if the PowerShellGet module is installed
			Write-Debug "Checking if the PowerShellGet module is installed..."
			Update-LoadingBar $loadingForm "Checking if the PowerShellGet module is installed..." 55
			if (-not (Get-Module -Name PowerShellGet -ListAvailable)) {
				Write-Debug "Installing the PowerShellGet module..."
				Update-LoadingBar $loadingForm "Installing the PowerShellGet module..." 60
				Install-Module PowerShellGet -Force -Repository PSGallery -Confirm:$false @extras
			}
		}
		catch {
			Write-Error "Error occurred while checking/installing the PowerShellGet module: $_"
		}

		try {
			# Import the PowerShellGet module
			Write-Debug "Importing the PowerShellGet module..."
			Update-LoadingBar $loadingForm "Importing the PowerShellGet module..." 65
			Import-Module -Name PowerShellGet -Scope Local -Force @extras
		}
		catch {

			Write-Error "Error occurred while importing the PowerShellGet module: $_"
		}

		try {
			# Check if the WindowsCompatibility module is installed
			Write-Debug "Checking if the WindowsCompatibility module is installed..."
			Update-LoadingBar $loadingForm "Checking if the WindowsCompatibility module is installed..." 70
			if (-not (Get-Module -Name WindowsCompatibility -ListAvailable)) {
				Write-Debug "Installing the WindowsCompatibility module..."
				Update-LoadingBar $loadingForm "Installing the WindowsCompatibility module..." 75
				Install-Module WindowsCompatibility -Force -AllowClobber @extras
			}
		}
		catch {
			Write-Error "Error occurred while checking/installing the WindowsCompatibility module: $_"
		}

		try {
			# Import the SmbShare module
			Write-Debug "Importing the SmbShare module..."
			Update-LoadingBar $loadingForm "Importing the SmbShare module..." 80
			Import-Module -Name SmbShare -Force @extras
		}
		catch {
			Write-Error "Error occurred while importing the SmbShare module: $_"
		}

		try {
			# Import the Scans module
			$moduleName = "scans"

			# Check if the module is already installed
			Write-Debug "Checking if the module '$moduleName' is already installed..."
			Update-LoadingBar $loadingForm "Checking if the module '$moduleName' is already installed..." 85
			$latestRelease = (Find-Module -Name $moduleName @extras | Sort-Object -Property Version -Descending | Select-Object -First 1).Version
			$installedModule = Get-InstalledModule -Name $moduleName @extras

			# Install the module if it is not already installed or if it is not the latest version
			if ($installedModule -and $installedModule.Version -eq $latestRelease) {
				Write-Debug "Module '$moduleName' is already $latestRelease."
				Update-LoadingBar $loadingForm "Module '$moduleName' is already $latestRelease." 90
			}
			else {
				if ($installedModule) {
					Write-Debug "Removing installed Module '$moduleName' current version $($installedModule.Version)."
					Update-LoadingBar $loadingForm "Removing installed Module '$moduleName' current version $($installedModule.Version)." 95
					Uninstall-Module -Name $moduleName -Force @extras
				}
				# Install the latest version of the module
				Write-Debug "Installing Module '$moduleName' version $latestRelease."
				Update-LoadingBar $loadingForm "Installing Module '$moduleName' version $latestRelease." 100
				Install-Module -Name $moduleName -AllowClobber -Force -SkipPublisherCheck -Scope CurrentUser -RequiredVersion $latestRelease -Confirm:$false @extras

				# Import the module
				Write-Debug "Importing Module '$moduleName'..."
				Update-LoadingBar $loadingForm "Importing Module '$moduleName'..." 105
				Import-Module $moduleName -Force @extras
			}
		}
		catch {
			Write-Error "Error occurred while importing the Scans module: $_"
		}
	}
	catch {
		Write-Error "Error occurred in the main script: $_"
	}
	finally {
		# Close the loading form
		Write-Debug "Closing the loading form..."
		Update-LoadingBar $loadingForm "Ready!" 110
		Start-Sleep -Milliseconds 500
		if (!$Quiet) {
			try {
				$loadingForm.Close() | Out-Null
			}
			catch {
				Write-Error "Error occurred while closing the loading form: $_"
			}
		}
	}

	if (!$Quiet) {
		try {
			# Get user details
			Write-Debug "Getting user details..."
			$userDetails = Show-ScanningSetupForm -scanUser $scanUser -folderPath $folderPath -shareName $shareName -description $description

			# Extract user details
			Write-Debug "Extracting user details..."
			$scanUser = $userDetails.scanUser
			$scanPass = $userDetails.scanPass
			$folderPath = $userDetails.folderPath
			$shareName = $userDetails.shareName
			$description = $userDetails.description

			# Show the loading screen
			Write-Debug "Showing the loading screen..."
			$loadingScreen = New-LoadingForm -maximum 25
			$loadingScreen.Form.Show()
			$loadingScreen.Form.Topmost = $true
		}
		catch {
			Write-Error "Error occurred while getting user details or showing the loading screen: $_"
		}
	} else {
		try {
			# Generate a random password and set to clipboard
			Write-Debug "Generating a random password..."
			$characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
			$scanPass = -join ((0..11) | ForEach-Object { $characters[(Get-Random -Minimum 0 -Maximum $characters.Length)] })
			$scanPass | Set-Clipboard
			Write-Host "A random password has been generated and copied to the clipboard."
		}
		catch {
			Write-Error "Error occurred while generating a random password: $_"
		}
	}

	try {
		# Setup the scanning user
		Write-Debug "Setting up the scanning user..."
		Set-ScanUser -scanUser $scanUser -scanPass $scanPass -description $description
		Hide-ScanUserFromLoginScreen -scanUser $scanUser

		# Setup the scanning folder
		Write-Debug "Setting up the scanning folder..."
		New-ScanFolder -folderPath $folderPath

		# Gathering the users and groups who will be given permission
		Write-Debug "Gathering the users and groups who will be given permission..."
		$users = @($Env:UserName, $scanUser, "Everyone")
		if ($domainJoined) {
			$users += "Domain Users"
		}

		# Set the permissions on the scanning folder for each uer
		Write-Debug "Setting the permissions on the scanning folder for each user..."
		foreach ($user in $users) {
			Write-Debug "Setting permissions for $user..."
			Set-ScanFolderPermissions -folderPath $folderPath -username $user -setPermissions $true
		}

		# Setup the SMB share
		Write-Debug "Setting up the SMB share..."
		Set-ScansSmbShare -shareName $shareName -folderPath $folderPath -scanUser $scanUser

		# Create a desktop shortcut
		Write-Debug "Creating a desktop shortcut..."
		New-DesktopShortcut -shortcutPath "C:\Users\Public\Desktop\Scans.lnk"

		# Set the network settings
		Write-Debug "Setting the network settings..."
		Set-NetworkSettings -domainJoined $domainJoined -enableFileAndPrinterSharing $true -enablePasswordProtectedSharing $true
	}
	catch {
		Write-Error "Error occurred while setting up scanning user, folder, SMB share, or network settings: $_"
	}

	if (!$Quiet) {
		try {
			# Close the loading screen
			Update-ProgressBar $loadingScreen "Finished!" 25 500
			$loadingScreen.Form.Close() | Out-Null

			$finished = New-LoadingForm $true $ENV:details 
			$finished.Form.ShowDialog() | Out-Null

			if ($finished.Form -eq [System.Windows.Forms.DialogResult]::OK) {
				$finished.Form.Close() | Out-Null
				Exit
			}
		}
		catch {
			Write-Error "Error occurred while closing the loading screen or showing the finished form: $_"			
		}
	} else {
		Write-Host "Scanning setup complete."
	}
}
catch {
	Write-Error "Error occurred: $_"
	Write-Error $_
}