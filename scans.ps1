# Setup variables and defaults
[string]$scanUser = 'scans'
[string]$scanPass = 'scans'
[string]$folderPath = 'C:\scans'
[string]$shareName = 'scans'
[string]$description = 'Scanning setup by PSP.'

# Load the .NET Framework classes
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Web
$ProgressPreference = 'SilentlyContinue'

$createUser = $true
$hideUser = $true
$createFolder = $true
$setPermissions = $true
$setShare = $true
$createShortcut = $true
$checkNetworkSettings = $true

# Download icon
$iconPath = 'C:\ProgramData\scans.ico'
Invoke-WebRequest 'https://raw.githubusercontent.com/mstrhakr/scans/main/img/scans.ico' -OutFile $iconPath | Out-Null;

function New-SettingsPage ($test) {
	# Create form
	$settings = New-Object System.Windows.Forms.Form
	$settings.Text = 'Settings'
	$settings.Icon = $iconPath
	$settings.Size = New-Object System.Drawing.Size(300, 200)
	$settings.StartPosition = 'CenterScreen'

	# Create checkbox
	$createUserCheckbox = New-Object System.Windows.Forms.CheckBox
	$createUserCheckbox.Location = New-Object System.Drawing.Point(10, 10)
	$createUserCheckbox.Size = New-Object System.Drawing.Size(250, 20)
	$createUserCheckbox.Text = 'Create new user account'
	$createUserCheckbox.Checked = $createUser

	# Add checkbox checked event
	$createUserCheckbox.Add_CheckedChanged(
		{
			if ($createUserCheckbox.Checked) {
				$script:createUser = $true
			}
			else {
				$script:createUser = $false
			}
		}
	)
	
	# Create checkbox
	$hideUserCheckbox = New-Object System.Windows.Forms.CheckBox
	$hideUserCheckbox.Location = New-Object System.Drawing.Point(10, 30)
	$hideUserCheckbox.Size = New-Object System.Drawing.Size(250, 20)
	$hideUserCheckbox.Text = 'Hide user account from login screen'
	$hideUserCheckbox.Checked = $hideUser

	# Add checkbox checked event
	$hideUserCheckbox.Add_CheckedChanged(
		{
			if ($hideUserCheckbox.Checked) {
				$script:hideUser = $true
			}
			else {
				$script:hideUser = $false
			}
		}
	)

	# Create checkbox
	$createFolderCheckbox = New-Object System.Windows.Forms.CheckBox
	$createFolderCheckbox.Location = New-Object System.Drawing.Point(10, 50)
	$createFolderCheckbox.Size = New-Object System.Drawing.Size(250, 20)
	$createFolderCheckbox.Text = 'Create scans folder'
	$createFolderCheckbox.Checked = $createFolder

	# Add checkbox checked event
	$createFolderCheckbox.Add_CheckedChanged(
		{
			if ($createFolderCheckbox.Checked) {
				$script:createFolder = $true
			}
			else {
				$script:createFolder = $false
			}
		}
	)

	# Create checkbox
	$setPermissionsCheckbox = New-Object System.Windows.Forms.CheckBox
	$setPermissionsCheckbox.Location = New-Object System.Drawing.Point(10, 70)
	$setPermissionsCheckbox.Size = New-Object System.Drawing.Size(250, 20)
	$setPermissionsCheckbox.Text = 'Set permissions on scans folder'
	$setPermissionsCheckbox.Checked = $setPermissions

	# Add checkbox checked event
	$setPermissionsCheckbox.Add_CheckedChanged(
		{
			if ($setPermissionsCheckbox.Checked) {
				$script:setPermissions = $true
			}
			else {
				$script:setPermissions = $false
			}
		}
	)

	# Create checkbox
	$setShareCheckbox = New-Object System.Windows.Forms.CheckBox
	$setShareCheckbox.Location = New-Object System.Drawing.Point(10, 90)
	$setShareCheckbox.Size = New-Object System.Drawing.Size(250, 20)
	$setShareCheckbox.Text = 'Set SMB share on scans folder'
	$setShareCheckbox.Checked = $setShare

	# Add checkbox checked event
	$setShareCheckbox.Add_CheckedChanged(
		{
			if ($setShareCheckbox.Checked) {
				$script:setShare = $true
			}
			else {
				$script:setShare = $false
			}
		}
	)

	# Create checkbox
	$createShortcutCheckbox = New-Object System.Windows.Forms.CheckBox
	$createShortcutCheckbox.Location = New-Object System.Drawing.Point(10, 110)
	$createShortcutCheckbox.Size = New-Object System.Drawing.Size(250, 20)
	$createShortcutCheckbox.Text = 'Create desktop shortcut'
	$createShortcutCheckbox.Checked = $createShortcut

	# Add checkbox checked event
	$createShortcutCheckbox.Add_CheckedChanged(
		{
			if ($createShortcutCheckbox.Checked) {
				$script:createShortcut = $true
			}
			else {
				$script:createShortcut = $false
			}
		}
	)

	# Create checkbox
	$checkNetworkSettingsCheckbox = New-Object System.Windows.Forms.CheckBox
	$checkNetworkSettingsCheckbox.Location = New-Object System.Drawing.Point(10, 130)
	$checkNetworkSettingsCheckbox.Size = New-Object System.Drawing.Size(250, 20)
	$checkNetworkSettingsCheckbox.Text = 'Check network settings'
	$checkNetworkSettingsCheckbox.Checked = $checkNetworkSettings

	# Add checkbox checked event
	$checkNetworkSettingsCheckbox.Add_CheckedChanged(
		{
			if ($checkNetworkSettingsCheckbox.Checked) {
				$script:checkNetworkSettings = $true
			}
			else {
				$script:checkNetworkSettings = $false
			}
		}
	)

	# Add checkbox to form
	$settings.Controls.Add($createUserCheckbox)
	$settings.Controls.Add($hideUserCheckbox)
	$settings.Controls.Add($createFolderCheckbox)
	$settings.Controls.Add($setPermissionsCheckbox)
	$settings.Controls.Add($setShareCheckbox)
	$settings.Controls.Add($createShortcutCheckbox)
	$settings.Controls.Add($checkNetworkSettingsCheckbox)

	# Show form
	$settings.ShowDialog()
}

# Create a new form with a title and a size
$scanningSetupForm = New-Object System.Windows.Forms.Form
$scanningSetupForm.Text = 'Scans.exe'
$scanningSetupForm.Icon = $iconPath
$scanningSetupForm.Size = New-Object System.Drawing.Size (300, 200)
$scanningSetupForm.StartPosition = 'CenterScreen'

# Create a text box for the user to choose a custom username
$scanUserLabel = New-Object	System.Windows.Forms.Label
$scanUserLabel.Location = New-Object System.Drawing.Point (10, 10)
$scanUserLabel.Size = New-Object System.Drawing.Size (70, 20)
$scanUserLabel.Text = 'Username:'
$scanningSetupForm.Controls.Add($scanUserLabel)
$scanUserTextBox = New-Object System.Windows.Forms.TextBox
$scanUserTextBox.Location = New-Object System.Drawing.Point (80, 10)
$scanUserTextBox.Size = New-Object System.Drawing.Size (190, 20)
$scanUserTextBox.Text = $scanUser
$scanningSetupForm.Controls.Add($scanUserTextBox)

# Create a text box for the user to choose a custom password
$scanPassLabel = New-Object	System.Windows.Forms.Label
$scanPassLabel.Location = New-Object System.Drawing.Point (10, 35)
$scanPassLabel.Size = New-Object System.Drawing.Size (70, 20)
$scanPassLabel.Text = 'Password:'
$scanningSetupForm.Controls.Add($scanPassLabel)
$scanPassTextBox = New-Object System.Windows.Forms.TextBox
$scanPassTextBox.Location = New-Object System.Drawing.Point (80, 35)
$scanPassTextBox.Size = New-Object System.Drawing.Size (190, 20)
$scanPassTextBox.Text = [System.Web.Security.Membership]::GeneratePassword(10, 0)
$scanningSetupForm.Controls.Add($scanPassTextBox)

# Create a text box for the user to choose a custom path
$folderPathLabel = New-Object	System.Windows.Forms.Label
$folderPathLabel.Location = New-Object System.Drawing.Point (10, 60)
$folderPathLabel.Size = New-Object System.Drawing.Size (70, 20)
$folderPathLabel.Text = 'Local Dir:'
$scanningSetupForm.Controls.Add($folderPathLabel)
$folderPathTextBox = New-Object System.Windows.Forms.TextBox
$folderPathTextBox.Location = New-Object System.Drawing.Point (80, 60)
$folderPathTextBox.Size = New-Object System.Drawing.Size (190, 20)
$folderPathTextBox.Text = $folderPath
$scanningSetupForm.Controls.Add($folderPathTextBox)

# Create a text box for the user to choose a smb share
$smbShareLabel = New-Object	System.Windows.Forms.Label
$smbShareLabel.Location = New-Object System.Drawing.Point (10, 85)
$smbShareLabel.Size = New-Object System.Drawing.Size (70, 20)
$smbShareLabel.Text = 'SMB Share:'
$scanningSetupForm.Controls.Add($smbShareLabel)
$smbShareTextBox = New-Object System.Windows.Forms.TextBox
$smbShareTextBox.Location = New-Object System.Drawing.Point (80, 85)
$smbShareTextBox.Size = New-Object System.Drawing.Size (190, 20)
$smbShareTextBox.Text = $shareName
$scanningSetupForm.Controls.Add($smbShareTextBox)

# Create an OK button and add it to the form
$okButton = New-Object System.Windows.Forms.Button
$okButton.Location = New-Object System.Drawing.Point (75, 120)
$okButton.Size = New-Object System.Drawing.Size (75, 23)
$okButton.Text = 'OK'
$okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$scanningSetupForm.AcceptButton = $okButton
$scanningSetupForm.Controls.Add($okButton)

# Create a Cancel button and add it to the form
$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Location = New-Object System.Drawing.Point (150, 120)
$cancelButton.Size = New-Object System.Drawing.Size (75, 23)
$cancelButton.Text = 'Cancel'
$cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$scanningSetupForm.CancelButton = $cancelButton
$scanningSetupForm.Controls.Add($cancelButton)

# Create settings button
$settingsButton = New-Object System.Windows.Forms.Button
$settingsButton.Location = New-Object System.Drawing.Point(10, 115)
$settingsButton.Size = New-Object System.Drawing.Size(30, 30)

# Load image from PNG file
$imagePath = [System.IO.Path]::GetTempPath() + [System.IO.Path]::GetRandomFileName()
Invoke-WebRequest 'https://raw.githubusercontent.com/mstrhakr/scans/main/img/settings.png' -OutFile $imagePath | Out-Null;
$image = [System.Drawing.Image]::FromFile($imagePath)
$thumbnailSize = New-Object System.Drawing.Size(($settingsButton.Width - 10), ($settingsButton.Height - 10))
$thumbnailImage = $image.GetThumbnailImage($thumbnailSize.Width, $thumbnailSize.Height, $null, [System.IntPtr]::Zero)
$settingsButton.Image = $thumbnailImage

# Add click event to open settings
$settingsButton.Add_Click({ New-SettingsPage })

# Add settings button to form
$scanningSetupForm.Controls.Add($settingsButton)

# Show the form and wait for the user input
$scanningSetupForm.Add_Shown({ $scanPassTextBox.Select() })
$result = $scanningSetupForm.ShowDialog()

# Check the result and get the text input
if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
	$script:scanUser = $scanUserTextBox.Text
	$script:scanPass = $scanPassTextBox.Text
	$script:folderPath = $folderPathTextBox.Text
	$script:shareName = $smbShareTextBox.Text
	Write-Verbose "Username: $script:username`nPassword: $script:password`nLocal Dir: $script:folderPath`nSMB Share: $script:shareName"
}
else {
	Write-Verbose "User canceled scanning setup"
	$scanningSetupForm.Close() | Out-Null;
	Exit
}
$details = New-Object System.Collections.ArrayList;
function createLoadingForm($done) {
	# Create a new form with a title and a size
	$script:loadingForm = New-Object System.Windows.Forms.Form
	$script:loadingForm.Text = 'Scans.exe - Loading...'
	if ($done -eq $true) {
		$script:loadingForm.Text = 'Scans.exe - ' + $script:details[0]
	}
 else {
		$script:loadingForm.Text = 'Scans.exe - Loading...'
	}
	$script:loadingForm.Icon = $iconPath
	$script:loadingForm.Size = New-Object System.Drawing.Size (300, 200)
	$script:loadingForm.StartPosition = 'CenterScreen'

	# Create a text box for the user to choose a custom password
	$script:loadingText = New-Object System.Windows.Forms.Label
	$script:loadingText.Location = New-Object System.Drawing.Point (10, 10)
	$script:loadingText.Size = New-Object System.Drawing.Size (280, 20)
	if ($done -eq $true) {
		$script:loadingText.Text = $script:details[0]
	}
 else {
		$script:loadingText.Text = 'Loading...'
	}
	$script:loadingForm.Controls.Add($script:loadingText)
	$script:progrssBarObject = New-Object System.Windows.Forms.ProgressBar
	$script:progrssBarObject.Location = New-Object System.Drawing.Point (10, 30)
	$script:progrssBarObject.Size = New-Object System.Drawing.Size (265, 20)
	$script:progrssBarObject.Minimum = 0
	$script:progrssBarObject.Maximum = 12
	if ($done -eq $true) {
		$script:progrssBarObject.Value = $script:progrssBarObject.Maximum
	}
 else {
		$script:progrssBarObject.Value = 0
	}
	$script:loadingForm.Controls.Add($script:progrssBarObject)
	$script:detailsBox = New-Object System.Windows.Forms.ListBox
	$script:detailsBox.ScrollAlwaysVisible = $true
	$script:detailsBox.Location = New-Object System.Drawing.Point (10, 60)
	$script:detailsBox.Size = New-Object System.Drawing.Size (265, 60)
	if ($done -eq $true) {
		foreach ($item in $script:details) {
			$script:detailsBox.Items.Add($item) | Out-Null;
		}
	}
	$script:loadingForm.Controls.Add($script:detailsBox)

	# Create a done button and add it to the form
	$doneButton = New-Object System.Windows.Forms.Button
	$doneButton.Location = New-Object System.Drawing.Point (95, 125)
	$doneButton.Size = New-Object System.Drawing.Size (100, 23)
	$doneButton.Text = 'Done'
	if ($done -eq $true) {
		$doneButton.Enabled = $true
	}
 else {
		$doneButton.Enabled = $false
	}
	$doneButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
	$loadingForm.AcceptButton = $doneButton
	$loadingForm.Controls.Add($doneButton)
}
$null = createLoadingForm $false
$loadingForm.Show()
$percent = 0
function Set-ProgressBar($text, $sleep = 500) {
	$script:loadingText.Text = $text
	$script:percent += 1
	$script:progrssBarObject.Value = $script:percent
	$script:details.Insert(0, $text) | Out-Null;
	$script:text = $text
	$script:detailsBox.Items.Insert(0, $text) | Out-Null;
	Start-Sleep -Milliseconds $sleep
}

# Gather computer details
Set-ProgressBar "Gathering local computer details"
$computerDetails = Get-CimInstance -ClassName Win32_ComputerSystem
$domainJoined = $computerDetails.PartOfDomain

# Creates scans user account if it doesn't exist, otherwise sets password for account
if ($createUser -eq $true) {
	Set-ProgressBar "Checking User Details"
	if (![boolean](Get-LocalUser -Name $scanUser -ErrorAction SilentlyContinue)) {
		Set-ProgressBar "Creating New User"
		New-LocalUser -Name $scanUser -Password $($scanPass | ConvertTo-SecureString -AsPlainText -Force) -Description "$description`nPassword: $scanPass" -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword -FullName "scans" | Out-Null;
	}
	else {
		Set-ProgressBar "Updating Existing User"
		Set-LocalUser -Name $scanUser -Password $($scanPass | ConvertTo-SecureString -AsPlainText -Force) -Description "$description`nPassword: $scanPass" -AccountNeverExpires -PasswordNeverExpires $true -UserMayChangePassword $false -FullName "scans" | Out-Null;
	}
}
if ($hideUser -eq $true) {
	# Hide scans account from login screen on non domain joined computers
	$path = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist'
	$hideAccount = Get-ItemProperty -path $path -name $scanUser -ErrorAction SilentlyContinue;
	if ($? -and $hideAccount.($scanUser) -eq 0) {
		Set-ProgressBar "User account is already hidden from login screen"
	}
	elseif (!$domainJoined) {
		Set-ProgressBar "Hiding scans user from login screen"
		if (!(Test-Path $path)) {
			Write-Verbose "Creating Registry Object at $path"
			New-Item -Path $path -Force | Out-Null;
		}
		New-ItemProperty -path $path -name $scanUser -value 0 -PropertyType 'DWord' -Force | Out-Null;
	}
	else {
		Set-ProgressBar "Computer is domain joined, continuing"
	}
}

if ($createFolder -eq $true) {
	# Check if scans folder exists, create if missing
	if (!(Test-Path -Path $folderPath)) {
		Set-ProgressBar "Creating scans folder" 200
		New-Item -Path $($folderPath.Split(':')[0] + ':/') -Name $folderPath.Split(':')[1] -ItemType Directory | Out-Null;
		#Check if creating folder was successful $? = Was last command successful?(T/F)
		if ($?) {
			Write-Verbose "New folder created at $folderPath."
		}
		else {
			Write-Error "Folder creation failed!`nManually Create Folder before Continuing!"
		}
	}
	else {
		Set-ProgressBar "Scans folder already exists"
	}
}

if ($setPermissions -eq $true) {
	# Grant full recursive permissions on the scan folder to the scan user and current local user
	Set-ProgressBar "Setting folder permissions" 100
	$folderAcl = (Get-Acl $folderPath)
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($Env:UserName, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
	$folderAcl.SetAccessRule($rule)
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($scanUser, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
	$folderAcl.SetAccessRule($rule)
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
	$folderAcl.SetAccessRule($rule)
	if ($domainJoined) {
		$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Users", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
		$folderAcl.SetAccessRule($rule)
	}
	Set-Acl $folderPath $folderAcl
}

if ($setShare -eq $true) {
	# Check if scans share exists, create if missing
	if (!((Get-SmbShare).Name).toLower().Contains($shareName)) {
		Set-ProgressBar "Creating SMB share"
		New-SmbShare -Name $shareName -Path $folderPath -FullAccess $scanUser | Out-Null;
	}
	else {
		Set-ProgressBar "Updating SMB share permissions"
		Grant-SmbShareAccess -Name $shareName -AccountName $scanUser -AccessRight Full -Force | Out-Null;
	}
}

if ($createShortcut -eq $true) {
	# Create scan folder desktop shortcut
	Set-ProgressBar "Creating Desktop Shortcut";
	$shortcutPath = "C:\Users\Public\Desktop\Scans.lnk";
	$iconPath = 'C:\ProgramData\scans.ico';
	$shellObject = New-Object -ComObject ("WScript.Shell");
	$desktopShortCut = $shellObject.CreateShortcut($shortcutPath);
	$desktopShortCut.TargetPath = $folderPath;
	$desktopShortCut.IconLocation = $iconPath;
	$desktopShortCut.Description = $description;
	$desktopShortCut.Save() | Out-Null;
}

if ($checkNetworkSettings -eq $true) {
	# Set network profile to Private if not domain joined.
	$networkCategory = (Get-NetConnectionProfile).NetworkCategory
	if (!$domainJoined -and $networkCategory -ne 'Private') {
		Set-ProgressBar "Set Network Category to Private"
		Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private
	}
	elseif ($domainJoined -and $networkCategory -ne 'DomainAuthenticated') {
		Set-ProgressBar "Set Network Category to Domain Authenticated"
		Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory DomainAuthenticated
	}
	else {
		Set-ProgressBar "Network Category is already $networkCategory"
	}

	# Check if network file and printer sharing is enabled
	$sharingEnabled = Get-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Direction Inbound | Where-Object { $_.Enabled -eq 'True' }

	if (!$sharingEnabled) {
		# If not enabled, enable it
		Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Direction Inbound -Enabled True -Profile $networkCategory
		Set-ProgressBar "Network file and printer sharing has been enabled."
	}
	else {
		Set-ProgressBar "Network file and printer sharing is already enabled."
	}

	# Check if network discovery is enabled
	$discoveryEnabled = Get-NetFirewallRule -DisplayGroup "Network Discovery" -Direction Inbound | Where-Object { $_.Enabled -eq 'True' }

	if (!$discoveryEnabled) {
		# If not enabled, enable it
		Set-NetFirewallRule -DisplayGroup "Network Discovery" -Direction Inbound -Enabled True -Profile $networkCategory
		Set-ProgressBar "Network discovery has been enabled."
	}
	else {
		Set-ProgressBar "Network discovery is already enabled."
	}
}

Set-ProgressBar "Finished" 0
$loadingForm.Close() | Out-Null;
createLoadingForm $true;
$loadingForm.ShowDialog() | Out-Null;
if ($done -eq [System.Windows.Forms.DialogResult]::OK) {
	$loadingForm.Close() | Out-Null;
	Exit;
}