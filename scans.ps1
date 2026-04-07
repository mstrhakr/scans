# Setup variables and defaults
[string]$scanUser = 'scans'
[string]$scanPass = 'scans'
[string]$folderPath = 'C:\scans'
[string]$shareName = 'scans'
[string]$description = 'Scans tool provided by mstrhakr on Github.'

# Load the .NET Framework classes
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName PresentationFramework
$ProgressPreference = 'SilentlyContinue'

# Detect OS capabilities for legacy fallback
$script:osVersion = [Environment]::OSVersion.Version
$script:hasLocalAccounts = [bool](Get-Command -Name 'Get-LocalUser' -ErrorAction SilentlyContinue)
$script:hasSmbShareCmdlets = [bool](Get-Command -Name 'Get-SmbShare' -ErrorAction SilentlyContinue)
$script:hasNetSecurity = [bool](Get-Command -Name 'Get-NetFirewallRule' -ErrorAction SilentlyContinue)
$script:hasNetConnection = [bool](Get-Command -Name 'Get-NetConnectionProfile' -ErrorAction SilentlyContinue)
$script:hasCimInstance = [bool](Get-Command -Name 'Get-CimInstance' -ErrorAction SilentlyContinue)
$script:hasSetClipboard = [bool](Get-Command -Name 'Set-Clipboard' -ErrorAction SilentlyContinue)

$createUser = $true
$hideUser = $true
$createFolder = $true
$setPermissions = $true
$setShare = $true
$createShortcut = $true
$checkNetworkSettings = $true

function New-RandomPassword {
	param([int]$Length = 10)
	$chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*+-=?'
	return -join ((1..$Length) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
}

function Initialize-ScanUser {
	param(
		[string]$Username,
		[string]$Password,
		[string]$Description,
		[bool]$HideFromLogin,
		[bool]$DomainJoined
	)
	$results = @()
	try {
		if ($script:hasLocalAccounts) {
			$securePass = $Password | ConvertTo-SecureString -AsPlainText -Force
			if (![boolean](Get-LocalUser -Name $Username -ErrorAction SilentlyContinue)) {
				New-LocalUser -Name $Username -Password $securePass -Description $Description -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword -FullName "scans" | Out-Null
				$results += @{ Status = 'Success'; Message = "Created new user '$Username'"; Error = $null }
			}
			else {
				Set-LocalUser -Name $Username -Password $securePass -Description $Description | Out-Null
				$results += @{ Status = 'Success'; Message = "Updated existing user '$Username'"; Error = $null }
			}
		}
		else {
			$existingUser = net user $Username 2>&1
			if ($LASTEXITCODE -ne 0) {
				net user $Username $Password /add /fullname:"scans" /comment:"$Description" /active:yes /expires:never /passwordchg:no | Out-Null
				# Set password to never expire via wmic
				wmic useraccount where "Name='$Username'" set PasswordExpires=FALSE 2>&1 | Out-Null
				$results += @{ Status = 'Success'; Message = "Created new user '$Username' (net user)"; Error = $null }
			}
			else {
				net user $Username $Password /comment:"$Description" | Out-Null
				$results += @{ Status = 'Success'; Message = "Updated existing user '$Username' (net user)"; Error = $null }
			}
		}
	}
	catch {
		$results += @{ Status = 'Failed'; Message = "Failed to configure user '$Username'"; Error = $_.Exception.Message }
	}

	if ($HideFromLogin) {
		$regPath = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist'
		try {
			$hideAccount = Get-ItemProperty -Path $regPath -Name $Username -ErrorAction SilentlyContinue
			if ($hideAccount -and $hideAccount.($Username) -eq 0) {
				$results += @{ Status = 'Success'; Message = 'User account is already hidden from login screen'; Error = $null }
			}
			elseif (!$DomainJoined) {
				if (!(Test-Path $regPath)) {
					New-Item -Path $regPath -Force | Out-Null
				}
				New-ItemProperty -Path $regPath -Name $Username -Value 0 -PropertyType 'DWord' -Force | Out-Null
				$results += @{ Status = 'Success'; Message = 'Hidden user from login screen'; Error = $null }
			}
			else {
				$results += @{ Status = 'Skipped'; Message = 'Computer is domain joined, skipping hide user'; Error = $null }
			}
		}
		catch {
			$results += @{ Status = 'Failed'; Message = 'Failed to hide user from login screen'; Error = $_.Exception.Message }
		}
	}
	return $results
}

function Initialize-ScanFolder {
	param(
		[string]$FolderPath,
		[string]$ScanUser,
		[bool]$SetPermissions,
		[bool]$DomainJoined
	)
	$results = @()

	# Create folder if missing
	try {
		if (!(Test-Path -Path $FolderPath)) {
			New-Item -Path $FolderPath -ItemType Directory -Force | Out-Null
			$results += @{ Status = 'Success'; Message = "Created folder at $FolderPath"; Error = $null }
		}
		else {
			$results += @{ Status = 'Success'; Message = 'Scans folder already exists'; Error = $null }
		}
	}
	catch {
		$results += @{ Status = 'Failed'; Message = "Failed to create folder at $FolderPath"; Error = $_.Exception.Message }
		return $results
	}

	# Set permissions
	if ($SetPermissions) {
		try {
			$folderAcl = Get-Acl $FolderPath
			$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($Env:UserName, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
			$folderAcl.SetAccessRule($rule)
			$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($ScanUser, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
			$folderAcl.SetAccessRule($rule)
			$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
			$folderAcl.SetAccessRule($rule)
			if ($DomainJoined) {
				$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Users", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
				$folderAcl.SetAccessRule($rule)
			}
			Set-Acl $FolderPath $folderAcl
			$results += @{ Status = 'Success'; Message = 'Folder permissions set'; Error = $null }
		}
		catch {
			$results += @{ Status = 'Failed'; Message = 'Failed to set folder permissions'; Error = $_.Exception.Message }
		}
	}
	return $results
}

function Initialize-ScanShare {
	param(
		[string]$ShareName,
		[string]$FolderPath,
		[string]$ScanUser
	)
	try {
		if ($script:hasSmbShareCmdlets) {
			if (!((Get-SmbShare).Name).toLower().Contains($ShareName)) {
				New-SmbShare -Name $ShareName -Path $FolderPath -FullAccess $ScanUser | Out-Null
				return @{ Status = 'Success'; Message = "Created SMB share '$ShareName'"; Error = $null }
			}
			else {
				Grant-SmbShareAccess -Name $ShareName -AccountName $ScanUser -AccessRight Full -Force | Out-Null
				return @{ Status = 'Success'; Message = "Updated SMB share permissions for '$ShareName'"; Error = $null }
			}
		}
		else {
			$existing = net share $ShareName 2>&1
			if ($LASTEXITCODE -ne 0) {
				net share "$ShareName=$FolderPath" "/grant:$ScanUser,FULL" | Out-Null
				return @{ Status = 'Success'; Message = "Created SMB share '$ShareName' (net share)"; Error = $null }
			}
			else {
				net share "$ShareName=$FolderPath" "/grant:$ScanUser,FULL" /yes | Out-Null
				return @{ Status = 'Success'; Message = "Updated SMB share '$ShareName' (net share)"; Error = $null }
			}
		}
	}
	catch {
		return @{ Status = 'Failed'; Message = "Failed to configure SMB share '$ShareName'"; Error = $_.Exception.Message }
	}
}

function Initialize-DesktopShortcut {
	param(
		[string]$FolderPath,
		[string]$IconPath,
		[string]$Description
	)
	try {
		$shortcutPath = "C:\Users\Public\Desktop\Scans.lnk"
		$shellObject = New-Object -ComObject ("WScript.Shell")
		$desktopShortCut = $shellObject.CreateShortcut($shortcutPath)
		$desktopShortCut.TargetPath = $FolderPath
		$desktopShortCut.IconLocation = $IconPath
		$desktopShortCut.Description = $Description
		$desktopShortCut.Save() | Out-Null
		return @{ Status = 'Success'; Message = 'Created desktop shortcut'; Error = $null }
	}
	catch {
		return @{ Status = 'Failed'; Message = 'Failed to create desktop shortcut'; Error = $_.Exception.Message }
	}
}

function Set-NetworkConfiguration {
	param([bool]$DomainJoined)
	$results = @()

	if ($script:hasNetConnection) {
		# Modern path: PS cmdlets (Win 8+)
		$networkProfile = Get-NetConnectionProfile | Select-Object -First 1
		$networkCategory = $networkProfile.NetworkCategory
		if (!$DomainJoined -and $networkCategory -ne 'Private') {
			try {
				$networkProfile | Set-NetConnectionProfile -NetworkCategory Private
				$results += @{ Status = 'Success'; Message = 'Set Network Category to Private'; Error = $null }
			}
			catch {
				$results += @{ Status = 'Failed'; Message = 'Failed to Set Network Category to Private'; Error = $_.Exception.Message }
			}
		}
		elseif ($DomainJoined) {
			$results += @{ Status = 'Skipped'; Message = 'Network Category is managed by domain, skipping'; Error = $null }
		}
		else {
			$results += @{ Status = 'Success'; Message = "Network Category is already $networkCategory"; Error = $null }
		}

		# Re-read after possible change
		$networkCategory = (Get-NetConnectionProfile | Select-Object -First 1).NetworkCategory
	}
	else {
		# Legacy path: netsh (Win 7)
		if (!$DomainJoined) {
			try {
				netsh advfirewall set currentprofile state on 2>&1 | Out-Null
				$results += @{ Status = 'Success'; Message = 'Ensured firewall profile is active (netsh)'; Error = $null }
			}
			catch {
				$results += @{ Status = 'Failed'; Message = 'Failed to configure firewall profile'; Error = $_.Exception.Message }
			}
		}
		else {
			$results += @{ Status = 'Skipped'; Message = 'Network Category is managed by domain, skipping'; Error = $null }
		}
	}

	# File and Printer Sharing
	if ($script:hasNetSecurity) {
		$networkCategory = (Get-NetConnectionProfile | Select-Object -First 1).NetworkCategory
		$sharingEnabled = Get-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Direction Inbound | Where-Object { $_.Enabled -eq 'True' -and $_.Profile -eq $networkCategory.ToString() }
		if ($sharingEnabled.count -eq 0) {
			try {
				Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Direction Inbound -Enabled True -Profile $networkCategory.ToString()
				$results += @{ Status = 'Success'; Message = 'Network file and printer sharing has been enabled.'; Error = $null }
			}
			catch {
				$results += @{ Status = 'Failed'; Message = 'Failed to enable Network File and Printer Sharing.'; Error = $_.Exception.Message }
			}
		}
		else {
			$results += @{ Status = 'Success'; Message = 'Network File and Printer Sharing is already enabled.'; Error = $null }
		}

		# Network Discovery
		$discoveryEnabled = Get-NetFirewallRule -DisplayGroup "Network Discovery" -Direction Inbound | Where-Object { $_.Enabled -eq 'True' -and $_.Profile -eq $networkCategory.ToString() }
		if ($discoveryEnabled.count -eq 0) {
			try {
				Set-NetFirewallRule -DisplayGroup "Network Discovery" -Direction Inbound -Enabled True -Profile $networkCategory.ToString()
				$results += @{ Status = 'Success'; Message = 'Network Discovery has been enabled.'; Error = $null }
			}
			catch {
				$results += @{ Status = 'Failed'; Message = 'Failed to Enable Network Discovery.'; Error = $_.Exception.Message }
			}
		}
		else {
			$results += @{ Status = 'Success'; Message = 'Network Discovery is already enabled.'; Error = $null }
		}
	}
	else {
		# Legacy path: netsh advfirewall (Win 7)
		try {
			netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes 2>&1 | Out-Null
			$results += @{ Status = 'Success'; Message = 'Network file and printer sharing has been enabled (netsh).'; Error = $null }
		}
		catch {
			$results += @{ Status = 'Failed'; Message = 'Failed to enable Network File and Printer Sharing.'; Error = $_.Exception.Message }
		}
		try {
			netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes 2>&1 | Out-Null
			$results += @{ Status = 'Success'; Message = 'Network Discovery has been enabled (netsh).'; Error = $null }
		}
		catch {
			$results += @{ Status = 'Failed'; Message = 'Failed to Enable Network Discovery.'; Error = $_.Exception.Message }
		}
	}
	return $results
}

# Download icon
$iconPath = 'C:\ProgramData\scans.ico'
Invoke-WebRequest 'https://raw.githubusercontent.com/mstrhakr/scans/main/img/scans.ico' -OutFile $iconPath | Out-Null

function New-SettingsPage {
	# Create form
	$settings = New-Object System.Windows.Forms.Form
	$settings.Text = 'Settings'
	$settings.Icon = [System.Drawing.Icon]::new($iconPath)
	$settings.Size = New-Object System.Drawing.Size(300, 200)
	$settings.StartPosition = 'CenterScreen'

	$createUserCheckbox = New-Object System.Windows.Forms.CheckBox
	$createUserCheckbox.Location = New-Object System.Drawing.Point(10, 10)
	$createUserCheckbox.Size = New-Object System.Drawing.Size(250, 20)
	$createUserCheckbox.Text = 'Create new user account'
	$createUserCheckbox.Checked = $createUser
	$createUserCheckbox.Add_CheckedChanged({ $script:createUser = $createUserCheckbox.Checked })

	$hideUserCheckbox = New-Object System.Windows.Forms.CheckBox
	$hideUserCheckbox.Location = New-Object System.Drawing.Point(10, 30)
	$hideUserCheckbox.Size = New-Object System.Drawing.Size(250, 20)
	$hideUserCheckbox.Text = 'Hide user account from login screen'
	$hideUserCheckbox.Checked = $hideUser
	$hideUserCheckbox.Add_CheckedChanged({ $script:hideUser = $hideUserCheckbox.Checked })

	$createFolderCheckbox = New-Object System.Windows.Forms.CheckBox
	$createFolderCheckbox.Location = New-Object System.Drawing.Point(10, 50)
	$createFolderCheckbox.Size = New-Object System.Drawing.Size(250, 20)
	$createFolderCheckbox.Text = 'Create scans folder'
	$createFolderCheckbox.Checked = $createFolder
	$createFolderCheckbox.Add_CheckedChanged({ $script:createFolder = $createFolderCheckbox.Checked })

	$setPermissionsCheckbox = New-Object System.Windows.Forms.CheckBox
	$setPermissionsCheckbox.Location = New-Object System.Drawing.Point(10, 70)
	$setPermissionsCheckbox.Size = New-Object System.Drawing.Size(250, 20)
	$setPermissionsCheckbox.Text = 'Set permissions on scans folder'
	$setPermissionsCheckbox.Checked = $setPermissions
	$setPermissionsCheckbox.Add_CheckedChanged({ $script:setPermissions = $setPermissionsCheckbox.Checked })

	$setShareCheckbox = New-Object System.Windows.Forms.CheckBox
	$setShareCheckbox.Location = New-Object System.Drawing.Point(10, 90)
	$setShareCheckbox.Size = New-Object System.Drawing.Size(250, 20)
	$setShareCheckbox.Text = 'Set SMB share on scans folder'
	$setShareCheckbox.Checked = $setShare
	$setShareCheckbox.Add_CheckedChanged({ $script:setShare = $setShareCheckbox.Checked })

	$createShortcutCheckbox = New-Object System.Windows.Forms.CheckBox
	$createShortcutCheckbox.Location = New-Object System.Drawing.Point(10, 110)
	$createShortcutCheckbox.Size = New-Object System.Drawing.Size(250, 20)
	$createShortcutCheckbox.Text = 'Create desktop shortcut'
	$createShortcutCheckbox.Checked = $createShortcut
	$createShortcutCheckbox.Add_CheckedChanged({ $script:createShortcut = $createShortcutCheckbox.Checked })

	$checkNetworkSettingsCheckbox = New-Object System.Windows.Forms.CheckBox
	$checkNetworkSettingsCheckbox.Location = New-Object System.Drawing.Point(10, 130)
	$checkNetworkSettingsCheckbox.Size = New-Object System.Drawing.Size(250, 20)
	$checkNetworkSettingsCheckbox.Text = 'Check network settings'
	$checkNetworkSettingsCheckbox.Checked = $checkNetworkSettings
	$checkNetworkSettingsCheckbox.Add_CheckedChanged({ $script:checkNetworkSettings = $checkNetworkSettingsCheckbox.Checked })

	# Create an OK button and add it to the form
	$okButton = New-Object System.Windows.Forms.Button
	$okButton.Location = New-Object System.Drawing.Point (150, 120)
	$okButton.Size = New-Object System.Drawing.Size (75, 23)
	$okButton.Text = 'OK'
	$okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
	$settings.AcceptButton = $okButton
	$settings.Controls.Add($okButton)

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
$scanningSetupForm.Icon = [System.Drawing.Icon]::new($iconPath)
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
$scanPassTextBox.Text = New-RandomPassword
$scanningSetupForm.Controls.Add($scanPassTextBox)

# Create a text box for the user to choose a custom path
$folderPathLabel = New-Object	System.Windows.Forms.Label
$folderPathLabel.Location = New-Object System.Drawing.Point (10, 60)
$folderPathLabel.Size = New-Object System.Drawing.Size (70, 20)
$folderPathLabel.Text = 'Local Dir:'
$scanningSetupForm.Controls.Add($folderPathLabel)
$folderPathTextBox = New-Object System.Windows.Forms.TextBox
$folderPathTextBox.Location = New-Object System.Drawing.Point (80, 60)
$folderPathTextBox.Size = New-Object System.Drawing.Size (160, 20)
$folderPathTextBox.Text = $folderPath
$scanningSetupForm.Controls.Add($folderPathTextBox)

# Create browse button for folder path
$browseButton = New-Object System.Windows.Forms.Button
$browseButton.Location = New-Object System.Drawing.Point (245, 59)
$browseButton.Size = New-Object System.Drawing.Size (25, 22)
$browseButton.Text = '...'
$browseButton.Add_Click({
	$folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
	$folderBrowser.Description = "Select folder for scans"
	$folderBrowser.SelectedPath = $folderPathTextBox.Text
	$folderBrowser.ShowNewFolderButton = $true
	
	if ($folderBrowser.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
		$folderPathTextBox.Text = $folderBrowser.SelectedPath
	}
})
$scanningSetupForm.Controls.Add($browseButton)

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
Invoke-WebRequest 'https://raw.githubusercontent.com/mstrhakr/scans/main/img/settings.png' -OutFile $imagePath | Out-Null
$image = [System.Drawing.Image]::FromFile($imagePath)
$thumbnailSize = New-Object System.Drawing.Size(($settingsButton.Width - 10), ($settingsButton.Height - 10))
$thumbnailImage = $image.GetThumbnailImage($thumbnailSize.Width, $thumbnailSize.Height, $null, [System.IntPtr]::Zero)
$image.Dispose()
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
	Write-Verbose "Username: $script:scanUser `nPassword: $script:scanPass `nLocal Dir: $script:folderPath`nSMB Share: $script:shareName"
}
else {
	Write-Verbose "User canceled scanning setup"
	$scanningSetupForm.Close() | Out-Null
	Exit 1
}
$details = New-Object System.Collections.ArrayList
$script:progressMax = 2
if ($createUser) { $script:progressMax += 2 }
if ($hideUser) { $script:progressMax += 1 }
if ($createFolder) { $script:progressMax += 1 }
if ($setPermissions) { $script:progressMax += 1 }
if ($setShare) { $script:progressMax += 1 }
if ($createShortcut) { $script:progressMax += 1 }
if ($checkNetworkSettings) { $script:progressMax += 3 }
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
	$script:loadingForm.Icon = [System.Drawing.Icon]::new($iconPath)
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
	$script:progressBarObject = New-Object System.Windows.Forms.ProgressBar
	$script:progressBarObject.Location = New-Object System.Drawing.Point (10, 30)
	$script:progressBarObject.Size = New-Object System.Drawing.Size (265, 20)
	$script:progressBarObject.Minimum = 0
	$script:progressBarObject.Maximum = $script:progressMax
	if ($done -eq $true) {
		$script:progressBarObject.Value = $script:progressBarObject.Maximum
	}
 	else {
		$script:progressBarObject.Value = 0
	}
	$script:loadingForm.Controls.Add($script:progressBarObject)
	$script:detailsBox = New-Object System.Windows.Forms.ListBox
	$script:detailsBox.ScrollAlwaysVisible = $true
	$script:detailsBox.Location = New-Object System.Drawing.Point (10, 60)
	$script:detailsBox.Size = New-Object System.Drawing.Size (265, 60)
	if ($done -eq $true) {
		foreach ($item in $script:details) {
			$script:detailsBox.Items.Add($item) | Out-Null
		}
	}
	$script:loadingForm.Controls.Add($script:detailsBox)

	# Create a done button and add it to the form
	$doneButton = New-Object System.Windows.Forms.Button
	$doneButton.Location = New-Object System.Drawing.Point (150, 125)
	$doneButton.Size = New-Object System.Drawing.Size (75, 23)
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
	
	# Create an OK button and add it to the form
	$copyPasswordButton = New-Object System.Windows.Forms.Button
	$copyPasswordButton.Location = New-Object System.Drawing.Point (50, 125)
	$copyPasswordButton.Size = New-Object System.Drawing.Size (100, 23)
	$copyPasswordButton.Text = 'Copy Password'
	if ($done -eq $true -and $createUser -eq $true) {
		$copyPasswordButton.Enabled = $true
	}
 	else {
		$copyPasswordButton.Enabled = $false
	}
	$copyPasswordButton.Add_Click({
		Set-Clipboard -Value $scanPass
		Write-Verbose "Copied scan password to clipboard: $scanPass"
		[System.Windows.MessageBox]::Show('Password has been copied to Clipboard')
	})
	$loadingForm.Controls.Add($copyPasswordButton)
}
$null = createLoadingForm $false
$loadingForm.Show()
$percent = 0
function Set-ProgressBar($text, $sleep = 250) {
	$script:loadingText.Text = $text
	$script:percent += 1
	$script:progressBarObject.Value = [Math]::Min($script:percent, $script:progressMax)
	$script:details.Insert(0, $text) | Out-Null
	$script:text = $text
	$script:detailsBox.Items.Insert(0, $text) | Out-Null
	Write-Verbose  "Progress Text: $text"
	[System.Windows.Forms.Application]::DoEvents()
	Start-Sleep -Milliseconds $sleep
}

# Gather computer details
Set-ProgressBar "Gathering local computer details"
$computerDetails = Get-CimInstance -ClassName Win32_ComputerSystem
$domainJoined = $computerDetails.PartOfDomain

# Create/update scans user account and hide from login screen
if ($createUser -eq $true) {
	$userResults = Initialize-ScanUser -Username $scanUser -Password $scanPass -Description $description -HideFromLogin $hideUser -DomainJoined $domainJoined
	foreach ($r in $userResults) {
		Set-ProgressBar $r.Message
		if ($r.Error) { Set-ProgressBar "  Error: $($r.Error)" 0 }
	}
}
elseif ($hideUser -eq $true) {
	$userResults = Initialize-ScanUser -Username $scanUser -Password $scanPass -Description $description -HideFromLogin $true -DomainJoined $domainJoined
	foreach ($r in $userResults) {
		Set-ProgressBar $r.Message
		if ($r.Error) { Set-ProgressBar "  Error: $($r.Error)" 0 }
	}
}

if ($createFolder -eq $true) {
	$folderResults = Initialize-ScanFolder -FolderPath $folderPath -ScanUser $scanUser -SetPermissions $setPermissions -DomainJoined $domainJoined
	foreach ($r in $folderResults) {
		Set-ProgressBar $r.Message
		if ($r.Error) { Set-ProgressBar "  Error: $($r.Error)" 0 }
	}
}

if ($setShare -eq $true) {
	$shareResult = Initialize-ScanShare -ShareName $shareName -FolderPath $folderPath -ScanUser $scanUser
	Set-ProgressBar $shareResult.Message
	if ($shareResult.Error) { Set-ProgressBar "  Error: $($shareResult.Error)" 0 }
}

if ($createShortcut -eq $true) {
	$shortcutResult = Initialize-DesktopShortcut -FolderPath $folderPath -IconPath $iconPath -Description $description
	Set-ProgressBar $shortcutResult.Message
	if ($shortcutResult.Error) { Set-ProgressBar "  Error: $($shortcutResult.Error)" 0 }
}

if ($checkNetworkSettings -eq $true) {
	$netResults = Set-NetworkConfiguration -DomainJoined $domainJoined
	foreach ($r in $netResults) {
		Set-ProgressBar $r.Message
		if ($r.Error) { Set-ProgressBar "  Error: $($r.Error)" 0 }
	}
}

Set-ProgressBar "Finished" 0
$loadingForm.Close() | Out-Null
createLoadingForm $true
$result = $loadingForm.ShowDialog()
if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
	$loadingForm.Close() | Out-Null
	Exit 0
}
