function Get-Icon {
	param (
		$ProgPref = 'SilentlyContinue',
		$OutFile = 'C:\ProgramData\scans.ico'
	)
	
	$ProgressPreference = $ProgPref
	if (-not (Test-Path $OutFile)) {
		Invoke-WebRequest 'https://raw.githubusercontent.com/mstrhakr/scans/main/scans.ico' -OutFile $OutFile | Out-Null
	}

	return $OutFile
}

function Show-ScanningSetupForm {

	param(
		[string]$scanUser = 'scans',
		[string]$scanPass,
		[string]$folderPath = 'C:\scans',
		[string]$shareName = 'scans',
		[string]$description = 'Scanning setup by Scans Utility.'
	)


	$icon = Get-Icon

	# Create a new form with a title and a size
	$scanningSetupForm = New-Object System.Windows.Forms.Form
	$scanningSetupForm.Text = 'Scans.exe'
	$scanningSetupForm.Icon = $icon
	$scanningSetupForm.Size = New-Object System.Drawing.Size(300, 250) # Adjusted size
	$scanningSetupForm.StartPosition = 'CenterScreen'
	$scanningSetupForm.FormBorderStyle = 'FixedDialog'
	$scanningSetupForm.MaximizeBox = $false
	$scanningSetupForm.MinimizeBox = $false

	# Create a text box for the user to choose a custom username
	$scanUserLabel = New-Object	System.Windows.Forms.Label
	$scanUserLabel.Location = New-Object System.Drawing.Point(10, 10)
	$scanUserLabel.Size = New-Object System.Drawing.Size(70, 20)
	$scanUserLabel.Text = 'Username:'
	$scanningSetupForm.Controls.Add($scanUserLabel)
	$scanUserTextBox = New-Object System.Windows.Forms.TextBox
	$scanUserTextBox.Location = New-Object System.Drawing.Point(80, 10)
	$scanUserTextBox.Size = New-Object System.Drawing.Size(190, 20)
	$scanUserTextBox.Text = $scanUser
	$scanningSetupForm.Controls.Add($scanUserTextBox)

	# Create a text box for the user to choose a custom password
	$scanPassLabel = New-Object	System.Windows.Forms.Label
	$scanPassLabel.Location = New-Object System.Drawing.Point(10, 35)
	$scanPassLabel.Size = New-Object System.Drawing.Size(70, 20)
	$scanPassLabel.Text = 'Password:'
	$scanningSetupForm.Controls.Add($scanPassLabel)
	$scanPassTextBox = New-Object System.Windows.Forms.TextBox
	$scanPassTextBox.Location = New-Object System.Drawing.Point(80, 35)
	if ($scanPass) {
		$scanPassTextBox.Text = $scanPass
	}
 else {
		$characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=<>?"
		$randomPassword = -join ($characters.ToCharArray() | Get-Random -Count 10)
		$scanPassTextBox.Text = $randomPassword
	}
	$scanningSetupForm.Controls.Add($scanPassTextBox)

	# Create a text box for the user to choose a custom path
	$folderPathLabel = New-Object	System.Windows.Forms.Label
	$folderPathLabel.Location = New-Object System.Drawing.Point(10, 60)
	$folderPathLabel.Size = New-Object System.Drawing.Size(70, 20)
	$folderPathLabel.Text = 'Local Dir:'
	$scanningSetupForm.Controls.Add($folderPathLabel)
	$folderPathTextBox = New-Object System.Windows.Forms.TextBox
	$folderPathTextBox.Location = New-Object System.Drawing.Point(80, 60)
	$folderPathTextBox.Size = New-Object System.Drawing.Size(190, 20)
	$folderPathTextBox.Text = $folderPath
	$scanningSetupForm.Controls.Add($folderPathTextBox)

	# Create a text box for the user to choose a smb share
	$smbShareLabel = New-Object	System.Windows.Forms.Label
	$smbShareLabel.Location = New-Object System.Drawing.Point(10, 85)
	$smbShareLabel.Size = New-Object System.Drawing.Size(70, 20)
	$smbShareLabel.Text = 'SMB Share:'
	$scanningSetupForm.Controls.Add($smbShareLabel)
	$smbShareTextBox = New-Object System.Windows.Forms.TextBox
	$smbShareTextBox.Location = New-Object System.Drawing.Point(80, 85)
	$smbShareTextBox.Size = New-Object System.Drawing.Size(190, 20)
	$smbShareTextBox.Text = $shareName
	$scanningSetupForm.Controls.Add($smbShareTextBox)

	# Create a text box for the user to choose a description
	$descriptionLabel = New-Object	System.Windows.Forms.Label
	$descriptionLabel.Location = New-Object System.Drawing.Point(10, 110)
	$descriptionLabel.Size = New-Object System.Drawing.Size(70, 20)
	$descriptionLabel.Text = 'Description:'
	$scanningSetupForm.Controls.Add($descriptionLabel)
	$descriptionTextBox = New-Object System.Windows.Forms.TextBox
	$descriptionTextBox.Location = New-Object System.Drawing.Point(80, 110)
	$descriptionTextBox.Size = New-Object System.Drawing.Size(190, 20)
	$descriptionTextBox.Text = $description
	$scanningSetupForm.Controls.Add($descriptionTextBox)

	$okButton = New-Object System.Windows.Forms.Button
	$okButton.Location = New-Object System.Drawing.Point(75, 150) # Adjusted location
	$okButton.Size = New-Object System.Drawing.Size(75, 23)
	$okButton.Text = 'OK'
	$okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
	$scanningSetupForm.AcceptButton = $okButton
	$scanningSetupForm.Controls.Add($okButton)

	$cancelButton = New-Object System.Windows.Forms.Button
	$cancelButton.Location = New-Object System.Drawing.Point(150, 150) # Adjusted location
	$cancelButton.Size = New-Object System.Drawing.Size(75, 23)
	$cancelButton.Text = 'Cancel'
	$cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
	$scanningSetupForm.CancelButton = $cancelButton
	$scanningSetupForm.Controls.Add($cancelButton)

	$scanningSetupForm.Topmost = $true
	$scanningSetupForm.Add_Shown({ $scanPassTextBox.Select() })
	$result = $scanningSetupForm.ShowDialog()

	if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
		$scanUser = $scanUserTextBox.Text
		$scanPass = $scanPassTextBox.Text
		$folderPath = $folderPathTextBox.Text
		$shareName = $smbShareTextBox.Text
		$description = $descriptionTextBox.Text

		# Create a custom object to store the values
		$resultObject = [PSCustomObject]@{
			ScanUser    = $scanUser
			ScanPass    = $scanPass
			FolderPath  = $folderPath
			ShareName   = $shareName
			Description = $description
		}

		# Return the custom object
		return $resultObject
	}
 else {
		Write-Error "You canceled scanning setup"
		$scanningSetupForm.Close() | Out-Null
		Exit
	}
}

function New-LoadingForm($done = $false, $details = $null, $maximum = 100) {

	$return = @{
		Form     = New-Object System.Windows.Forms.Form
		Controls = @{
			Text   = New-Object System.Windows.Forms.Label
			Bar    = New-Object System.Windows.Forms.ProgressBar
			Box    = New-Object System.Windows.Forms.ListBox
			Button = New-Object System.Windows.Forms.Button
		}
	}

	$return.Form.Icon = Get-Icon
	$return.Form.Size = New-Object System.Drawing.Size(300, 200)
	$return.Form.StartPosition = 'CenterScreen'
	$return.Form.MaximizeBox = $false
	$return.Form.MinimizeBox = $false
	$return.Form.FormBorderStyle = 'FixedDialog'
	$return.Form.TopMost = $true

	$return.Controls.Text.Location = New-Object System.Drawing.Point(10, 10)
	$return.Controls.Text.Size = New-Object System.Drawing.Size(280, 20)

	$return.Controls.Bar.Location = New-Object System.Drawing.Point(10, 30)
	$return.Controls.Bar.Size = New-Object System.Drawing.Size(265, 20)
	$return.Controls.Bar.Minimum = 0
	$return.Controls.Bar.Maximum = $maximum

	$return.Controls.Box.ScrollAlwaysVisible = $true
	$return.Controls.Box.Location = New-Object System.Drawing.Point(10, 60)
	$return.Controls.Box.Size = New-Object System.Drawing.Size(265, 60)

	$return.Controls.Button.Location = New-Object System.Drawing.Point(95, 125)
	$return.Controls.Button.Size = New-Object System.Drawing.Size(100, 23)
	$return.Controls.Button.Text = 'Done'
	$return.Controls.Button.DialogResult = [System.Windows.Forms.DialogResult]::OK
	$return.Form.AcceptButton = $return.Controls.Button

	if ($done -and $null -ne $details) {
		$return.Form.Text = 'Scans.exe - Finished!'
		$return.Controls.Text.Text = 'Finished!'
		$return.Controls.Bar.Value = $return.Controls.Bar.Maximum
		foreach ($detail in $details.Split('||')) {
			$return.Controls.Box.Items.Insert(0, $detail) | Out-Null
		}
		$return.Controls.Button.Enabled = $true
	}
 else {
		$return.Form.Text = 'Scans.exe - Loading...'
		$return.Controls.Text.Text = 'Loading...'
		$return.Controls.Bar.Value = 0
		$return.Controls.Button.Enabled = $false
		$return.Form.Update()
	}

	foreach ($control in $return.Controls.Values) {
		$return.Form.Controls.Add($control)
	}

	return $return
}

function Update-ProgressBar {
	param(
		[Parameter(Mandatory = $true)]
		[PSCustomObject]$Form,
		[Parameter(Mandatory = $true)]
		[string]$text,
		[int]$value,
		[int]$sleep = 500
	)
	Write-Debug $text
	if ($env:quiet -eq $false) {
		$Form.Controls.Text.Text = $text

		# If a value is provided, set the progress bar to that value
		if ($value) {
			$Form.Controls.Bar.Value = $value
		}
		else {
			$Form.Controls.Bar.Value++
		}
		$ENV:details += "||" + $text
		$Form.Controls.Box.Items.Insert(0, $text)
		$Form.Form.Refresh()
		Start-Sleep -Milliseconds $sleep
	}
}

function Set-ScanUser {
	param(
		[Parameter(Mandatory = $true)]
		[string]$scanUser,
		[Parameter(Mandatory = $true)]
		[string]$scanPass,
		[Parameter(Mandatory = $true)]
		[string]$description
	)

	# Convert the password to a secure string
	$securePassword = $scanPass | ConvertTo-SecureString -AsPlainText -Force

	# Check if the user account exists
	Update-ProgressBar $loadingScreen "Checking if User Account Exists"
	if (![boolean](Get-LocalUser -Name $scanUser -ErrorAction SilentlyContinue)) {
		Write-Debug "Creating New User: $scanUser"
		Update-ProgressBar $loadingScreen "Creating New User: $scanUser"
		New-LocalUser -Name $scanUser -Password $securePassword -Description $description -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword -FullName "scans" | Out-Null
	} else {
		# Check if the password is set correctly
		Write-Debug "Checking if Password is Set Correctly"
		Update-ProgressBar $loadingScreen "Checking if Password is Set Correctly"
		Add-Type -AssemblyName System.DirectoryServices.AccountManagement
		$pc = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('machine', $env:COMPUTERNAME)
		[bool]$passwordCorrect = $pc.ValidateCredentials($scanUser, $scanPass)

		if (!$passwordCorrect) {
			Write-Debug "Updating Existing User: $scanUser"
			Update-ProgressBar $loadingScreen "Updating Existing User: $scanUser"
			Set-LocalUser -Name $scanUser -Password $securePassword -Description $description -AccountNeverExpires -PasswordNeverExpires $true -UserMayChangePassword $false -FullName "scans" | Out-Null
		}
		else {
			Write-Debug "User account '$scanUser' exists and password is set correctly."
			Update-ProgressBar $loadingScreen "User account '$scanUser' exists and password is set correctly."
		}
	}
}

function Test-UserAccountAndPassword {
	param(
		[Parameter(Mandatory = $true)]
		[string]$scanUser,
		[Parameter(Mandatory = $true)]
		[string]$scanPass
	)

	$userExists = Get-LocalUser -Name $scanUser -ErrorAction SilentlyContinue
	if ($userExists) {
		$securePassword = $scanPass | ConvertTo-SecureString -AsPlainText -Force
		$credentials = New-Object System.Management.Automation.PSCredential($scanUser, $securePassword)
		$passwordCorrect = Test-LocalUserPassword -InputObject $userExists -Credential $credentials
		if ($passwordCorrect) {
			Write-Debug "User account '$scanUser' exists and password is set correctly."
		}
		else {
			Write-Debug "User account '$scanUser' exists but password is not set correctly."
		}
	}
 else {
		Write-Debug "User account '$scanUser' does not exist."
	}
}


function Hide-ScanUserFromLoginScreen {
	param(
		[Parameter(Mandatory = $true)]
		[string]$scanUser
	)

	$path = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist'
	try {
		$hideAccount = Get-ItemProperty -Path $path -Name $scanUser -ErrorAction Stop

		if ($hideAccount -and $hideAccount.($scanUser) -eq 0) {
			Update-ProgressBar $loadingScreen "User account is already hidden from login screen"
		}
		else {
			Update-ProgressBar $loadingScreen "Hiding scans user from login screen"
			if (!(Test-Path $path)) {
				Write-Debug "Creating Registry Object at $path"
				New-Item -Path $path -Force | Out-Null
			}
			New-ItemProperty -Path $path -Name $scanUser -Value 0 -PropertyType 'DWord' -Force | Out-Null
		}
	}
 catch {
		Write-Error "Failed to hide scans user from login screen. Error: $_"
	}
}

function New-ScanFolder {
	param(
		[Parameter(Mandatory = $true)]
		[string]$folderPath
	)

	try {
		if (!(Test-Path -Path $folderPath)) {
			Update-ProgressBar $loadingScreen "Creating scans folder"
			New-Item -Path $folderPath -ItemType Directory -ErrorAction Stop | Out-Null
		}
		else {
			Update-ProgressBar $loadingScreen "Scans folder already exists"
		}
	}
 catch {
		Write-Error "Folder creation failed!`nManually create the folder before continuing!"
	}
}

function Test-FolderExistence {
	param(
		[Parameter(Mandatory = $true)]
		[string]$folderPath
	)

	if (Test-Path -Path $folderPath -PathType Container) {
		Write-Output "Folder '$folderPath' exists."
		return $true
	}
 else {
		Write-Output "Folder '$folderPath' does not exist."
		return $false
	}
}


function Set-ScanFolderPermissions {
	param(
		[Parameter(Mandatory = $true)]
		[string]$folderPath,
		[Parameter(Mandatory = $true)]
		[string]$username,
		[Parameter()]
		[bool]$setPermissions = $false
	)


	$localComputer = Get-CimInstance -ClassName Win32_ComputerSystem
	# Check if username is a local user or a domain user
	if ($username -eq "Everyone") {
		$username = "Everyone"
	}
 elseif ($username -eq "Domain Users") {
		$username = "$env:USERDOMAIN\Domain Users"
	}
 elseif (Get-LocalUser -Name $username -ErrorAction SilentlyContinue) {
		$username = "$env:COMPUTERNAME\$username"
	}
 elseif ($localComputer.PartOfDomain -eq $true -and (Get-ADUser -Filter { SamAccountName -eq $username } -ErrorAction Continue)) {
		$username = "$env:USERDOMAIN\$username"
	}
 else {
		Write-Error "User account '$username' does not exist."
	}
	$folderAcl = (Get-Acl $folderPath)
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
		$username,
		"FullControl",
		"ContainerInherit,ObjectInherit",
		"None",
		"Allow"
	)

	if ($folderAcl.Access | Where-Object { $_.IdentityReference.Value -eq $username -and $_.AccessControlType -eq "Allow" }) {
		Update-ProgressBar $loadingScreen "Permission for $username already exists"
	}
 else {
		if ($setPermissions) {
			Update-ProgressBar $loadingScreen "Setting Permissions for $username"
			$folderAcl.AddAccessRule($rule)
			Set-Acl -Path $folderPath -AclObject $folderAcl 
		}
		else {
			Update-ProgressBar $loadingScreen "Permission for $username does not exist"
		}
	}
}

function Set-ScansSmbShare {
	param(
		[Parameter(Mandatory = $true)]
		[string]$shareName,
		[Parameter(Mandatory = $true)]
		[string]$folderPath,
		[Parameter(Mandatory = $true)]
		[string]$scanUser
	)

	if (!((Get-SmbShare).Name).ToLower().Contains($shareName)) {
		Update-ProgressBar $loadingScreen "Creating SMB share"
		New-SmbShare -Name $shareName -Path $folderPath -FullAccess $scanUser | Out-Null
	}
 else {
		Update-ProgressBar $loadingScreen "Updating SMB share permissions"
		Grant-SmbShareAccess -Name $shareName -AccountName $scanUser -AccessRight Full -Force | Out-Null
	}
}

function Set-NetworkSettings {
	param(
		[Parameter(Mandatory = $true)]
		[bool]$domainJoined,
		[Parameter(Mandatory = $true)]
		[bool]$enableFileAndPrinterSharing,
		[Parameter(Mandatory = $true)]
		[bool]$enablePasswordProtectedSharing
	)

	Update-ProgressBar $loadingScreen "Checking Network Category"
	$networkCategory = (Get-NetConnectionProfile).NetworkCategory
	if (!$domainJoined -and $networkCategory -ne 'Private') {
		Update-ProgressBar $loadingScreen "Set Network Category to Private"
		Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private
	}
 else {
		Update-ProgressBar $loadingScreen "Network Category is already $networkCategory"
	}

	if ($enableFileAndPrinterSharing) {
		Update-ProgressBar $loadingScreen "Checking if File and Printer Sharing is enabled"
		$fileAndPrinterSharingRule = Get-NetFirewallRule -DisplayGroup "File and Printer Sharing"
		if ($fileAndPrinterSharingRule.Enabled -eq $false) {
			Update-ProgressBar $loadingScreen "Enabling File and Printer Sharing"
			Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Enabled True
		}
		else {
			Update-ProgressBar $loadingScreen "File and Printer Sharing is already enabled"
		}
	}

	if ($enablePasswordProtectedSharing) {
		Update-ProgressBar $loadingScreen "Checking if Password Protected Sharing is enabled"
		$smbServerConfig = Get-SmbServerConfiguration
		if ($smbServerConfig.EnableSMB2Protocol -eq $false -or
			$smbServerConfig.EnableSecuritySignature -eq $false -or
			$smbServerConfig.RequireSecuritySignature -eq $false) {
			Update-ProgressBar $loadingScreen "Enabling Password Protected Sharing"
			Set-SmbServerConfiguration -EnableSMB2Protocol $true -Confirm:$false
			Set-SmbServerConfiguration -EnableSecuritySignature $true -Confirm:$false
			Set-SmbServerConfiguration -RequireSecuritySignature $true -Confirm:$false
		}
		else {
			Update-ProgressBar $loadingScreen "Password Protected Sharing is already enabled"
		}
	}
}

function New-DesktopShortcut {
	param(
		[string]$shortcutPath = "C:\Users\Public\Desktop\Scans.lnk"
	)

	$icon = Get-Icon
	Update-ProgressBar $loadingScreen "Creating Desktop Shortcut"
	$shellObject = New-Object -ComObject ("WScript.Shell")
	$desktopShortCut = $shellObject.CreateShortcut($shortcutPath)
	$desktopShortCut.TargetPath = $folderPath
	$desktopShortCut.IconLocation = $icon
	$desktopShortCut.Description = $description
	$desktopShortCut.Save() | Out-Null
}