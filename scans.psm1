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
        [string]$scanPass = $null,
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
    if ($scanPass -ne $null) {
        $scanPassTextBox.Text = $scanPass
    } else {
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
            ScanUser = $scanUser
            ScanPass = $scanPass
            FolderPath = $folderPath
            ShareName = $shareName
            Description = $description
        }

        # Return the custom object
        return $resultObject
    } else {
        Write-Error "You canceled scanning setup"
        $scanningSetupForm.Close() | Out-Null
        return $null
    }
}

function New-LoadingForm($done = $false, $details = $null) {

	$return = @{
		Form = New-Object System.Windows.Forms.Form
		Controls = @{
			Text = New-Object System.Windows.Forms.Label
			Bar = New-Object System.Windows.Forms.ProgressBar
			Box = New-Object System.Windows.Forms.ListBox
			Button = New-Object System.Windows.Forms.Button
		}
	}

	$return.Form.Icon = Get-Icon
	$return.Form.Size = New-Object System.Drawing.Size(300, 200)
	$return.Form.StartPosition = 'CenterScreen'

	$return.Controls.Text.Location = New-Object System.Drawing.Point(10, 10)
	$return.Controls.Text.Size = New-Object System.Drawing.Size(280, 20)

	$return.Controls.Bar.Location = New-Object System.Drawing.Point(10, 30)
	$return.Controls.Bar.Size = New-Object System.Drawing.Size(265, 20)
	$return.Controls.Bar.Minimum = 0
	$return.Controls.Bar.Maximum = 25

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
			$return.Controls.Box.Items.Add($detail) | Out-Null
		}
		$return.Controls.Button.Enabled = $true
	} else {
		$return.Form.Text = 'Scans.exe - Loading...'
		$return.Controls.Text.Text = 'Loading...'
		$return.Controls.Bar.Value = 0
		$return.Controls.Button.Enabled = $false
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
		[int]$sleep = 500
	)
	Write-Verbose $text
	$Form.Controls.Text.Text = $text
	$Form.Controls.Bar.Value++
	$ENV:details += "||" + $text
	$Form.Controls.Box.Items.Insert(0, $text)
	Start-Sleep -Milliseconds $sleep
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

	$securePassword = $scanPass | ConvertTo-SecureString -AsPlainText -Force

	if (![boolean](Get-LocalUser -Name $scanUser -ErrorAction SilentlyContinue)) {
		Write-Verbose "Creating New User: $scanUser"
		Update-ProgressBar $loadingScreen "Creating New User: $scanUser"
		New-LocalUser -Name $scanUser -Password $securePassword -Description $description -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword -FullName "scans" | Out-Null
	} else {
		Write-Verbose "Updating Existing User: $scanUser"
		Update-ProgressBar $loadingScreen "Updating Existing User: $scanUser"
		Set-LocalUser -Name $scanUser -Password $securePassword -Description $description -AccountNeverExpires -PasswordNeverExpires $true -UserMayChangePassword $false -FullName "scans" | Out-Null
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
			Write-Verbose "User account '$scanUser' exists and password is set correctly."
		} else {
			Write-Verbose "User account '$scanUser' exists but password is not set correctly."
		}
	} else {
		Write-Verbose "User account '$scanUser' does not exist."
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
		} else {
			Update-ProgressBar $loadingScreen "Hiding scans user from login screen"
			if (!(Test-Path $path)) {
				Write-Verbose "Creating Registry Object at $path"
				New-Item -Path $path -Force | Out-Null
			}
			New-ItemProperty -Path $path -Name $scanUser -Value 0 -PropertyType 'DWord' -Force | Out-Null
		}
	} catch {
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
		} else {
			Update-ProgressBar $loadingScreen "Scans folder already exists"
		}
	} catch {
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
	} else {
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
		[bool]$setPermissions = $false  # Added new parameter with default value $false
	)

	$currentUser = $env:USERNAME
	$isDomainUser = $false

	if ($username -eq $currentUser) {
		$isDomainUser = (Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain
	}

	$folderAcl = (Get-Acl $folderPath)
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($username, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")

	if ($folderAcl.Access | Where-Object { $_.IdentityReference.Value -eq $username -and $_.AccessControlType -eq "Allow" }) {
		Update-ProgressBar $loadingScreen "Permission for $username already exists"
	} else {
		if ($isDomainUser -and $setPermissions) {  # Check if $isDomainUser is true and $setPermissions is true
			Update-ProgressBar $loadingScreen "Setting Permissions for $username"
			$folderAcl.AddAccessRule($rule)
			Set-Acl -Path $folderPath -AclObject $folderAcl  # Set the modified ACL
		} else {
			Update-ProgressBar $loadingScreen "Set permissions for $username"
		}
	}
}

function Set-SmbShare {
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
	} else {
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

	$networkCategory = (Get-NetConnectionProfile).NetworkCategory

	if (!$domainJoined -and $networkCategory -ne 'Private') {
		Update-ProgressBar $loadingScreen "Set Network Category to Private"
		Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private
	} elseif ($domainJoined -and $networkCategory -ne 'DomainAuthenticated') {
		Update-ProgressBar $loadingScreen "Set Network Category to Domain Authenticated"
		Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory DomainAuthenticated
	} else {
		Update-ProgressBar $loadingScreen "Network Category is already $networkCategory"
	}

	if ($enableFileAndPrinterSharing) {
		$fileAndPrinterSharingRule = Get-NetFirewallRule -DisplayGroup "File and Printer Sharing"
		if ($fileAndPrinterSharingRule.Enabled -eq $false) {
			Update-ProgressBar $loadingScreen "Enabling File and Printer Sharing"
			Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Enabled True
		} else {
			Update-ProgressBar $loadingScreen "File and Printer Sharing is already enabled"
		}
	}

	if ($enablePasswordProtectedSharing) {
		$smbServerConfig = Get-SmbServerConfiguration
		if ($smbServerConfig.EnableSMB2Protocol -eq $false -or
			$smbServerConfig.EnableSecuritySignature -eq $false -or
			$smbServerConfig.RequireSecuritySignature -eq $false) {
			Update-ProgressBar $loadingScreen "Enabling Password Protected Sharing"
			Set-SmbServerConfiguration -EnableSMB2Protocol $true -Confirm:$false
			Set-SmbServerConfiguration -EnableSecuritySignature $true -Confirm:$false
			Set-SmbServerConfiguration -RequireSecuritySignature $true -Confirm:$false
		} else {
			Update-ProgressBar $loadingScreen "Password Protected Sharing is already enabled"
		}
	}
}

function New-DesktopShortcut {
	param(
		[string]$shortcutPath= "C:\Users\Public\Desktop\Scans.lnk"
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