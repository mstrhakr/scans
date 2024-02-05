# v1.4.0.1
# Added gui for exe deployment
# Setup variables and defaults
[string]$username = 'scans'
[string]$password = 'scans'
[string]$folderPath = 'C:\scans'
[string]$shareName = 'scans'
[string]$description = 'Scanning setup by PSP.'

# Load the .NET Framework classes
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Web

# Download icon
Invoke-WebRequest 'https://raw.githubusercontent.com/mstrhakr/scans/main/scans.ico' -OutFile 'C:\ProgramData\scans.ico' | Out-Null;

# Create a new form with a title and a size
$scanningSetupForm = New-Object System.Windows.Forms.Form
$scanningSetupForm.Text = 'Choose your scanning options below.'
$scanningSetupForm.Icon = 'C:\ProgramData\scans.ico'
$scanningSetupForm.Size = New-Object System.Drawing.Size (300,200)
$scanningSetupForm.StartPosition = 'CenterScreen'

# Create a text box for the user to choose a custom username
$usernameLabel = New-Object	System.Windows.Forms.Label
$usernameLabel.Location = New-Object System.Drawing.Point (10,10)
$usernameLabel.Size = New-Object System.Drawing.Size (70,20)
$usernameLabel.Text = 'Username:'
$scanningSetupForm.Controls.Add($usernameLabel)
$usernameTextBox = New-Object System.Windows.Forms.TextBox
$usernameTextBox.Location = New-Object System.Drawing.Point (75,10)
$usernameTextBox.Size = New-Object System.Drawing.Size (150,20)
$usernameTextBox.Text = $username
$scanningSetupForm.Controls.Add($usernameTextBox)

# Create a text box for the user to choose a custom password
$passwordLabel = New-Object	System.Windows.Forms.Label
$passwordLabel.Location = New-Object System.Drawing.Point (10,30)
$passwordLabel.Size = New-Object System.Drawing.Size (70,20)
$passwordLabel.Text = 'Password:'
$scanningSetupForm.Controls.Add($passwordLabel)
$passwordTextBox = New-Object System.Windows.Forms.TextBox
$passwordTextBox.Location = New-Object System.Drawing.Point (75,30)
$passwordTextBox.Size = New-Object System.Drawing.Size (260,20)
$passwordTextBox.Text = $password # [System.Web.Security.Membership]::GeneratePassword(10, 0)
$scanningSetupForm.Controls.Add($passwordTextBox)

# Create a text box for the user to choose a custom path
$folderPathLabel = New-Object	System.Windows.Forms.Label
$folderPathLabel.Location = New-Object System.Drawing.Point (10,50)
$folderPathLabel.Size = New-Object System.Drawing.Size (70,20)
$folderPathLabel.Text = 'Local Dir:'
$scanningSetupForm.Controls.Add($folderPathLabel)
$folderPathTextBox = New-Object System.Windows.Forms.TextBox
$folderPathTextBox.Location = New-Object System.Drawing.Point (75,50)
$folderPathTextBox.Size = New-Object System.Drawing.Size (260,20)
$folderPathTextBox.Text = $folderPath
$scanningSetupForm.Controls.Add($folderPathTextBox)

# Create a text box for the user to choose a smb share
$smbShareLabel = New-Object	System.Windows.Forms.Label
$smbShareLabel.Location = New-Object System.Drawing.Point (10,70)
$smbShareLabel.Size = New-Object System.Drawing.Size (70,20)
$smbShareLabel.Text = 'SMB Share:'
$scanningSetupForm.Controls.Add($smbShareLabel)
$smbShareTextBox = New-Object System.Windows.Forms.TextBox
$smbShareTextBox.Location = New-Object System.Drawing.Point (75,70)
$smbShareTextBox.Size = New-Object System.Drawing.Size (260,20)
$smbShareTextBox.Text = $shareName
$scanningSetupForm.Controls.Add($smbShareTextBox)

# Create an OK button and add it to the form
$okButton = New-Object System.Windows.Forms.Button
$okButton.Location = New-Object System.Drawing.Point (75,120)
$okButton.Size = New-Object System.Drawing.Size (75,23)
$okButton.Text = 'OK'
$okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$scanningSetupForm.AcceptButton = $okButton
$scanningSetupForm.Controls.Add($okButton)

# Create a Cancel button and add it to the form
$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Location = New-Object System.Drawing.Point (150,120)
$cancelButton.Size = New-Object System.Drawing.Size (75,23)
$cancelButton.Text = 'Cancel'
$cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$scanningSetupForm.CancelButton = $cancelButton
$scanningSetupForm.Controls.Add($cancelButton)

# Show the form and wait for the user input
$scanningSetupForm.Topmost = $true
$scanningSetupForm.Add_Shown({$passwordTextBox.Select()})
$result = $scanningSetupForm.ShowDialog()

# Check the result and get the text input
if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
	$script:username = $usernameTextBox.Text
	$script:password = $passwordTextBox.Text
	$script:folderPath = $folderPathTextBox.Text
	$script:shareName = $smbShareTextBox.Text
	Write-Output "Username: $script:username`nPassword: $script:password`nLocal Dir: $script:folderPath`nSMB Share: $script:shareName"
} else {
	Write-Error "You canceled scanning setup"
	Exit
}
$scanningSetupForm.Close() | Out-Null;

# Creates scans user account if it doesn't exist, otherwise sets password for account
if(![boolean](Get-LocalUser -Name $username -ErrorAction SilentlyContinue)) {
	Write-Output "Creating New User.`nUsername: $username`nPassword: $password"
	New-LocalUser -Name $username -Password $($password | ConvertTo-SecureString -AsPlainText -Force) -Description $description -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword -FullName "scans" | Out-Null;
	if(!$?){Write-Error $?.Error}
} else {
	Write-Output "Updating User.`nUsername: $username`nPassword: $password"
	Set-LocalUser -Name $username -Password $($password | ConvertTo-SecureString -AsPlainText -Force) -Description $description -AccountNeverExpires -PasswordNeverExpires $true -UserMayChangePassword $false -FullName "scans" | Out-Null;
	if(!$?){Write-Error $?.Error}
}

# Hide scans account from login screen on non domain joined computers
$computerDetails = Get-CimInstance -ClassName Win32_ComputerSystem
$domainJoined = $computerDetails.PartOfDomain
$path = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist'
$hideAccount = Get-ItemProperty -path $path -name $username -ErrorAction SilentlyContinue;
if($? -and $hideAccount.($username) -eq 0){
	Write-Output "User account is already hidden from login screen"
} elseif(!$domainJoined){
	Write-Output "Hiding scans user from login screen"
	if(!(Test-Path $path)){
		Write-Verbose "Creating Registry Object at $path"
		New-Item -Path $path -Force | Out-Null;
	}
	New-ItemProperty -path $path -name $username -value 0 -PropertyType 'DWord' -Force | Out-Null;
}

# Check if scans folder exists, create if missing
if(!(Test-Path -Path $folderPath)){
	Write-Output "Scans folder doesn't exist. Creating Folder at $folderPath"
	New-Item -Path $($folderPath.Split(':')[0] + ':/') -Name $folderPath.Split(':')[1] -ItemType Directory | Out-Null;
    #Check if creating folder was successful $? = Was last command successful?(T/F)
	if ($?) {
		Write-Output "New folder created at $folderPath."
	} else {
		Write-Error "Folder creation failed!`nManually Create Folder before Continuing!"
	}
} else {
	Write-Output "Scans folder already exists"
}

# Grant full recursive permissions on the scan folder to the scan user and all local users
$folderAcl = (Get-Acl $folderPath)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($username, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$folderAcl.SetAccessRule($rule)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$folderAcl.SetAccessRule($rule)
if($domainJoined){
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Users", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
	$folderAcl.SetAccessRule($rule)
}
Write-Output "Setting folder permissions"
Set-Acl $folderPath $folderAcl

# Check if scans share exists, create if missing
if(!((Get-SmbShare).Name).toLower().Contains($shareName)){
	Write-Output "Creating SMB share"
    New-SmbShare -Name $shareName -Path $folderPath -FullAccess $username | Out-Null;
} else {
	Write-Output "Updating SMB share permissions"
    Grant-SmbShareAccess -Name $shareName -AccountName $username -AccessRight Full -Force | Out-Null;
}

# Create scan folder desktop shortcut
$shellObject = New-Object -ComObject ("WScript.Shell");
$desktopShortCut = $shellObject.CreateShortcut("C:\Users\Public\Desktop\Scans.lnk");
$desktopShortCut.TargetPath = $folderPath;
$desktopShortCut.IconLocation = 'C:\ProgramData\scans.ico';
$desktopShortCut.Description = $description;
Write-Output "Creating Desktop Shortcut"
$desktopShortCut.Save() | Out-Null;

# Set network profile to Private if not domain joined.
$networkCategory = (Get-NetConnectionProfile).NetworkCategory
Write-Output "Checking Net Connection Profile"
if(!$domainJoined -and $networkCategory -ne 'Private'){
	$msg = "Set Net Connection Profile to Private"
	Write-Output $msg
	Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private
} elseif ($domainJoined -and $networkCategory -ne 'DomainAuthenticated'){
	$msg = "Set Net Connection Profile to Domain Authenticated"
	Write-Output $msg
	Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory DomainAuthenticated
} else {
	Write-Output "Net Connection Profile is already set to $networkCategory"
}