#v1.3.0.0
# Setup variables and defaults
[string]$username = "scans"
[string]$password = "scans"
[string]$folderPath = "C:\scans"
[string]$shareName = "scans"
[string]$description = "Scanning setup by PSP."


# Load the .NET Framework classes
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Web

# Create a new form with a title and a size
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Password Preference'
$form.Size = New-Object System.Drawing.Size(300,200)
$form.StartPosition = 'CenterScreen'

# Create a label with the prompt message and add it to the form
$label = New-Object System.Windows.Forms.Label
$label.Text = 'Please choose one of the password options below:'
$label.Location = New-Object System.Drawing.Point(10,10)
$label.AutoSize = $true
$form.Controls.Add($label)

# Create a button for option 1 and add it to the form
$button1 = New-Object System.Windows.Forms.Button
$button1.Text = 'Just Use "scans"'
$button1.Location = New-Object System.Drawing.Point(75,50)
$button1.Size = New-Object System.Drawing.Size(150,25)
$form.Controls.Add($button1)

# Create a button for option 2 and add it to the form
$button2 = New-Object System.Windows.Forms.Button
$button2.Text = 'Use Custom Password'
$button2.Location = New-Object System.Drawing.Point(75,100)
$button2.Size = New-Object System.Drawing.Size(150,25)
$form.Controls.Add($button2)

# Define what happens when the user clicks on the buttons
$button1.Add_Click({
    Write-Host 'The password will be set to "scans"'
    $form.Close()
})

$button2.Add_Click({
    $form.Close()
	# Create a new form with a title and a size
	$form = New-Object System.Windows.Forms.Form
	$form.Text = 'Enter new password'
	$form.Size = New-Object System.Drawing.Size (300,200)
	$form.StartPosition = 'CenterScreen'

	# Create a label with the input message and add it to the form
	$label = New-Object System.Windows.Forms.Label
	$label.Text = 'Please enter the new password:'
	$label.Location = New-Object System.Drawing.Point (10,10)
	$label.AutoSize = $true
	$form.Controls.Add($label)

	# Create a text box for the user input and add it to the form
	$textBox = New-Object System.Windows.Forms.TextBox
	$textBox.Location = New-Object System.Drawing.Point (10,40)
	$textBox.Size = New-Object System.Drawing.Size (260,20)
	$textBox.Text = [System.Web.Security.Membership]::GeneratePassword(10, 0)
	$form.Controls.Add($textBox)

	# Create an OK button and add it to the form
	$okButton = New-Object System.Windows.Forms.Button
	$okButton.Location = New-Object System.Drawing.Point (75,120)
	$okButton.Size = New-Object System.Drawing.Size (75,23)
	$okButton.Text = 'OK'
	$okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
	$form.AcceptButton = $okButton
	$form.Controls.Add($okButton)

	# Create a Cancel button and add it to the form
	$cancelButton = New-Object System.Windows.Forms.Button
	$cancelButton.Location = New-Object System.Drawing.Point (150,120)
	$cancelButton.Size = New-Object System.Drawing.Size (75,23)
	$cancelButton.Text = 'Use "scans"'
	$cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
	$form.CancelButton = $cancelButton
	$form.Controls.Add($cancelButton)

	# Show the form and wait for the user input
	$form.Topmost = $true
	$form.Add_Shown({$textBox.Select()})
	$result = $form.ShowDialog()

	# Check the result and get the text input
	if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
		# The user clicked OK
		$script:password = $textBox.Text
		Write-Host "Scans Password: $($textBox.Text)"
	} else {
		# The user clicked Cancel
		Write-Host "You canceled the input box: using scans as password"
	}
    $form.Close()
})

# Show the form and wait for the user input
$form.ShowDialog()

# Creates scans user account if it doesn't exist, otherwise sets password for account
if(![boolean](Get-LocalUser -Name $username -ErrorAction SilentlyContinue)) {
	Write-Output "Creating New User: $username"
	New-LocalUser -Name $username -Password $($password | ConvertTo-SecureString -AsPlainText -Force) -Description $description -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword -FullName "scans";
} else {
	Write-Output "Updating User: $username"
	Set-LocalUser -Name $username -Password $($password | ConvertTo-SecureString -AsPlainText -Force) -Description $description -AccountNeverExpires -PasswordNeverExpires $true -UserMayChangePassword $false -FullName "scans";
}


# Hide scans account from login screen on non domain joined computers
$computerDetails = Get-CimInstance -ClassName Win32_ComputerSystem
if(!$computerDetails.PartOfDomain){	
	Write-Output "Computer is not domain joined"
	$path = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist';
	if(!(Test-Path $path)){
		Write-Output "Creating Registry Object"
		New-Item -Path $path -Force | Out-Null;
	}
	Write-Output "Hiding scans user from login screen"
	New-ItemProperty -path $path -name $username -value 0 -PropertyType 'DWord' -Force | Out-Null;
}

# Check if scans folder exists, create if missing
if(!(Test-Path -Path $folderPath)){
	Write-Warning "Scans folder doesn't exist, creating"
    New-Item -Path $($folderPath.Split(':')[0] + ':/') -Name $folderPath.Split(':')[1] -ItemType Directory | Out-Null;
} else {
	Write-Output "Scans folder already exists"
}

# Grant full recursive permissions on the scan folder to the scan user and all local users
$folderAcl = (Get-Acl $folderPath)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($username, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$folderAcl.SetAccessRule($rule)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$folderAcl.SetAccessRule($rule)
if($computerDetails.PartOfDomain){
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

# Create scan folder shortcut
$shellObject = New-Object -ComObject ("WScript.Shell");
$desktopShortCut = $shellObject.CreateShortcut("C:\Users\Public\Desktop\Scans.lnk");
$desktopShortCut.TargetPath = $folderPath;

# Get the Windows build number
$build = (Get-CimInstance Win32_OperatingSystem).BuildNumber

# Compare the build number with the known values for Windows 10 and Windows 11
if ($build -lt 22000) {
    # This is Windows 10
	$desktopShortCut.IconLocation = "%SystemRoot%\system32\imageres.dll,244";
} elseif ($build -ge 22000) {
    # This is Windows 11
	$desktopShortCut.IconLocation = "%SystemRoot%\system32\imageres.dll,245";
}

$desktopShortCut.Description = $description;
Write-Output "Creating Desktop Shortcut"
$desktopShortCut.Save() | Out-Null;

# Set network profile to Private if not domain joined.
if(!$computerDetails.PartOfDomain){
	Write-Output "Setting Net Connection Profile to Private"
	Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private
} else {
	Write-Output "Setting Net Connection Profile to Domain Authenticated"
	Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory DomainAuthenticated
}


if ($password -eq "scans"){
	$clipboard = 'Copied computer name to clipboard'
	Set-Clipboard $computerDetails.Name
} else {
	$clipboard = "Copied custom password to clipboard"
	Set-Clipboard $password
}

# Notify user about setup
Write-Output "Notifing user of scanning details"
$shellObject.Popup("Scanning setup is complete.
Desktop shortcut has been created.

Username: $username
Password: $password
Remote Dir: \\$($computerDetails.Name)\$shareName
Local Dir: $folderPath

$clipboard") | Out-Null;
