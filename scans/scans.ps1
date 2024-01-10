# Setup parameters and defaults
param (
	[string]$username = "scans",
	[string]$password = "scans",
	[string]$folderPath = "C:\scans",
	[string]$shareName = "scans",
	[string]$description = "Scanning setup by PSP."
)

# Creates scans user account if it doesn't exist, otherwise sets password for account
if(![boolean](Get-LocalUser -Name $username -ErrorAction Ignore)) {
	Write-Output "Creating New User: $username"
	New-LocalUser -Name $username -Password $($password | ConvertTo-SecureString -AsPlainText -Force) -Description $description -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword -FullName "scans" -ErrorAction Ignore | Out-Null;
} else {
	Write-Output "Updating User: $username"
	Set-LocalUser -Name $username -Password $($password | ConvertTo-SecureString -AsPlainText -Force) -Description $description -ErrorAction Ignore | Out-Null;
}


# Hide scans account from login screen on non domain joined computers
$computerDetails = Get-CimInstance -ClassName Win32_ComputerSystem
if(!$computerDetails.PartOfDomain){	
	Write-Output "Computer is part not domain joined"
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
	Write-Output "Scans folder doesn't exist, creating"
    New-Item -Path $($folderPath.Split(':')[0] + ':/') -Name $folderPath.Split(':')[1] -ItemType Directory | Out-Null;
} else {
	Write-Output "Scans folder already exists"
}

# Grant full recursive permissions on the scan folder to the scan user and all local users
$folderAcl = (Get-Acl $folderPath)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($username, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$folderAcl.SetAccessRule($rule)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$folderAcl.SetAccessRule($rule)
if((Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain){
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
if(!(Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain){
	Write-Output "Setting Net Connection Profile to Private"
	Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private
} else {
	Write-Output "Setting Net Connection Profile to Domain Authenticated"
	Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory DomainAuthenticated
}

Write-Output "Setting clipboard to computer name"
Set-Clipboard $computerDetails.Name

# Notify user about setup
Write-Output "Notifing user of scanning details"
$shellObject.Popup("Scanning setup is complete.
Computer Name: $($computerDetails.Name)
*Computer name saved to clipboard*
Username: $username
Password: $password
SMB Share: $shareName
Local Dir: $folderPath") | Out-Null;
