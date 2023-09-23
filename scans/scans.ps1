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
	New-LocalUser -Name $username -Password $($password | ConvertTo-SecureString -AsPlainText -Force) -Description $description -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword -FullName "scans" -ErrorAction Ignore | Out-Null;
} else {
	Set-LocalUser -Name $username -Password $($password | ConvertTo-SecureString -AsPlainText -Force) -Description $description -ErrorAction Ignore | Out-Null;
}


# Hide scans account from login screen on non domain joined computers
if(!(Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain){	
	$path = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist';
	if(!(Test-Path $path)){
		New-Item -Path $path -Force | Out-Null;
	}
	New-ItemProperty -path $path -name $username -value 0 -PropertyType 'DWord' -Force | Out-Null;
}

# Check if scans folder exists, create if missing
if(!(Test-Path -Path $folderPath)){
    New-Item -Path $folderPath.Split(':')[0] + ':' -Name $folderPath.Split(':')[1] -ItemType Directory | Out-Null;
}

# Grant full recursive permissions on the scan folder to the scan user and all local users
$folderAcl = (Get-Acl $folderPath)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($username, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$folderAcl.SetAccessRule($rule)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("users", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$folderAcl.SetAccessRule($rule)
Set-Acl $folderPath $folderAcl

# Check if scans share exists, create if missing
if(!((Get-SmbShare).Name).toLower().Contains($shareName)){
    New-SmbShare -Name $shareName -Path $folderPath -FullAccess $username | Out-Null;
} else {
    Grant-SmbShareAccess -Name $shareName -AccountName $username -AccessRight Full -Force | Out-Null;
}

# Create scan folder shortcut
$shellObject = New-Object -ComObject ("WScript.Shell");
$desktopShortCut = $shellObject.CreateShortcut("C:\Users\Public\Desktop\Scans.lnk");
$desktopShortCut.TargetPath = $folderPath;
$desktopShortCut.IconLocation = "%SystemRoot%\system32\imageres.dll,245";
$desktopShortCut.Description = $description;
$desktopShortCut.Save() | Out-Null;

# Notify user about setup
<# $shellObject.Popup("Scanning setup is complete.
Username: $username
Password: $password
SMB Share: $shareName
Local Dir: C:\$folderPath"); #>