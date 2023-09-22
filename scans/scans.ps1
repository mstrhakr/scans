# Setup scan user variables
$user = "scans"; # Read-Host -Prompt "Enter Username";
$password = "scans"; # Read-Host -Prompt "Enter Password";
$folderName = "scans";
$txt = "Scanning setup by PSP.";

# Creates scans user account if it doesn't exist, otherwise sets password for account
if(![boolean](Get-LocalUser -Name $user -ErrorAction Ignore)) {
	New-LocalUser -Name $user -Password $($password | ConvertTo-SecureString -AsPlainText -Force) -Description $txt -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword -FullName "scans" -ErrorAction Ignore | Out-Null;
} else {
	Set-LocalUser -Name $user -Password $($password | ConvertTo-SecureString -AsPlainText -Force) -Description $txt -ErrorAction Ignore | Out-Null;
}


# Hide scans account from login screen on non domain joined computers
if(!(Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain){	
	$path = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist';
	if(!(Test-Path $path)){
		New-Item -Path $path -Force | Out-Null;
	}
	New-ItemProperty -path $path -name $user -value 0 -PropertyType 'DWord' -Force | Out-Null;
}

# Check if scans folder exists, create if missing
if(!(Test-Path -Path "C:\$folderName")){
    New-Item -Path 'C:\' -Name $folderName -ItemType Directory | Out-Null;
}

# Check if scans share exists, create if missing
if(!((Get-SmbShare).Name).toLower().Contains($folderName)){
    New-SmbShare -Name $folderName -Path "C:\$folderName" -FullAccess $user | Out-Null;
} else {
    Grant-SmbShareAccess -Name $folderName -AccountName $user -AccessRight Full -Force | Out-Null;
}

# Create scan folder shortcut
$Shell = New-Object -ComObject ("WScript.Shell");
$ShortCut = $Shell.CreateShortcut("C:\Users\Public\Desktop\Scans.lnk");
$ShortCut.TargetPath = "C:\$folderName";
$ShortCut.IconLocation = "%SystemRoot%\system32\imageres.dll,245";
$ShortCut.Description = $txt;
$ShortCut.Save() | Out-Null;