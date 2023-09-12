#Setup scan user variables
$user = "scans"
$password = "scans" | ConvertTo-SecureString -asPlainText -Force

#Creates scans user account if it doesn't exist, otherwise sets password for account
if(![boolean](Get-LocalUser -Name $user -ErrorAction Ignore)) {
	Write-Debug "Adding scans account"
	New-LocalUser -Name $user -Password $password -Description "scans" -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword -FullName "scans" -ErrorAction Ignore | Out-Null
} else {
	Write-Debug "Setting up scans account"
	Set-LocalUser -Name $user -Password $password -Description "scans" -ErrorAction Ignore | Out-Null
}


#Hide scans account from login screen on non domain joined computers
if(!(Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain){	
	$path = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist'
	$value = 0
	$name = $user
	if(!(Test-Path $path)){
		New-Item -Path $path -Force
	}
	New-ItemProperty -path $path -name $name -value $value -PropertyType 'DWord' -Force | Out-Null
}

#Check if scans folder exists, create if missing
if(!(Test-Path -Path 'C:\scans')){
    New-Item -Path 'C:\' -Name 'scans' -ItemType Directory
}

#Check if scans scare exists, create if missing
if(!((Get-SmbShare).Name).toLower().Contains('scans')){
    New-SmbShare -Name 'scans' -Path 'C:\scans' -FullAccess $user
} else {
    Grant-SmbShareAccess -Name "scans" -AccountName $user -AccessRight Full
}