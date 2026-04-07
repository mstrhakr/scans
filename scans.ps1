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
$script:iconUri = [Uri]::new($iconPath)

# --- WPF Settings Dialog ---
function New-SettingsPage {
	[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Settings" Height="270" Width="300" WindowStartupLocation="CenterScreen" ResizeMode="NoResize">
    <StackPanel Margin="12">
        <CheckBox Name="chkCreateUser" Content="Create new user account" Margin="0,0,0,6"/>
        <CheckBox Name="chkHideUser" Content="Hide user from login screen" Margin="0,0,0,6"/>
        <CheckBox Name="chkCreateFolder" Content="Create scans folder" Margin="0,0,0,6"/>
        <CheckBox Name="chkSetPermissions" Content="Set folder permissions" Margin="0,0,0,6"/>
        <CheckBox Name="chkSetShare" Content="Set SMB share" Margin="0,0,0,6"/>
        <CheckBox Name="chkCreateShortcut" Content="Create desktop shortcut" Margin="0,0,0,6"/>
        <CheckBox Name="chkNetworkSettings" Content="Check network settings" Margin="0,0,0,6"/>
        <Button Name="btnOK" Content="OK" Width="75" Height="24" HorizontalAlignment="Right" Margin="0,12,0,0"/>
    </StackPanel>
</Window>
"@
	$reader = [System.Xml.XmlNodeReader]::new($xaml)
	$window = [Windows.Markup.XamlReader]::Load($reader)
	$window.Icon = [System.Windows.Media.Imaging.BitmapImage]::new($script:iconUri)

	$window.FindName('chkCreateUser').IsChecked = $script:createUser
	$window.FindName('chkHideUser').IsChecked = $script:hideUser
	$window.FindName('chkCreateFolder').IsChecked = $script:createFolder
	$window.FindName('chkSetPermissions').IsChecked = $script:setPermissions
	$window.FindName('chkSetShare').IsChecked = $script:setShare
	$window.FindName('chkCreateShortcut').IsChecked = $script:createShortcut
	$window.FindName('chkNetworkSettings').IsChecked = $script:checkNetworkSettings

	$window.FindName('btnOK').Add_Click({
		$script:createUser = [bool]$window.FindName('chkCreateUser').IsChecked
		$script:hideUser = [bool]$window.FindName('chkHideUser').IsChecked
		$script:createFolder = [bool]$window.FindName('chkCreateFolder').IsChecked
		$script:setPermissions = [bool]$window.FindName('chkSetPermissions').IsChecked
		$script:setShare = [bool]$window.FindName('chkSetShare').IsChecked
		$script:createShortcut = [bool]$window.FindName('chkCreateShortcut').IsChecked
		$script:checkNetworkSettings = [bool]$window.FindName('chkNetworkSettings').IsChecked
		$window.DialogResult = $true
	})

	$window.ShowDialog() | Out-Null
}

# --- WPF Setup Window ---
[xml]$setupXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Scans Setup" Height="210" Width="360" WindowStartupLocation="CenterScreen" ResizeMode="NoResize">
    <Grid Margin="12">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="75"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <TextBlock Grid.Row="0" Text="Username:" VerticalAlignment="Center" Margin="0,0,0,6"/>
        <TextBox Grid.Row="0" Grid.Column="1" Grid.ColumnSpan="2" Name="txtUsername" Margin="0,0,0,6"/>
        <TextBlock Grid.Row="1" Text="Password:" VerticalAlignment="Center" Margin="0,0,0,6"/>
        <TextBox Grid.Row="1" Grid.Column="1" Grid.ColumnSpan="2" Name="txtPassword" Margin="0,0,0,6"/>
        <TextBlock Grid.Row="2" Text="Local Dir:" VerticalAlignment="Center" Margin="0,0,0,6"/>
        <TextBox Grid.Row="2" Grid.Column="1" Name="txtFolderPath" Margin="0,0,4,6"/>
        <Button Grid.Row="2" Grid.Column="2" Name="btnBrowse" Content="..." Width="28" Margin="0,0,0,6"/>
        <TextBlock Grid.Row="3" Text="SMB Share:" VerticalAlignment="Center" Margin="0,0,0,6"/>
        <TextBox Grid.Row="3" Grid.Column="1" Grid.ColumnSpan="2" Name="txtShareName" Margin="0,0,0,6"/>
        <StackPanel Grid.Row="5" Grid.ColumnSpan="3" Orientation="Horizontal" HorizontalAlignment="Right">
            <Button Name="btnSettings" Content="&#x2699;" Width="30" Height="28" Margin="0,0,8,0" FontSize="16" ToolTip="Settings"/>
            <Button Name="btnOK" Content="OK" Width="75" Height="24" Margin="0,0,8,0" IsDefault="True"/>
            <Button Name="btnCancel" Content="Cancel" Width="75" Height="24" IsCancel="True"/>
        </StackPanel>
    </Grid>
</Window>
"@
$reader = [System.Xml.XmlNodeReader]::new($setupXaml)
$setupWindow = [Windows.Markup.XamlReader]::Load($reader)
$setupWindow.Icon = [System.Windows.Media.Imaging.BitmapImage]::new($script:iconUri)

$setupWindow.FindName('txtUsername').Text = $scanUser
$setupWindow.FindName('txtPassword').Text = New-RandomPassword
$setupWindow.FindName('txtFolderPath').Text = $folderPath
$setupWindow.FindName('txtShareName').Text = $shareName

$setupWindow.FindName('btnBrowse').Add_Click({
	$folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
	$folderBrowser.Description = "Select folder for scans"
	$folderBrowser.SelectedPath = $setupWindow.FindName('txtFolderPath').Text
	$folderBrowser.ShowNewFolderButton = $true
	if ($folderBrowser.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
		$setupWindow.FindName('txtFolderPath').Text = $folderBrowser.SelectedPath
	}
})

$setupWindow.FindName('btnSettings').Add_Click({ New-SettingsPage })
$setupWindow.FindName('btnOK').Add_Click({ $setupWindow.DialogResult = $true })

$setupResult = $setupWindow.ShowDialog()

if ($setupResult -eq $true) {
	$script:scanUser = $setupWindow.FindName('txtUsername').Text
	$script:scanPass = $setupWindow.FindName('txtPassword').Text
	$script:folderPath = $setupWindow.FindName('txtFolderPath').Text
	$script:shareName = $setupWindow.FindName('txtShareName').Text
	Write-Verbose "Username: $script:scanUser `nPassword: $script:scanPass `nLocal Dir: $script:folderPath`nSMB Share: $script:shareName"
}
else {
	Write-Verbose "User canceled scanning setup"
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

[xml]$progressXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Scans Setup - Loading..." Height="240" Width="360" WindowStartupLocation="CenterScreen" ResizeMode="NoResize">
    <Grid Margin="12">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" Name="txtStatus" Text="Loading..." Margin="0,0,0,6"/>
        <ProgressBar Grid.Row="1" Name="progressBar" Height="20" Minimum="0" Value="0" Margin="0,0,0,6"/>
        <ListBox Grid.Row="2" Name="lstDetails" Margin="0,0,0,8"/>
        <StackPanel Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Right">
            <Button Name="btnCopyPassword" Content="Copy Password" Width="110" Height="24" IsEnabled="False" Margin="0,0,8,0"/>
            <Button Name="btnDone" Content="Done" Width="75" Height="24" IsEnabled="False"/>
        </StackPanel>
    </Grid>
</Window>
"@
$reader = [System.Xml.XmlNodeReader]::new($progressXaml)
$script:progressWindow = [Windows.Markup.XamlReader]::Load($reader)
$script:progressWindow.Icon = [System.Windows.Media.Imaging.BitmapImage]::new($script:iconUri)
$script:progressWindow.FindName('progressBar').Maximum = $script:progressMax

# Prevent closing during work
$script:progressWindow.Add_Closing({
	if (-not $script:progressWindow.FindName('btnDone').IsEnabled) {
		$_.Cancel = $true
	}
})

$script:progressWindow.FindName('btnCopyPassword').Add_Click({
	if ($script:hasSetClipboard) {
		Set-Clipboard -Value $scanPass
	}
	else {
		[System.Windows.Forms.Clipboard]::SetText($scanPass)
	}
	Write-Verbose "Copied scan password to clipboard: $scanPass"
	[System.Windows.MessageBox]::Show('Password has been copied to Clipboard')
})

$script:progressWindow.FindName('btnDone').Add_Click({
	$script:progressWindow.Close()
})

$script:progressWindow.Show()
$percent = 0
function Set-ProgressBar($text, $sleep = 250) {
	$script:progressWindow.FindName('txtStatus').Text = $text
	$script:percent += 1
	$script:progressWindow.FindName('progressBar').Value = [Math]::Min($script:percent, $script:progressMax)
	$script:details.Insert(0, $text) | Out-Null
	$script:progressWindow.FindName('lstDetails').Items.Insert(0, $text) | Out-Null
	Write-Verbose "Progress Text: $text"
	[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
	Start-Sleep -Milliseconds $sleep
}

# Gather computer details
Set-ProgressBar "Gathering local computer details"
if ($script:hasCimInstance) {
	$computerDetails = Get-CimInstance -ClassName Win32_ComputerSystem
}
else {
	$computerDetails = Get-WmiObject -Class Win32_ComputerSystem
}
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
$script:progressWindow.Title = 'Scans Setup - Finished'
$script:progressWindow.FindName('btnDone').IsEnabled = $true
if ($createUser) { $script:progressWindow.FindName('btnCopyPassword').IsEnabled = $true }
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([action]{}, [System.Windows.Threading.DispatcherPriority]::Background)

# Block until user closes the progress window
$frame = [System.Windows.Threading.DispatcherFrame]::new()
$script:progressWindow.Add_Closed({ $frame.Continue = $false })
[System.Windows.Threading.Dispatcher]::PushFrame($frame)
Exit 0
