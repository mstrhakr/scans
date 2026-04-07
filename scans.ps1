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

# --- Error popup helper ---
function Show-ErrorAndExit {
	param(
		[string]$Title,
		[string]$Message,
		[string]$Remediation
	)
	$body = "$Message`n`nHow to fix:`n$Remediation"
	[System.Windows.MessageBox]::Show($body, $Title, 'OK', 'Error') | Out-Null
	Exit 1
}

# --- Common error remediation messages ---
$script:Remediation = @{
	NotAdmin       = "Right-click start button and select 'Powershell/Terminal (Admin)'."
	NoInternet     = "Check your network connection and ensure you can reach github.com.`nIf behind a proxy, configure your system proxy settings."
	OldPowerShell  = "Install Windows Management Framework 3.0 or later from:`nhttps://www.microsoft.com/en-us/download/details.aspx?id=54616"
	TrustRelation  = "The domain trust is broken. Run the following from an admin prompt:`nTest-ComputerSecureChannel -Repair -Credential (Get-Credential)`nOr rejoin the machine to the domain."
	AccessDenied   = "The current user does not have permission. Ensure you are running as Administrator and the folder is not read-only."
	ShareInUse     = "Close any open files or Explorer windows pointing to the share, then try again."
}

# --- Preflight checks ---
# 1. Require Administrator
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	Show-ErrorAndExit -Title 'Administrator Required' `
		-Message 'This script must be run as Administrator to create users, shares, and configure network settings.' `
		-Remediation $script:Remediation.NotAdmin
}

# 2. Require PowerShell 3.0+
if ($PSVersionTable.PSVersion.Major -lt 3) {
	Show-ErrorAndExit -Title 'PowerShell Version Too Old' `
		-Message "This script requires PowerShell 3.0 or later. You are running $($PSVersionTable.PSVersion)." `
		-Remediation $script:Remediation.OldPowerShell
}

# Detect OS capabilities for legacy fallback
$script:hasLocalAccounts = [bool](Get-Command -Name 'Get-LocalUser' -ErrorAction SilentlyContinue)
$script:hasSmbShareCmdlets = [bool](Get-Command -Name 'Get-SmbShare' -ErrorAction SilentlyContinue)
$script:hasNetSecurity = [bool](Get-Command -Name 'Get-NetFirewallRule' -ErrorAction SilentlyContinue)
$script:hasNetConnection = [bool](Get-Command -Name 'Get-NetConnectionProfile' -ErrorAction SilentlyContinue)
$script:hasCimInstance = [bool](Get-Command -Name 'Get-CimInstance' -ErrorAction SilentlyContinue)
$script:hasSetClipboard = [bool](Get-Command -Name 'Set-Clipboard' -ErrorAction SilentlyContinue)

# --- Theme detection (Solarized Light/Dark, defaults to Dark) ---
$script:useDarkTheme = $true
try {
	$themeReg = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'AppsUseLightTheme' -ErrorAction SilentlyContinue
	if ($themeReg -and $themeReg.AppsUseLightTheme -eq 1) { $script:useDarkTheme = $false }
} catch { }

if ($script:useDarkTheme) {
	$script:thBg = '#002b36'; $script:thBgAlt = '#073642'
	$script:thFg = '#839496'; $script:thFgEm = '#93a1a1'; $script:thFgStrong = '#eee8d5'
	$script:thAccent = '#268bd2'; $script:thAccentHi = '#2aa198'
	$script:thBorder = '#586e75'; $script:thBtnText = '#fdf6e3'
} else {
	$script:thBg = '#fdf6e3'; $script:thBgAlt = '#eee8d5'
	$script:thFg = '#657b83'; $script:thFgEm = '#586e75'; $script:thFgStrong = '#073642'
	$script:thAccent = '#268bd2'; $script:thAccentHi = '#2aa198'
	$script:thBorder = '#93a1a1'; $script:thBtnText = '#fdf6e3'
}

$script:themeResources = @"
    <Window.Resources>
        <Style TargetType="Button">
            <Setter Property="Background" Value="$($script:thAccent)"/>
            <Setter Property="Foreground" Value="$($script:thBtnText)"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}" CornerRadius="3"
                                Padding="6,3" SnapsToDevicePixels="True">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="$($script:thAccentHi)"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Opacity" Value="0.45"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style TargetType="TextBox">
            <Setter Property="Background" Value="$($script:thBgAlt)"/>
            <Setter Property="Foreground" Value="$($script:thFgStrong)"/>
            <Setter Property="BorderBrush" Value="$($script:thBorder)"/>
            <Setter Property="Padding" Value="4,3"/>
        </Style>
        <Style TargetType="TextBlock">
            <Setter Property="Foreground" Value="$($script:thFg)"/>
        </Style>
        <Style TargetType="CheckBox">
            <Setter Property="Foreground" Value="$($script:thFg)"/>
        </Style>
        <Style TargetType="ProgressBar">
            <Setter Property="Background" Value="$($script:thBgAlt)"/>
            <Setter Property="Foreground" Value="$($script:thAccent)"/>
            <Setter Property="BorderBrush" Value="$($script:thBorder)"/>
        </Style>
        <Style TargetType="ListBox">
            <Setter Property="Background" Value="$($script:thBgAlt)"/>
            <Setter Property="Foreground" Value="$($script:thFg)"/>
            <Setter Property="BorderBrush" Value="$($script:thBorder)"/>
        </Style>
        <Style TargetType="{x:Type ScrollBar}" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
            <Setter Property="Background" Value="$($script:thBgAlt)"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="{x:Type ScrollBar}" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
                        <Grid>
                            <Border Background="{TemplateBinding Background}" CornerRadius="4"/>
                            <Track Name="PART_Track" IsDirectionReversed="True">
                                <Track.Thumb>
                                    <Thumb>
                                        <Thumb.Style>
                                            <Style TargetType="Thumb">
                                                <Setter Property="Template">
                                                    <Setter.Value>
                                                        <ControlTemplate TargetType="Thumb">
                                                            <Border Background="$($script:thBorder)" CornerRadius="4"
                                                                    Margin="1" SnapsToDevicePixels="True"/>
                                                        </ControlTemplate>
                                                    </Setter.Value>
                                                </Setter>
                                            </Style>
                                        </Thumb.Style>
                                    </Thumb>
                                </Track.Thumb>
                            </Track>
                        </Grid>
                        <ControlTemplate.Triggers>
                            <Trigger Property="Orientation" Value="Horizontal">
                                <Setter TargetName="PART_Track" Property="IsDirectionReversed" Value="False"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>
"@

# --- DWM title bar theming (Win10 1809+ dark mode, Win11 22H2+ caption color) ---
$script:hasDwmTheming = $false
if (-not ([System.Management.Automation.PSTypeName]'DwmHelper').Type) {
	try {
		Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class DwmHelper {
    [DllImport("dwmapi.dll", PreserveSig = true)]
    public static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);
    [DllImport("shell32.dll", SetLastError = true)]
    public static extern void SetCurrentProcessExplicitAppUserModelID([MarshalAs(UnmanagedType.LPWStr)] string AppID);
}
"@ -ErrorAction Stop
	} catch { }
}
if (([System.Management.Automation.PSTypeName]'DwmHelper').Type) {
	$script:hasDwmTheming = $true
	# Give the process its own taskbar identity so Windows shows our icon instead of PowerShell's
	try { [DwmHelper]::SetCurrentProcessExplicitAppUserModelID('mstrhakr.scans.setup') } catch { }
}

function Set-WindowTheme($window) {
	if (-not $script:hasDwmTheming) { return }
	$window.Add_SourceInitialized({
		try {
			$helper = [System.Windows.Interop.WindowInteropHelper]::new($this)
			$hwnd = $helper.Handle
			# DWMWA_USE_IMMERSIVE_DARK_MODE = 20 (Win10 1809+)
			$darkMode = if ($script:useDarkTheme) { 1 } else { 0 }
			[DwmHelper]::DwmSetWindowAttribute($hwnd, 20, [ref]$darkMode, 4) | Out-Null
			# DWMWA_CAPTION_COLOR = 35 (Win11 22H2+)
			$bgHex = $script:thBg.TrimStart('#')
			$r = [Convert]::ToInt32($bgHex.Substring(0,2), 16)
			$g = [Convert]::ToInt32($bgHex.Substring(2,2), 16)
			$b = [Convert]::ToInt32($bgHex.Substring(4,2), 16)
			$colorRef = $r -bor ($g -shl 8) -bor ($b -shl 16)
			[DwmHelper]::DwmSetWindowAttribute($hwnd, 35, [ref]$colorRef, 4) | Out-Null
		} catch { }
	})
}

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
	$rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
	$bytes = [byte[]]::new($Length)
	$rng.GetBytes($bytes)
	$result = -join ((0..($Length - 1)) | ForEach-Object { $chars[[int]($bytes[$_] % $chars.Length)] })
	$rng.Dispose()
	return $result
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
			# Sanitize inputs for external commands to prevent injection
			$safeUser = $Username -replace '[^a-zA-Z0-9_\-]', ''
			$safePass = $Password -replace '"', ''
			$safeDesc = $Description -replace '"', ''
			$existingUser = net user $safeUser 2>&1
			if ($LASTEXITCODE -ne 0) {
				net user $safeUser $safePass /add /fullname:"scans" /comment:"$safeDesc" /active:yes /expires:never /passwordchg:no | Out-Null
				# Set password to never expire via wmic
				wmic useraccount where "Name='$safeUser'" set PasswordExpires=FALSE 2>&1 | Out-Null
				$results += @{ Status = 'Success'; Message = "Created new user '$Username' (net user)"; Error = $null }
			}
			else {
				net user $safeUser $safePass /comment:"$safeDesc" | Out-Null
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
			$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
			$folderAcl.SetAccessRule($rule)
			if ($DomainJoined) {
				$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Users", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
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
			if (!((Get-SmbShare).Name).toLower().Contains($ShareName.toLower())) {
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
		# Map DomainAuthenticated to Domain for firewall cmdlets
		$firewallProfile = if ($networkCategory -eq 'DomainAuthenticated') { 'Domain' } else { $networkCategory.ToString() }
		$sharingEnabled = Get-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Direction Inbound | Where-Object { $_.Enabled -eq 'True' -and $_.Profile -eq $firewallProfile }
		if ($sharingEnabled.count -eq 0) {
			try {
				Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Direction Inbound -Enabled True -Profile $firewallProfile
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
		$discoveryEnabled = Get-NetFirewallRule -DisplayGroup "Network Discovery" -Direction Inbound | Where-Object { $_.Enabled -eq 'True' -and $_.Profile -eq $firewallProfile }
		if ($discoveryEnabled.count -eq 0) {
			try {
				Set-NetFirewallRule -DisplayGroup "Network Discovery" -Direction Inbound -Enabled True -Profile $firewallProfile
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

# Download icon (skip if already cached to avoid file-lock on re-run)
$iconPath = 'C:\ProgramData\scans.ico'
if (!(Test-Path $iconPath)) {
	try {
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
		Invoke-WebRequest 'https://raw.githubusercontent.com/mstrhakr/scans/main/img/scans.ico' -OutFile $iconPath -ErrorAction Stop | Out-Null
	}
	catch {
		Show-ErrorAndExit -Title 'Download Failed' `
			-Message "Could not download the application icon.`n`n$($_.Exception.Message)" `
			-Remediation $script:Remediation.NoInternet
	}
}
$script:iconUri = [Uri]::new($iconPath)

# --- Embedded settings gear icon (base64 PNG, theme-aware via OpacityMask) ---
$script:settingsIconBase64 = 'iVBORw0KGgoAAAANSUhEUgAAAGAAAABkCAQAAADTAP2lAAAAxHpUWHRSYXcgcHJvZmlsZSB0eXBlIGV4aWYAAHjabVDbEcMgDPtnio4AlkPscUiT3nWDjl+DnV5oqzvkhxJhnI7X85FuHVQ48bJK1VqzgZWVmiWSHW1wyTx4oIZk9dRPlUMga8EivJT4o5z98jHw0CxbLkZyD2GbBY0LSL6MyAP6RD3fw0jDCORCCYPW4ikq6/UJ25FniJ/UiWUe+6debXv7YveA6EBBNgaqD4B+OKFZAmOC2ocZOjpszDjNbCH/9nQivQHrcFkdUfZFZgAAASNpQ0NQSUNDIHByb2ZpbGUAAHicnZC/SsNQFMZ/aUVF7KQ4iEIG1y6CmRz8h8GhUNMIRqc0abGYxJCkFN/AN9GH6SAIPoOzgrPfjQ4OZvHCyffjcM733Rto2UmUlgsHkGZV4XqHwWVwZS+90Wabjr67YVTmvcGpT+P5fMUy+tI1Xs1zf57FeFRG0rkqi/KiAmtf7Myq3LCK9VvfOxY/iO04zWLxk3gnTmPDZtdLk2n042luszrKLgamr9rC5YwefWyGTJmQUNGVZuqc4LAndSkIuackkiaM1JtppuJGVMrJ5Ujki3SbhrzNOq+vlKE8JvIyCXek8jR5mP/7vfZxXm9aG/M8LMK61Va1xmN4f4ROAGvPsHLdkLX8+20NM0498883fgEty1CH2lf0fwAADXZpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+Cjx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IlhNUCBDb3JlIDQuNC4wLUV4aXYyIj4KIDxyZGY6UkRGIHhtbG5zOnJkZj0iaHR0cDovL3d3dy53My5vcmcvMTk5OS8wMi8yMi1yZGYtc3ludGF4LW5zIyI+CiAgPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIKICAgIHhtbG5zOnhtcE1NPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvbW0vIgogICAgeG1sbnM6c3RFdnQ9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZUV2ZW50IyIKICAgIHhtbG5zOmRjPSJodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyIKICAgIHhtbG5zOkdJTVA9Imh0dHA6Ly93d3cuZ2ltcC5vcmcveG1wLyIKICAgIHhtbG5zOnRpZmY9Imh0dHA6Ly9ucy5hZG9iZS5jb20vdGlmZi8xLjAvIgogICAgeG1sbnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIgogICB4bXBNTTpEb2N1bWVudElEPSJnaW1wOmRvY2lkOmdpbXA6NmZhZmE1Y2EtN2VhNy00YTA1LTgzODAtZTM4M2UyMTZhOGZjIgogICB4bXBNTTpJbnN0YW5jZUlEPSJ4bXAuaWlkOmU0NDU3ODRmLTkyNTktNDc3Ny05YWI5LTg3OWU2ZWNjMGMzOSIKICAgeG1wTU06T3JpZ2luYWxEb2N1bWVudElEPSJ4bXAuZGlkOmFiYjc3ZGRiLTYyYmQtNGQ5Yi1iYzViLTk4YTBmM2VlZWY5NCIKICAgZGM6Rm9ybWF0PSJpbWFnZS9wbmciCiAgIEdJTVA6QVBJPSIyLjAiCiAgIEdJTVA6UGxhdGZvcm09IldpbmRvd3MiCiAgIEdJTVA6VGltZVN0YW1wPSIxNzExNzE3NDgwNTk0NDgyIgogICBHSU1QOlZlcnNpb249IjIuMTAuMzYiCiAgIHRpZmY6T3JpZW50YXRpb249IjEiCiAgIHhtcDpDcmVhdG9yVG9vbD0iR0lNUCAyLjEwIgogICB4bXA6TWV0YWRhdGFEYXRlPSIyMDI0OjAzOjI5VDA5OjA0OjQwLTA0OjAwIgogICB4bXA6TW9kaWZ5RGF0ZT0iMjAyNDowMzoyOVQwOTowNDo0MC0wNDowMCI+CiAgIDx4bXBNTTpIaXN0b3J5PgogICAgPHJkZjpTZXE+CiAgICAgPHJkZjpsaQogICAgICBzdEV2dDphY3Rpb249InNhdmVkIgogICAgICBzdEV2dDpjaGFuZ2VkPSIvIgogICAgICBzdEV2dDppbnN0YW5jZUlEPSJ4bXAuaWlkOjc5NjdmN2QxLTUyMTgtNDM5Ni05NTUwLTVkN2M1YzJmMmExNiIKICAgICAgc3RFdnQ6c29mdHdhcmVBZ2VudD0iR2ltcCAyLjEwIChXaW5kb3dzKSIKICAgICAgc3RFdnQ6d2hlbj0iMjAyNC0wMy0yOVQwOTowNDo0MCIvPgogICAgPC9yZGY6U2VxPgogICA8L3htcE1NOkhpc3Rvcnk+CiAgPC9yZGY6RGVzY3JpcHRpb24+CiA8L3JkZjpSREY+CjwveDp4bXBtZXRhPgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgCjw/eHBhY2tldCBlbmQ9InciPz6lj/qJAAAAAmJLR0QA/4ePzL8AAAAJcEhZcwAACxMAAAsTAQCanBgAAAAHdElNRQfoAx0NBCiKEThwAAAG8UlEQVR42t2cW2xURRjHf3NWqFRku1yUFQI7FDAUtSUUUzRoQghaUBNijbQ18fIgJj4IvEhifDDRxBdvqAnqA77QaqzRoIJBokGUNlqQgiVcusxK0IKI3XJptbp7fEBkl57dnplzSs/xe9yd75v5z3wz893mCHwjaXEdFcxhJtOYzESilDIKwQD99PIb3Ryji4N08qvK+tWr8EdMwhKreZLpRFw0zvATb9qvpnwBEfEHQOwJ1hPDctXYIsZd4mS6PTArIGEP8zSZ9jBf+dC35csClDJbm2c2pQQGQDnXaPOMZUZwANxsxHVLcABUGXFVBgSANAVQJYMBwLZMVci2AgFAxJlkxDhJxIOxByoMr8MIFcEAUDkCnP4BSJhuYYCqxMgDEJ4AeLdkrnKeVSGppZ/P6R7SXol6uFFnEKV3yEM6zt2MYautUu4ARBH30Uwp8CdfyiY+obcIjGWMMQYwhlreKzL0KPfSwGJKgD5RH9vc48YalTV8wdicH87wGZvs7fw5eAbktbQbGHKX6BAL1FmHfVUiltDIcsbl/HyeJaptSAByGq3c4NDVST6kiTaVyWk7jmaWeVTiLdSrMzkyI9TQwP1c79D2FxaqY0UByKv5iprCly5J3ucDDpBlPPfwDOU+HMNJXuATerCo4AEepLyIl9LKYvVHQQASXuWpoW0HzvEHMecDwJD+pocSrnXhYL3GauUMQJBYzmaf7NPhoyz3pT6znQDICXQwheDTcarU6UFOvYTXuZMw0DgmlG1OD7qJF/EoYaFHxKLLVEhGaGUB4aF2ai4c6BdXoD5Uw4dqGnJWQI6mk5mEi7qYqwYurkBj6IYPM2n8dwVkhA7mEj7qtCtTGQtYGsrhw1yxFCwJqwgrPSERcgqKUSEF8BfSYmVohw+jWGlRR5ipTsized6XfzbjIdpJ0gPEKKea2X4lU/Lo3FXsZ6HPQn/hLZpIKjvH0hXMoJFVjr6eF9ovZA1bKfNNYD8v8rI6V8BNH8ta1nkIAlxOaWrFFEbfwkf+JBs4zIPsVcWDJFW87ykMcImOsmJg3wVbaDIt3O6DhbhMnRq6mZzEFqo99/YtderEv7aQOsFSNnkUeMjd8EGdYhmHPfa2iaXqRI5Hlv6r7GNhc4dx1rKPu5XrpGO6L/Y1DxvfP1mes9ekBi5zKdN2bAdHqDUU+xwtaY3mZSeFxWLDqXqEN1J2obDKQj5EP+1wnBtVnx6LvIaDTNXuqZv7ac1d6rwgiiLVym10aIvdYPfpstjn2aDdTwe3p1rzNdUpNhqlmVoNsRnK1U/6uiCnk9S6nbfQoAbFsh3CWKqXOr7XEHyAY0bafIwDGq2/o045hOId43CqjzXYrkXv1mibp0Xs1mi7VvU7/VEokLiLLtfCk2ZFGwqSrhsfYZfzHwUAKJv9roX/bnwduefcr2wtAGCoFlecCgBICI3s+3jj3t1z3pwQWgDEQma5Fl5uVvOQQCM9MkvcpgFAjuEVDatovpkFJYSGTSp4RZa6BCCjtHCrxkgqmGa0BNOZo9F6AS0yOiQAgUywQzNxF+GhhIkCNWp6ybXskFIMWpr/jzEnoZ7tmJTATGVNQlN7WGMwfIiznXqZt/wXl9QSz7Ke0YYHYo34NH1S4/ys5F1Dz2MUKxBlO9N2ngrJUt6+EK724FIucudSgpzENx4d+008fkFpR8Kpv44tzPfLqQ99WCUyscZw4zrRBB4mEtudHigY2FrHRib71FuM+sgOIXddodBiOQ3DEFpsHa7gbobD/wV3x1NONbOGJ7grZGuR6pTgU5tFC2GmFiGncjTEKaYZFsfZGtr538pxS2EQYAoKbVBYwDY6Qzn8TraBBSrDS6EE8JLK/A+KPSIA6UwszYqQAVitfsh1aJpoD9Xw22nK88hUhrVkQzP8LGsvFuBecil3sjE0ADay08GpD03Z5c9UXiq7zHHqU6dZFQI1yrIqddrBqQeIHWG8C9vU5ixnKPG1xvdvTpNhtIsY3+us73EOq4CCdbQVHXoXLzCPicSJ85hGDqEYJXmMOHEmMo/n6SoaF2/j6SFyZCEvv4dCDyDYbjs/gPieGz2FAaqdHkCIEpbQwD0GDyCgjFjOExSGeIIiV9LsAUCDai4Swch7gkJ97+bBKR3HTaPzCEhG6TYuoOknrjw+AvL8DkrCj8Zlm53c5PVVt+ej0Ia9xsx7vSfiPANIeQKQGnkAYFBb4Z3TVwAHyBjxZbRKDYYPgN3NKSPGU3Z3IACIrEZWP5f2iWwgACjTbbw3OB/G6BipLewXgH1XkGtYACQ5r81zjqPBAdBnUAd6mL7AAFDwjjbTO8qXufPr+0J7OMMsxrmakAwpnufNtC8VST594Qku+0RVnAlX5hNV/wDkVh2zQRBX5QAAAABJRU5ErkJggg=='
$script:settingsIconBitmap = $null
try {
	$stream = [System.IO.MemoryStream]::new([Convert]::FromBase64String($script:settingsIconBase64))
	$bmp = [System.Windows.Media.Imaging.BitmapImage]::new()
	$bmp.BeginInit()
	$bmp.StreamSource = $stream
	$bmp.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
	$bmp.EndInit()
	$bmp.Freeze()
	$script:settingsIconBitmap = $bmp
} catch { }

# --- WPF Settings Dialog ---
function New-SettingsPage {
	[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Settings" Height="310" Width="340" WindowStartupLocation="CenterScreen" ResizeMode="NoResize"
        Background="$($script:thBg)" Foreground="$($script:thFg)" FontFamily="Segoe UI" FontSize="13">
$($script:themeResources)
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
	Set-WindowTheme $window

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
        Title="Scans Setup" Height="250" Width="440" WindowStartupLocation="CenterScreen" ResizeMode="NoResize" ShowInTaskbar="True"
        Background="$($script:thBg)" Foreground="$($script:thFg)" FontFamily="Segoe UI" FontSize="13">
$($script:themeResources)
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
            <Button Name="btnSettings" Width="30" Height="28" Margin="0,0,8,0" ToolTip="Settings">
                <Rectangle Name="rectSettingsIcon" Width="16" Height="16" Fill="$($script:thBtnText)"/>
            </Button>
            <Button Name="btnOK" Content="OK" Width="75" Height="24" Margin="0,0,8,0" IsDefault="True"/>
            <Button Name="btnCancel" Content="Cancel" Width="75" Height="24" IsCancel="True"/>
        </StackPanel>
    </Grid>
</Window>
"@
$reader = [System.Xml.XmlNodeReader]::new($setupXaml)
$setupWindow = [Windows.Markup.XamlReader]::Load($reader)
$setupWindow.Icon = [System.Windows.Media.Imaging.BitmapImage]::new($script:iconUri)
Set-WindowTheme $setupWindow

# Apply gear icon as OpacityMask so it picks up the theme fill color
if ($script:settingsIconBitmap) {
	$brush = [System.Windows.Media.ImageBrush]::new($script:settingsIconBitmap)
	$setupWindow.FindName('rectSettingsIcon').OpacityMask = $brush
}

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
	Write-Verbose "Username: $script:scanUser `nLocal Dir: $script:folderPath`nSMB Share: $script:shareName"
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
        Title="Scans Setup - Loading..." Height="300" Width="440" WindowStartupLocation="CenterScreen" ResizeMode="NoResize" ShowInTaskbar="True"
        Background="$($script:thBg)" Foreground="$($script:thFg)" FontFamily="Segoe UI" FontSize="13">
$($script:themeResources)
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
Set-WindowTheme $script:progressWindow
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
	Write-Verbose "Copied scan password to clipboard"
	[System.Windows.MessageBox]::Show('Password has been copied to Clipboard')
})

$script:progressWindow.FindName('btnDone').Add_Click({
	$script:progressWindow.Close()
})

$script:progressWindow.Show()
$script:percent = 0
$script:hasErrors = $false

function Get-ErrorRemediation([string]$errorText) {
	switch -Regex ($errorText) {
		'trust relationship'        { return $script:Remediation.TrustRelation }
		'Access is denied|access denied|UnauthorizedAccess' { return $script:Remediation.AccessDenied }
		'share.*in use|being used'  { return $script:Remediation.ShareInUse }
		default { return $null }
	}
}

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

function Show-StepResult($result) {
	Set-ProgressBar $result.Message
	if ($result.Error) {
		$script:hasErrors = $true
		Set-ProgressBar "  Error: $($result.Error)" 0
		$tip = Get-ErrorRemediation $result.Error
		if ($tip) { Set-ProgressBar "  Tip: $tip" 0 }
	}
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
	foreach ($r in $userResults) { Show-StepResult $r }
}
elseif ($hideUser -eq $true) {
	$userResults = Initialize-ScanUser -Username $scanUser -Password $scanPass -Description $description -HideFromLogin $true -DomainJoined $domainJoined
	foreach ($r in $userResults) { Show-StepResult $r }
}

if ($createFolder -eq $true) {
	$folderResults = Initialize-ScanFolder -FolderPath $folderPath -ScanUser $scanUser -SetPermissions $setPermissions -DomainJoined $domainJoined
	foreach ($r in $folderResults) { Show-StepResult $r }
}

if ($setShare -eq $true) {
	$shareResult = Initialize-ScanShare -ShareName $shareName -FolderPath $folderPath -ScanUser $scanUser
	Show-StepResult $shareResult
}

if ($createShortcut -eq $true) {
	$shortcutResult = Initialize-DesktopShortcut -FolderPath $folderPath -IconPath $iconPath -Description $description
	Show-StepResult $shortcutResult
}

if ($checkNetworkSettings -eq $true) {
	$netResults = Set-NetworkConfiguration -DomainJoined $domainJoined
	foreach ($r in $netResults) { Show-StepResult $r }
}

Set-ProgressBar "Finished" 0
if ($script:hasErrors) {
	$script:progressWindow.Title = 'Scans Setup - Completed with errors'
	$script:progressWindow.FindName('txtStatus').Text = 'Completed with errors (see details above)'
}
else {
	$script:progressWindow.Title = 'Scans Setup - Finished'
}
$script:progressWindow.FindName('btnDone').IsEnabled = $true
if ($createUser) { $script:progressWindow.FindName('btnCopyPassword').IsEnabled = $true }
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([action]{}, [System.Windows.Threading.DispatcherPriority]::Background)

# Block until user closes the progress window
$frame = [System.Windows.Threading.DispatcherFrame]::new()
$script:progressWindow.Add_Closed({ $frame.Continue = $false })
[System.Windows.Threading.Dispatcher]::PushFrame($frame)
Exit 0
