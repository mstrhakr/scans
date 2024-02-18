#Import tests module
Import-Module Pester

Describe "SetScanFolderPermissions Tests" {
    BeforeAll {
        # Import the module to be tested
        . $PSScriptRoot\scans.ps1

        # Set up test folder
        $testFolderPath = "C:\TestFolder"
        New-Item -ItemType Directory -Path $testFolderPath | Out-Null
    }

    AfterAll {
        # Clean up test folder
        $testFolderPath = "C:\TestFolder"
        Remove-Item -Path $testFolderPath -Recurse -Force | Out-Null
    }

    Context "When folder path, scan user" {
        It "Should set folder permissions for the scan user" {
            $username = 'TestScanUser'

            Set-ScanFolderPermissions -folderPath $testFolderPath -username $username

            # Assert folder permissions are set correctly
            $acl = Get-Acl -Path $testFolderPath
            $currentUserPermission = $acl.Access | Where-Object { $_.IdentityReference.Value -eq $username }
            $currentUserPermission.AccessControlType | Should Be "Allow"
            $currentUserPermission.FileSystemRights | Should Be "FullControl"
        }

        It "Should set folder permissions for Everyone (Special Account)" {
            $username = "ScanUser"

            Set-ScanFolderPermissions -folderPath $testFolderPath -username $username

            # Assert folder permissions are set correctly
            $acl = Get-Acl -Path $testFolderPath
            $everyonePermission = $acl.Access | Where-Object { $_.IdentityReference.Value -eq $username }
            $everyonePermission.AccessControlType | Should Be "Allow"
            $everyonePermission.FileSystemRights | Should Be "FullControl"
        }

        It "Should set folder permissions for Domain Users when domain joined" {
            $username = "TestDomain\TestCurrentUser"

            Set-ScanFolderPermissions -folderPath $testFolderPath -username $username

            # Assert folder permissions are set correctly
            $acl = Get-Acl -Path $testFolderPath
            $domainUsersPermission = $acl.Access | Where-Object { $_.IdentityReference.Value -eq $username }
            $domainUsersPermission.AccessControlType | Should Be "Allow"
            $domainUsersPermission.FileSystemRights | Should Be "FullControl"
        }
    }

    Context "When folder path, scan user, or domain joined are invalid" {
        It "Should not make any changes to folder permissions" {
            $folderPath = "InvalidPath"
            $username = "ScanUser"

            Set-ScanFolderPermissions -folderPath $folderPath -username $username

            # Assert no changes made to folder permissions
            $acl = Get-Acl -Path $folderPath
            $acl.Access | Should BeNullOrEmpty
        }
    }
}

Describe "Show-ScanningSetupForm Tests" {
    Context "When form is shown and user clicks OK" {
        It "Should update global variables with user input" {
            # Arrange
            $scanUser = "TestUser"
            $scanPass = "TestPassword"
            $folderPath = "C:\TestFolder"
            $shareName = "TestShare"
            $expectedScanUser = "NewUser"
            $expectedScanPass = "NewPassword"
            $expectedFolderPath = "C:\NewFolder"
            $expectedShareName = "NewShare"
            $scanningSetupFormMock = @{
                ShowDialog = { [System.Windows.Forms.DialogResult]::OK }
                Controls = @{
                    scanUserTextBox = @{
                        Text = $expectedScanUser
                    }
                    scanPassTextBox = @{
                        Text = $expectedScanPass
                    }
                    folderPathTextBox = @{
                        Text = $expectedFolderPath
                    }
                    smbShareTextBox = @{
                        Text = $expectedShareName
                    }
                }
            }

            # Act
            $script:scanUser = $scanUser
            $script:scanPass = $scanPass
            $script:folderPath = $folderPath
            $script:shareName = $shareName
            $result = Show-ScanningSetupForm -scanningSetupForm $scanningSetupFormMock

            # Assert
            $result | Should Be $null
            $script:scanUser | Should Be $expectedScanUser
            $script:scanPass | Should Be $expectedScanPass
            $script:folderPath | Should Be $expectedFolderPath
            $script:shareName | Should Be $expectedShareName
        }
    }

    Context "When form is shown and user clicks Cancel" {
        It "Should display an error message and exit the script" {
            # Arrange
            $scanUser = "TestUser"
            $scanPass = "TestPassword"
            $folderPath = "C:\TestFolder"
            $shareName = "TestShare"
            $scanningSetupFormMock = @{
                ShowDialog = { [System.Windows.Forms.DialogResult]::Cancel }
                Close = {}
            }

            # Act
            $script:scanUser = $scanUser
            $script:scanPass = $scanPass
            $script:folderPath = $folderPath
            $script:shareName = $shareName
            $result = Show-ScanningSetupForm -scanningSetupForm $scanningSetupFormMock

            # Assert
            $result | Should Be $null
            $script:scanUser | Should Be $scanUser
            $script:scanPass | Should Be $scanPass
            $script:folderPath | Should Be $folderPath
            $script:shareName | Should Be $shareName
            $Error[0].Exception.Message | Should Be "You canceled scanning setup"
        }
    }
}

Describe "New-LoadingForm Tests" {
    Context "When done is $true and details is not null" {
        It "Should create a loading form with finished status and details" {
            # Arrange
            $done = $true
            $details = @("Detail 1", "Detail 2", "Detail 3")

            # Act
            $result = New-LoadingForm -done $done -details $details

            # Assert
            $result.Form.Icon | Should Be "C:\ProgramData\scans.ico"
            $result.Form.Size | Should Be ([System.Drawing.Size]::new(300, 200))
            $result.Form.StartPosition | Should Be "CenterScreen"
            $result.Controls.Text.Location | Should Be ([System.Drawing.Point]::new(10, 10))
            $result.Controls.Text.Size | Should Be ([System.Drawing.Size]::new(280, 20))
            $result.Controls.Bar.Location | Should Be ([System.Drawing.Point]::new(10, 30))
            $result.Controls.Bar.Size | Should Be ([System.Drawing.Size]::new(265, 20))
            $result.Controls.Bar.Minimum | Should Be 0
            $result.Controls.Bar.Maximum | Should Be 15
            $result.Controls.Box.ScrollAlwaysVisible | Should Be $true
            $result.Controls.Box.Location | Should Be ([System.Drawing.Point]::new(10, 60))
            $result.Controls.Box.Size | Should Be ([System.Drawing.Size]::new(265, 60))
            $result.Controls.Button.Location | Should Be ([System.Drawing.Point]::new(95, 125))
            $result.Controls.Button.Size | Should Be ([System.Drawing.Size]::new(100, 23))
            $result.Controls.Button.Text | Should Be "Done"
            $result.Controls.Button.DialogResult | Should Be ([System.Windows.Forms.DialogResult]::OK)
            $result.Form.AcceptButton | Should Be $result.Controls.Button
            $result.Form.Text | Should Be "Scans.exe - Finished!"
            $result.Controls.Text.Text | Should Be "Finished!"
            $result.Controls.Bar.Value | Should Be $result.Controls.Bar.Maximum
            $result.Controls.Box.Items | Should Be $details
            $result.Controls.Button.Enabled | Should Be $true
        }
    }

    Context "When done is $false or details is null" {
        It "Should create a loading form with loading status and disabled button" {
            # Arrange
            $done = $false
            $details = $null

            # Act
            $result = New-LoadingForm -done $done -details $details

            # Assert
            $result.Form.Icon | Should Be "C:\ProgramData\scans.ico"
            $result.Form.Size | Should Be ([System.Drawing.Size]::new(300, 200))
            $result.Form.StartPosition | Should Be "CenterScreen"
            $result.Controls.Text.Location | Should Be ([System.Drawing.Point]::new(10, 10))
            $result.Controls.Text.Size | Should Be ([System.Drawing.Size]::new(280, 20))
            $result.Controls.Bar.Location | Should Be ([System.Drawing.Point]::new(10, 30))
            $result.Controls.Bar.Size | Should Be ([System.Drawing.Size]::new(265, 20))
            $result.Controls.Bar.Minimum | Should Be 0
            $result.Controls.Bar.Maximum | Should Be 15
            $result.Controls.Box.ScrollAlwaysVisible | Should Be $true
            $result.Controls.Box.Location | Should Be ([System.Drawing.Point]::new(10, 60))
            $result.Controls.Box.Size | Should Be ([System.Drawing.Size]::new(265, 60))
            $result.Controls.Button.Location | Should Be ([System.Drawing.Point]::new(95, 125))
            $result.Controls.Button.Size | Should Be ([System.Drawing.Size]::new(100, 23))
            $result.Controls.Button.Text | Should Be "Done"
            $result.Controls.Button.DialogResult | Should Be ([System.Windows.Forms.DialogResult]::OK)
            $result.Form.AcceptButton | Should Be $result.Controls.Button
            $result.Form.Text | Should Be "Scans.exe - Loading..."
            $result.Controls.Text.Text | Should Be "Loading..."
            $result.Controls.Bar.Value | Should Be 0
            $result.Controls.Button.Enabled | Should Be $false
        }
    }
}

Describe "Update-ProgressBar Tests" {
    It "Should update the form controls with the provided text" {
        # Arrange
        $text = "Updating progress..."
        $sleep = 500
        $formMock = @{
            Controls = @{
                Text = @{
                    Text = ""
                }
                Bar = @{
                    Value = 0
                }
                Box = @{
                    Items = @()
                }
            }
        }

        # Act
        Update-ProgressBar -Form $formMock -text $text -sleep $sleep

        # Assert
        $formMock.Controls.Text.Text | Should Be $text
        $formMock.Controls.Bar.Value | Should Be 1
        $formMock.Box.Items[0] | Should Be $text
    }
}

Describe "Set-ScanUser Tests" {
    Context "When the user does not exist" {
        It "Should create a new user with the provided username and password" {
            # Arrange
            $scanUser = "TestUser"
            $scanPass = "TestPassword"
            $description = "Test Description"
            $loadingScreenMock = @{
                Controls = @{
                    Text = @{
                        Text = ""
                    }
                }
            }

            # Act
            Set-ScanUser -scanUser $scanUser -scanPass $scanPass -description $description -loadingScreen $loadingScreenMock

            # Assert
            $loadingScreenMock.Controls.Text.Text | Should Be "Creating New User: $scanUser"
            $createdUser = Get-LocalUser -Name $scanUser
            $createdUser | Should Not Be $null
            $createdUser.Description | Should Be "$description`nPassword: $scanPass"
        }
    }

    Context "When the user already exists" {
        It "Should update the existing user with the provided username and password" {
            # Arrange
            $scanUser = "TestUser"
            $scanPass = "TestPassword"
            $description = "Test Description"
            $loadingScreenMock = @{
                Controls = @{
                    Text = @{
                        Text = ""
                    }
                }
            }

            # Act
            Set-ScanUser -scanUser $scanUser -scanPass $scanPass -description $description -loadingScreen $loadingScreenMock

            # Assert
            $loadingScreenMock.Controls.Text.Text | Should Be "Updating Existing User: $scanUser"
            $updatedUser = Get-LocalUser -Name $scanUser
            $updatedUser | Should Not Be $null
            $updatedUser.Description | Should Be "$description`nPassword: $scanPass"
        }
    }
}

Describe "Hide-ScanUserFromLoginScreen Tests" {
    Context "When the user account is not hidden" {
        It "Should hide the scans user from the login screen" {
            # Arrange
            $scanUser = "TestUser"
            $domainJoined = $false
            $loadingScreenMock = @{
                Controls = @{
                    Text = @{
                        Text = ""
                    }
                }
            }

            # Act
            Hide-ScanUserFromLoginScreen -scanUser $scanUser -domainJoined $domainJoined -loadingScreen $loadingScreenMock

            # Assert
            $loadingScreenMock.Controls.Text.Text | Should Be "Hiding scans user from login screen"
            $hiddenValue = (Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist' -Name $scanUser).($scanUser)
            $hiddenValue | Should Be 0
        }
    }

    Context "When the user account is already hidden" {
        It "Should display a message that the user account is already hidden" {
            # Arrange
            $scanUser = "TestUser"
            $domainJoined = $false
            $loadingScreenMock = @{
                Controls = @{
                    Text = @{
                        Text = ""
                    }
                }
            }

            # Act
            Hide-ScanUserFromLoginScreen -scanUser $scanUser -domainJoined $domainJoined -loadingScreen $loadingScreenMock

            # Assert
            $loadingScreenMock.Controls.Text.Text | Should Be "User account is already hidden from login screen"
        }
    }
}

Describe "New-ScanFolder Tests" {
    Context "When the folder does not exist" {
        It "Should create a new folder at the provided path" {
            # Arrange
            $folderPath = "C:\TestFolder"
            $loadingScreenMock = @{
                Controls = @{
                    Text = @{
                        Text = ""
                    }
                }
            }

            # Act
            New-ScanFolder -folderPath $folderPath -loadingScreen $loadingScreenMock

            # Assert
            $loadingScreenMock.Controls.Text.Text | Should Be "Creating scans folder"
            $folderExists = Test-Path -Path $folderPath
            $folderExists | Should Be $true
        }
    }

    Context "When the folder already exists" {
        It "Should display a message that the folder already exists" {
            # Arrange
            $folderPath = "C:\TestFolder"
            $loadingScreenMock = @{
                Controls = @{
                    Text = @{
                        Text = ""
                    }
                }
            }

            # Act
            New-ScanFolder -folderPath $folderPath -loadingScreen $loadingScreenMock

            # Assert
            $loadingScreenMock.Controls.Text.Text | Should Be "Scans folder already exists"
        }
    }
}

Describe "Set-ScanFolderPermissions Tests" {
    Context "When the folder permissions for the user already exist" {
        It "Should display a message that the permission already exists" {
            # Arrange
            $folderPath = "C:\TestFolder"
            $username = "TestUser"
            $loadingScreenMock = @{
                Controls = @{
                    Text = @{
                        Text = ""
                    }
                }
            }
            $folderAclMock = @{
                Access = @(
                    @{
                        IdentityReference = @{
                            Value = $username
                        }
                        AccessControlType = "Allow"
                    }
                )
            }

            # Act
            Set-ScanFolderPermissions -folderPath $folderPath -username $username -loadingScreen $loadingScreenMock -folderAcl $folderAclMock

            # Assert
            $loadingScreenMock.Controls.Text.Text | Should Be "Permission for $username already exists"
        }
    }

    Context "When the folder permissions for the user do not exist" {
        It "Should add a new permission for the user" {
            # Arrange
            $folderPath = "C:\TestFolder"
            $username = "TestUser"
            $loadingScreenMock = @{
                Controls = @{
                    Text = @{
                        Text = ""
                    }
                }
            }
            $folderAclMock = @{
                Access = @()
                AddAccessRule = {}
            }

            # Act
            $result = Set-ScanFolderPermissions -folderPath $folderPath -username $username -loadingScreen $loadingScreenMock -folderAcl $folderAclMock

            # Assert
            $result | Should Be $true
            $loadingScreenMock.Controls.Text.Text | Should Be "Setting Permissions for $username"
            $folderAclMock.Access | Should Contain @{ IdentityReference = @{ Value = $username }; AccessControlType = "Allow" }
        }
    }
}

Describe "Set-SmbShare Tests" {
    Context "When the SMB share does not exist" {
        It "Should create a new SMB share with the provided name and folder path" {
            # Arrange
            $shareName = "TestShare"
            $folderPath = "C:\TestFolder"
            $scanUser = "TestUser"
            $loadingScreenMock = @{
                Controls = @{
                    Text = @{
                        Text = ""
                    }
                }
            }

            # Act
            Set-SmbShare -shareName $shareName -folderPath $folderPath -scanUser $scanUser -loadingScreen $loadingScreenMock

            # Assert
            $loadingScreenMock.Controls.Text.Text | Should Be "Creating SMB share"
            $smbShare = Get-SmbShare | Where-Object { $_.Name -eq $shareName }
            $smbShare | Should Not Be $null
            $smbShare.Path | Should Be $folderPath
            $smbShare.PermittedUsers | Should Contain $scanUser
            $smbShare.PermittedUsersAccess | Should Be "Full"
        }
    }

    Context "When the SMB share already exists" {
        It "Should update the SMB share permissions with the provided scan user" {
            # Arrange
            $shareName = "TestShare"
            $folderPath = "C:\TestFolder"
            $scanUser = "TestUser"
            $loadingScreenMock = @{
                Controls = @{
                    Text = @{
                        Text = ""
                    }
                }
            }

            # Act
            Set-SmbShare -shareName $shareName -folderPath $folderPath -scanUser $scanUser -loadingScreen $loadingScreenMock

            # Assert
            $loadingScreenMock.Controls.Text.Text | Should Be "Updating SMB share permissions"
            $smbShare = Get-SmbShare | Where-Object { $_.Name -eq $shareName }
            $smbShare | Should Not Be $null
            $smbShare.Path | Should Be $folderPath
            $smbShare.PermittedUsers | Should Contain $scanUser
            $smbShare.PermittedUsersAccess | Should Be "Full"
        }
    }
}

Describe "Set-NetworkSettings Tests" {
    Context "When the computer is not domain joined and network category is not Private" {
        It "Should set the network category to Private" {
            # Arrange
            $domainJoined = $false
            $enableFileAndPrinterSharing = $true
            $enablePasswordProtectedSharing = $true
            $loadingScreenMock = @{
                Controls = @{
                    Text = @{
                        Text = ""
                    }
                }
            }
            $netConnectionProfileMock = @{
                NetworkCategory = "Public"
            }

            # Act
            Set-NetworkSettings -domainJoined $domainJoined -enableFileAndPrinterSharing $enableFileAndPrinterSharing -enablePasswordProtectedSharing $enablePasswordProtectedSharing -loadingScreen $loadingScreenMock -netConnectionProfile $netConnectionProfileMock

            # Assert
            $loadingScreenMock.Controls.Text.Text | Should Be "Set Network Category to Private"
            $netConnectionProfileMock | Should HaveProperty NetworkCategory -Value "Private"
        }
    }

    Context "When the computer is domain joined and network category is not DomainAuthenticated" {
        It "Should not change the network category" {
            # Arrange
            $domainJoined = $true
            $enableFileAndPrinterSharing = $true
            $enablePasswordProtectedSharing = $true
            $loadingScreenMock = @{
                Controls = @{
                    Text = @{
                        Text = ""
                    }
                }
            }
            $netConnectionProfileMock = @{
                NetworkCategory = "Private"
            }

            # Act
            Set-NetworkSettings -domainJoined $domainJoined -enableFileAndPrinterSharing $enableFileAndPrinterSharing -enablePasswordProtectedSharing $enablePasswordProtectedSharing -loadingScreen $loadingScreenMock -netConnectionProfile $netConnectionProfileMock

            # Assert
            $loadingScreenMock.Controls.Text.Text | Should BeNullOrEmpty
            $netConnectionProfileMock | Should HaveProperty NetworkCategory -Value "Private"
        }
    }
}

Describe "Set-ScanUser Tests" {
    Context "When the user does not exist" {
        It "Should create a new user with the provided username and password" {
            # Arrange
            $scanUser = "TestUser"
            $scanPass = "TestPassword"
            $description = "Test Description"

            # Act
            Set-ScanUser -scanUser $scanUser -scanPass $scanPass -description $description

            # Assert
            $user = Get-LocalUser -Name $scanUser
            $user | Should Not Be $null
            $user.Name | Should Be $scanUser
            $user.Description | Should Be "$description`nPassword: $scanPass"
            $user.AccountNeverExpires | Should Be $true
            $user.PasswordNeverExpires | Should Be $true
            $user.UserMayNotChangePassword | Should Be $true
            $user.FullName | Should Be "scans"
        }
    }

    Context "When the user already exists" {
        It "Should update the existing user with the provided password and description" {
            # Arrange
            $scanUser = "TestUser"
            $scanPass = "TestPassword"
            $description = "Test Description"

            # Create the user
            New-LocalUser -Name $scanUser -Password (ConvertTo-SecureString -String "OldPassword" -AsPlainText -Force) -Description "Old Description" -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword -FullName "scans" | Out-Null

            # Act
            Set-ScanUser -scanUser $scanUser -scanPass $scanPass -description $description

            # Assert
            $user = Get-LocalUser -Name $scanUser
            $user | Should Not Be $null
            $user.Name | Should Be $scanUser
            $user.Description | Should Be "$description`nPassword: $scanPass"
            $user.AccountNeverExpires | Should Be $true
            $user.PasswordNeverExpires | Should Be $true
            $user.UserMayChangePassword | Should Be $false
            $user.FullName | Should Be "scans"
        }
    }
}