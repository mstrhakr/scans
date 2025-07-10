# **Scanning Setup Utility**
## The Basics

Either run the exe found in releases or paste the following into an admin powershell window.

``` powershell
irm https://raw.githubusercontent.com/mstrhakr/scans/main/scans.ps1 | iex
```

The exe is compiled with PS2EXE from the source available ![here](https://github.com/MScholtes/PS2EXE).

This script completely setups the user environment to allow a quick scan to SMB setup

This includes:
- Creating or updating the scans user account
- Creating the scans folder at **C:\scans** (by default)
- Setting local permissions for the scans folder
- Sharing the scans folder via SMB as ***scans*** (by default)
- Setting SMB permissions for the SMB share
- Creating a desktop shortcut to the scans folder
- Setting the Network Category to Private
- Enable File and Folder Sharing
- Enable Network Discovery

All you have to do is run scans.exe and follow the prompts, it's as easy as that.

First choose the inputs, the password is randomly generated at 10 characters long.

![Setup](img/scans-setup.png)

Then if you want choose to disable any of the options on the settings page.

![Settings](img/scans-settings.png)

Then wait for the utility to complete all the required changes to your system.

![Loading](img/scans-loading.png)

When the utility is finished, click 'Done' to close the window.

![Finished](img/scans-finished.png)

> Note: You must disable Real-Time Scanning in your AV software to run this utility via the scans.exe available in the releases section
