# **Scanning Setup Utility**
## The Basics

The exe is compiled with PS2EXE from the source available here.

This script completely setups the user environment to allow a quick scan to SMB setup

This includes:
- Creating or updating the scans user account
- Creating the scans folder at **C:\scans** (by default)
- Setting local permissions for the scans folder
- Sharing the scans folder via SMB as ***scans*** (by default)
- Setting SMB permissions for the SMB share
- Creating a desktop shortcut to the scans folder
- Setting the Network Category to Private

All you have to do is run scans.exe and follow the prompts, it's as easy as that.

First change any settings you want, the password is randomly generated 10 characters.

![Setup](https://github.com/mstrhakr/scans/blob/8278e8857e73fb1e950445fa734a13b6c6588c3d/img/scans-setup.png)

Then wait for the utility to complete all the required changes to your system.

![Loading](https://github.com/mstrhakr/scans/blob/8278e8857e73fb1e950445fa734a13b6c6588c3d/img/scans-loading.png)

When the utility is finished, click 'Done' to close the window.

![Finished](https://github.com/mstrhakr/scans/blob/8278e8857e73fb1e950445fa734a13b6c6588c3d/img/scans-finished.png)

> Note: You must disable Real-Time Scanning in your AV software to run this utility
