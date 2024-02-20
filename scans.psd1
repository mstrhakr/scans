#
# Module manifest for module 'scans'
#
# Generated by: nszit
#
# Generated on: 2/17/2024
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'scans.psm1'

# Version number of this module.
ModuleVersion = '1.3.0.53'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = 'e1764cc2-f679-40c8-a7fb-43149e8537a1'

# Author of this module
Author = 'Nick Szittai'

# Company or vendor of this module
CompanyName = 'mstrhakr'

# Copyright statement for this module
Copyright = '(c) 2024 Nick Szittai. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Powershell module for setting up a scanning folder and share.'

# Minimum version of the Windows PowerShell engine required by this module
# PowerShellVersion = ''

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# CLRVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
# RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
RequiredAssemblies = @('System.Windows.Forms', 'System.Drawing', 'System.Web')

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = 'Get-Icon', 'Show-ScanningSetupForm', 'New-LoadingForm', 'Set-ScanUser', 'Hide-ScanUserFromLoginScreen', 'New-ScanFolder', 'Set-ScanFolderPermissions', 'Set-ScansSmbShare', 'New-DesktopShortcut', 'Set-NetworkSettings', 'Update-ProgressBar'

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = '*'

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = '*'

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        # Tags = @()

        # A URL to the license for this module.
        # LicenseUri = ''

        # A URL to the main website for this project.
        ProjectUri = 'https://www.github.com/mstrhakr/scans'

        # A URL to an icon representing this module.
        IconUri = 'https://raw.githubusercontent.com/mstrhakr/scans/main/scans.ico'

        # ReleaseNotes of this module
        # ReleaseNotes = ''

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}
