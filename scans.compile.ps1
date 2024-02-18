# Import the Scans module
Import-Module ./Scans.psm1 -Function Get-Icon

# Read the current module manifest
$manifest = Get-Content -Path .\scans.psd1

# Extract the current version number
$versionLine = $manifest | Where-Object { $_ -match "ModuleVersion" }
$version = $versionLine.Split('=')[1].Trim().Trim("'")

# Set the path to the PS2EXE.ps1 script
$ps2exeScriptPath = Join-Path -Path $PSScriptRoot -ChildPath "PS2EXE.ps1"

# Set the path to the scans.ps1 script
$scansScriptPath = Join-Path -Path $PSScriptRoot -ChildPath "scans.ps1"

# Set the output path for the compiled executable
$outputPath = Join-Path -Path $PSScriptRoot -ChildPath "scans.exe"

# Set the details for the compiled executable
$details = @{
    Title = "Scans"
    Description = "Scanning setup utility."
    CompanyName = "Printer Source Plus"
    ProductName = "Scans"
}

# Compile the scans.ps1 script using PS2EXE.ps1
& $ps2exeScriptPath -inputFile $scansScriptPath -outputFile $outputPath -noOutput -noConsole -iconFile (Get-Icon) -title $details.Title -description $details.Description -company $details.CompanyName -product $details.ProductName -version $version -verbose
