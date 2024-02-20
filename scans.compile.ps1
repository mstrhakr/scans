param (
    [string]$Version,
    [switch]$Verbose
)
$extras = @{}
if($Verbose) {
    $VerbosePreference = 'Continue'
    $extras['Verbose'] = $true
}

# Import the Scans module
Import-Module ./Scans.psm1 -Function Get-Icon @extras

# Set the path to the PS2EXE.ps1 script
$ps2exeScriptPath = Join-Path -Path $PSScriptRoot -ChildPath "PS2EXE.ps1" @extras

# Set the path to the scans.ps1 script
$scansScriptPath = Join-Path -Path $PSScriptRoot -ChildPath "scans.ps1" @extras

# Set the output path for the compiled executable
$outputPath = Join-Path -Path $PSScriptRoot -ChildPath "scans.exe" @extras

# Set the details for the compiled executable
$details = @{
    Title = "Scans"
    Description = "Scanning setup utility."
    CompanyName = "Printer Source Plus"
    ProductName = "Scans"
}

# Compile the scans.ps1 script using PS2EXE.ps1
try {
    & $ps2exeScriptPath -inputFile $scansScriptPath -outputFile $outputPath -noOutput -noConsole -iconFile (Get-Icon) -title $details.Title -description $details.Description -company $details.CompanyName -product $details.ProductName -version $Version @extras
    Write-Host "Compiled executable created at $outputPath"
} catch {
    Write-Error $_.Exception.Message
}
