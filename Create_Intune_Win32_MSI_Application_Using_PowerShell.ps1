# SYNOPSIS
# Create Windows Win32 MSI Application in Intune Using PowerShell.

# DESCRIPTION
# This script automates the creation of Windows Win32 MSI Applications in Intune using PowerShell.

# DEMO
# YouTube video link → https://www.youtube.com/@chandermanipandey8763

# INPUTS
# Provide all required information in the User Input section.

# OUTPUTS
# Automatically creates a Windows Win32 MSI Application in Intune using PowerShell.

# Download the AzCopy portable binary
# https://aka.ms/downloadazcopy-v10-windows

# NOTES
# Version:         1.0  
# Author:          Chander Mani Pandey  
# Creation Date:   3 Mar 2025

# Revision Version 1.2: 24 Mar 2025
# - Added logic to detect file size. Your MSI file size must be 9MB or more.
# - Added logic to detect file type. If not an MSI file, the script exits.


# Find the author on:  
# YouTube:    https://www.youtube.com/@chandermanipandey8763  
# Twitter:    https://twitter.com/Mani_CMPandey  
# LinkedIn:   https://www.linkedin.com/in/chandermanipandey  
# BlueSky:    https://bsky.app/profile/chandermanipandey.bsky.social
# GitHub:     https://github.com/ChanderManiPandey2022


cls﻿
Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force -ErrorAction 'Stop' 

$error.clear() ## this is the clear error history 

$ErrorActionPreference = 'SilentlyContinue';


#======================================================================================================================================================================#
#======================================================================================================================================================================#
#==================================================================User Input Section Start ===========================================================================#

# Define Paths and Variables
$InputPath = "C:\Temp\Win32App\Google_Chrome\AppSetupFile"
$InstallerFile = "GoogleChrome.msi"
$OutputPath = "C:\Temp\Win32App\Google_Chrome\AppOutputFile"
$imagePathLogo = "C:\TEMP\win32app\google_chrome\applogo\548818.png"
$IntuneWinUtilPath = "C:\TEMP\Win32App\IntuneWinAppUtil\IntuneWinAppUtil.exe"
$toolPathAzCopy = "C:\TEMP\Win32App\AzCopy\azcopy.exe"
$logPathAzCopy = "C:\Windows\Temp\AzLog"
$GroupID = "9b87a4b9-7e16-44ac-9651-e6ff535755ef" # Entra Group Object ID
$InstallMode = "available" # Assignment options: available, required, uninstall

#===================================================================User Input Section End ============================================================================#
#======================================================================================================================================================================#
#======================================================================================================================================================================#

# Function to check, install, and import a module
function Ensure-Module {
    param (
        [string]$moduleToCheck
    )
    $moduleStatus = Get-Module -Name $moduleToCheck -ListAvailable
    Write-Host "Checking if '$moduleToCheck' is installed" -ForegroundColor Yellow
    if ($moduleStatus -eq $null) {
        Write-Host "'$moduleToCheck' is not installed" -ForegroundColor Red
        Write-Host "Installing '$moduleToCheck'" -ForegroundColor Yellow
        Install-Module $moduleToCheck -Force
        Write-Host "'$moduleToCheck' has been installed successfully" -ForegroundColor Green
    }
    else {
        Write-Host "'$moduleToCheck' is already installed" -ForegroundColor Green
    }
    Write-Host "Importing '$moduleToCheck' module" -ForegroundColor Yellow
    Import-Module $moduleToCheck -Force
    Write-Host "'$moduleToCheck' module imported successfully" -ForegroundColor Green
}
Write-host ""
# Ensure Microsoft.Graph.DeviceManagement.Enrollment is installed and imported
Ensure-Module -moduleToCheck "Microsoft.Graph.Authentication"

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "DeviceManagementApps.ReadWrite.All" -NoWelcome -ErrorAction Stop


#======================================================================================================================================================================#
#======================================================================================================================================================================#
Write-Host ""
Write-Host "============================================================================================================================================================" -ForegroundColor Yellow
Write-Host "============================================================================================================================================================" -ForegroundColor Yellow
Write-Host ""

$CreateWin32Apps = @"
   *****  *****   *****  *****  *****  *****     *****    ****   ****    *****
  *       *    *  *      *   *    *    *         *   *    *   *  *   *   *
  *       *****   ****   *****    *    *****     *****    ****   ****    *****
  *       *  *    *      *   *    *    *         *   *    *      *           *
   *****  *   *   *****  *   *    *    *****     *   *    *      *       *****
"@

Write-Host $CreateWin32Apps -ForegroundColor Cyan

Write-Host ""
Write-Host "===========================================================================================================================================================" -ForegroundColor Yellow
Write-Host "===========================================================================================================================================================" -ForegroundColor Yellow
Write-Host ""

$FilePath = Join-Path -Path $InputPath -ChildPath $InstallerFile

if (Test-Path $FilePath) {
    if ($InstallerFile -match '\.msi$') {
        $FileSizeMB = (Get-Item $FilePath).Length / 1MB
        
        if ($FileSizeMB -gt 9) {
            Write-Host "File size is greater than 9MB. Continuing..." -ForegroundColor Green
            

           Function Test-SourceFile(){
param
( 
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    $SourceFile
)
    try {
            if(!(test-path "$SourceFile")){
            Write-Host
            Write-Host "Source File '$sourceFile' doesn't exist..." -ForegroundColor Red
            throw
            }
        }
    catch {
		Write-Host -ForegroundColor Red $_.Exception.Message;
        Write-Host
		break
   }}
#======================================================================================================================================================================#
#======================================================================================================================================================================#


#prepare the app by using the Microsoft Win32 Content Prep Tool
# Define Input Variables

# Validate Input Path
If (-not (Test-Path -Path $InputPath)) {
    throw "Cannot find input path: [$InputPath]"
}

# Validate Installer File
If (-not (Test-Path -Path "$InputPath\$InstallerFile")) {
    throw "Cannot find installer file: [$InstallerFile]"
}

# Create Output Directory if it doesn't exist
If (-not (Test-Path -Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# Validate IntuneWinAppUtil.exe existence
If (-not (Test-Path -Path $IntuneWinUtilPath)) {
    throw "Cannot find IntuneWinAppUtil.exe at: [$IntuneWinUtilPath]"
}
Write-host ""
Write-host "Creating $IntuneWinFile file...." -ForegroundColor Yellow
# Start Processing
Start-Process -FilePath $IntuneWinUtilPath -ArgumentList "-c `"$InputPath`" -s `"$InstallerFile`" -o `"$OutputPath`" -q" -NoNewWindow -Wait


# Generate Output File Name
$InstallerFullPath = (Get-Item -Path "$InputPath\$InstallerFile").FullName
$BaseFileName = [System.IO.Path]::GetFileNameWithoutExtension($InstallerFullPath)
$IntuneWinFile = "$BaseFileName.intunewin"
$filePathApp = "$OutputPath\$IntuneWinFile"

# Verify Output File Creation
If (Test-Path -Path "$OutputPath\$IntuneWinFile") {
    Write-Host "$IntuneWinFile file successfully created" -ForegroundColor green
} else {
    Write-host  "File $IntuneWinFile not created" -ForegroundColor Red
}
#======================================================================================================================================================================#
#======================================================================================================================================================================#

Function Get-IntuneWinXML(){

param
(
[Parameter(Mandatory=$true)]
$SourceFile,

[Parameter(Mandatory=$true)]
$fileName,

[Parameter(Mandatory=$false)]
[ValidateSet("false","true")]
[string]$removeitem = "true"
)

Test-SourceFile "$SourceFile"

$Directory = [System.IO.Path]::GetDirectoryName("$SourceFile")

Add-Type -Assembly System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead("$SourceFile")

    $zip.Entries | where {$_.Name -like "$filename" } | foreach {

    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$Directory\$filename", $true)

    }

$zip.Dispose()

[xml]$IntuneWinXML = gc "$Directory\$filename"

return $IntuneWinXML

if($removeitem -eq "true"){ remove-item "$Directory\$filename" }

}

#======================================================================================================================================================================#
#======================================================================================================================================================================#
Function Get-IntuneWinFile(){

param
(
[Parameter(Mandatory=$true)]
$SourceFile,

[Parameter(Mandatory=$true)]
$fileName,

[Parameter(Mandatory=$false)]
[string]$Folder = "win32"
)

    $Directory = [System.IO.Path]::GetDirectoryName("$SourceFile")

    if(!(Test-Path "$Directory\$folder")){

        New-Item -ItemType Directory -Path "$Directory" -Name "$folder" | Out-Null

    }

    Add-Type -Assembly System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead("$SourceFile")

        $zip.Entries | where {$_.Name -like "$filename" } | foreach {

        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$Directory\$folder\$filename", $true)

        }

    $zip.Dispose()

    return "$Directory\$folder\$filename"

    if($removeitem -eq "true"){ remove-item "$Directory\$filename" }

}

$SourceFile = $filePathApp
$filename = "IntunePackage.intunewin"
$IntuneWinFile = Get-IntuneWinFile "$SourceFile" -fileName "IntunePackage.intunewin"
$DetectionXML = Get-IntuneWinXML "$SourceFile" -fileName "detection.xml"
$InstallCmd = "%SystemRoot%\System32\msiexec.exe /i `"$($DetectionXML.ApplicationInfo.SetupFile)`" /quiet /norestart /l*v `"C:\Windows\Logs\$($DetectionXML.ApplicationInfo.name)_Install.log`""
$UninstallCMD = "%SystemRoot%\System32\msiexec.exe /x `"$($DetectionXML.ApplicationInfo.MsiInfo.MsiProductCode)`" /quiet /norestart /l*v `"C:\Windows\Logs\$($DetectionXML.ApplicationInfo.name)_UnInstall.log`""
[int64]$Size = $DetectionXML.ApplicationInfo.UnencryptedContentSize
$EncrySize = (Get-Item "$IntuneWinFile").Length

#======================================================================================================================================================================#
#======================================================================================================================================================================#

$appDetails = @{
    "@odata.type" = "#microsoft.graph.win32LobApp"
    applicableArchitectures = "x64,x86"  # Changed to a string (Fix for 'StartArray' error)
    allowAvailableUninstall = $true
    categories =  @() 
    description = $DetectionXML.ApplicationInfo.name
    developer = $DetectionXML.ApplicationInfo.MsiInfo.MsiPublisher+" Application"
    displayName = $DetectionXML.ApplicationInfo.name
    displayVersion = $DetectionXML.ApplicationInfo.MsiInfo.MsiProductVersion
    fileName = $IntuneWinFile
    installCommandLine = $InstallCmd
    installExperience = @{
        deviceRestartBehavior = "suppress"
        maxRunTimeInMinutes = 60
        runAsAccount = "$($DetectionXML.ApplicationInfo.MsiInfo.MsiExecutionContext)"
    }
    informationUrl = ""
    isFeatured = $false
    roleScopeTagIds = @() 
    notes = $DetectionXML.ApplicationInfo.MsiInfo.MsiPublisher+" Application"
    minimumSupportedWindowsRelease = "1607"
    msiInformation = $null
    owner = "Created By Chander Mani Pandey"
    privacyInformationUrl = ""
    publisher = $DetectionXML.ApplicationInfo.MsiInfo.MsiPublisher
    returnCodes = @(
        @{ returnCode = 0; type = "success" }
        @{ returnCode = 1707; type = "success" }
        @{ returnCode = 3010; type = "softReboot" }
        @{ returnCode = 1641; type = "hardReboot" }
        @{ returnCode = 1618; type = "retry" }
    )
    rules = @(
        @{
            "@odata.type" = "#microsoft.graph.win32LobAppProductCodeRule"
            productVersionOperator = "notConfigured"
            productCode = $DetectionXML.ApplicationInfo.MsiInfo.MsiProductCode
        }
    )
    runAs32Bit = $false
    setupFilePath = "$($DetectionXML.ApplicationInfo.SetupFile)"
    uninstallCommandLine = $UninstallCMD
}

Write-host ""
Write-Host "Creating $($DetectionXML.ApplicationInfo.name) Application In Intune Portal" -ForegroundColor Yellow
$uriCreateApp = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps"
$appCreated = Invoke-MgGraphRequest -Method POST -Uri $uriCreateApp -Body ($appDetails | ConvertTo-Json -Depth 10)
Write-Host "$($DetectionXML.ApplicationInfo.name) Application metadata created successfully" -ForegroundColor Green
Write-Host "$($DetectionXML.ApplicationInfo.name) version is $($DetectionXML.ApplicationInfo.MsiInfo.MsiProductVersion)" -ForegroundColor Green  
Write-Host "$($DetectionXML.ApplicationInfo.name) publisher is $($DetectionXML.ApplicationInfo.MsiInfo.MsiPublisher)" -ForegroundColor Green  
Write-Host "$($DetectionXML.ApplicationInfo.name) GUID is $($appCreated.id)" -ForegroundColor Green
Write-Host "$($DetectionXML.ApplicationInfo.name) custom log location is "C:\Windows\Logs\$($DetectionXML.ApplicationInfo.name)_Install.log"" -ForegroundColor Green
$uriContentVersion = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($appCreated.id)/microsoft.graph.win32LobApp/contentVersions"
$contentVersionCreated = Invoke-MgGraphRequest -Method POST -Uri $uriContentVersion -Body "{}"
Write-Host "Application Content version created and ID is $($contentVersionCreated.id)" -ForegroundColor Green

Write-Host
#Write-Host "Getting Encryption Information for '$SourceFile'..." -ForegroundColor Yellow

$encryptionInfo = @{};
$encryptionInfo.encryptionKey = $DetectionXML.ApplicationInfo.EncryptionInfo.EncryptionKey
$encryptionInfo.macKey = $DetectionXML.ApplicationInfo.EncryptionInfo.macKey
$encryptionInfo.initializationVector = $DetectionXML.ApplicationInfo.EncryptionInfo.initializationVector
$encryptionInfo.mac = $DetectionXML.ApplicationInfo.EncryptionInfo.mac
$encryptionInfo.profileIdentifier = "ProfileVersion1";
$encryptionInfo.fileDigest = $DetectionXML.ApplicationInfo.EncryptionInfo.fileDigest
$encryptionInfo.fileDigestAlgorithm = $DetectionXML.ApplicationInfo.EncryptionInfo.fileDigestAlgorithm

$fileEncryptionInfo = @{};
$fileEncryptionInfo.fileEncryptionInfo = $encryptionInfo;

#======================================================================================================================================================================#
#======================================================================================================================================================================#

# Upload to Azure Storage
Write-Host "Creating File Content..." -ForegroundColor Yellow
$fileContent = @{
    "@odata.type" = "#microsoft.graph.mobileAppContentFile"
    name          = "IntunePackage.intunewin"
    size          = $Size  # Integer type is acceptable here
    sizeEncrypted = $EncrySize   # Integer type
    isDependency  = $false
    manifest      = $null     
}


$uriFileContent = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($appCreated.id)/microsoft.graph.win32LobApp/contentVersions/$($contentVersionCreated.id)/files"  
$fileContentCreated = Invoke-MgGraphRequest -Method POST -Uri $uriFileContent -Body ( $fileContent | ConvertTo-Json)

do {
    Start-Sleep -Seconds 5
    $uriFileStatus = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($appCreated.id)/microsoft.graph.win32LobApp/contentVersions/$($contentVersionCreated.id)/files/$($fileContentCreated.id)"
    $fileStatus = Invoke-MgGraphRequest -Method GET -Uri $uriFileStatus
} while ($fileStatus.uploadState -ne "azureStorageUriRequestSuccess")
Write-Host "Created File Content" -ForegroundColor Green
Write-host ""
#Write-Host "Uploading the file to Azure Storage..." -ForegroundColor Yellow

# Function to upload file using AzCopy
$env:AZCOPY_LOG_LOCATION=$logPathAzCopy
function Upload-UsingAzCopy {
    param (
        [string]$fileToUpload, 
        [string]$destinationUri
    )
    if (!(Test-Path $toolPathAzCopy)) {
        Write-Host "AzCopy.exe not found. Please install AzCopy and try again."
        exit 1
    }
    
    Write-Host "Using AzCopy.exe to upload file on Azure Blob" -ForegroundColor White
    & $toolPathAzCopy copy $fileToUpload $destinationUri --recursive=true
    
    if ($?) {
        Write-Host "Application Content Upload successful on Azure Blob via AzCopy.exe" -ForegroundColor Green
    } else {
        Write-Host "Application Content Upload failed via AzCopy.exe"  -ForegroundColor Red
    }
}

# Always use AzCopy for upload
Write-Host "Uploading Application content using AzCopy.exe on Azure Blob" -ForegroundColor yellow
Upload-UsingAzCopy -fileToUpload $IntuneWinFile -destinationUri $fileStatus.azureStorageUri

# Commit the uploaded file
Write-Host ""
Write-Host "Start Committing file" -ForegroundColor Yellow
$commitData = @{
    fileEncryptionInfo = $encryptionInfo
}
$uriCommit = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($appCreated.id)/microsoft.graph.win32LobApp/contentVersions/$($contentVersionCreated.id)/files/$($fileContentCreated.id)/commit"
Invoke-MgGraphRequest -Method POST -Uri $uriCommit -Body ($commitData | ConvertTo-Json)
Start-Sleep -Seconds 20
$retryCount = 0
$maxRetries = 10
do {
    Start-Sleep -Seconds 10
    $uriFileStatus = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($appCreated.id)/microsoft.graph.win32LobApp/contentVersions/$($contentVersionCreated.id)/files/$($fileContentCreated.id)"
    $fileStatus = Invoke-MgGraphRequest -Method GET -Uri $uriFileStatus
    if ($fileStatus.uploadState -eq "commitFileFailed") {
        $commitResponse = Invoke-MgGraphRequest -Method POST -Uri $uriCommit -Body ($commitData | ConvertTo-Json)
        $retryCount++
    }
} while ($fileStatus.uploadState -ne "commitFileSuccess" -and $retryCount -lt $maxRetries)

if ($fileStatus.uploadState -eq "commitFileSuccess") {
    Write-Host "File committed successfully" -ForegroundColor Green
}
else {
    Write-Host "Failed to commit file after $maxRetries attempts." -ForegroundColor red
    exit 1
}

# Update app with committed content version
$uriUpdateApp = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($appCreated.id)"
$updateData = @{
    "@odata.type"           = "#microsoft.graph.win32LobApp"
    committedContentVersion = $contentVersionCreated.id
}
Invoke-MgGraphRequest -Method PATCH -Uri $uriUpdateApp -Body ($updateData | ConvertTo-Json)

#======================================================================================================================================================================#
#======================================================================================================================================================================#

# Updated/Uploaded application logo
Write-host ""
Write-Host "Updating/Uploading $appName logo" -ForegroundColor Yellow

# Convert the logo to base64
$logoBase64 = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($imagePathLogo))
# Prepare the request body
$ApplogoBody = @{
    "@odata.type" = "#microsoft.graph.mimeContent"
    "type"        = "image/png"
    "value"       = $logoBase64
}

$uriLogoUpdate = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($appCreated.id)"
$Body = @{
    "@odata.type" = "#microsoft.graph.win32LobApp"
    "largeIcon"   = $ApplogoBody
}
Invoke-MgGraphRequest -Method PATCH -Uri $uriLogoUpdate -Body ($Body | ConvertTo-Json -Depth 10)
Write-Host "Updated/Uploaded $ProductName logo" -ForegroundColor green


#======================================================================================================================================================================#
#======================================================================================================================================================================#

# Adding an application assignment using the Graph API...
Write-host ""
Write-Host "Adding $($DetectionXML.ApplicationInfo.name) application assignment......." -ForegroundColor Yellow

$ApiResource = "deviceAppManagement/mobileApps/$($appCreated.id)/assign"

$RequestUri = "https://graph.microsoft.com/beta/$ApiResource"

# Validate inputs

if (-not ($($appCreated.id))) { Write-Host "No Application Id specified" -ForegroundColor Red; exit }

if (-not $GroupID) { Write-Host "No Target Group Id specified" -ForegroundColor Red; exit }

if (-not $InstallMode) { Write-Host "No Install Intent specified" -ForegroundColor Red; exit }

# JSON body

$JsonBody = @"
{
    "mobileAppAssignments": [
        {
            "@odata.type": "#microsoft.graph.mobileAppAssignment",
            "target": {
                "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                "groupId": "$GroupID"
            },
            "intent": "$InstallMode"
        }
    ]
}
"@

# Invoke API request

try 
{
    Invoke-MgGraphRequest -Uri $RequestUri -Method Post -Body $JsonBody -ContentType "application/json"
}
 catch
  {
    $Exception = $_.Exception
 
    $ErrorResponse = $Exception.Response.GetResponseStream()
 
    $StreamReader = New-Object System.IO.StreamReader($ErrorResponse)
 
    $StreamReader.BaseStream.Position = 0
 
    $StreamReader.DiscardBufferedData()
 
    $ResponseContent = $StreamReader.ReadToEnd()
 
    Write-Host "Response content:`n$ResponseContent" -ForegroundColor Red
 
    Write-Error "Request to $RequestUri failed with HTTP Status $($Exception.Response.StatusCode) $($Exception.Response.StatusDescription)"
}

Write-Host "$($DetectionXML.ApplicationInfo.name) Win32 application assigned successfully." -ForegroundColor Green

Write-host ""

#======================================================================================================================================================================#
#======================================================================================================================================================================#

# Removing temporary files and folder
# Define folders to delete
$folders = @("$env:USERPROFILE\.azcopy", $logPathAzCopy, $filePathApp)

# Loop through each folder and delete if it exists
Write-Host "Removing temporary files and folder" -ForegroundColor Yellow
$folders | ForEach-Object { if (Test-Path $_) { Remove-Item -Path $_ -Recurse -Force } }
Write-Host "Removed temporary files and folder" -ForegroundColor Green
Write-Host ""
#======================================================================================================================================================================#
#======================================================================================================================================================================#

 } 
 else 
 {
           
  Write-Host "$InstallerFile Application size is less than 9 MB. Exiting.." -ForegroundColor Red
  exit
 }
   } 
 else 
 {
  Write-Host "Invalid file extension. The file must be a .msi file. Exiting..." -ForegroundColor Red
  exit
    }
}
 else {
    Write-Host "File not found: $FilePath. Exiting..." -ForegroundColor Red
  exit
}

#DisConnect MgGraph 
DisConnect-MgGraph 

#======================================================================================================================================================================#
#======================================================================================================================================================================#
