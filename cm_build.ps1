#requires -RunAsAdministrator
#requires -version 3
<#
.SYNOPSIS
    SCCM site server installation script
.DESCRIPTION
    Yeah, what he said.
.PARAMETER XmlFile
    [string](optional) Path and Name of XML input file
.PARAMETER NoCheck
    [switch](optional) Skip platform validation restrictions
.PARAMETER NoReboot
    [switch](optional) Suppress reboots until very end
.NOTES
    1.1.0 - DS - 2017.08.16
    1.0.0 - DS - 2017.08.14
    
    Read the associated XML to make sure the path and filename values
    all match up like you need them to.

.EXAMPLE
    .\cm_build.ps1 -XmlFile .\cm_build.xml -Verbose
#>

[CmdletBinding()]
param (
    [parameter(Mandatory=$True, HelpMessage="Path and name of XML input file")]
        [ValidateNotNullOrEmpty()]
        [string] $XmlFile,
    [parameter(Mandatory=$False, HelpMessage="Skip platform validation checking")]
        [switch] $NoCheck,
    [parameter(Mandatory=$False, HelpMessage="Suppress reboots")]
        [switch] $NoReboot
)

$basekey = 'HKLM:\SOFTWARE\CM_BUILD'

# begin-functions

function Get-TimeOffset {
    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        $StartTime
    )
    $StopTime = Get-Date
    $Offset = [timespan]::FromSeconds(((New-TimeSpan -Start $StartTime -End $StopTime).TotalSeconds).ToString()).ToString("hh\:mm\:ss")
    Write-Output $Offset
}

function Set-CMBuildRegVal {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [string] $KeyName, 
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [string] $Value
    )
    Write-Verbose "[function: set-cmbuildregval]"
    try {
        New-Item -Path $basekey -ErrorAction SilentlyContinue | Out-Null
        New-Item -Path $basekey\PROCESSED -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
        Write-Error "FAIL: Unable to set registry path"
        break
    }
    try {
        New-Item -Path $basekey\PROCESSED\$KeyName -Value $Value -ErrorAction SilentlyContinue | Out-Null
        Write-Verbose "INFO: writing registry key $KeyName"
        Write-Output $True
    }
    catch {
        Write-Verbose "ERROR: failed to write to registry!"
    }
}

function Test-PendingReboot {
    if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -EA Ignore) { Write-Output $true }
    if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -EA Ignore) { Write-Output $true }
    if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -EA Ignore) { Write-Output $true }
    try { 
        $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
        $status = $util.DetermineIfRebootPending()
        if (($status -ne $null) -and $status.RebootPending){
            Write-Output $true
        }
    }
    catch {}
    Write-Output $false
}

function Get-ConfigData {
    param (
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [string] $XmlFile
    )
    Write-Verbose "[function:get-configdata] loading xml data from: $XmlFile"
    if (-not(Test-Path $XmlFile)) {
        Write-Warning "ERROR: configuration file not found: $XmlFile"
    }
    else {
        try {
            [xml]$data = Get-Content $XmlFile
            Write-Output $data
        }
        catch {
            Write-Warning "failed to import configuration data"
        }
    }
}

function Show-CMBuildParams {
    [CmdletBinding()]
    param ()
    Write-Verbose "info: project customer... $($project.customer.name)"
    Write-Verbose "info: project author..... $($project.author.name)"
    Write-Verbose "info: project version.... $($project.version.name) `($($project.version.comment)`)"
    Write-Verbose "info: site server........ $($project.siteserver.name)"
    Write-Verbose "info: packages........... $($packages.count)"
    Write-Verbose "info: payloads........... $($payloads.count)"
    Write-Verbose "info: features........... $($features.count)"
    Write-Verbose "info: detect rules....... $($detects.count)"
    Write-Verbose "info: folders............ $($folders.count)"
    Write-Verbose "info: files.............. $($newfiles.count)"
    Write-Verbose "info: references......... $($refs.count)"    
}

function Set-NewFolders {
    [CmdletBinding()]
    param($Folders)
    Write-Verbose "-----------------------------"    
    Write-Verbose "[function: set-newfolders]"
    $result = $True
    foreach ($folder in $Folders) {
        $folderName = $folder.name
        foreach ($fn in $folderName.split(',')) {
            if (-not(Test-Path $fn)) {
                Write-Verbose "info: creating folder: $fn"
                try {
                    New-Item -Path $fn -ItemType Directory -ErrorAction Stop | Out-Null
                    $WaitAfter = $True
                }
                catch {
                    Write-Warning "error: unable to create folder: $fn"
                    $result = $False
                }
            }
            else {
                Write-Verbose "info: folder exists: $fn"
            }
        }
    }
    if ($WaitAfter) {
        Write-Verbose "info: pausing for 5 seconds"
        Start-Sleep -Seconds 5
    }
    Write-Output $result
}

function Set-NewFiles {
    [CmdletBinding()]
    param ($Files)
    Write-Verbose "-----------------------------"
    Write-Verbose "[function: set-newfiles]"
    $result = $True
    foreach ($fileSet in $Files) {
        $filename = $fileSet.name
        $filepath = $fileSet.path 
        $fullName = "$filePath\$filename"
        $fileComm = $fileSet.comment 
        $filekeys = $fileSet.keys.key
        Write-Verbose "`tfilename: $fullName"
        Write-Verbose "`tcomment: $fileComm"
        if (-not (Test-Path $fullName)) {
            Write-Verbose "info: creating new file: $fullName"
        }
        else {
            Write-Verbose "info: overwriting file: $fullName"
        }
        $data = ""
        foreach ($filekey in $filekeys) {
            $keyname = $filekey.name
            $keyval  = $filekey.value
            if ($keyname.StartsWith('__')) {
                if ($data -ne "") {
                    $data += "`r`n`[$keyval`]`r`n"
                }
                else {
                    $data += "`[$keyval`]`r`n"
                }
            }
            else {
                $data += "$keyname=`"$keyval`"`r`n"
            }
        } # foreach
        $data | Out-File $fullname -Force
    } # foreach
    Write-Output $result
}

function Add-ServerRoles {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [string] $RoleName,
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [string[]] $FeaturesList,
        [parameter(Mandatory=$False)]
            [string] $AlternateSource = "",
        [parameter(Mandatory=$False)]
            [string] $LogFile = "roles.log"
    )
    Write-Verbose "-----------------------------"
    Write-Verbose "[function: add-serverroles]"
    $time1  = Get-Date
    $result = 0
    $FeaturesList | 
    Foreach-Object {
        $FeatureCode = $_
        Write-Verbose "info: installing role or feature: $FeatureCode"
        $time3 = Get-Date

        if ($AlternateSource -ne "") {
            try {
                $exitcode = Install-WindowsFeature -Name $FeatureCode -IncludeManagementTools -LogPath "F:\CM_BUILD\$LogFile" -Source $AlternateSource -ErrorAction Stop
                $result = $exitcode
            }
            catch {
                $result = -1
            }
            Write-Output "info: $FeatureCode exitcode: $exitcode"
            #Write-Warning "error: $($error[0].Exception)"
        }
        else {
            try {
                $exitcode = Install-WindowsFeature -Name $FeatureCode -IncludeManagementTools -LogPath "F:\CM_BUILD\$LogFile" -ErrorAction Stop
                $result = $exitcode
            }
            catch {
                $result = -1
            }
            Write-Output "info: $FeatureCode exitcode: $exitcode"
            #Write-Warning "error: $($error[0].Exception)"
        }
        $time4 = Get-TimeOffset -StartTime $time3
        Write-Verbose "info: $FeatureCode runtime = $time4"
    } # foreach-object
    Write-Verbose "info: result = $result"
    if ($result -eq 0) {
        Set-CMBuildRegVal -KeyName 'SERVERROLES' -Value $(Get-Date)
    }
    $time2 = Get-TimeOffset -StartTime $time1
    Write-Verbose "info: function runtime = $time2"
    Write-Output $result
}

function Set-SqlConfiguration {
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$False)]
            [int] $MemRatio = 80
    )
    Write-Verbose "[function: set-sqlconfiguration]"
    Write-Verbose "info: MemRatio = $MemRatio"
    $time1 = Get-Date
    $dblRatio = $MemRatio * 0.01
    Install-Module -Name PowerShellGet -Force
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module dbatools -SkipPublisherCheck -Force
    $TotalMem = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty TotalPhysicalMemory)
    $actMax   = [math]::Round($TotalMem/1GB,0)
    $newMax   = [math]::Round(($TotalMem / 1MB)*$dblRatio,0)
    $curMax   = Get-DbaMaxMemory -SqlServer (&hostname)
    Write-Verbose "info: total memory is $actMax GB"
    Write-Verbose "info: recommended SQL max is $newMax GB"
    Write-Verbose "info: current SQL max is $curMax GB"
    if ($actMax -lt 7) {
        Write-Verbose "warning: Server has $actMax GB of memory - SQL Config cannot be optimized"
        Set-CMBuildRegVal -KeyName 'SQLCONFIG' -Value $(Get-Date)
        $result = 0
    }
    elseif ($curMax -ne $newMax) {
        try {
            Set-DbaMaxMemory -SqlServer (&hostname) -MaxMb $newMax
            Write-Verbose "info: maximum memory allocation is now: $newMax"
            Set-CMBuildRegVal -KeyName 'SQLCONFIG' -Value $(Get-Date)
            $result = 0
        }
        catch {
            Write-Verbose "warning: unable to change memory allocation"
        }
    }
    $time2 = Get-TimeOffset -StartTime $time1
    Write-Verbose "info: function runtime = $time2"
    Write-Output $result
}

function Install-Payload {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [string] $Name,
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [string] $SourceFile,
        [parameter(Mandatory=$False)]
            [string] $OptionParams = ""
    )
    Write-Verbose "[function: install-payload]"
    Write-Verbose "info: name = $Name"
    Write-Verbose "info: sourcefile = $SourceFile"
    Write-Verbose "info: optionparams = $OptionParams"
    Write-Host "Installing: $Name" -ForegroundColor Green
    
    if (-not(Test-Path $SourceFile)) {
        Write-Warning "error: source file not found: $SourceFile"
        break
    }
    if ($SourceFile.EndsWith('.msi')) {
        if ($OptionParams -ne "") {
            $ArgList = "/i $SourceFile $OptionParams"
        }
        else {
            $ArgList = "/i $SourceFile /qb! /norestart"
        }
        $SourceFile = "msiexec.exe"
    }
    else {
        $ArgList = $OptionParams
    }
    $result = 0
    Write-Verbose "info: launcher... $SourceFile"
    Write-Verbose "info: arguments.. $ArgList"
    $time1 = Get-Date
    try {
        $p = Start-Process -FilePath $SourceFile -ArgumentList $ArgList -NoNewWindow -Wait -PassThru -ErrorAction Stop
        if ((0,3010,1605,1641,1618,1707).Contains($p.ExitCode)) {
            $result = 0
        }
        else {
            $result = $p.ExitCode
        }
    }
    catch {
        Write-Warning "error: failed to execute installation: $Name"
        Write-Warning "error: $($error[0].Exception)"
        $result = -1
    }
    if (Test-PendingReboot) {
        if ($NoReboot) {
            Write-Host "Reboot is required but suppressed" -ForegroundColor Cyan
        }
        else {
            Write-Host "Reboot will be requested" -ForegroundColor Magenta
            <#
            Stop-Transcript
            Restart-Computer
            #>
        }
    }
    Get-TimeOffset -StartTime $time1
    $time2 = Get-TimeOffset -StartTime $time1
    Write-Output "info: function runtime = $time2"
    Write-Output $result
}

# end-functions

$RunTime1 = Get-Date
Write-Output "info: begin process at $(Get-Date)"
Set-CMBuildRegVal -KeyName 'START' -Value $(Get-Date)

[xml]$xmldata = Get-ConfigData $XmlFile
$project  = $xmldata.configuration.project
$packages = $xmldata.configuration.packages.package | ? {$_.enabled -eq 'true'}
$payloads = $xmldata.configuration.payloads.payload
$features = $xmldata.configuration.features.feature
$detects  = $xmldata.configuration.detections.detect
$folders  = $xmldata.configuration.folders.folder
$files    = $xmldata.configuration.files.file
$newfiles = $xmldata.configuration.files.file
$refs     = $xmldata.configuration.references.reference
$AltSource = $refs | Where-Object {$_.name -eq 'WindowsServer'} | Select-Object -ExpandProperty path

Show-CMBuildParams

Set-Location $env:USERPROFILE
$tsFile = "$($env:TEMP)\cm_build$($env:COMPUTERNAME)_transaction.log"
Start-Transcript -Path $tsFile

Write-Output "------------------- BEGIN $(Get-Date) -------------------"
Write-Verbose "info: alternate windows source = $AltSource"

Write-Host "Creating Folders and data files" -ForegroundColor Green

if (-not (Set-NewFolders -Folders $folders)) {
    Write-Warning "error: failed to create folders (aborting)"
    break
}
if (-not (Set-NewFiles -Files $files)) {
    Write-Warning "error: failed to create files (aborting)"
    break
}

Write-Host "Executing project configuration" -ForegroundColor Green
Write-Verbose "-----------------------------"

foreach ($package in $packages) {
    $pkgName = $package.name
    $pkgType = $package.type 
    $pkgComm = $package.comment 
    $payload = $payloads | Where-Object {$_.name -eq $pkgName}
    $pkgSrc  = $payload.path 
    $pkgFile = $payload.file
    $pkgArgs = $payload.params
    $detRule = $detects  | Where-Object {$_.name -eq $pkgName}
    $detPath = $detRule.path
    $detType = $detRule.type

    Write-Verbose "info: package name.... $pkgName"
    Write-Verbose "info: package type.... $pkgType"
    Write-Verbose "info: package comment. $pkgComm"
    Write-Verbose "info: payload source.. $pkgSrc"
    Write-Verbose "info: payload file.... $pkgFile"
    Write-Verbose "info: payload args.... $pkgArgs"
    Write-Verbose "info: rule type....... $detType"
    if ($detType -eq 'synthetic') {
        # example "HKLM:\SOFTWARE\CM_BUILD\PROCESS\WSUS"
        $detPath = "$detPath\$pkgName"
    }
    Write-Verbose "info: detect rule..... $detPath"
    if (Test-Path $detPath) {
        Write-Verbose "info: install state... installed"
    }
    else {
        Write-Verbose "info: install state... not installed"
        switch ($pkgType) {
            'feature' {
                Write-Host "Installing $pkgComm" -ForegroundColor Green
                $xdata = ($xmldata.configuration.features.feature | Where-Object {$_.name -eq $pkgName} | Foreach-Object {$_.innerText}).Split(',')
                $x = Add-ServerRoles -RoleName $pkgName -FeaturesList $xdata -AlternateSource $AltSource
                Write-Verbose "info: exit code = $x"
                break
            }
            'function' {
                switch ($pkgName) {
                    'SQLCONFIG' {
                        Write-Host "$pkgComm" -ForegroundColor Green
                        $x = Set-SqlConfiguration
                        Write-Verbose "info: exit code = $x"
                        break
                    }
                    default {
                        Write-Warning "not function mapping for: $PkgName"
                        break
                    }
                }
                break
            }
            'payload' {
                Write-Host "Installing $pkgComm" -ForegroundColor Green
                if ($pkgName -eq 'CONFIGMGR') {
                    Write-Host "Tip: Monitor C:\ConfigMgrSetup.log for progress" -ForegroundColor Green
                }
                $runFile = "$pkgSrc\$pkgFile"
                $x = Install-Payload -Name $pkgName -SourceFile $runFile -OptionParams $pkgArgs
                Write-Verbose "info: exit code = $x"
                if ($x -ne 0) {
                    Write-Warning "error: step failure at: $pkgName"
                    break
                }
            }
            default {
                Write-Warning "invalid package type value: $pkgType"
                break
            }
        }
    }
    Write-Verbose "-----------------------------"
}

Write-Output "info: finished at $(Get-Date)"
$RunTime2 = Get-TimeOffset -StartTime $RunTime1
Write-Output "info: total time = $RunTime2"
if ((Test-PendingReboot) -and ($NoReboot)) {
    Write-Host "REBOOT in 30 SECONDS - or press CTRL`+C to abort" -ForegroundColor Cyan
    Start-Sleep -Seconds 30
    Restart-Computer -Force
}
