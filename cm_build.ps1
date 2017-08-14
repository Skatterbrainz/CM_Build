#requires -RunAsAdministrator
#requires -Version 3
<#
.SYNOPSIS
    SCCM site server installation script
.DESCRIPTION
    Yeah, what he said.
.PARAMETER xmlfile
    [string](optional) Path and Name of XML input file
.PARAMETER NoCheck
    [switch](optional) Skip platform validation restrictions
.PARAMETER NoReboot
    [switch](optional) Suppress reboot requests
.NOTES
    Version 1.0.0 - DS - 2017.08.14
    
    Read the associated XML to make sure the path and filename values
    all match up like you need them to.
#>
[CmdletBinding()]
param (
    [parameter(Mandatory=$False, HelpMessage="Path and name of XML input file")]
        [string] $xmlfile = ".\cm_build.xml",
    [parameter(Mandatory=$False, HelpMessage="Skip platform validation checks")]
        [switch] $NoCheck,
    [parameter(Mandatory=$False, HelpMessage="Suppress reboot requests")]
        [switch] $NoReboot
)

Set-Location $env:USERPROFILE
Start-Transcript -Path ".\cm_build_$($env:COMPUTERNAME)_transaction.log" -Append
Write-Output "------------------- BEGIN $(Get-Date) -------------------"

function Get-TimeOffset {
    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        $StartTime
    )
    $StopTime = Get-Date
    $Offset = [timespan]::FromSeconds(((New-TimeSpan -Start $StartTime -End $StopTime).TotalSeconds).ToString()).ToString("hh\:mm\:ss")
    Write-Host "Processing completed. Total runtime: $Offset (hh`:mm`:ss)" -ForegroundColor Magenta
}

function Set-CMBuildRegVal {
    [CmdletBinding()]
    param($KeyName, $Value)
    try {
        New-Item -Path HKLM:\SOFTWARE\CM_BUILD -ErrorAction SilentlyContinue | Out-Null
        New-Item -Path HKLM:\SOFTWARE\CM_BUILD\PROCESSED -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
        Write-Error "FAIL: Unable to set registry path"
        break
    }
    try {
        New-Item -Path HKLM:\SOFTWARE\CM_BUILD\PROCESSED\$KeyName -Value $Value -ErrorAction SilentlyContinue | Out-Null
        Write-Verbose "INFO: writing registry key $KeyName"
        Write-Output $True
    }
    catch {
        Write-Verbose "ERROR: failed to write to registry!"
    }
}

#Adapted from https://gist.github.com/altrive/5329377
#Based on <http://gallery.technet.microsoft.com/scriptcenter/Get-PendingReboot-Query-bdb79542>
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

function Test-Platform {
    param ()
    Write-Verbose "[test-platform]"
    $os = Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty caption
    if (($os -like "*Windows Server 2012 R2*") -or ($os -like "*Windows Server 2016*")) {
        Write-Verbose "info: passed rule = operating system"
        $mem = [math]::Round($(gwmi Win32_ComputerSystem | Select-Object -ExpandProperty TotalPhysicalMemory)/1GB,0)
        if ($mem -ge 8) {
            Write-Verbose "info: passed rule = minimmum memory allocation"
            Write-Output $True
        }
        else {
            Write-Host "FAIL: System has $mem GB of memory. ConfigMgr requires 8 GB of memory or more" -ForegroundColor Red
        }
    }
    else {
        Write-Host "FAIL: Operating System must be Windows Server 2012 R2 or 2016" -ForegroundColor Red
    }
}

function Import-ConfigData {
    Write-Verbose "[import-configdata] loading xml data from: $xmlfile"
    if (-not(Test-Path $xmlfile)) {
        Write-Warning "ERROR: configuration file not found: $xmlfile"
    }
    else {
        try {
            [xml]$xmldata = Get-Content $xmlfile
            Write-Output $xmldata
        }
        catch {
            Write-Warning "failed to import configuration data"
        }
    }
}

function Install-Payload {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [string] $Name,
        [parameter(Mandatory=$False)]
            [string] $Detect = "",
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [string] $SourceFile,
        [parameter(Mandatory=$False)]
            [ValidateNotNullOrEmpty()]
            [string] $InstallPath="",
        [parameter(Mandatory=$False)]
            [string] $OptionParams = ""
    )
    Write-Verbose "[install-payload]: $Name"
    Write-Host "Installing: $Name" -ForegroundColor Green
    $time1 = Get-Date
    if (-not(Test-Path $SourceFile)) {
        Write-Host "Source file not found: $SourceFile" -ForegroundColor Red
        break
    }
    if (($InstallPath -ne "") -and (-not(Test-Path $InstallPath))) { 
        Write-Verbose "creating folder: $InstallPath"
        New-Item -Path $InstallPath -ItemType Directory
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
    Write-Verbose "launcher....: $SourceFile"
    Write-Verbose "arguments...: $ArgList"
    
    try {
        $p = Start-Process -FilePath "$SourceFile" -Wait -ArgumentList $ArgList -PassThru -ErrorAction Stop
        Write-Output $p.ExitCode
    }
    catch {
        Write-Warning "failed to execute installation: $Name"
        Write-Warning "Error: $($error[0].Exception)"
    }
    if (Test-PendingReboot) {
        if ($NoReboot) {
            Write-Host "Reboot is required but suppressed" -ForegroundColor Cyan
        }
        else {
            Write-Host "Reboot server now" -ForegroundColor Magenta
            Stop-Transcript
            Restart-Computer
        }
    }
    Get-TimeOffset -StartTime $time1
}

function Install-ServerRoles {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$False)]
            [string] $AlternateSource=""
    )
    Write-Verbose "[install-serverroles]"
    Write-Verbose "`tINFO: alternateSource = $AlternateSource"
    $time1 = Get-Date
    $roles =@('BITS','BITS-IIS-Ext','NET-Framework-45-ASPNET','NET-Framework-Core','NET-Framework-Features',
    'NET-WCF-HTTP-Activation45','RDC','RSAT','RSAT-Bits-Server','RSAT-Feature-Tools','WAS','WAS-Config-APIs',
    'WAS-Process-Model','Web-App-Dev','Web-Asp-Net','Web-Asp-Net45','Web-Common-Http','Web-Default-Doc',
    'Web-Dir-Browsing','Web-Filtering','Web-Health','Web-Http-Errors','Web-Http-Logging','Web-Http-Redirect',
    'Web-Http-Tracing','Web-ISAPI-Ext','Web-ISAPI-Filter','Web-Log-Libraries','Web-Metabase','Web-Mgmt-Compat',
    'Web-Mgmt-Console','Web-Mgmt-Tools','Web-Net-Ext','Web-Net-Ext45','Web-Performance','Web-Request-Monitor',
    'Web-Security','Web-Server','Web-Stat-Compression','Web-Static-Content','Web-WebServer','Web-Windows-Auth',
    'Web-WMI')

    $roles | 
        Foreach-Object {
            $FeatureCode = $_.ToString()
            Write-Verbose "`tINFO: installing role or feature: $FeatureCode"
            try {
                if ($AlternateSource -ne "") {
                    $exitcode = Install-WindowsFeature -Name $FeatureCode -IncludeManagementTools -Source $AlternateSource -ErrorAction Stop
                }
                else {
                    $exitcode = Install-WindowsFeature -Name $FeatureCode -IncludeManagementTools -ErrorAction Stop
                }
                Write-Output "`tINFO: $FeatureCode exitcode: $exitcode"
            }
            catch {
                Write-Warning "`tERROR: failed to add role or feature: $FeatureCode"
                Write-Warning "`tERROR: $($error[0].Exception)"
            }
        } # foreach-object
    Set-CMBuildRegVal -KeyName ROLES1 -Value $(Get-Date)
    Write-Verbose "`tINFO: finished installing roles and features"
    if (Test-PendingReboot) {
        if ($NoReboot) {
            Write-Host "Reboot is required but suppressed" -ForegroundColor Cyan
        }
        else {
            Write-Host "Reboot server now" -ForegroundColor Magenta
            Stop-Transcript
            Restart-Computer
        }
    }
    Get-TimeOffset -StartTime $time1
}

function Write-Folders {
    param($DataSet)
    Write-Verbose "loading folder data"
    $targets = $DataSet.configuration.targets.target
    foreach ($target in $targets) {
        $appName    = $target.name
        $folderPath = $target.path 
        foreach ($fp in ($folderPath -split ',')) {
            Write-Verbose "`tINFO: new folder $fp"
            if (-not(Test-Path $fp -PathType Container)) {
                try {
                    New-Item -Path $fp -ItemType Directory -ErrorAction Stop | Out-Null
                    Write-Verbose "`tINFO: folder created: $fp"
                }
                catch {
                    Write-Warning "`tERROR: failed to create folder: $fp"
                    break
                }
            }
            else {
                Write-Verbose "`tINFO: folder already exists: $fp"
            }
        }
    } # foreach
}

function Write-NewFiles {
    [CmdletBinding()]
    param($DataSet)
    Write-Verbose "loading newfile keys"
    $newfiles = $DataSet.configuration.newfiles.newfile
    foreach ($newfile in $newfiles) {
        $filename = $newfile.name
        $filepath = $newfile.path
        $fullname = "$filepath\$filename"
        $filekeys = $newfile.keys.key

        if (Test-Path $filepath) {
            Write-Verbose "`tINFO: replacing file: $fullname"
        }
        else {
            Write-Verbose "`tINFO: creating file: $fullname"
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
        $data | Out-File $fullname
    } # foreach
}

function Install-WsusRole {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$False)]
            [string] $AlternateSource=""
    )
    Write-Verbose "[install-wsusrole]"
    $time1 = Get-Date
    $roles =@('UpdateServices-Services','UpdateServices-DB','UpdateServices-RSAT')
    $roles | 
        Foreach-Object {
            $FeatureCode = $_.ToString()
            Write-Verbose "INFO: installing role or feature: $FeatureCode"
            try {
                if ($AlternateSource -ne "") {
                    $exitcode = Install-WindowsFeature -Name $FeatureCode -IncludeManagementTools -Source $AlternateSource -ErrorAction Stop
                }
                else {
                    $exitcode = Install-WindowsFeature -Name $FeatureCode -IncludeManagementTools -ErrorAction Stop
                }
                Write-Output "INFO: $FeatureCode exitcode: $exitcode"
            }
            catch {
                Write-Warning "ERROR: failed to add role or feature: $FeatureCode"
                Write-Warning "ERROR: $($error[0].Exception)"
            }
        } # foreach-object
    Write-Verbose "INFO: wsus installation completed"
    if (Test-PendingReboot) {
        if ($NoReboot) {
            Write-Host "Reboot is required but suppressed" -ForegroundColor Cyan
        }
        else {
            Write-Host "Reboot server now" -ForegroundColor Magenta
            Stop-Transcript
            Restart-Computer
        }
    }
    Get-TimeOffset -StartTime $time1
}

function Set-WsusConfiguration {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [string] $UpdatesFolder
    )
    Write-Verbose "[set-wsusconfiguration]"
    $time1 = Get-Date
    Write-Output "INFO: invoking wsus post installation setup..."
    $sqlhost = "$($env:COMPUTERNAME).$($env:USERDNSDOMAIN)"
    write-output "INFO: wsus SQL_INSTANCE_NAME=$sqlhost"
    write-output "INFO: wsus CONTENT_DIR=$UpdatesFolder"
    try {
        & 'C:\Program Files\Update Services\Tools\WsusUtil.exe' postinstall SQL_INSTANCE_NAME=$sqlhost CONTENT_DIR=$UpdatesFolder | Out-Null
        Set-CMBuildRegVal -KeyName WSUSCONFIG -Value $(Get-Date)
    }
    catch {
        Write-Warning "ERROR: Unable to invoke WSUS post-install configuration"
    }
    Get-TimeOffset -StartTime $time1
}

function Set-SqlConfiguration {
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$False)]
            [int]$MemRatio = 80
    )
    Write-Verbose "[set-sqlconfiguration]"
    $time1 = Get-Date
    Write-Verbose "INFO: Memory Ratio: $MemRatio percent of total physical memory"
    $dblRatio = $MemRatio * 0.01
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module dbatools -SkipPublisherCheck -Force
    Write-Host "Configuring server memory limits..." -ForegroundColor Green
    $TotalMem = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty TotalPhysicalMemory)
    $actMax   = [math]::Round($TotalMem/1GB,0)
    $newMax   = [math]::Round(($TotalMem / 1MB)*$dblRatio,0)
    $curMax   = Get-DbaMaxMemory -SqlServer (&hostname)
    if ($actMax -lt 7) {
        Write-Warning "System has $actMax GB of memory - SQL Config cannot be optimized"
        $result = 0
    }
    elseif ($curMax -ne $newMax) {
        try {
            Set-DbaMaxMemory -SqlServer (&hostname) -MaxMb $newMax
            Write-Verbose "INFO: maximum memory allocation is now: $newMax"
            Set-CMBuildRegVal -KeyName SQLCONFIG -Value $(Get-Date)
            $result = 0
        }
        catch {
            Write-Warning "unable to change memory allocation"
        }
    }
    Get-TimeOffset -StartTime $time1
    Write-Output $result
}

function Invoke-Scripts {
    param ($DataSet)
    Write-Verbose "[invoke-scripts]"
    $scripts = $xmldata.configuration.scripts.script | Where-Object {$_.enabled -eq "true"}
    foreach ($script in $scripts) {
        $xtime1     = Get-Date
        $appName    = $script.name
        $scriptName = $script.file
        $scriptPath = $script.source
        $scriptArgs = $script.params
        $installDir = $script.target
        $appDetect  = $script.detect
        $DoReboot   = $script.reboot
        Write-Verbose "`tPackage.....: $appName"
        Write-Verbose "`tscriptName..: $scriptName"
        Write-Verbose "`tscriptPath..: $scriptPath"
        Write-Verbose "`tscriptArgs..: $scriptArgs"
        Write-Verbose "`tinstallDir..: $installDir"
        
        $continue = $False

        if ($appDetect -ne "") {
            Write-Verbose "`tdetection...: $appDetect"
            if (Test-Path $appDetect) {
                Write-Verbose "`tdetection...: $appName is already installed (skipping)"
            }
            else {
                Write-Verbose "`tdetection...: $appName is not installed"
                $continue = $True
            }
        }
        else {
            $continue = $True
        }
        if ($continue) {
            Write-Verbose "`tinstalling..: $appName"
            if ($scriptName -eq 'payload') {
                $result = Install-Payload -Name $appName -SourceFile $scriptPath -OptionParams $scriptArgs
            }
            elseif ($scriptName -eq 'serverroles') {
                $altpath = $xmldata.configuration.general.altsource.path
                $result = Install-ServerRoles -AlternateSource $altpath
            }
            elseif ($scriptName -eq 'configsql') {
                $result = Set-SqlConfiguration
            }
            elseif ($scriptName -eq 'configwsus') {
                $altpath = $xmldata.configuration.general.altsource.path
                $result = Install-WsusRole -AlternateSource $altpath
                $result = Set-WsusConfiguration
            }
            elseif (Test-Path $scriptName) {
                Write-Output "running: $scriptName"
                $Package = ".\$scriptName -Name `"$appName`""
                if ($scriptPath -ne "") {
                    $Package += " -SourceFile `"$scriptPath`""
                }
                if ($scriptArgs -ne "") {
                    $Package += " -OptionParams `"$scriptArgs`""
                }
                if ($installDir -ne "") {
                    $Package += " -InstallPath `"$installDir`""
                }
                $Package += ';$?'
                Write-Verbose "executing: $Package"
                try {
                    $result = Invoke-Expression "& $Package" -ErrorAction Stop
                    Write-Output "script completed: $result"
                }
                catch {
                    Write-Warning "failed to execute installation: $scriptName"
                    Write-Warning "Error: $($error[0].Exception)"
                    break
                }
                if ($result -ne 0) {
                    Write-Error $error[0]
                    break
                }
                if ($DoReboot -eq "true") {
                    Write-Output "restarting computer now"
                    Stop-Transcript
                    Restart-Computer
                }
            }
            else {
                Write-Warning "script file not found: $scriptName"
                break
            }
        }
        Get-TimeOffset -StartTime $xtime1
        Write-Verbose "-------------------------------------"
    } # foreach
}


Write-Verbose "BEGIN EXECUTION..."
if ($NoCheck) {
    Write-Verbose "info: platform validation skipped"
}
elseif (-not(Test-Platform)) {
    Write-Error "FAIL: Unable to continue - system is not supported"
    break
}
Set-CMBuildRegVal -KeyName "GENERAL" -Value $(Get-Date)
$xmldata = Import-ConfigData
Write-Folders -DataSet $xmldata
Write-NewFiles -DataSet $xmldata
Invoke-Scripts -DataSet $xmldata

$result = "completed"
Stop-Transcript
Write-Output $result
