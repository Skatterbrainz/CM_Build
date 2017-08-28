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
    1.1.43 - DS - 2017.08.27
    1.1.0  - DS - 2017.08.16
    1.0.0  - DS - 2017.08.14
    
    Read the associated XML to make sure the path and filename values
    all match up like you need them to.

.EXAMPLE
    .\cm_build.ps1 -XmlFile .\cm_build.xml -Verbose
    .\cm_build.ps1 -XmlFile .\cm_build.xml -NoCheck -NoReboot -Verbose
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
$ScriptVersion = '1.1.43'
$basekey  = 'HKLM:\SOFTWARE\CM_BUILD'
$RunTime1 = Get-Date

function Get-ScriptDirectory {
    $Invocation = (Get-Variable MyInvocation -Scope 1).Value
    Split-Path $Invocation.MyCommand.Path
}
function Write-Log {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$True)]
            [ValidateSet('info','error','warning')]
            [string] $Category,
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [string] $Message
    )
    Write-Verbose "$(Get-Date -f 'yyyy-M-dd HH:MM:ss')`t$Category`t$Message"
    "$(Get-Date -f 'yyyy-M-dd HH:MM:ss')  $Category  $Message" | Out-File -FilePath $logFile -Append -Force
}

$ScriptPath   = Get-ScriptDirectory
$successcodes = (0,1003,3010,1605,1618,1641,1707)
$LogsFolder   = "$ScriptPath\Logs"
if (-not(Test-Path $LogsFolder)) {New-Item -Path $LogsFolder -Type Directory}
$tsFile  = "$LogsFolder\cm_build_$($env:COMPUTERNAME)_transaction.log"
$logFile = "$LogsFolder\cm_build_$($env:COMPUTERNAME)_details.log"

try {
    Start-Transcript -Path $tsFile
}
catch {
    Write-Error $error[0]
    break
}

Write-Log -Category "info" -Message "------------------- BEGIN $(Get-Date) -------------------"
Write-Log -Category "info" -Message "script version = $ScriptVersion"
Write-Log -Category "info" -Message "importing required modules"

try {Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -ErrorAction Stop}
catch {}
if (Get-Module -ListAvailable -Name PowerShellGet) {
    Write-Log -Category "info" -Message "PowerShellGet module is already installed"
}
else {
    Write-Log -Category "info" -Message "installing PowerShellGet module"
    Install-Module -Name PowerShellGet
}
if (Get-Module -ListAvailable -Name dbatools) {
    Write-Log -Category "info" -Message "dbatools module is already installed"
}
else {
    Write-Log -Category "info" -Message "installing dbatools module"
    Install-Module dbatools -SkipPublisherCheck -Force
}

Clear-Host
Write-Log -Category "info" -Message "defining internal functions"

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

function Test-Platform {
    param ()
    Write-Log -Category "info" -Message "function: test-platform"
    $os = Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty caption
    if (($os -like "*Windows Server 2012 R2*") -or ($os -like "*Windows Server 2016*")) {
        Write-Log -Category "info" -Message "passed rule = operating system"
        $mem = [math]::Round($(Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty TotalPhysicalMemory)/1GB,0)
        if ($mem -ge 8) {
            Write-Log -Category "info" -Message "passed rule = minimmum memory allocation"
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

function Set-CMBuildTaskCompleted {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [string] $KeyName, 
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [string] $Value
    )
    Write-Log -Category "info" -Message "function: Set-CMBuildTaskCompleted"
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
        Write-Log -Category "info" -Message "writing registry key $KeyName"
    }
    catch {
        Write-Log -Category "error" -Message "failed to write to registry!"
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

function Get-CMBuildConfigData {
    param (
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [string] $XmlFile
    )
    Write-Host "Loading configuration data" -ForegroundColor Green
    Write-Log -Category "info" -Message "[function:Get-CMBuildConfigData] loading xml data from: $XmlFile"
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

function Set-CMBuildFolders {
    [CmdletBinding()]
    param($Folders)
    Write-Host "Configuring folders" -ForegroundColor Green
    Write-Log -Category "info" -Message "----------------------------------------------------"
    Write-Log -Category "info" -Message "[function: Set-CMBuildFolders]"
    $result = $True
    foreach ($folder in $Folders) {
        $folderName = $folder.name
        foreach ($fn in $folderName.split(',')) {
            if (-not(Test-Path $fn)) {
                Write-Log -Category "info" -Message "creating folder: $fn"
                try {
                    New-Item -Path $fn -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
                    $WaitAfter = $True
                }
                catch {
                    Write-Warning "error: unable to create folder: $fn"
                    $result = $False
                }
            }
            else {
                Write-Log -Category "info" -Message "folder already exists: $fn"
            }
        }
    }
    if ($WaitAfter) {
        Write-Log -Category "info" -Message "pausing for 5 seconds"
        Start-Sleep -Seconds 5
    }
    Write-Log -Category "info" -Message "function result = $result"
    Write-Output $result
}

function Set-CMBuildFiles {
    [CmdletBinding()]
    param ($Files)
    Write-Host "Configuring files" -ForegroundColor Green
    Write-Log -Category "info" -Message "----------------------------------------------------"
    Write-Log -Category "info" -Message "[function: Set-CMBuildFiles]"
    $result = $True
    foreach ($fileSet in $Files) {
        $filename = $fileSet.name
        $filepath = $fileSet.path 
        $fullName = "$filePath\$filename"
        $fileComm = $fileSet.comment 
        $filekeys = $fileSet.keys.key
        Write-Log -Category "info" -Message "filename: $fullName"
        Write-Log -Category "info" -Message "tcomment: $fileComm"
        if (-not (Test-Path $fullName)) {
            Write-Log -Category "info" -Message "creating new file: $fullName"
        }
        else {
            Write-Log -Category "info" -Message "overwriting file: $fullName"
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
    Write-Log -Category "info" -Message "function result = $result"
    Write-Output $result
}

function Install-CMBuildServerRoles {
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
            [string] $LogFile = "serverroles.log"
    )
    Write-Host "Installing Windows Server Roles and Features" -ForegroundColor Green
    Write-Log -Category "info" -Message "----------------------------------------------------"
    Write-Log -Category "info" -Message "[function: Install-CMBuildServerRoles]"
    $time1  = Get-Date
    $result = 0
    $FeaturesList | 
    Foreach-Object {
        $FeatureCode = $_
        Write-Log -Category "info" -Message "installing feature: $FeatureCode"
        $time3 = Get-Date
        if ($AlternateSource -ne "") {
            Write-Log -Category "info" -Message "referencing alternate windows content source"
            try {
                $output   = Install-WindowsFeature -Name $FeatureCode -LogPath "$LogsFolder\$LogFile" -Source $AlternateSource
                $exitcode = $output.ExitCode.Value__
                if ($successcodes.Contains($exitcode)) {
                    $result = 0
                }
                else {
                    Write-Log -Category "error" -Message "installation of $FeatureCode failed with exit code: $exitcode"
                    $result = -1
                }
            }
            catch {
                Write-Log -Category "error" -Message "installation of $FeatureCode failed horribly!"
                $_
                $result = -2
            }
            Write-Log -Category "info" -Message "$FeatureCode exitcode: $exitcode"
        }
        else {
            try {
                $output   = Install-WindowsFeature -Name $FeatureCode -LogPath "$LogsFolder\$LogFile"
                $exitcode = $output.ExitCode.Value__
                if ($successcodes.Contains($exitcode)) {
                    $result = 0
                }
                else {
                    Write-Log -Category "error" -Message "installation of $FeatureCode failed with exit code: $exitcode"
                    $result = -1
                }
            }
            catch {
                Write-Log -Category "error" -Message "installation of $FeatureCode failed horribly!"
                $_
                $result = -2
            }
            Write-Log -Category "info" -Message "$FeatureCode exitcode: $exitcode"
        } # if
        $time4 = Get-TimeOffset -StartTime $time3
        Write-Log -Category "info" -Message "internal : $FeatureCode runtime = $time4"
    } # foreach-object

    Write-Log -Category "info" -Message "result = $result"
    if ($result -eq 0) {
        Set-CMBuildTaskCompleted -KeyName 'SERVERROLES' -Value $(Get-Date)
    }
    $time2 = Get-TimeOffset -StartTime $time1
    Write-Log -Category "info" -Message "function runtime = $time2"
    Write-Output $result
}

function Install-CMBuildServerRolesFile {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [string] $PackageName,
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [string] $PackageFile,
        [parameter(Mandatory=$False)]
            [string] $LogFile = "serverrolesfile.log"
    )
    Write-Host "Installing Windows Server Roles and Features" -ForegroundColor Green
    Write-Log -Category "info" -Message "----------------------------------------------------"
    Write-Log -Category "info" -Message "[function: Install-CMBuildServerRolesfile]"
    if (Test-Path $PackageFile) {
        if ($AltSource -ne "") {
            Write-Log -Category "info" -Message "referencing alternate windows content source"
            try {
                Write-Log -Category "info" -Message "installing features from configuration file: $PackageFile using alternate source"
                $result = Install-WindowsFeature -ConfigurationFilePath $PackageFile -LogPath "$LogsFolder\$LogFile" -Source $AltSource -ErrorAction Continue
                if ($successcodes.Contains($result.ExitCode.Value__)) {
                    $result = 0
                    Set-CMBuildTaskCompleted -KeyName $PackageName -Value $(Get-Date)
                    Write-Log -Category "info" -Message "installion was successful"
                }
                else {
                    Write-Log -Category "error" -Message "failed to install features!"
                    Write-Log -Category "error" -Message "result: $($result.ExitCode.Value__)"
                    $result = -1
                }
            }
            catch {
                Write-Error $_
                break
            }
        }
        else {
            try {
                Write-Log -Category "info" -Message "installing features from configuration file: $PackageFile"
                $result = Install-WindowsFeature -ConfigurationFilePath $PackageFile -LogPath "$LogsFolder\$LogFile" -ErrorAction Continue | Out-Null
                if ($successcodes.Contains($result.ExitCode.Value__)) {
                    $result = 0
                    Set-CMBuildTaskCompleted -KeyName $PackageName -Value $(Get-Date)
                    Write-Log -Category "info" -Message "installion was successful"
                }
                else {
                    Write-Log -Category "error" -Message "failed to install features!"
                    Write-Log -Category "error" -Message "result: $($result.ExitCode.Value__)"
                    $result = -1
                }
            }
            catch {
                Write-Log -Category "error" -Message "failed to install features!"
                Write-Error $_
                break
            }
        }
    }
    else {
        Write-Warning "ERROR: role configuration file $PackageFile was not found!"
        break
    }
    Write-Output $result
}

function Set-CMBuildWsusConfiguration {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [string] $UpdatesFolder
    )
    Write-Log -Category "info" -Message "----------------------------------------------------"
    Write-Log -Category "info" -Message "[function: Set-CMBuildWsusConfiguration]"
    $time1 = Get-Date
    Write-Log -Category "info" -Message "verifying WSUS role installation for SQL database connectivity"
    if (-not ((Get-WindowsFeature UpdateServices-DB | Select-Object -ExpandProperty Installed) -eq $True)) {
        Write-Log -Category "error" -Message "WSUS is not installed properly (aborting)"
        break
    }
    $sqlhost = "$($env:COMPUTERNAME).$($env:USERDNSDOMAIN)"
    Write-Log -Category "info" -Message "wsus SQL_INSTANCE_NAME=$sqlhost"
    Write-Log -Category "info" -Message "wsus CONTENT_DIR=$UpdatesFolder"
    try {
        & 'C:\Program Files\Update Services\Tools\WsusUtil.exe' postinstall SQL_INSTANCE_NAME=$sqlhost CONTENT_DIR=$UpdatesFolder | Out-Null
        $result = 0
    }
    catch {
        Write-Warning "ERROR: Unable to invoke WSUS post-install configuration"
    }
    $time2 = Get-TimeOffset -StartTime $time1
    Write-Log -Category "info" -Message "function runtime = $time2"
    Write-Output $result
}

function Set-CMBuildSqlConfiguration {
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$False)]
            [int] $MemRatio = 80
    )
    Write-Log -Category "info" -Message "----------------------------------------------------"
    Write-Log -Category "info" -Message "function: Set-CMBuildSqlConfiguration"
    Write-Log -Category "info" -Message "SQL MemRatio = $MemRatio"
    $time1 = Get-Date
    $dblRatio = $MemRatio * 0.01
    $TotalMem = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty TotalPhysicalMemory)
    $actMax   = [math]::Round($TotalMem/1GB,0)
    $newMax   = [math]::Round(($TotalMem / 1MB)*$dblRatio,0)
    $curMax   = Get-DbaMaxMemory -SqlServer (&hostname)
    Write-Log -Category "info" -Message "total memory is $actMax GB"
    Write-Log -Category "info" -Message "recommended SQL max is $newMax GB"
    Write-Log -Category "info" -Message "current SQL max is $curMax GB"
    if ($actMax -lt 7) {
        Write-Log -Category "warning" -Message "Server has $actMax GB of memory - SQL Config cannot be optimized"
        $result = 0
    }
    elseif ($curMax -ne $newMax) {
        try {
            Set-DbaMaxMemory -SqlServer (&hostname) -MaxMb $newMax
            Write-Log -Category "info" -Message "maximum memory allocation is now: $newMax"
            Set-CMBuildTaskCompleted -KeyName 'SQLCONFIG' -Value $(Get-Date)
            $result = 0
        }
        catch {
            Write-Log -Category "warning" -Message "unable to change memory allocation"
        }
    }
    $time2 = Get-TimeOffset -StartTime $time1
    Write-Log -Category "info" -Message "function runtime = $time2"
    Write-Output $result
}

function Install-CMBuildPayload {
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
    Write-Log -Category "info" -Message "----------------------------------------------------"
    Write-Log -Category "info" -Message "function: Install-CMBuildPayload"
    Write-Log -Category "info" -Message "payload name..... $Name"
    Write-Log -Category "info" -Message "sourcefile....... $SourceFile"
    Write-Log -Category "info" -Message "input arguments.. $OptionParams"
    
    if (-not(Test-Path $SourceFile)) {
        Write-Log -Category "error" -Message "source file not found: $SourceFile"
        Write-Output -1
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
    Write-Log -Category "info" -Message "source file...... $SourceFile"
    Write-Log -Category "info" -Message "new arguments.... $ArgList"
    $time1 = Get-Date
    $result = 0
    try {
        $p = Start-Process -FilePath $SourceFile -ArgumentList $ArgList -NoNewWindow -Wait -PassThru -ErrorAction Continue
        if ((0,3010,1605,1641,1618,1707).Contains($p.ExitCode)) {
            Write-Log -Category "info" -Message "aggregating a success code."
            Set-CMBuildTaskCompleted -KeyName $Name -Value $(Get-Date)
            $result = 0
        }
        else {
            Write-Log -Category "info" -Message "internal : exit code = $($p.ExitCode)"
            $result = $p.ExitCode
        }
    }
    catch {
        Write-Warning "error: failed to execute installation: $Name"
        Write-Warning "error: $($error[0].Exception)"
        Write-Log -Category "error" -Message "internal : exit code = -1"
        $result = -1
    }
    if (Test-PendingReboot) {
        if ($NoReboot) {
            Write-Host "Reboot is required but suppressed" -ForegroundColor Cyan
        }
        else {
            Write-Host "Reboot will be requested" -ForegroundColor Magenta
        }
    }
    $time2 = Get-TimeOffset -StartTime $time1
    Write-Log -Category "info" -Message "function runtime = $time2"
    Write-Log -Category "info" -Message "function result = $result"
    Write-Output $result
}

function Get-WsusUpdatesPath {
    param ($FolderSet)
    $fpath = $FolderSet | Where-Object {$_.comment -like 'WSUS*'} | Select-Object -ExpandProperty name
    if (-not($fpath) -or ($fpath -eq "")) {
        Write-Warning "error: missing WSUS updates storage path setting in XML file. Refer to FOLDERS section."
        break
    }
    Write-Output $fpath
}

function Invoke-BPAtest {
    [CmdletBinding()]
    param ($FeatureCode)
    Import-module BestPractices
    switch ($FeatureCode) {
        'WSUS' {
            # ref: https://blogs.technet.microsoft.com/heyscriptingguy/2013/04/15/installing-wsus-on-windows-server-2012/
            Invoke-BpaModel -ModelId Microsoft/Windows/UpdateServices
            Get-BpaResult -ModelId Microsoft/Windows/UpdateServices |
                Select-Object Title,Severity,Compliance | Format-List
            break
        }
    }
}

function Invoke-CMBuildRegKeys {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$True)]
            $DataSet,
        [parameter(Mandatory=$True)]
            [ValidateSet('before','after')]
            [string] $Order
    )
    Write-Host "Configuring registry keys" -ForegroundColor Green
    Write-Log -Category "info" -Message "----------------------------------------------------"
    Write-Log -Category "info" -Message "[function: Invoke-CMBuildRegKeys]"
    Write-Log -Category "info" -Message "keygroup order = $Order"

    $keys = $DataSet | Where-Object {$_.enabled -eq 'true'}
    foreach ($key in $keys) {
        $regName  = $key.name
        $regOrder = $key.order
        $reg = $null
        if ($regOrder -eq $Order) {
            $regPath = $key.path
            $regVal  = $key.value
            $regData = $key.data
            switch ($regPath.substring(0,4)) {
                'HKLM' {
                    try {
                        $reg = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,'default')
                        Write-Log -Category "info" -Message "opened registry hive $($regPath.Substring(0,4)) successfully"
                    }
                    catch {
                        $_
                    }
                    break
                }
            }
            if ($reg) {
                try {
                    $keyset = $reg.OpenSubKey($regPath.Substring(6))
                    $val = $keyset.GetValue($regVal)
                    Write-Log -Category "info" -Message "current value = $val"
                    if (!!(Get-Item -Path $regPath)) {
                        Write-Log -Category "info" -Message "registry key path exists: $regPath"
                    }
                    else {
                        Write-Log -Category "info" -Message "registry key path not found, creating: $regPath"
                        New-Item -Path $regPath -Force | Out-Null
                    }
                    Write-Log -Category "info" -Message "adding/updating registry value: $regVal --> $regData"
                    New-ItemProperty -Path $regPath -Name $regVal -Value $regData -PropertyType STRING -Force | Out-Null
                    $keyset = $reg.OpenSubKey($regPath.Substring(6))
                    $val = $keyset.GetValue($regVal)
                    Write-Log -Category "info" -Message "registry value updated: $val"
                }
                catch {}
            }
        }
    }
}

function Test-CMBuildPackage {
    param (
        [parameter(Mandatory=$False)]
        [string] $PackageName = ""
    )
    Write-Log -Category "info" -Message "[function: Test-CMBuildPackage]"
    $detRule = $detects | Where-Object {$_.name -eq $PackageName}
    if (($detRule) -and ($detRule -ne "")) {
        Write-Output (Test-Path $detRule)
    }
    else {
        Write-Output $True
    }
}

function Invoke-CMBuildPackage {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$True)]
            [string] $Name,
        [parameter(Mandatory=$True)]
            [string] $PackageType,
        [parameter(Mandatory=$False)]
            [string] $PayloadSource="",
        [parameter(Mandatory=$False)]
            [string] $PayloadFile="",
        [parameter(Mandatory=$False)]
            [string] $PayloadArguments=""
    )
    Write-Log -Category "info" -Message "function: invoke-cmbuildpackage"
    Write-Log -Category "info" -Message "package type = $PackageType"
    switch ($PackageType) {
        'feature' {
            Write-Log -Category "info" -Message "installation feature = $Name"
            Write-Host "Installing $pkgComm" -ForegroundColor Green
            $xdata = ($xmldata.configuration.features.feature | 
                Where-Object {$_.name -eq $Name} | 
                    Foreach-Object {$_.innerText}).Split(',')
            $result = Install-CMBuildServerRoles -RoleName $Name -FeaturesList $xdata -AlternateSource $AltSource
            Write-Log -Category "info" -Message "exit code = $result"
            Set-CMBuildTaskCompleted -KeyName $Name -Value $(Get-Date)
            break
        }
        'function' {
            $result = Invoke-CMBuildFunction -Name $Name -Comment $pkgComm
            if ($result -ne 0) {
                Write-Warning "error: step failure [function] at: $Name"
                $continue = $False
            }
            break
        }
        'payload' {
            $result = Invoke-CMBuildPayload -Name $Name -SourcePath $PayloadSource -PayloadFile $PayloadFile -PayloadArguments $PayloadArguments
            if ($result -ne 0) {
                Write-Warning "error: step failure [payload] at: $Name"
                $continue = $False
            }
            break
        }
        default {
            Write-Warning "invalid package type value: $PackageType"
            break
        }
    } # switch
    Write-Log -Category "info" -Message "function result = $result"
    Write-Output $result
}

function Invoke-CMBuildPayload {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [string] $Name,
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]    
            [string] $SourcePath,
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [string] $PayloadFile,
        [parameter(Mandatory=$False)]
            [string] $PayloadArguments = "",
        [parameter(Mandatory=$False)]
            [string] $Comment = ""
    )
    Write-Host "Installing $Name" -ForegroundColor Green
    Write-Log -Category "info" -Message "installation payload = $Name"
    Write-Log -Category "info" -Message "comment = $Comment"
    switch ($pkgName) {
        'CONFIGMGR' {
            Write-Host "Tip: Monitor C:\ConfigMgrSetup.log for progress" -ForegroundColor Green
            $runFile = "$SourcePath\$PayloadFile"
            $x = Install-CMBuildPayload -Name $Name -SourceFile $runFile -OptionParams $PayloadArguments
            Write-Log -Category "info" -Message "exit code = $x"
            break
        }
        'SQLSERVER' {
            Write-Host "Tip: Monitor $($env:PROGRAMFILES)\Microsoft SQL Server\130\Setup Bootstrap\Logs\summary.txt for progress" -ForegroundColor Green
            $runFile = "$SourcePath\$PayloadFile"
            $x = Install-CMBuildPayload -Name $Name -SourceFile $runFile -OptionParams $PayloadArguments
            Write-Log -Category "info" -Message "exit code = $x"
            break
        }
        'SERVERROLES' {
            $runFile = "$((Get-ChildItem $xmlfile).DirectoryName)\$PayloadFile"
            $x = Install-CMBuildServerRolesFile -PackageName $Name -PackageFile $runFile
            Write-Log -Category "info" -Message "exit code = $x"
            break
        }
        default {
            $runFile = "$SourcePath\$PayloadFile"
            $x = Install-CMBuildPayload -Name $Name -SourceFile $runFile -OptionParams $PayloadArguments
            Write-Log -Category "info" -Message "exit code = $x"
            break
        }
    } # switch
    Write-Log -Category "info" -Message "function result = $result"
    Write-Output $x
} 

function Invoke-CMBuildFunction {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [string] $Name,
        [parameter(Mandatory=$False)]
            [string] $Comment=""
    )
    Write-Log -Category "info" -Message "installation function = $Name"
    switch ($Name) {
        'SQLCONFIG' {
            Write-Host "$Comment" -ForegroundColor Green
            $result = Set-CMBuildSqlConfiguration
            Write-Verbose "info: exit code = $result"
            Set-CMBuildTaskCompleted -KeyName $Name -Value $(Get-Date)
            break
        }
        'WSUSCONFIG' {
            Write-Host "$Comment" -ForegroundColor Green
            $fpath = Get-WsusUpdatesPath -FolderSet $xmldata.configuration.folders.folder
            if (-not($fpath)) {
                $result = -1
                break
            }
            $result = Set-CMBuildWsusConfiguration -UpdatesFolder $fpath
            Write-Verbose "info: exit code = $result"
            Set-CMBuildTaskCompleted -KeyName $Name -Value $(Get-Date)
            break
        }
        default {
            Write-Warning "There is no function mapping for: $Name"
            break
        }
    } # switch
    Write-Log -Category "info" -Message "function result = $result"
    Write-Output $result
}

function Disable-InternetExplorerESC {
    Write-Verbose "----------------------------------------------------"
    Write-Log -Category "info" -Message "Disabling IE Enhanced Security Configuration."
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey  = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    if ((Get-ItemProperty -Path $AdminKey -Name "IsInstalled" | Select-Object -ExpandProperty IsInstalled) -ne 0) {
        try {
            Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force
            Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 -Force
            Stop-Process -Name Explorer -Force
            Write-Output 0
        }
        catch {Write-Output -1}
        Write-Log -Category "info" -Message "IE Enhanced Security Configuration (ESC) has been disabled."
    }
    else {
        Write-Log -Category "info" -Message "IE Enhanced Security Configuration (ESC) is already disabled."
    }
}

function Enable-InternetExplorerESC {
    Write-Verbose "----------------------------------------------------"
    Write-Log -Category "info" -Message "Enabling IE Enhanced Security Configuration."
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey  = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    if ((Get-ItemProperty -Path $AdminKey -Name "IsInstalled" | Select-Object -ExpandProperty IsInstalled) -ne 1) {
        try {
            Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 1 -Force
            Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 1 -Force
            Stop-Process -Name Explorer -Force
            Write-Log -Category "info" -Message "IE Enhanced Security Configuration (ESC) has been enabled."
        }
        catch {Write-Output -1}
    }
    else {
        Write-Log -Category "info" -Message "IE Enhanced Security Configuration (ESC) is already enabled."
    }
}

function Disable-UserAccessControl {
    Write-Verbose "----------------------------------------------------"
    Write-Log -Category "info" -Message "Disabling User Access Control (UAC)."
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000 -Force
    Write-Log -Category "info" -Message "User Access Control (UAC) has been disabled."
}

function Get-CMBuildInstallState {
    param (
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [string] $PackageName,
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [string] $RuleType, 
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [string] $RuleData
    )
    Write-Log -Category "info" -Message "[function: Get-CMBuildInstallState]"
    Write-Log -Category "info" -Message "detection type = $RuleType"
    Write-Log -Category "info" -Message "detection rule = $RuleData"
    switch ($RuleType.ToLower()) {
        'automatic' {
            $result = (Test-Path $RuleData)
            break
        }
        'synthetic' {
            $detPath = "$RuleData\$PackageName"
            Write-Log -Category "info" -Message "detection rule = $detPath"
            $result  = (Test-Path $detPath)
            break
        }
        'feature' {
            try {
                $result = ((Get-WindowsFeature $RuleData | Select-Object -ExpandProperty Installed) -eq $True)
            }
            catch {}
            break
        }
    }
    Write-Log -Category "info" -Message "function result = $result"
    Write-Output $result
}

# end-functions

[xml]$xmldata = Get-CMBuildConfigData $XmlFile
Write-Log -Category "info" -Message "----------------------------------------------------"
Set-CMBuildTaskCompleted -KeyName 'START' -Value $(Get-Date)

$project   = $xmldata.configuration.project
$AltSource = $xmldata.configuration.references.reference | 
    Where-Object {$_.name -eq 'WindowsServer'} | 
        Select-Object -ExpandProperty path
Write-Log -Category "info" -Message "alternate windows source = $AltSource"

Set-Location $env:USERPROFILE

Write-Log -Category "info" -Message "----------------------------------------------------"
Write-Log -Category "info" -Message "project info....... $($project.comment)"

if (-not (Set-CMBuildFolders -Folders $xmldata.configuration.folders.folder)) {
    Write-Warning "error: failed to create folders (aborting)"
    break
}
if (-not (Set-CMBuildFiles -Files $xmldata.configuration.files.file)) {
    Write-Warning "error: failed to create files (aborting)"
    break
}

Write-Host "Executing project configuration" -ForegroundColor Green

Disable-InternetExplorerESC | Out-Null
Invoke-CMBuildRegKeys -DataSet $xmldata.configuration.regkeys.regkey -Order "before" | Out-Null

Write-Log -Category "info" -Message "beginning package execution"
Write-Log -Category "info" -Message "----------------------------------------------------"
$continue = $True

foreach ($package in $xmldata.configuration.packages.package | Where-Object {$_.enabled -eq 'true'}) {
    if ($continue) {
        $pkgName  = $package.name
        $pkgType  = $package.type 
        $pkgComm  = $package.comment 
        $payload  = $xmldata.configuration.payloads.payload | Where-Object {$_.name -eq $pkgName}
        $pkgSrc   = $payload.path 
        $pkgFile  = $payload.file
        $pkgArgs  = $payload.params
        $detRule  = $xmldata.configuration.detections.detect | Where-Object {$_.name -eq $pkgName}
        $detPath  = $detRule.path
        $detType  = $detRule.type
        $depends  = $package.dependson

        Write-Log -Category "info" -Message "package name.... $pkgName"
        Write-Log -Category "info" -Message "package type.... $pkgType"
        Write-Log -Category "info" -Message "package comment. $pkgComm"
        Write-Log -Category "info" -Message "payload source.. $pkgSrc"
        Write-Log -Category "info" -Message "payload file.... $pkgFile"
        Write-Log -Category "info" -Message "payload args.... $pkgArgs"
        Write-Log -Category "info" -Message "rule type....... $detType"

        if (!(Test-CMBuildPackage -PackageName $dependson)) {
            Write-Log -Category "error" -Message "dependency missing: $depends"
            $continue = $False
            break
        }
        if (($detType -eq "") -or ($detPath -eq "") -or (-not($detPath))) {
            Write-Log -Category "error" -Message "detection rule is missing for $pkgName (aborting)"
            $continue = $False
            break
        }
        $installed = $False
        $installed = Get-CMBuildInstallState -PackageName $pkgName -RuleType $detType -RuleData $detPath
        if ($installed) {
            Write-Log -Category "info" -Message "install state... $pkgName is INSTALLED"
        }
        else {
            Write-Log -Category "info" -Message "install state... $pkgName is NOT INSTALLED"
            $x = Invoke-CMBuildPackage -Name $pkgName -PackageType $pkgType -PayloadSource $pkgSrc -PayloadFile $pkgFile -PayloadArguments $pkgArgs
            if ($x -ne 0) {$continue = $False; break}
        }
        Write-Log -Category "info" -Message "----------------------------------------------------"
    }
    else {
        Write-Warning "STOP! aborted at step [$pkgName] $(Get-Date)"
        break
    }
} # foreach

Invoke-CMBuildRegKeys -DataSet $xmldata.configuration.regkeys.regkey -Order "after"

Write-Host "Processing finished at $(Get-Date)" -ForegroundColor Green
$RunTime2 = Get-TimeOffset -StartTime $RunTime1
Write-Log -Category "info" -Message "finished at $(Get-Date) - total runtime = $RunTime2"
if ((Test-PendingReboot) -and ($NoReboot)) {
    Write-Host "A REBOOT is REQUIRED" -ForegroundColor Cyan
#    Start-Sleep -Seconds 30
#    Restart-Computer -Force
}
Stop-Transcript
