#requires -RunAsAdministrator
#requires -version 3
#requires -modules ServerManager
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
.PARAMETER Detailed
    [switch](optional) Show verbose output
.NOTES
	1.3.04 - DS - 2017.10.05
    
    Read the associated XML to make sure the path and filename values
    all match up like you need them to.

.EXAMPLE
    .\cm_build.ps1 -XmlFile .\cm_build.xml -Verbose
    .\cm_build.ps1 -XmlFile .\cm_build.xml -NoCheck -NoReboot -Verbose
#>

[CmdletBinding()]
param (
    [parameter(Mandatory=$True, HelpMessage="Path or URI of XML input file")]
        [ValidateNotNullOrEmpty()]
        [string] $XmlFile,
    [parameter(Mandatory=$False, HelpMessage="Skip platform validation checking")]
        [switch] $NoCheck,
    [parameter(Mandatory=$False, HelpMessage="Suppress reboots")]
        [switch] $NoReboot,
    [parameter(Mandatory=$False, HelpMessage="Display verbose output")]
        [switch] $Detailed,
    [parameter(Mandatory=$False, HelpMessage="Override control set from XML file")]
        [switch] $Override
)
$ScriptVersion = '1.3.04'
$basekey  = 'HKLM:\SOFTWARE\CM_BUILD'
$RunTime1 = Get-Date
$HostFullName = "$($env:COMPUTERNAME).$($env:USERDNSDOMAIN)"

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
    if ($Detailed) {
        Write-Host "DETAILED`: $(Get-Date -f 'yyyy-M-dd HH:mm:ss')`t$Category`t$Message" -ForegroundColor Cyan
    }
}

$ScriptPath   = Get-ScriptDirectory
$successcodes = (0,1003,3010,1605,1618,1641,1707)
$LogsFolder   = "$ScriptPath\Logs"
$HostName     = $env:COMPUTERNAME
if (-not(Test-Path $LogsFolder)) {New-Item -Path $LogsFolder -Type Directory}
$tsFile  = "$LogsFolder\cm_build`_$HostName`_transaction.log"
$logFile = "$LogsFolder\cm_build`_$HostName`_details.log"

try {stop-transcript -ErrorAction SilentlyContinue} catch {}
try {Start-Transcript -Path $tsFile -Force} catch {}

Write-Log -Category "info" -Message "******************* BEGIN $(Get-Date) *******************"
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
if (Get-Module -ListAvailable -Name SqlServer) {
    Write-Log -Category "info" -Message "SqlServer module is already installed"
}
else {
    Write-Log -Category "info" -Message "installing SqlServer module"
    Install-Module SqlServer -Force -AllowClobber
}
if (Get-Module -ListAvailable -Name dbatools) {
    Write-Log -Category "info" -Message "DbaTools module is already installed"
}
else {
    Write-Log -Category "info" -Message "installing DbaTools module"
    Install-Module DbaTools -Force -AllowClobber
}
if (-not(Test-Path "c:\ProgramData\chocolatey\choco.exe")) {
    Write-Log -Category "info" -Message "installing chocolatey..."
    if ($WhatIfPreference) {
        Write-Log -Category "info" -Message "Chocolatey is not installed. Bummer dude. This script would attempt to install it first."
    }
    else {
        Invoke-Expression ((New-Object Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }
    Write-Log -Category "info" -Message "installation completed"
}
else {
    Write-Log -Category "info" -Message "chocolatey is already installed"
}
if (-not(Test-Path "c:\ProgramData\chocolatey\choco.exe")) {
	Write-Log -Category "error" -Message "chocolatey install failed!"
	break
}
if (-not(Get-Module -Name "Carbon")) {
	Write-Log -Category "info" -Message "installing Carbon package"
	cinst carbon -y
}
#Clear-Host
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

function Test-CMxPlatform {
    param ()
    Write-Log -Category "info" -Message "function: Test-CMxPlatform"
    $os = Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty caption
    if (($os -like "*Windows Server 2012 R2*") -or ($os -like "*Windows Server 2016*")) {
        Write-Log -Category "info" -Message "passed rule = operating system"
        $mem = [math]::Round($(Get-WmiObject -Class Win32_ComputerSystem | 
            Select-Object -ExpandProperty TotalPhysicalMemory)/1GB,0)
        if ($mem -ge 16) {
            Write-Log -Category "info" -Message "passed rule = minimmum memory allocation"
            Write-Output $True
        }
        else {
            Write-Host "FAIL: System has $mem GB of memory. ConfigMgr requires 16 GB of memory or more" -ForegroundColor Red
        }
    }
    else {
        Write-Host "FAIL: Operating System must be Windows Server 2012 R2 or 2016" -ForegroundColor Red
    }
}

function Set-CMxTaskCompleted {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [string] $KeyName, 
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [string] $Value
    )
    Write-Log -Category "info" -Message "function: Set-CMxTaskCompleted"
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

function Get-CMxConfigData {
    param (
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [string] $XmlFile
    )
    Write-Host "Loading configuration data" -ForegroundColor Green
    if ($XmlFile.StartsWith("http")) {
        try {
            [xml]$data = Invoke-RestMethod -Uri $XmlFile
            Write-Output $data
        }
        catch {
            Write-Log -Category "error" -Message "failed to import data from Uri: $XmlFile"
        }
    }
    else {
        if (-not(Test-Path $XmlFile)) {
            Write-Warning "ERROR: configuration file not found: $XmlFile"
        }
        else {
            try {
                [xml]$data = Get-Content $XmlFile
                Write-Output $data
            }
            catch {
                Write-Log -Category "error" -Message "failed to import data from file: $XmlFile"
            }
        }
    }
}
function Import-CMxFolders {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param(
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        $DataSet
    )
    Write-Host "Configuring folders" -ForegroundColor Green
    $result = $True
    $timex  = Get-Date
    foreach ($item in $DataSet.configuration.folders.folder | Where-Object {$_.use -eq '1'}) {
        $folderName = $item.name
        foreach ($fn in $folderName.split(',')) {
            if (-not(Test-Path $fn)) {
                Write-Log -Category "info" -Message "creating folder: $fn"
                try {
                    New-Item -Path $fn -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
                    $WaitAfter = $True
                }
                catch {
                    Write-Log -Category "error" -Message $_.Exception.Message
                    $result = $False
                    break
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
    Write-Log -Category "info" -Message "function runtime = $(Get-TimeOffset -StartTime $timex)"
    Write-Log -Category "info" -Message "function result = $result"
    Write-Output $result
}

function Import-CMxFiles {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        $DataSet
    )
    Write-Host "Configuring files" -ForegroundColor Green
    $result = $True
    $timex  = Get-Date
    foreach ($item in $DataSet.configuration.files.file | Where-Object {$_.use -eq '1'}) {
        $filename = $item.name
        $filepath = $item.path 
        $fullName = "$filePath\$filename"
        $fileComm = $item.comment 
        $filekeys = $item.keys.key
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
            $keyval  = Convert-CmxString $DataSet -Stringval $filekey.value
            if ($keyname.StartsWith('__')) {
                if ($data -ne "") {
                    $data += "`r`n`[$keyval`]`r`n"
                }
                else {
                    $data += "`[$keyval`]`r`n"
                }
            }
            else {
				if ($keyname -eq "SQLSYSADMINACCOUNTS") {
					$kv = $(foreach ($y in $keyval.split(',')) {'"' + $y + '"'}) -join " "
					$data += "$keyname=$kv`r`n"
				}
				else {
					$data += "$keyname=`"$keyval`"`r`n"
				}
            }
        } # foreach
        try {
            $data | Out-File $fullname -Force
        }
        catch {
            Write-Log -Category error -Message "Failed to write file: $fullname"
            $result = $False
        }
    } # foreach
    Write-Log -Category "info" -Message "function result = $result"
    Write-Log -Category "info" -Message "function runtime = $(Get-TimeOffset -StartTime $timex)"
    Write-Output $result
}

function Import-CMxServerRoles {
    [CmdletBinding(SupportsShouldProcess=$True)]
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
    $timex  = Get-Date
    $result = 0
    $FeaturesList | 
    Foreach-Object {
        $FeatureCode = $_
        Write-Log -Category "info" -Message "installing feature: $FeatureCode"
        $timez = Get-Date
        if ($AlternateSource -ne "") {
            Write-Log -Category "info" -Message "referencing alternate windows content source"
            try {
                $output   = Install-WindowsFeature -Name $FeatureCode -LogPath "$LogsFolder\$LogFile" -Source "$AlternateSource\sources\sxs"
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
                Write-Log -Category "error" -Message $_.Exception.Message
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
                Write-Log -Category "error" -Message $_.Exception.Message
                $result = -2
            }
            Write-Log -Category "info" -Message "$FeatureCode exitcode: $exitcode"
        } # if
        Write-Log -Category "info" -Message "internal : $FeatureCode runtime = $(Get-TimeOffset -StartTime $timez)"
        Write-Log -Category "info" -Message "- - - - - - - - - - - - - - - - - - - - - - - - - - -"
    } # foreach-object

    Write-Log -Category "info" -Message "result = $result"
    if ($result -eq 0) {
        Set-CMxTaskCompleted -KeyName 'SERVERROLES' -Value $(Get-Date)
    }
    Write-Log -Category "info" -Message "function runtime = $(Get-TimeOffset -StartTime $timex)"
    Write-Output $result
}

function Import-CMxServerRolesFile {
    [CmdletBinding(SupportsShouldProcess=$True)]
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
    if (Test-Path $PackageFile) {
        if ($AltSource -ne "") {
            Write-Log -Category "info" -Message "referencing alternate windows content source: $AltSource"
            try {
                Write-Log -Category "info" -Message "installing features from configuration file: $PackageFile using alternate source"
                $result = Install-WindowsFeature -ConfigurationFilePath $PackageFile -LogPath "$LogsFolder\$LogFile" -Source "$AltSource\sources\sxs" -ErrorAction Continue
                if ($successcodes.Contains($result.ExitCode.Value__)) {
                    $result = 0
                    Set-CMxTaskCompleted -KeyName $PackageName -Value $(Get-Date)
                    Write-Log -Category "info" -Message "installion was successful"
                }
                else {
                    Write-Log -Category "error" -Message "failed to install features!"
                    Write-Log -Category "error" -Message "result: $($result.ExitCode.Value__)"
                    $result = -1
                }
            }
            catch {
                Write-Log -Category "error" -Message $_.Exception.Message
                break
            }
        }
        else {
            try {
                Write-Log -Category "info" -Message "installing features from configuration file: $PackageFile"
                $result = Install-WindowsFeature -ConfigurationFilePath $PackageFile -LogPath "$LogsFolder\$LogFile" -ErrorAction Continue | Out-Null
                if ($successcodes.Contains($result.ExitCode.Value__)) {
                    $result = 0
                    Set-CMxTaskCompleted -KeyName $PackageName -Value $(Get-Date)
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
                Write-Log -Category "error" -Message $_.Exception.Message
            }
        }
    }
    else {
        Write-Warning "ERROR: role configuration file $PackageFile was not found!"
        break
    }
    Write-Output $result
}

function Invoke-CMxWsusConfiguration {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [string] $UpdatesFolder
    )
    Write-Host "Configuring WSUS features" -ForegroundColor Green
    $timex = Get-Date
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
		Write-Log -Category "error" -Message $_.Exception.Message
		$result = $false
    }
    Write-Log -Category "info" -Message "function runtime = $(Get-TimeOffset -StartTime $timex)"
    Write-Output $result
}

function Get-CMxTotalMemory {
    [math]::Round((Get-WmiObject -Class Win32_PhysicalMemory | 
        Select-Object -ExpandProperty Capacity | 
            Measure-Object -Sum).sum/1gb,0)
}

function Invoke-CMxSqlConfiguration {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param(
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        $DataSet
    )
    Write-Host "Configuring SQL Server settings" -ForegroundColor Green
    $timex  = Get-Date
    $result = 0
    foreach ($item in $DataSet.configuration.sqloptions.sqloption | Where-Object {$_.use -eq '1'}) {
        $optName = $item.name
        $optData = $item.param
        $optDB   = $item.db
        $optComm = $item.comment
        Write-Log -Category "info" -Message "option name..... $optName"
        Write-Log -Category "info" -Message "option db....... $optDB"
        Write-Log -Category "info" -Message "option param.... $optData"
        Write-Log -Category "info" -Message "option comment.. $optComm"
        switch ($optName) {
            'SqlServerMemoryMax' {
                Write-Log -Category "info" -Message "SQL - configuring = maximum memory limit"
                if ($optData.EndsWith("%")) {
                    Write-Log -Category "info" -Message "SQL - configuring relative memory limit"
                    [int]$MemRatio = $optData.Replace("%","")
                    $dblRatio = $MemRatio * 0.01
                    # convert total memory GB to MB
                    $actMax   = Get-CMxTotalMemory
                    $newMax   = $actMax * $dblRatio
                    $curMax   = [math]::Round((Get-SqlMaxMemory -SqlInstance $HostFullName).SqlMaxMB/1024,0)
                    Write-Log -Category "info" -Message "SQL - total memory (GB)....... $actMax"
                    Write-Log -Category "info" -Message "SQL - recommended max (GB).... $newMax"
                    Write-Log -Category "info" -Message "SQL - current max (GB)........ $curMax"
                    if ($curMax -eq $newMax) {
                        Write-Log -Category "info" -Message "SQL - current max is already set"
                        $result = 0
                    }
                    elseif (($actMax - $newMax) -le 4) {
                        Write-Log -Category "warning" -Message "SQL - recommended max would not allow 4GB for OS (skipping)"
                        $result = 0
                    } 
                    else {
                        # convert GB to MB for cmdlet
                        $newMax = [math]::Round($newMax * 1024,0)
                        Write-Log -Category "info" -Message "SQL - adjusting max memory to $newMax MB"
                        try {
                            Set-SqlMaxMemory -SqlInstance $HostFullName -MaxMB $newMax | Out-Null
                            Write-Log -Category "info" -Message "SQL - maximum memory allocation is now: $newMax"
                            Set-CMxTaskCompleted -KeyName 'SQLCONFIG' -Value $(Get-Date)
                            $result = 0
                        }
                        catch {
                            Write-Log -Category "error" -Message "SQL - failed to change memory allocation!"
                        }
                    }
                }
                else {
                    Write-Log -Category "info" -Message "configuring static memory limit"
                    $curMax =  (Get-SqlMaxMemory -SqlInstance $HostFullName).SqlMaxMB
                    try {
                        Set-SqlMaxMemory -SqlInstance $HostFullName -MaxMb [int]$optData -Silent | Out-Null
                    }
                    catch {
                        Write-Log -Category "error" -Message "failed to set max memory"
                    }
                }
                break
            }
            'SetDBRecoveryModel' {
                Write-Log -Category "info" -Message "SQL - configuring = database recovery model"
                try {
                    $db = Get-SqlDatabase -ServerInstance $HostFullName -Name $optDB
                }
                catch {
                    $db = $null
                }
                if ($db) {
                    $curModel = $db.RecoveryModel
                    Write-Log -Category "info" -Message "SQL - current recovery model.... $curModel"
                    if ($curModel -ne $optData) {
                        if ($optData -eq 'FULL') {
                            try {
                                $db.RecoveryModel = [Microsoft.SqlServer.Management.Smo.RecoveryModel]::Full;
                                $db.Alter();
                                Write-Log -Category "info" -Message "SQL - successfully configured for $optData"
                            }
                            catch {
                                Write-Log -Category "error" -Message "SQL - failed to configure for $optData"
                                $result = $False
                            }
                        }
                        else {
                            try {
                                $db.RecoveryModel = [Microsoft.SqlServer.Management.Smo.RecoveryModel]::Simple;
                                $db.Alter();
                                Write-Log -Category "info" -Message "SQL - successfully configured for $optData"
                            }
                            catch {
                                Write-Log -Category "error" -Message "SQL - failed to configure for $optData"
                                $result = $False
                            }
                        }
                    } # if
                } # if
            }
        } # switch
    } # foreach
    Write-Log -Category "info" -Message "function runtime = $(Get-TimeOffset -StartTime $timex))"
    Write-Output $result
}

function Get-CmxWsusUpdatesPath {
    param ($FolderSet)
    $fpath = $FolderSet | Where-Object {$_.comment -like 'WSUS*'} | Select-Object -ExpandProperty name
    if (-not($fpath) -or ($fpath -eq "")) {
        Write-Warning "error: missing WSUS updates storage path setting in XML file. Refer to FOLDERS section."
        break
    }
    Write-Output $fpath
}

function Set-CMxRegKeys {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            $DataSet,
        [parameter(Mandatory=$True)]
            [ValidateSet('before','after')]
            [string] $Order
    )
    Write-Host "Configuring registry keys" -ForegroundColor Green
    Write-Log -Category "info" -Message "keygroup order = $Order"
    $result = $True
    foreach ($item in $DataSet.configuration.regkeys.regkey | Where-Object {$_.use -eq '1'}) {
        $regName  = $item.name
        $regOrder = $item.order
        $reg = $null
        if ($regOrder -eq $Order) {
            $regPath = $item.path
            $regVal  = $item.value
            $regData = $item.data
            switch ($regPath.substring(0,4)) {
                'HKLM' {
                    try {
                        $reg = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,'default')
                        Write-Log -Category "info" -Message "opened registry hive $($regPath.Substring(0,4)) successfully"
                    }
                    catch {
                        Write-Log -Category "error" -Message $_.Exception.Message
                        $result = $False
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
                catch {
                    Write-Log -Category "error" -Message $_.Exception.Message
                    $result = $False
                }
            }
        }
    }
    Write-Output $result
}

function Test-CMxPackage {
    param (
        [parameter(Mandatory=$False)]
        [string] $PackageName = ""
    )
    Write-Log -Category "info" -Message "[function: Test-CMxPackage]"
    $detRule = $detects | Where-Object {$_.name -eq $PackageName}
    if (($detRule) -and ($detRule -ne "")) {
        Write-Output (Test-Path $detRule)
    }
    else {
        Write-Output $True
    }
}

function Invoke-CMxPackage {
    [CmdletBinding(SupportsShouldProcess=$True)]
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
    Write-Log -Category "info" -Message "function: Invoke-CMxPackage"
    Write-Log -Category "info" -Message "package type = $PackageType"
    switch ($PackageType) {
        'feature' {
            Write-Log -Category "info" -Message "installation feature = $Name"
            Write-Host "Installing $pkgComm" -ForegroundColor Green
            $xdata = ($xmldata.configuration.features.feature | 
                Where-Object {$_.name -eq $Name} | 
                    Foreach-Object {$_.innerText}).Split(',')
            $result = Import-CMxServerRoles -RoleName $Name -FeaturesList $xdata -AlternateSource $AltSource
            Write-Log -Category "info" -Message "exit code = $result"
            if ($result -or ($result -eq 0)) { 
                Set-CMxTaskCompleted -KeyName $Name -Value $(Get-Date) 
            }
            else {
                Write-Warning "error: step failure [feature] at: $Name"
                $continue = $False
            }
            break
        }
        'function' {
            $result = Invoke-CMxFunction -Name $Name -Comment $pkgComm
			if (!($result -or ($result -eq 0))) { 
                Write-Warning "error: step failure [function] at: $Name"
                $continue = $False
            }
            break
        }
        'payload' {
            $result = Start-CMxPayload -Name $Name -SourcePath $PayloadSource -PayloadFile $PayloadFile -PayloadArguments $PayloadArguments
            if (!($result -or ($result -eq 0))) { 
                Write-Warning "error: step failure [payload] at: $Name"
                $continue = $False
            }
            break
        }
        default {
            Write-Warning "invalid package type value: $PackageType"
            $continue
            break
        }
    } # switch
    Write-Log -Category "info" -Message "[Invoke-CMxPackage] result = $result"
    Write-Output $result
}

function Start-CMxPayload {
    [CmdletBinding(SupportsShouldProcess=$True)]
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
    Write-Host "Installing payload: $Name" -ForegroundColor Green
    Write-Log -Category "info" -Message "installation payload = $Name"
    Write-Log -Category "info" -Message "comment = $Comment"
    switch ($pkgName) {
        'CONFIGMGR' {
            Write-Host "Tip: Monitor C:\ConfigMgrSetup.log for progress" -ForegroundColor Green
            $runFile = "$SourcePath\$PayloadFile"
            $x = Invoke-CMxPayloadInstaller -Name $Name -SourceFile $runFile -OptionParams $PayloadArguments
            Write-Log -Category "info" -Message "exit code = $x"
            break
        }
        'SQLSERVER' {
            Write-Host "Tip: Monitor $($env:PROGRAMFILES)\Microsoft SQL Server\130\Setup Bootstrap\Logs\summary.txt for progress" -ForegroundColor Green
            $runFile = "$SourcePath\$PayloadFile"
            $x = Invoke-CMxPayloadInstaller -Name $Name -SourceFile $runFile -OptionParams $PayloadArguments
            Write-Log -Category "info" -Message "exit code = $x"
            break
        }
        'SERVERROLES' {
            $runFile = "$((Get-ChildItem $xmlfile).DirectoryName)\$PayloadFile"
            $x = Import-CMxServerRolesFile -PackageName $Name -PackageFile $runFile
            Write-Log -Category "info" -Message "exit code = $x"
            break
        }
        default {
            $runFile = "$SourcePath\$PayloadFile"
            $x = Invoke-CMxPayloadInstaller -Name $Name -SourceFile $runFile -OptionParams $PayloadArguments
            Write-Log -Category "info" -Message "exit code = $x"
            break
        }
    } # switch
    Write-Log -Category "info" -Message "[Invoke-CMxPayload] result = $result"
    Write-Output $x
} 

function Invoke-CMxPayloadInstaller {
    [CmdletBinding(SupportsShouldProcess=$True)]
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
    Write-Log -Category "info" -Message "function: Invoke-CMxPayloadInstaller"
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
            Set-CMxTaskCompleted -KeyName $Name -Value $(Get-Date)
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
    Write-Log -Category "info" -Message "function runtime = $(Get-TimeOffset -StartTime $time1)"
    Write-Log -Category "info" -Message "function result = $result"
    Write-Output $result
}

function Invoke-CMxFunction {
    [CmdletBinding(SupportsShouldProcess=$True)]
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
            $result = Invoke-CMxSqlConfiguration -DataSet $xmldata
            Write-Verbose "info: exit code = $result"
            Set-CMxTaskCompleted -KeyName $Name -Value $(Get-Date)
            break
        }
        'WSUSCONFIG' {
            Write-Host "$Comment" -ForegroundColor Green
            $fpath = Get-CmxWsusUpdatesPath -FolderSet $xmldata.configuration.folders.folder
            if (-not($fpath)) {
                $result = -1
                break
            }
            $result = Invoke-CMxWsusConfiguration -UpdatesFolder $fpath
            Write-Verbose "info: exit code = $result"
            Set-CMxTaskCompleted -KeyName $Name -Value $(Get-Date)
            break
        }
		'LOCALACCOUNTS' {
			$result = Import-CMxLocalAccounts -DataSet $xmldata
			if ($result -eq $True) {
				Set-CMxTaskCompleted -KeyName $Name -Value $(Get-Date)
			}
			break
		}
        default {
            Write-Warning "There is no function mapping for: $Name"
            break
        }
    } # switch
    Write-Log -Category "info" -Message "[Invoke-CMxFunction] result = $result"
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

function Get-CMxInstallState {
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
    Write-Log -Category "info" -Message "[function: Get-CMxInstallState]"
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

function Import-CMxLocalAccounts {
	[CmdletBinding(SupportsShouldProcess=$True)]
	param (
		[parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		$DataSet
	)
	Write-Host "Configuring Local accounts and group memberships" -ForegroundColor Green
	$result = 0
	$time1  = Get-Date
	foreach ($item in $DataSet.configuration.localaccounts.localaccount | Where-Object {$_.use -eq "1"}) {
		$itemName   = $item.name
		$itemGroup  = $item.memberof
		$itemRights = $item.rights
		if (Get-LocalGroupMember -Group "$itemGroup" -Member "$itemName" -ErrorAction SilentlyContinue) {
			Write-Log -Category "info" -Message "$itemName is already a member of $itemGroup"
			if ($itemRights.Length -gt 0) {
				Set-CMxLocalAccountRights -UserName "$itemName" -Privileges "$itemRights" | Out-Null
			}
		}
		else {
			Write-Log -Category "info" -Message "$itemName is not a member of $itemGroup"
			try {
				Add-LocalGroupMember -Group "$itemGroup" -Member "$itemName"
				if (Get-LocalGroupMember -Group "$itemGroup" -Member "$itemName" -ErrorAction SilentlyContinue) {
					Write-Log -Category "info" -Message "$itemName has been added to $itemGroup"
					if ($itemRights.Length -gt 0) {
						Set-CMxLocalAccountRights -UserName "$itemName" -Privileges "$itemRights" | Out-Null
					}
				}
				else {
					Write-Log -Category "error" -Message $_.Exception.Message
					$result = $False
					break
				}
			}
			catch {
				Write-Log -Category "error" -Message $_.Exception.Message
				$result = $False
				break
			}
		}
	} # foreach
    Write-Log -Category "info" -Message "function runtime = $(Get-TimeOffset -StartTime $time1)"
	Write-Output $result
}

<#
.NOTES
	reference: http://get-carbon.org/Grant-Privilege.html
#>
function Set-CMxLocalAccountRights {
	param (
		[parameter(Mandatory=$True)]
			[ValidateNotNullOrEmpty()]
			[string] $UserName,
		[parameter(Mandatory=$True)]
			[ValidateNotNullOrEmpty()]
			[string] $Privileges
	)
	Write-Log -Category "info" -Message "Set-CMxServiceLogonRights: $UserName"
	[array]$privs = Get-Privilege -Identity $UserName
	$result = $False
	if ($privs.Count -gt 0) {
		foreach ($right in $Privileges.Split(',')) {
			if ($privs -contains $right) {
				Write-Log -Category "info" -Message "$right, already granted to: $UserName"
				$result = $True
			}
			else {
				Write-Log -Category "info" -Message "granting: $right, to: $UserName"
				Grant-Privilege -Identity $UserName -Privilege $right
			}
		} # foreach
	}
	else {
		foreach ($right in $Privileges.Split(',')) {
			Write-Log -Category "info" -Message "granting: $right, to: $UserName"
			Grant-Privilege -Identity $UserName -Privilege $right
		} # foreach
	}
	Write-Output $result
}

function Convert-CmxString {
	param(
		[parameter(Mandatory=$True)]
			[ValidateNotNullOrEmpty()] $DataSet,
		[parameter(Mandatory=$False)]
			[string] $StringVal = ""
	)
	$fullname  = $DataSet.configuration.project.hostname
	$shortname = $DataSet.configuration.project.host
	$sitecode  = $DataSet.configuration.project.sitecode
	#Write-Log -Category "info" -Message "full name = $fullname"
	#Write-Log -Category "info" -Message "short name = $shortname"
	if ($StringVal -ne "") {
		Write-Output $((($StringVal -replace '@HOST@', "$shortname") -replace '@HOSTNAME@', "$fullname") -replace '@SITECODE@', $sitecode)
	}
	else {
		Write-Output ""
	}
}

# end-functions

[xml]$xmldata = Get-CMxConfigData $XmlFile
Write-Log -Category "info" -Message "----------------------------------------------------"
Set-CMxTaskCompleted -KeyName 'START' -Value $(Get-Date)

if ($Override) {
    $controlset = $xmldata.configuration.packages.package | Out-GridView -Title "Select Packages to Run" -PassThru
}
else {
    $controlset = $xmldata.configuration.packages.package | Where-Object {$_.use -eq '1'}
}

if ($controlset) {
	$project   = $xmldata.configuration.project
	$AltSource = $xmldata.configuration.sources.source | 
		Where-Object {$_.name -eq 'WIN10'} | 
			Select-Object -ExpandProperty path
	Write-Log -Category "info" -Message "alternate windows source = $AltSource"

	#Set-Location $env:USERPROFILE

	Write-Log -Category "info" -Message "----------------------------------------------------"
	Write-Log -Category "info" -Message "project info....... $($project.comment)"

	if (-not (Import-CMxFolders -DataSet $xmldata)) {
		Write-Warning "error: failed to create folders (aborting)"
		break
	}
	if (-not (Import-CMxFiles -DataSet $xmldata)) {
		Write-Warning "error: failed to create files (aborting)"
		break
	}

	Write-Host "Executing project configuration" -ForegroundColor Green

	Disable-InternetExplorerESC | Out-Null
	Set-CMxRegKeys -DataSet $xmldata -Order "before" | Out-Null

	Write-Log -Category "info" -Message "beginning package execution"
	Write-Log -Category "info" -Message "----------------------------------------------------"
	$continue = $True
	$pkgcount = 0
	foreach ($package in $controlset) {
		if ($continue) {
			$pkgName  = $package.name
			$pkgType  = $package.type 
			$pkgComm  = $package.comment 
			$payload  = $xmldata.configuration.payloads.payload | Where-Object {$_.name -eq $pkgName}
			#$pkgSrc   = $payload.path // changed in 1.3
			$pkgSrcX  = $xmldata.configuration.sources.source | Where-Object {$_.name -eq $pkgName}
			$pkgSrc   = $pkgSrcX.path
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

			if (!(Test-CMxPackage -PackageName $dependson)) {
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
			$installed = Get-CMxInstallState -PackageName $pkgName -RuleType $detType -RuleData $detPath
			if ($installed) {
				Write-Log -Category "info" -Message "install state... $pkgName is INSTALLED"
			}
			else {
				Write-Log -Category "info" -Message "install state... $pkgName is NOT INSTALLED"
				$x = Invoke-CMxPackage -Name $pkgName -PackageType $pkgType -PayloadSource $pkgSrc -PayloadFile $pkgFile -PayloadArguments $pkgArgs
				if ($x -ne 0) {$continue = $False; break}
			}
			$pkgcount += 1
			Write-Log -Category "info" -Message "----------------------------------------------------"
		}
		else {
			Write-Warning "STOP! aborted at step [$pkgName] $(Get-Date)"
			break
		}
	} # foreach

	if (($pkgcount -gt 0) -and ($continue)) {
		Set-CMxRegKeys -DataSet $xmldata -Order "after" | Out-Null
	}
}

Write-Host "Processing finished at $(Get-Date)" -ForegroundColor Green
$RunTime2 = Get-TimeOffset -StartTime $RunTime1
Write-Log -Category "info" -Message "finished at $(Get-Date) - total runtime = $RunTime2"
if ((Test-PendingReboot) -and ($NoReboot)) {
    Write-Host "A REBOOT is REQUIRED" -ForegroundColor Cyan
#    Start-Sleep -Seconds 30
#    Restart-Computer -Force
}
Stop-Transcript
