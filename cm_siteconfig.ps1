#requires -RunAsAdministrator
#requires -version 3
<#
.SYNOPSIS
    SCCM site configuration script
.DESCRIPTION
    Yeah, what he said.
.PARAMETER XmlFile
    [string](optional) Path and Name of XML input file
.PARAMETER ForceBoundaries
    [switch](optional) Force custom site boundaries
.PARAMETER NoCheck
    [switch](optional) Skip platform validation restrictions
.NOTES
    1.1.9 - DS - 2017.08.24
    
    Read the associated XML to make sure the path and filename values
    all match up like you need them to.

.EXAMPLE
    .\cm_siteconfig.ps1 -XmlFile .\cm_siteconfig.xml -Verbose
#>

[CmdletBinding()]
param (
    [parameter(Mandatory=$True, HelpMessage="Path and name of XML input file")]
        [ValidateNotNullOrEmpty()]
        [string] $XmlFile,
    [parameter(Mandatory=$False)]
        [switch] $ForceBoundaries
)

function Get-ScriptDirectory {
    $Invocation = (Get-Variable MyInvocation -Scope 1).Value
    Split-Path $Invocation.MyCommand.Path
}

$basekey = 'HKLM:\SOFTWARE\CM_SITECONFIG'
$ScriptVersion = '1.1.9'
$ScriptPath   = Get-ScriptDirectory
$LogsFolder   = "$ScriptPath\Logs"
if (-not(Test-Path $LogsFolder)) {New-Item -Path $LogsFolder -Type Directory}
$tsFile  = "$LogsFolder\cm_siteconfig_$($env:COMPUTERNAME)_transaction.log"
$logFile = "$LogsFolder\cm_siteconfig_$($env:COMPUTERNAME)_details.log"

try {
    Start-Transcript -Path $tsFile -Force
}
catch {
    Write-Error "Failed to open transcript log file"
    break
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
    #"$(Get-Date -f 'yyyy-M-dd HH:MM:ss')  $Category  $Message" | Out-File -FilePath $logFile -Append -Force
}

$RunTime1 = Get-Date
Write-Log -Category "info" -Message "Script version.... $ScriptVersion"

Set-Location "$($env:USERPROFILE)\Documents"
if (-not(Test-Path $XmlFile)) {
    Write-Warning "unable to locate input file: $XmlFile"
    break
}

$AutoBoundaries = $False

# --------------------------------------------------------------------
# functions

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

function Get-CMModule {
    [CmdletBinding()]
    param ()
    Write-Verbose "Importing ConfigurationManager module"
    if (-not(Get-Module ConfigurationManager)) {
        Write-Output "Importing the ConfigurationManager powershell module"
        try {
            Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" 
            Write-Output $True
        }
        catch {}
    }
    else {
        Write-Output $True
    }
}

function Set-CMSiteDiscoveryMethods {
    [CmdletBinding()]
    param ($DataSet)
    Write-Log -Category "info" -Message "----------------------------------------------------"
    <#
    Write-Verbose "info: defining one-year time span values"
    $StartDate = Get-Date -f "yyyy/M/dd 00:00:00"
    $EndDate   = (Get-Date).AddYears(1) -f "yyyy/M/dd 00:00:00"
    Write-Verbose "info: startDate = $StartDate"
    Write-Verbose "info: endDate = $EndDate"

    Write-Verbose "info: defining interval schedules"
    foreach ($sch in $DataSet.schedules.schedule) {
        $schName = $sch.name
        $schUnit = $sch.units
        $schVal  = $sch.value
        Write-Verbose "schedule: $schName"
        # create schedule object
        # $sch15min  = New-CMSchedule -RecurInterval Minutes -Start "$StartDate" -End "$EndDate" -RecurCount 15
        # $schHourly = New-CMSchedule -RecurInterval Hours -Start "$StartDate" -End "$EndDate" -RecurCount 1
        # $schDaily  = New-CMSchedule -RecurInterval Days -Start "$StartDate" -End "$EndDate" -RecurCount 1
        # $schWeekly = New-CMSchedule -RecurInterval Days -Start "$StartDate" -End "$EndDate" -RecurCount 7
    }
    #>
    Write-Host "Configuring Discovery Methods" -ForegroundColor Green
    $disc = $DataSet.configuration.cmsite.discoveries.discovery | ? {$_.enabled -eq 'true'}
    foreach ($dm in $disc) {
        $discName = $dm.name
        Write-Log -Category "info" -Message "- - - - - - - - - - - - - - - - - - - - - - - - - - - -"
        Write-Log -Category "info" -Message "discovery method = $discName"
        $dmx = $disc | Where-Object {$_.name -eq $discName}
        $options = $dmx.options
        if ($options) {
            Write-Log -Category "info" -Message "additional options are specified"
            $ADContainer      = ""
            $ADAttributes     = $null
            $SubnetBoundaries = $False
            $ADSiteBoundaries = $False
            $FilterPassword1  = $False
            $FilterPassword2  = $null
            $FilterLogon1     = $False
            $FilterLogon2     = $null
            $EnableDelta      = $False

            foreach ($option in $options.Split('|')) {
                $optset = $option.Split(':')
                if ($optset.length -eq 2) {
                    Write-Log -Category "info" -Message "(option) name= $($optset[0]) ... value= $($optset[1])"
                    switch ($optset[0]) {
                        'ADContainer' {
                            $ADContainer = $optset[1]
                            break
                        }
                        'ADAttributes' {
                            $ADAttributes = $optset[1].Split(',')
                            break
                        }
                        'EnableSubnetBoundaryCreation' {
                            $SubnetBoundaries = $True
                            $AutoBoundaries   = $True
                            break
                        }
                        'EnableFilteringExpiredPassword' {
                            $FilterPassword1 = $True
                            $FilterPassword2 = $optset[1]
                            break
                        }
                        'EnableFilteringExpiredLogon' {
                            $FilterLogon1 = $True
                            $FilterLogon2 = $optset[1]
                            break
                        }
                        'EnableDeltaDiscovery' {
                            $EnableDelta = $True
                            break
                        }
                    } # switch
                }
                else {
                    Write-Log -Category "info" -Message "option: name= $optset ... value= True"
                }
            } # foreach
        } # if
        
        switch ($discName) {
            'ActiveDirectoryForestDiscovery' {
                Write-Log -Category "info" -Message "FOREST DISCOVERY"
                try {
                    Set-CMDiscoveryMethod -ActiveDirectoryForestDiscovery -SiteCode $sitecode -Enabled $True -EnableSubnetBoundaryCreation $SubnetBoundaries -ErrorAction SilentlyContinue
                    Write-Log -Category "info" -Message "AD forest discovery configured successfully"
                }
                catch {}
                break
            }
            'ActiveDirectorySystemDiscovery' {
                Write-Log -Category "info" -Message "SYSTEM DISCOVERY"
                if ($FilterPassword1 -and $FilterLogon1) {
                    try {
                        Set-CMDiscoveryMethod -ActiveDirectorySystemDiscovery -SiteCode $sitecode -Enabled $True -ActiveDirectoryContainer "LDAP://$ADContainer" -EnableDeltaDiscovery $EnableDelta -EnableFilteringExpiredLogon $FilterLogon1 -TimeSinceLastLogonDays $FilterLogon2 -EnableFilteringExpiredPassword $FilterPassword1 -TimeSinceLastPasswordUpdateDays $FilterPassword2 -Recursive -ErrorAction SilentlyContinue | Out-Null
                        Write-Log -Category "info" -Message "AD system discovery configured successfully (A)"
                    }
                    catch {
                        $_
                    }
                }
                elseif ($FilterPassword1) {
                    try {
                        Set-CMDiscoveryMethod -ActiveDirectorySystemDiscovery -SiteCode $sitecode -Enabled $True -ActiveDirectoryContainer "LDAP://$ADContainer" -EnableDeltaDiscovery $EnableDelta -EnableFilteringExpiredPassword $FilterPassword1 -TimeSinceLastPasswordUpdateDays $FilterPassword2 -Recursive -ErrorAction SilentlyContinue | Out-Null
                        Write-Log -Category "info" -Message "AD system discovery configured successfully (B)"
                    }
                    catch {
                        $_
                    }
                }
                elseif ($FilterLogon1) {
                    try {
                        Set-CMDiscoveryMethod -ActiveDirectorySystemDiscovery -SiteCode $sitecode -Enabled $True -ActiveDirectoryContainer "LDAP://$ADContainer" -EnableDeltaDiscovery $EnableDelta -EnableFilteringExpiredLogon $FilterLogon1 -TimeSinceLastLogonDays $FilterLogon2 -Recursive -ErrorAction SilentlyContinue | Out-Null
                        Write-Log -Category "info" -Message "AD system discovery configured successfully (C)"
                    }
                    catch {
                        $_
                    }
                }
                else {
                    try {
                        Set-CMDiscoveryMethod -ActiveDirectorySystemDiscovery -SiteCode $sitecode -Enabled $True -ActiveDirectoryContainer "LDAP://$ADContainer" -EnableDeltaDiscovery $EnableDelta -Recursive -ErrorAction SilentlyContinue | Out-Null
                        Write-Log -Category "info" -Message "AD system discovery configured successfully (D)"
                    }
                    catch {
                        $_
                    }
                }
                break
            }
            'ActiveDirectoryUserDiscovery' {
                Write-Log -Category "info" -Message "USER DISCOVERY"
                if ($ADAttributes -ne $null) {
                    Write-Log -Category "info" -Message "assigning custom AD attributes"
                    try {
                        Set-CMDiscoveryMethod -ActiveDirectoryUserDiscovery -SiteCode $sitecode -Enabled $True -ActiveDirectoryContainer "LDAP://$ADContainer" -EnableDeltaDiscovery $EnableDelta -Recursive -AddAdditionalAttribute $ADAttributes -ErrorAction SilentlyContinue | Out-Null
                        Write-Log -Category "info" -Message "AD user discovery configured successfully (A)"
                    }
                    catch {
                        $_
                    }
                }
                else {
                    try {
                        Set-CMDiscoveryMethod -ActiveDirectoryUserDiscovery -SiteCode $sitecode -Enabled $True -ActiveDirectoryContainer "LDAP://$ADContainer" -EnableDeltaDiscovery $EnableDelta -Recursive -ErrorAction SilentlyContinue | Out-Null
                        Write-Log -Category "info" -Message "AD user discovery configured successfully (B)"
                    }
                    catch {
                        $_
                    }
                }
                break
            }
            'ActiveDirectoryGroupDiscovery' {
                Write-Log -Category "info" -Message "GROUP DISCOVERY"
                try {
                    Set-CMDiscoveryMethod -ActiveDirectoryGroupDiscovery -SiteCode $sitecode -Enabled $True -EnableDeltaDiscovery $EnableDelta -EnableFilteringExpiredLogon $True -TimeSinceLastLogonDays 90 -EnableFilteringExpiredPassword $True -TimeSinceLastPasswordUpdateDays 90 -ErrorAction SilentlyContinue | Out-Null
                    Write-Log -Category "info" -Message "info: AD group discovery configured successfully"
                }
                catch {}
                break
            }
        } # switch
    } # foreach
} # function

function Set-CMSiteADForest {
    [CmdletBinding()]
    param ($DataSet)
    $adforest = $DataSet.configuration.cmsite.forest
    Write-Log -Category "info" -Message "----------------------------------------------------"
    Write-Host "Configuring AD Forest" -ForegroundColor Green
    try {
        New-CMActiveDirectoryForest -ForestFqdn "$adforest" -EnableDiscovery $True -ErrorAction SilentlyContinue
        Write-Log -Category "info" -Message "active directory forest has been configured: $adforest"
        Write-Output $True
    }
    catch {
        if ($_.Exception.Message -eq 'An object with the specified name already exists.') {
            Write-Log -Category "info" -Message "AD forest $adforest already defined"
            Write-Output $True
        }
        else {
            Write-Error $_
        }
    }
}

function Set-CMSiteBoundaryGroups {
    [CmdletBinding()]
    param ($DataSet)
    Write-Log -Category "info" -Message "----------------------------------------------------"
    Write-Host "Configuring Site Boundary Groups" -ForegroundColor Green
    $bglist = $DataSet.configuration.cmsite.boundarygroups.boundarygroup
    foreach ($bg in $bglist) {
        $bgName = $bg.name
        $bgComm = $bg.comment
        $bgServer = $bg.SiteSystemServer
        $bgLink   = $bg.LinkType
        Write-Log -Category "info" -Message "- - - - - - - - - - - - - - - - - - - - - - - - - -"
        Write-Log -Category "info" -Message "boundary group name = $bgName"
        if ($bgServer) {
            $bgSiteServer = @{$bgServer = $bgLink}
            Write-Log -Category "info" -Message "site server assigned: $bgServer ($bgLink)"
            try {
                New-CMBoundaryGroup -Name $bgName -Description $bgComm -DefaultSiteCode $sitecode -AddSiteSystemServer $bgSiteServer -ErrorAction SilentlyContinue | Out-Null
                Write-Log -Category "info" -Message "boundary group $bgName created"
            }
            catch {
                Write-Log -Category "info" -Message "boundary group $bgName already exists."
                try {
                    Set-CMBoundaryGroup -Name $bgName -DefaultSiteCode $sitecode -AddSiteSystemServer $bgSiteServer -ErrorAction SilentlyContinue | Out-Null
                    Write-Log -Category "info" -Message "boundary group $bgName has been updated"
                }
                catch {
                    Write-Error $_
                }
            }
        }
        else {
            Write-Log -Category "info" -Message "boundary group $bgName does not have an assigned site server."
            try {
                New-CMBoundaryGroup -Name $bgName -Description $bgComm -DefaultSiteCode $sitecode -ErrorAction SilentlyContinue | Out-Null
                Write-Log -Category "info" -Message "boundary group $bgName created"
            }
            catch {
                Write-Log -Category "info" -Message "boundary group $bgName already exists."
                try {
                    Set-CMBoundaryGroup -Name $bgName -DefaultSiteCode $sitecode -ErrorAction SilentlyContinue | Out-Null
                    Write-Log -Category "info" -Message "boundary group $bgName has been updated"
                }
                catch {
                    Write-Error $_
                }
            }
        } # if
    } # foreach
}

function Set-Boundaries {
    [CmdletBinding()]
    param ($DataSet)
    Write-Log -Category "info" -Message "----------------------------------------------------"
    Write-Host "Configuring Site Boundaries" -ForegroundColor Green
    $blist = $DataSet.configuration.cmsite.boundaries.boundary
    foreach ($bx in $blist) {
        $bName = $bx.name
        $bType = $bx.type
        $bData = $bx.value
        $bGrp  = $bx.boundarygroup
        $bComm = $bx.comment
        Write-Log -Category "info" -Message "- - - - - - - - - - - - - - - - - - - - - - - - - -"
        Write-Log -Category "info" -Message "boundary name = $bName"
        Write-Log -Category "info" -Message "comment = $bComm"
        Write-Log -Category "info" -Message "data = $bData"
        Write-Log -Category "info" -Message "type = $bType"
        Write-Log -Category "info" -Message "boundary group = $bGrp"
        try {
            $bx = New-CMBoundary -Name $bName -Type IPRange -Value $bData -ErrorAction Stop
            Write-Log -Category "info" -Message "boundary [$bName] created"
        }
        catch {
            Write-Log -Category "info" -Message "boundary [$bName] already exists"
            try {
                $bx = Get-CMBoundary -BoundaryName $bName -ErrorAction Stop
                Write-Log -Category "info" -Message "getting boundary information for $bName"
                $bID = $bx.BoundaryID
                Write-Log -Category "info" -Message "boundary [$bName] identifier = $bID"
            }
            catch {
                Write-Log -Category "error" -Message "unable to create or update boundary: $bName"
                $bID = $null
                break
            }
        }
        if ($bID -and $bGrp) {
            Write-Log -Category "info" -Message "assigning boundary [$bName] to boundary group: $bGrp"
            try {
                $bg = Get-CMBoundaryGroup -Name $bGrp -ErrorAction Stop
                $bgID = $bg.GroupID
                Write-Log -Category "info" -Message "boundary group identifier = $bgID"
            }
            catch {
                Write-Log -Category "error" -Message "unable to obtain boundary group [$bGrp]"
                $bgID = $null
            }
            if ($bgID) {
                try {
                    Add-CMBoundaryToGroup -BoundaryId $bx.BoundaryID -BoundaryGroupId $bg.GroupID
                    Write-Log -Category "info" -Message "boundary ($bName) added to boundary group ($bGrp)"
                }
                catch {
                    Write-Log -Category "error" -Message "oops?"
                }
            }
        }
        else {
            Write-Log -Category "info" -Message "oundary [$bName] is not assigned to a boundary group"
        }
    } # foreach
}

function Set-CMSiteServerRoles {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$True)] $DataSet
    )
    Write-Log -Category "info" -Message "function: set-cmsiteserverroles"
    foreach ($siterole in $DataSet.configuration.cmsite.sitesystemroles | Where-Object {$_.enabled -eq 'true'}) {
        $roleName = $siterole.name
        Write-Log -Category "info" -Message "role: $roleName"
        switch ($RoleName) {
            'aisync' {
                try {
                    $x = Set-CMAssetIntelligenceSynchronizationPoint -Enable $True -EnableSynchronization $True -PassThru
                    if ($x) {
                        foreach ($opt in $siterole.roleoptions.roleoption) {
                            $optionName = $opt.name
                            Write-Log -Category "info" -Message "option: $optionName"
                            Set-CMAssetIntelligenceClass -EnableReportingClass $optionName | Out-Null
                        }
                        $result = $True
                    }
                }
                catch { Write.Error $_ }
                break
            }
            # next rolename...
        } # switch
    } # foreach
    Write-Output $result
}

function Set-CMSiteAIClasses {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$True)]
        $DataSet
    )
    Write-Verbose "----------------------------------------------------"
    Write-Host "Configuring Asset Intelligence classes" -ForegroundColor Green
    foreach ($aiclass in $DataSet.configuration.cmsite.aiclasses.aiclass) {
        $cname = $aiclass.name
        Write-Verbose "enable class: $cname"
        Set-CMAssetIntelligenceClass -EnableReportingClass $cname | Out-Null
    }
}

function Set-CMSiteConfigFolders {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [string] $SiteCode,
        [parameter(Mandatory=$True)]
            $DataSet
    )
    Write-Log -Category "info" -Message "function set-cmsitefolders"
    $result = $true
    foreach ($folder in $DataSet.configuration.cmsite.folders.folder) {
        $folderName = $folder.name
        $folderPath = $folder.path
        try {
            New-Item -Path "$SiteCode`:\$folderPath" -Name $folderName -Force
            Write-Log -Category "info" -Message "folder created: $folderName"
        }
        catch {
            Write-Log -Category "error" -Message "folder failed: $folderName"
            $_
            $result = $False
            break
        }
    } # foreach
    Write-Output $result
}

function Set-CMSiteQueries {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        $DataSet
    )
    Write-Log -Category "info" -Message "function set-cmsitequeries"
    $result = $True
    foreach ($query in $DataSet.configuration.cmsite.queries.query) {
        $queryName = $query.name
        $queryComm = $query.comment
        $queryType = $query.class
        $queryExp  = $query.expression
        try {
            New-CMQuery -Name $queryName -Expression $queryExp -Comment $queryComm -TargetClassName $queryType
            Write-Log -Category "info" -Message "query created: $queryName"
        }
        catch {
            Write-Log -Category "error" -Message "query failed: $queryName"
            $_
            $result = $False
            break
        }
    } # foreach
    Write-Output $result
}

# --------------------------------------------------------------------

Set-Location $env:USERPROFILE
$tsFile = "$($env:TEMP)\cm_siteconfig_$($env:COMPUTERNAME)_transaction.log"
Write-Log -Category "info" -Message "transaction log = $tsFile"
try {
    Start-Transcript -Path $tsFile -ErrorAction SilentlyContinue
}
catch {
    Write-Warning "unable to start transcript"
}

Write-Output "------------------- BEGIN $(Get-Date) -------------------"

Write-Log -Category "info" -Message "loading xml data"
[xml]$xmldata = Get-Content $XmlFile
$sitecode = $xmldata.configuration.cmsite.sitecode
if (($sitecode -eq "") -or (-not($sitecode))) {
    Write-Warning "unable to load XML data from $xmlFile"
    break
}
Write-Log -Category "info" -Message "site code = $sitecode"

if ($sitecode -eq "") {
    Write-Warning "site code could not be obtained"
    break
}
if (-not (Get-CMModule)) {
    Write-Warning "failed to load ConfigurationManager powershell module"
    break
}

# Set the current location to be the site code.
Write-Log -Category "info" -Message "mounting CM Site provider_ $sitecode`:"
Set-Location "$sitecode`:" 

$Site = Get-CMSite -SiteCode $sitecode
Write-Log -Category "info" -Message "site version = $($site.Version)"

Set-CMSiteADForest -DataSet $xmldata
Set-CMSiteDiscoveryMethods -DataSet $xmldata
#Invoke-CMSystemDiscovery 
Set-CMSiteBoundaryGroups -DataSet $xmldata
if ((-not($AutoBoundaries)) -or ($ForceBoundaries)) {
    Set-Boundaries -DataSet $xmldata
}
Set-CMSiteServerRoles -DataSet $xmldata
Set-CMSiteAIClasses -DataSet $xmldata

if (Set-CMSiteConfigFolders -SiteCode $sitecode -DataSet $xmldata) {
    Write-Host "Console folders have been created" -ForegroundColor Green
}
else {
    Write-Warning "Failed to create console folders"
}
if (Set-CMSiteQueries -DataSet $cmdata) {
    Write-Host "Custom Queries have been created" -ForegroundColor Green
}
else {
    Write-Warning "Failed to create custom queries"
}

Write-Log -Category "info" -Message "---------------------------------------------------"
Write-Log -Category "info" -Message "restore working path to user profile"
Set-Location -Path $env:USERPROFILE

Write-Host "------------------- BEGIN $(Get-Date) -------------------" -ForegroundColor Green
Write-Host "---------------- COMPLETED $(Get-Date) ------------------" -ForegroundColor Green
$time2 = Get-TimeOffset -StartTime $RunTime1
Write-Log -Category "info" -Message "total runtime (hh:mm:ss) = $time2"

Stop-Transcript
