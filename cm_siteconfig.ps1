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
    1.1.1 - DS - 2017.08.23
    
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
$basekey = 'HKLM:\SOFTWARE\CM_SITECONFIG'
$ScriptVersion = '1.1.1.8'

$RunTime1 = Get-Date
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
        Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" 
    }
}

function Set-DiscoveryMethods {
    [CmdletBinding()]
    param ($DataSet)

    Write-Verbose "----------------------------------------------------"
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
    $disc = $DataSet.discoveries.discovery | ? {$_.enabled -eq 'true'}
    foreach ($dm in $disc) {
        $discName = $dm.name
        Write-Verbose "- - - - - - - - - - - - - - - - - - - - - - - - - - - -"
        Write-Verbose "info: discovery method = $discName"
        $dmx = $disc | Where-Object {$_.name -eq $discName}
        $options = $dmx.options
        if ($options) {
            Write-Verbose "info: additional options are specified"
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
                    Write-Verbose "`tinfo: (option) name= $($optset[0]) ... value= $($optset[1])"
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
                    Write-Verbose "`toption: name= $optset ... value= True"
                }
            } # foreach
        } # if
        
        switch ($discName) {
            'ActiveDirectoryForestDiscovery' {
                Write-Verbose "info: FOREST DISCOVERY"
                try {
                    Set-CMDiscoveryMethod -ActiveDirectoryForestDiscovery -SiteCode $sitecode -Enabled $True -EnableSubnetBoundaryCreation $SubnetBoundaries -ErrorAction SilentlyContinue
                    Write-Verbose "info: AD forest discovery configured successfully"
                }
                catch {}
                break
            }
            'ActiveDirectorySystemDiscovery' {
                Write-Verbose "info: SYSTEM DISCOVERY"
                if ($FilterPassword1 -and $FilterLogon1) {
                    try {
                        Set-CMDiscoveryMethod -ActiveDirectorySystemDiscovery -SiteCode $sitecode -Enabled $True -ActiveDirectoryContainer "LDAP://$ADContainer" -EnableDeltaDiscovery $EnableDelta -EnableFilteringExpiredLogon $FilterLogon1 -TimeSinceLastLogonDays $FilterLogon2 -EnableFilteringExpiredPassword $FilterPassword1 -TimeSinceLastPasswordUpdateDays $FilterPassword2 -Recursive -ErrorAction SilentlyContinue | Out-Null
                        Write-Verbose "info: AD system discovery configured successfully (A)"
                    }
                    catch {
                        $_
                    }
                }
                elseif ($FilterPassword1) {
                    try {
                        Set-CMDiscoveryMethod -ActiveDirectorySystemDiscovery -SiteCode $sitecode -Enabled $True -ActiveDirectoryContainer "LDAP://$ADContainer" -EnableDeltaDiscovery $EnableDelta -EnableFilteringExpiredPassword $FilterPassword1 -TimeSinceLastPasswordUpdateDays $FilterPassword2 -Recursive -ErrorAction SilentlyContinue | Out-Null
                        Write-Verbose "info: AD system discovery configured successfully (B)"
                    }
                    catch {
                        $_
                    }
                }
                elseif ($FilterLogon1) {
                    try {
                        Set-CMDiscoveryMethod -ActiveDirectorySystemDiscovery -SiteCode $sitecode -Enabled $True -ActiveDirectoryContainer "LDAP://$ADContainer" -EnableDeltaDiscovery $EnableDelta -EnableFilteringExpiredLogon $FilterLogon1 -TimeSinceLastLogonDays $FilterLogon2 -Recursive -ErrorAction SilentlyContinue | Out-Null
                        Write-Verbose "info: AD system discovery configured successfully (C)"
                    }
                    catch {
                        $_
                    }
                }
                else {
                    try {
                        Set-CMDiscoveryMethod -ActiveDirectorySystemDiscovery -SiteCode $sitecode -Enabled $True -ActiveDirectoryContainer "LDAP://$ADContainer" -EnableDeltaDiscovery $EnableDelta -Recursive -ErrorAction SilentlyContinue | Out-Null
                        Write-Verbose "info: AD system discovery configured successfully (D)"
                    }
                    catch {
                        $_
                    }
                }
                break
            }
            'ActiveDirectoryUserDiscovery' {
                Write-Verbose "info: USER DISCOVERY"
                if ($ADAttributes -ne $null) {
                    Write-Verbose "info: assigning custom AD attributes"
                    try {
                        Set-CMDiscoveryMethod -ActiveDirectoryUserDiscovery -SiteCode $sitecode -Enabled $True -ActiveDirectoryContainer "LDAP://$ADContainer" -EnableDeltaDiscovery $EnableDelta -Recursive -AddAdditionalAttribute $ADAttributes -ErrorAction SilentlyContinue | Out-Null
                        Write-Verbose "info: AD user discovery configured successfully (A)"
                    }
                    catch {
                        $_
                    }
                }
                else {
                    try {
                        Set-CMDiscoveryMethod -ActiveDirectoryUserDiscovery -SiteCode $sitecode -Enabled $True -ActiveDirectoryContainer "LDAP://$ADContainer" -EnableDeltaDiscovery $EnableDelta -Recursive -ErrorAction SilentlyContinue | Out-Null
                        Write-Verbose "info: AD user discovery configured successfully (B)"
                    }
                    catch {
                        $_
                    }
                }
                break
            }
            'ActiveDirectoryGroupDiscovery' {
                Write-Verbose "info: GROUP DISCOVERY"
                try {
                    Set-CMDiscoveryMethod -ActiveDirectoryGroupDiscovery -SiteCode $sitecode -Enabled $True -EnableDeltaDiscovery $EnableDelta -EnableFilteringExpiredLogon $True -TimeSinceLastLogonDays 90 -EnableFilteringExpiredPassword $True -TimeSinceLastPasswordUpdateDays 90 -ErrorAction SilentlyContinue | Out-Null
                    Write-Output "info: AD group discovery configured successfully"
                }
                catch {}
                break
            }
        } # switch
    } # foreach
} # function

function Set-ADForest {
    [CmdletBinding()]
    param ($DataSet)
    $adforest = $DataSet.forest
    Write-Verbose "----------------------------------------------------"
    Write-Host "Configuring AD Forest" -ForegroundColor Green
    try {
        New-CMActiveDirectoryForest -ForestFqdn "$adforest" -EnableDiscovery $True -ErrorAction SilentlyContinue
        Write-Output $True
    }
    catch {
        if ($_.Exception.Message -eq 'An object with the specified name already exists.') {
            Write-Verbose "info: AD forest $adforest already defined"
            Write-Output $True
        }
        else {
            Write-Error $_
        }
    }
}

function Set-BoundaryGroups {
    [CmdletBinding()]
    param ($DataSet)
    Write-Verbose "----------------------------------------------------"
    Write-Host "Configuring Site Boundary Groups" -ForegroundColor Green
    $bglist = $DataSet.boundarygroups.boundarygroup
    foreach ($bg in $bglist) {
        $bgName = $bg.name
        $bgComm = $bg.comment
        $bgServer = $bg.SiteSystemServer
        $bgLink   = $bg.LinkType
        Write-Verbose "- - - - - - - - - - - - - - - - - - - - - - - - - -"
        Write-Verbose "info: boundary group name = $bgName"
        if ($bgServer) {
            $bgSiteServer = @{$bgServer = $bgLink}
            Write-Verbose "info: site server assigned: $bgServer ($bgLink)"
            try {
                New-CMBoundaryGroup -Name $bgName -Description $bgComm -DefaultSiteCode $sitecode -AddSiteSystemServer $bgSiteServer -ErrorAction SilentlyContinue | Out-Null
                Write-Verbose "info: boundary group $bgName created"
            }
            catch {
                Write-Verbose "info: boundary group $bgName already exists."
                try {
                    Set-CMBoundaryGroup -Name $bgName -DefaultSiteCode $sitecode -AddSiteSystemServer $bgSiteServer -ErrorAction SilentlyContinue | Out-Null
                    Write-Verbose "info: boundary group $bgName has been updated"
                }
                catch {
                    Write-Error $_
                }
            }
        }
        else {
            Write-Verbose "info: boundary group $bgName does not have an assigned site server."
            try {
                New-CMBoundaryGroup -Name $bgName -Description $bgComm -DefaultSiteCode $sitecode -ErrorAction SilentlyContinue | Out-Null
                Write-Verbose "info: boundary group $bgName created"
            }
            catch {
                Write-Verbose "info: boundary group $bgName already exists."
                try {
                    Set-CMBoundaryGroup -Name $bgName -DefaultSiteCode $sitecode -ErrorAction SilentlyContinue | Out-Null
                    Write-Verbose "info: boundary group $bgName has been updated"
                }
                catch {
                    Write-Error $_
                }
            }
        }
    }
}

function Set-Boundaries {
    [CmdletBinding()]
    param ($DataSet)
    Write-Verbose "----------------------------------------------------"
    Write-Host "Configuring Site Boundaries" -ForegroundColor Green
    $blist = $DataSet.boundaries.boundary
    foreach ($bx in $blist) {
        $bName = $bx.name
        $bType = $bx.type
        $bData = $bx.value
        $bGrp  = $bx.boundarygroup
        $bComm = $bx.comment
        Write-Verbose "- - - - - - - - - - - - - - - - - - - - - - - - - -"
        Write-Verbose "info: boundary name = $bName"
        Write-Verbose "info: comment = $bComm"
        Write-Verbose "info: data = $bData"
        Write-Verbose "info: type = $bType"
        Write-Verbose "info: boundary group = $bGrp"
        try {
            $bx = New-CMBoundary -Name $bName -Type IPRange -Value $bData -ErrorAction Stop
            Write-Verbose "info: boundary [$bName] created"
        }
        catch {
            Write-Verbose "info: boundary [$bName] already exists"
            try {
                $bx = Get-CMBoundary -BoundaryName $bName -ErrorAction Stop
                Write-Verbose "info: getting boundary information for $bName"
                $bID = $bx.BoundaryID
                Write-Verbose "info: boundary [$bName] identifier = $bID"
            }
            catch {
                Write-Verbose "error: unable to create or update boundary: $bName"
                $bID = $null
                break
            }
        }
        if ($bID -and $bGrp) {
            Write-Verbose "info: assigning boundary [$bName] to boundary group: $bGrp"
            try {
                $bg = Get-CMBoundaryGroup -Name $bGrp -ErrorAction Stop
                $bgID = $bg.GroupID
                Write-Verbose "info: boundary group identifier = $bgID"
            }
            catch {
                Write-Verbose "error: unable to obtain boundary group [$bGrp]"
                $bgID = $null
            }
            if ($bgID) {
                try {
                    Add-CMBoundaryToGroup -BoundaryId $bx.BoundaryID -BoundaryGroupId $bg.GroupID
                    Write-Verbose "info: boundary ($bName) added to boundary group ($bGrp)"
                }
                catch {
                    Write-Verbose "error: oops?"
                }
            }
        }
        else {
            Write-Verbose "info: boundary [$bName] is not assigned to a boundary group"
        }
    } # foreach
}

function Set-CMSiteServerRoles {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$True)] $DataSet
    )
    Write-Verbose "function: set-cmsiteserverroles"
    foreach ($siterole in $DataSet.configuration.cmsite.sitesystemroles | Where-Object {$_.enabled -eq 'true'}) {
        $roleName = $siterole.name
        Write-Verbose "role: $roleName"
        switch ($RoleName) {
            'aisync' {
                try {
                    $x = Set-CMAssetIntelligenceSynchronizationPoint -Enable $True -EnableSynchronization $True -PassThru
                    if ($x) {
                        foreach ($opt in $siterole.roleoptions.roleoption) {
                            $optionName = $opt.name
                            Write-Verbose "option: $optionName"
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

function Set-AIClasses {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$True)]
        $DataSet
    )
    Write-Verbose "----------------------------------------------------"
    Write-Host "Configuring Asset Intelligence classes" -ForegroundColor Green
    foreach ($aiclass in $DataSet.cmsite.aiclasses.aiclass) {
        $cname = $aiclass.name
        Write-Verbose "enable class: $cname"
        Set-CMAssetIntelligenceClass -EnableReportingClass $cname | Out-Null
    }
}

# --------------------------------------------------------------------

Set-Location $env:USERPROFILE
$tsFile = "$($env:TEMP)\cm_siteconfig_$($env:COMPUTERNAME)_transaction.log"
Write-Verbose "info: transaction log = $tsFile"
try {
    Start-Transcript -Path $tsFile -ErrorAction SilentlyContinue
}
catch {
    Write-Warning "unable to start transcript"
}

Write-Output "------------------- BEGIN $(Get-Date) -------------------"

Write-Verbose "info: loading xml data"
[xml]$xmldata = Get-Content $XmlFile
$cmdata   = $xmldata.configuration.cmsite
$sitecode = $cmdata.sitecode
Write-Verbose "info: site code = $sitecode"

if ($sitecode -eq "") {
    Write-Warning "site code could not be obtained"
    break
}
Get-CMModule

# Set the current location to be the site code.
Write-Verbose "info: mounting CM Site provider_ $sitecode`:"
Set-Location "$sitecode`:" 

$Site = Get-CMSite -SiteCode $sitecode
Write-Verbose "info: site version = $($site.Version)"

Set-ADForest -DataSet $cmdata
Set-DiscoveryMethods -DataSet $cmdata
#Invoke-CMSystemDiscovery 
Set-BoundaryGroups -DataSet $cmdata
if ((-not($AutoBoundaries)) -or ($ForceBoundaries)) {
    Set-Boundaries -DataSet $cmdata
}
Set-CMSiteServerRoles -DataSet $cmdata
Set-AIClasses -DataSet $cmdata

Write-Verbose "info: restore working path to user profile"
Set-Location -Path $env:USERPROFILE

Write-Host "Completed : $(Get-Date)" -ForegroundColor Green
$time2 = Get-TimeOffset -StartTime $RunTime1
Write-Verbose "info: total runtime (hh:mm:ss) = $time2"
Stop-Transcript
