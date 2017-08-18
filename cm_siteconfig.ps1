#requires -RunAsAdministrator
#requires -version 3
<#
.SYNOPSIS
    SCCM site configuration script
.DESCRIPTION
    Yeah, what he said.
.PARAMETER XmlFile
    [string](optional) Path and Name of XML input file
.PARAMETER NoCheck
    [switch](optional) Skip platform validation restrictions
.NOTES
    1.1.1 - DS - 2017.08.17
    
    Read the associated XML to make sure the path and filename values
    all match up like you need them to.

.EXAMPLE
    .\cm_siteconfig.ps1 -XmlFile .\cm_siteconfig.xml -Verbose
#>

[CmdletBinding()]
param (
    [parameter(Mandatory=$True, HelpMessage="Path and name of XML input file")]
        [ValidateNotNullOrEmpty()]
        [string] $XmlFile
)

$XmlFile = "\\FS1\apps\MS\CM_BUILD\1.1.0\cm_siteconfig.xml"

$basekey = 'HKLM:\SOFTWARE\CM_BUILD'

$RunTime1 = Get-Date
Set-Location "$($env:USERPROFILE)\Documents"
if (-not(Test-Path $XmlFile)) {
    Write-Warning "unable to locate input file: $XmlFile"
    break
}

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
                try {
                    Set-CMDiscoveryMethod -ActiveDirectoryForestDiscovery -SiteCode $sitecode -Enabled $True -EnableSubnetBoundaryCreation $SubnetBoundaries -ErrorAction SilentlyContinue
                    Write-Verbose "AD forest discovery configured successfully"
                }
                catch {}
                break
            }
            'ActiveDirectorySystemDiscovery' {
                if ($FilterPassword1 -and $FilterLogon1) {
                    try {
                        Set-CMDiscoveryMethod -ActiveDirectorySystemDiscovery -SiteCode $sitecode -Enabled $True -ActiveDirectoryContainer $ADContainer -EnableDeltaDiscovery $EnableDelta -EnableFilteringExpiredLogon $FilterLogon1 -TimeSinceLastLogonDays $FilterLogon2 -EnableFilteringExpiredPassword $FilterPassword1 -TimeSinceLastPasswordUpdateDays $FilterPassword2 -Recursive -ErrorAction SilentlyContinue | Out-Null
                        Write-Verbose "AD system discovery configured successfully (A)"
                    }
                    catch {}
                }
                elseif ($FilterPassword1) {
                    try {
                        Set-CMDiscoveryMethod -ActiveDirectorySystemDiscovery -SiteCode $sitecode -Enabled $True -ActiveDirectoryContainer $ADContainer -EnableDeltaDiscovery $EnableDelta -EnableFilteringExpiredPassword $FilterPassword1 -TimeSinceLastPasswordUpdateDays $FilterPassword2 -Recursive -ErrorAction SilentlyContinue | Out-Null
                        Write-Verbose "AD system discovery configured successfully (B)"
                    }
                    catch {}
                }
                elseif ($FilterLogon1) {
                    try {
                        Set-CMDiscoveryMethod -ActiveDirectorySystemDiscovery -SiteCode $sitecode -Enabled $True -ActiveDirectoryContainer $ADContainer -EnableDeltaDiscovery $EnableDelta -EnableFilteringExpiredLogon $FilterLogon1 -TimeSinceLastLogonDays $FilterLogon2 -Recursive -ErrorAction SilentlyContinue | Out-Null
                        Write-Verbose "AD system discovery configured successfully (C)"
                    }
                    catch {}
                }
                else {
                    try {
                        Set-CMDiscoveryMethod -ActiveDirectorySystemDiscovery -SiteCode $sitecode -Enabled $True -ActiveDirectoryContainer $ADContainer -EnableDeltaDiscovery $EnableDelta -Recursive -ErrorAction SilentlyContinue | Out-Null
                        Write-Verbose "AD system discovery configured successfully (D)"
                    }
                    catch {}
                }
                break
            }
            'ActiveDirectoryUserDiscovery' {
                if ($ADAttributes -ne $null) {
                    try {
                        Set-CMDiscoveryMethod -ActiveDirectoryUserDiscovery -SiteCode $sitecode -Enabled $True -ActiveDirectoryContainer $ADContainer -EnableDeltaDiscovery $EnableDelta -Recursive -AddAdditionalAttribute $ADAttributes -ErrorAction SilentlyContinue | Out-Null
                        Write-Verbose "AD user discovery configured successfully (A)"
                    }
                    catch {}
                }
                else {
                    try {
                        Set-CMDiscoveryMethod -ActiveDirectoryUserDiscovery -SiteCode $sitecode -Enabled $True -ActiveDirectoryContainer $ADContainer -EnableDeltaDiscovery $EnableDelta -Recursive -ErrorAction SilentlyContinue | Out-Null
                        Write-Verbose "AD user discovery configured successfully (B)"
                    }
                    catch {}
                }
                break
            }
            'ActiveDirectoryGroupDiscovery' {
                try {
                    Set-CMDiscoveryMethod -ActiveDirectoryGroupDiscovery -SiteCode $sitecode -Enabled $True -EnableDeltaDiscovery $EnableDelta -EnableFilteringExpiredLogon $True -TimeSinceLastLogonDays 90 -EnableFilteringExpiredPassword $True -TimeSinceLastPasswordUpdateDays 90 -ErrorAction SilentlyContinue | Out-Null
                    Write-Output "AD group discovery configured successfully"
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
        Write-Verbose "info: boundary group name = $bgName"
        if ($bgServer) {
            $bgSiteServer = @{$bgServer = $bgLink}
            try {
                New-CMBoundaryGroup -Name $bgName -Description $bgComm -DefaultSiteCode $sitecode -AddSiteSystemServer $bgSiteServer -ErrorAction SilentlyContinue | Out-Null
                Write-Verbose "info: boundary group created"
            }
            catch {
                if ($error[0].Exception -eq 'An object with the specified name already exists') {
                    try {
                        Set-CMBoundaryGroup -Name $bgName -DefaultSiteCode $sitecode -AddSiteSystemServer $bgSiteServer -ErrorAction SilentlyContinue | Out-Null
                        Write-Verbose "info: boundary group updated"
                    }
                    catch {
                        Write-Error $_
                    }
                }
                else {
                    Write-Verbose "error: boundary group failed"
                    Write-Error $_
                }
            }
        }
        else {
            try {
                New-CMBoundaryGroup -Name $bgName -Description $bgComm -DefaultSiteCode $sitecode -ErrorAction SilentlyContinue | Out-Null
                Write-Verbose "info: boundary group created"
            }
            catch {
                if ($error[0].Exception -eq 'An object with the specified name already exists') {
                    try {
                        Set-CMBoundaryGroup -Name $bgName -DefaultSiteCode $sitecode -ErrorAction SilentlyContinue | Out-Null
                        Write-Verbose "info: boundary group updated"
                    }
                    catch {
                        Write-Error $_
                    }
                }
                else {
                    Write-Verbose "error: boundary group failed"
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
        Write-Verbose "info: boundary name = $bName"
        if ($bGrp) {
            # get boundary group
            try {
                Write-Verbose "info: Configuring Site Boundaries: $bName"
                $b1 = New-CMBoundary -Name $bName -Type IPRange -Value $bData -ErrorAction SilentlyContinue | Out-Null
            }
            catch [System.Exception] {
                #write-host $_
                if ($error[0].Exception -eq 'An object with the specified name already exists') {
                    Write-Verbose "info: getting existing boundary information: $bName"
                    $b1 = Get-CMBoundary -BoundaryName $bName
                }
            }
            if ($b1) {
                try {
                    $bg1 = Get-CMBoundaryGroup -Name $bGrp -ErrorAction SilentlyContinue | Out-Null
                    if ($bg1) {
                        Add-CMBoundaryToGroup -BoundaryId $b1.BoundaryID -BoundaryGroupId $bg1.GroupID | Out-Null
                    }
                    else {
                        Write-Warning "failed to assign boundary to boundary group"
                    }
                }
                catch {
                    Write-Warning "unable to get boundary group 'NA-US-East-Norfolk'"
                }
            }
        }
        else {
            # no boundary group
        }
    }
}

function Set-BoundaryRelationships {
    [CmdletBinding()]
    param ($DataSet)
    <#
    try {
        New-CMBoundaryGroupRelationship -SourceGroupId $bgID
    }
    catch {}
    #>
}

# --------------------------------------------------------------------

Set-Location $env:USERPROFILE
$tsFile = "$($env:TEMP)\cm_build$($env:COMPUTERNAME)_transaction.log"
Write-Verbose "info: transaction log = $tsFile"
#Start-Transcript -Path $tsFile

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

#Set-ADForest -DataSet $cmdata
Set-DiscoveryMethods -DataSet $cmdata
#Invoke-CMSystemDiscovery 
Set-BoundaryGroups -DataSet $cmdata
Set-Boundaries -DataSet $cmdata
#Set-BoundaryRelationships -DataSet $cmdata

Write-Verbose "info: restore working path to user profile"
Set-Location -Path $env:USERPROFILE

Write-Host "Completed : $(Get-Date)" -ForegroundColor Green
$time2 = Get-TimeOffset -StartTime $RunTime1
Write-Verbose "info: total runtime (hh:mm:ss) = $time2"
#Stop-Transcript
