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
.PARAMETER Detailed
    [switch](optional) Verbose output without using -Verbose
.PARAMETER Override
    [switch](optional) Allow override of Controls in XML file using GUI (gridview) selection at runtime
.NOTES
    1.2.24 - DS - 2017.09.05
    
    Read the associated XML to make sure the path and filename values
    all match up like you need them to.

.EXAMPLE
    .\cm_siteconfig.ps1 -XmlFile .\cm_siteconfig.xml -Detailed
.EXAMPLE
    .\cm_siteconfig.ps1 -XmlFile .\cm_siteconfig.xml -Override
.EXAMPLE
    .\cm_siteconfig.ps1 -XmlFile .\cm_siteconfig.xml -Detailed -Override
#>

[CmdletBinding(SupportsShouldProcess=$True)]
param (
    [parameter(Mandatory=$True, HelpMessage="Path and name of XML input file")]
        [ValidateNotNullOrEmpty()]
        [string] $XmlFile,
    [parameter(Mandatory=$False, HelpMessage="Force custom site boundary creation from XML file")]
        [switch] $ForceBoundaries,
    [parameter(Mandatory=$False, HelpMessage="Display verbose output")]
        [switch] $Detailed,
    [parameter(Mandatory=$False, HelpMessage="Override control set from XML file")]
        [switch] $Override
)

function Get-ScriptDirectory {
    $Invocation = (Get-Variable MyInvocation -Scope 1).Value
    Split-Path $Invocation.MyCommand.Path
}

$basekey       = 'HKLM:\SOFTWARE\CM_SITECONFIG'
$ScriptVersion = '1.2.24'
$ScriptPath    = Get-ScriptDirectory
$LogsFolder    = "$ScriptPath\Logs"
if (-not(Test-Path $LogsFolder)) {New-Item -Path $LogsFolder -Type Directory}
$tsFile        = "$LogsFolder\cm_siteconfig_$($env:COMPUTERNAME)_transaction.log"
$logFile       = "$LogsFolder\cm_siteconfig_$($env:COMPUTERNAME)_details.log"
$HostName      = "$($env:COMPUTERNAME).$($env:USERDNSDOMAIN)"

try {stop-transcript -ErrorAction SilentlyContinue} catch {}
try {Start-Transcript -Path $tsFile -Force} catch {}

Write-Host "------------------- BEGIN $(Get-Date) -------------------" -ForegroundColor Green

function Write-Log {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [parameter(Mandatory=$True)]
            [ValidateSet('info','error','warning')]
            [string] $Category,
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [string] $Message
    )
    if ($Detailed) {
        Write-Host "DETAILED`: $(Get-Date -f 'yyyy-M-dd HH:MM:ss')`t$Category`t$Message" -ForegroundColor Cyan
    }
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

function Import-CmxModule {
    [CmdletBinding()]
    param ()
    Write-Log -Category info -Message "Importing ConfigurationManager module"
    if (-not(Get-Module ConfigurationManager)) {
        Write-Host "Importing the ConfigurationManager powershell module" -ForegroundColor Green
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

function Import-CmxDiscoveryMethods {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        $DataSet
    )
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
    $result = $True
    $Time1  = Get-Date
    foreach ($item in $DataSet.configuration.cmsite.discoveries.discovery | Where-Object {$_.use -eq '1'}) {
        $discName = $item.name
        $discOpts = $item.options
        Write-Log -Category "info" -Message "configuring discovery method = $discName"
        switch ($discName) {
            'ActiveDirectoryForestDiscovery' {
                try {
                    Set-CMDiscoveryMethod -ActiveDirectoryForestDiscovery -SiteCode $sitecode -Enabled $True -ErrorAction SilentlyContinue | Out-Null
                    Write-Log -Category info -Message "discovery has been enabled. configuring options"
                    if ($discOpts.length -gt 0) {
                        foreach ($opt in $discOpts.Split('|')) {
                            Write-Log -Category info -Message "option = $opt"
                            switch ($opt) {
                                'EnableActiveDirectorySiteBoundaryCreation' {
                                    Set-CMDiscoveryMethod -ActiveDirectoryForestDiscovery -SiteCode $sitecode -Enabled $True -EnableActiveDirectorySiteBoundaryCreation $True | Out-Null
                                }
                                'EnableSubnetBoundaryCreation' {
                                    Set-CMDiscoveryMethod -ActiveDirectoryForestDiscovery -SiteCode $sitecode -Enabled $True -EnableSubnetBoundaryCreation $True | Out-Null
                                }
                            }
                        } # foreach
                    }
                }
                catch {
                    Write-Log -Category error -Message $_.Exception.Message
                    $result = $False
                }
                break
            }
            'ActiveDirectorySystemDiscovery' {
                try {
                    Set-CMDiscoveryMethod -ActiveDirectorySystemDiscovery -SiteCode $sitecode -Enabled $True -ErrorAction Continue | Out-Null
                    Write-Log -Category info -Message "discovery has been enabled. configuring options"
                    foreach ($opt in $discOpts.Split("|")) {
                        $optx = $opt.Split(':')
                        Write-Log -Category info -Message "option = $($optx[0])"
                        switch ($optx[0]) {
                            'ADContainer' {
                                Set-CMDiscoveryMethod -ActiveDirectorySystemDiscovery -SiteCode $sitecode -ActiveDirectoryContainer "LDAP://$ADContainer" -Recursive | Out-Null
                                break
                            }
                            'EnableDetaDiscovery' {
                                Set-CMDiscoveryMethod -ActiveDirectorySystemDiscovery -SiteCode $sitecode -EnableDeltaDiscovery $True | Out-Null
                                break
                            }
                            'EnableFilteringExpiredLogon' {
                                Set-CMDiscoveryMethod -ActiveDirectorySystemDiscovery -SiteCode $sitecode -EnableFilteringExpiredLogon $True -TimeSinceLastLogonDays $optx[1] | Out-Null
                                break
                            }
                            'EnableFilteringExpiredPassword' {
                                Set-CMDiscoveryMethod -ActiveDirectorySystemDiscovery -SiteCode $sitecode -EnableFilteringExpiredPassword $True -TimeSinceLastPasswordUpdateDays $optx[1] | Out-Null
                                break
                            }
                        } # switch
                    } # foreach
                }
                catch {
                    Write-Log -Category error -Message $_.Exception.Message
                    $result = $False
                }
                break
            }
            'ActiveDirectoryGroupDiscovery' {
                try {
                    Set-CMDiscoveryMethod -ActiveDirectoryGroupDiscovery -SiteCode $sitecode -Enabled $True -ErrorAction SilentlyContinue | Out-Null
                    Write-Log -Category info -Message "discovery has been enabled. configuring options"
                    foreach ($opt in $discOpts.Split("|")) {
                        $optx = $opt.Split(':')
                        Write-Log -Category info -Message "option = $($optx[0])"
                        switch ($optx[0]) {
                            'EnableDeltaDiscovery' {
                                Set-CMDiscoveryMethod -ActiveDirectoryGroupDiscovery -SiteCode $sitecode -EnableDeltaDiscovery $True | Out-Null
                                break
                            }
                            'EnableFilteringExpiredLogon' {
                                Set-CMDiscoveryMethod -ActiveDirectoryGroupDiscovery -SiteCode $sitecode -EnableFilteringExpiredLogon $True -TimeSinceLastLogonDays $optx[1] | Out-Null
                                break
                            }
                            'EnableFilteringExpiredPassword' {
                                Set-CMDiscoveryMethod -ActiveDirectoryGroupDiscovery -SiteCode $sitecode -EnableFilteringExpiredPassword $True -TimeSinceLastPasswordUpdateDays 90 | Out-Null
                                break
                            }
                        } # switch
                    } # foreach
                }
                catch {
                    Write-Log -Category error -Message "AD group discovery setting failed!"
                }
                break
            }
            'ActiveDirectoryUserDiscovery' {
                try {
                    Set-CMDiscoveryMethod -ActiveDirectoryUserDiscovery -SiteCode $sitecode -Enabled $True -ErrorAction SilentlyContinue | Out-Null
                    Write-Log -Category info -Message "discovery has been enabled. configuring options"
                    foreach ($opt in $discOpts.Split("|")) {
                        $optx = $opt.Split(':')
                        Write-Log -Category info -Message "option = $($optx[0])"
                        switch ($optx[0]) {
                            'ADContainer' {
                                Set-CMDiscoveryMethod -ActiveDirectoryUserDiscovery -SiteCode $sitecode -ActiveDirectoryContainer "LDAP://$ADContainer" -Recursive | Out-Null
                                break
                            }
                            'EnableDetaDiscovery' {
                                Set-CMDiscoveryMethod -ActiveDirectoryUserDiscovery -SiteCode $sitecode -EnableDeltaDiscovery $True | Out-Null
                                break
                            }
                            'ADAttributes' {
                                Set-CMDiscoveryMethod -ActiveDirectoryUserDiscovery -SiteCode $sitecode -AddAdditionalAttribute $optx[1].split(',') | Out-Null
                                break
                            }
                        } # switch
                    } # foreach
                }
                catch {
                    Write-Log -Category error -Message $_.Exception.Message
                    $result = $False
                }
                break
            }
            'NetworkDiscovery' {
                try {
                    Set-CMDiscoveryMethod -NetworkDiscovery -SiteCode $sitecode -Enabled $True -ErrorAction SilentlyContinue | Out-Null
                    Write-Log -Category info -Message "discovery has been enabled. configuring options"
                }
                catch {
                    Write-Log -Category error -Message $_.Exception.Message
                    $result = $False
                }
                break
            }
            'HeartbeatDiscovery' {
                try {
                    Set-CMDiscoveryMethod -Heartbeat -SiteCode $sitecode -Enabled $True -ErrorAction SilentlyContinue | Out-Null
                    Write-Log -Category info -Message "discovery has been enabled. configuring options"
                }
                catch {
                    Write-Log -Category error -Message $_.Exception.Message
                    $result = $False
                }
                break
            }
        } # switch
        Write-Verbose "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
    } # foreach
    Write-Log -Category info -Message "function runtime: $(Get-TimeOffset $time1)"
    Write-Output $result
} # function

function Set-CmxADForest {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        $DataSet
    )
    $adforest = $DataSet.configuration.cmsite.forest
    Write-Host "Configuring AD Forest" -ForegroundColor Green
    $result = $True
    $Time1  = Get-Date
    try {
        New-CMActiveDirectoryForest -ForestFqdn "$adforest" -EnableDiscovery $True -ErrorAction SilentlyContinue
        Write-Log -Category "info" -Message "item created successfully: $adforest"
        Write-Output $True
    }
    catch {
        if ($_.Exception.Message -eq 'An object with the specified name already exists.') {
            Write-Log -Category "info" -Message "item already exists"
            Write-Output $True
        }
        else {
            Write-Log -Category error -Message $_.Exception.Message
            $result = $false
            break
        }
    }
    Write-Log -Category info -Message "function runtime: $(Get-TimeOffset $time1)"
    Write-Output $result
}

function Import-CmxBoundaryGroups {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        $DataSet
    )
    Write-Host "Configuring Site Boundary Groups" -ForegroundColor Green
    $result = $True
    $Time1  = Get-Date
    foreach ($item in $DataSet.configuration.cmsite.boundarygroups.boundarygroup | Where-Object {$_.use -eq '1'}) {
        $bgName   = $item.name
        $bgComm   = $item.comment
        $bgServer = $item.SiteSystemServer
        $bgLink   = $item.LinkType
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
                    Write-Log -Category error -Message $_.Exception.Message
                    $result = $False
                    break
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
                    Write-Log -Category error -Message $_.Exception.Message
                    $result = $false
                    break
                }
            }
        } # if
        Write-Log -Category "info" -Message "- - - - - - - - - - - - - - - - - - - - - - - - - -"
    } # foreach
    Write-Log -Category info -Message "function runtime: $(Get-TimeOffset $time1)"
    Write-Output $result
}

function Set-CmxBoundaries {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        $DataSet
    )
    Write-Host "Configuring Site Boundaries" -ForegroundColor Green
    $result = $True
    $Time1  = Get-Date
    foreach ($item in $DataSet.configuration.cmsite.boundaries.boundary | Where-Object {$_.use -eq '1'}) {
        $bName = $item.name
        $bType = $item.type
        $bData = $item.value
        $bGrp  = $item.boundarygroup
        $bComm = $item.comment
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
                $bx = Get-CMBoundary -BoundaryName $bName -ErrorAction SilentlyContinue
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
                $bg = Get-CMBoundaryGroup -Name $bGrp -ErrorAction SilentlyContinue
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
    Write-Log -Category info -Message "function runtime: $(Get-TimeOffset $time1)"
    Write-Output $result
}

function Set-CmxSiteServerRoles {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [parameter(Mandatory=$True)] 
        [ValidateNotNullOrEmpty()]
        $DataSet
    )
    Write-Host "Configuring Site System Roles" -ForegroundColor Green
    $result = $True
    $Time1  = Get-Date
    foreach ($item in $DataSet.configuration.cmsite.sitesystemroles.sitesystemrole | Where-Object {$_.use -eq '1'}) {
        $roleName = $item.name
        $roleComm = $item.comment
        Write-Log -Category "info" -Message "configuring site system role: $roleComm [$roleName]"
        switch ($RoleName) {
            'aisp' {
                try {
                    Set-CMAssetIntelligenceSynchronizationPoint -Enable $True -EnableSynchronization $True -ErrorAction SilentlyContinue
                    Write-Log -Category "info" -Message "asset intelligence sync point is now enabled"
                    $x = $True
                }
                catch {
                    try {
                        $x = Get-CMAssetIntelligenceSynchronizationPoint -SiteCode "$sitecode" -SiteSystemServerName "$hostname" -ErrorAction SilentlyContinue
                        Write-Log -Category "info" -Message "asset intelligence sync point was already enabled"
                        $ExistingDP = $True
                    }
                    catch {
                        Write-Log -Category error -Message $_.Exception.Message
                    }
                }
                if ($x) {
                    foreach ($roleopt in $siterole.roleoptions.roleoption | Where-Object {$_.use -eq "1"}) {
                        switch ($roleopt.name) {
                            'EnableAllReportingClass' {
                                Write-Log -Category info -Message "enabling all reporting classes"
                                try {
                                    Set-CMAssetIntelligenceClass -EnableAllReportingClass | Out-Null
                                }
                                catch {
                                    Write-Log -Category error -Message $_.Exception.Message
                                }
                                break
                            }
                            'EnabledReportingClass' {
                                Write-Log -Category info -Message "enabling class: $($roleopt.params)"
                                try {
                                    Set-CMAssetIntelligenceClass -EnableReportingClass $roleopt.params | Out-Null
                                }
                                catch {
                                    Write-Log -Category error -Message $_.Exception.Message
                                }
                                break
                            }
                        } # switch
                    } # foreach
                }
                else {
                    Write-Log -Category "error" -Message "failed to configure asset intelligence sync point!"
                }
                break
            }
            'dp' {
                try {
                    $dp = Get-CMDistributionPoint -SiteSystemServerName "$hostname" -ErrorAction SilentlyContinue
                    Write-Log -Category "info" -Message "$hostname is already a distribution point"
                }
                catch {
                    Write-Log -Category "info" -Message "$hostname is not a distribution point"
                    $dp = Add-CMDistributionPoint -SiteSystemServerName "$hostname"
                }
                if ($dp) {
                    $code = "Set-CMDistributionPoint `-SiteCode `"$sitecode`" `-SiteSystemServerName `"$hostname`""
                    foreach ($roleopt in $siterole.roleoptions.roleoption | Where-Object {$_.use -eq "1"}) {
                        $param = $roleopt.params
                        if ($param -eq '@') {
                            $param = "`-$($roleopt.name)"
                        }
                        elseif ($param -eq 'true') {
                            $param = "`-$($roleopt.name) `$True"
                        }
                        elseif ($param -eq 'false') {
                            $param = "`-$($roleopt.name) `$False"
                        }
                        elseif ($roleopt.name -like "*password*") {
                            $param = "`-$($roleopt.name) `$(ConvertTo-SecureString -String `"$param`" -AsPlainText -Force)"
                        }
                        else {
                            $param = "`-$($roleopt.name) `"$($roleopt.params)`""
                        }
                        $code += " $param"
                        Write-Log -Category "info" -Message "dp option >> $param"
                    } # foreach
                    Write-Log -Category "info" -Message "command >> $code"
                    try {
                        Invoke-Expression -Command $code -ErrorAction Stop
                        Write-Log -Category info -Message "expression has been applied successfully"
                    }
                    catch {
                        Write-Log -Category error -Message $_.Exception.Message
                        $result = $False
                    }
                }
                break
            }
            'sup' {
                if (Get-CMSoftwareUpdatePoint) {
                    Write-Log -Category info -Message "software update point has already been configured"
                }
                else {
                    $code = "Add-CMSoftwareUpdatePoint `-SiteSystemServerName `"$hostname`" `-SiteCode `"$sitecode`""
                    foreach ($roleopt in $siterole.roleoptions.roleoption | Where-Object {$_.use -eq "1"}) {
                        $optname = $roleopt.name
                        $params  = $roleopt.params
                        if ($optName -eq 'WsusAccessAccount') {
                            if ($params -eq 'NULL') {
                                $code += " `-WsusAccessAccount `$null"
                            }
                            else {
                                $code += "` -WsusAccessAccount `"$params`""
                            }
                        }
                        else {
                            $code += " `-$optName $params"
                        }
                    } # foreach
                    Write-Log -Category "info" -Message "command >> $code"
                    try {
                        Invoke-Expression -Command $code -ErrorAction Stop
                        Write-Log -Category info -Message "expression has been applied successfully"
                    }
                    catch {
                        Write-Log -Category error -Message $_.Exception.Message
                        $result = $False
                    }
                }
                break
            }
            'scp' {
                foreach ($roleopt in $siterole.roleoptions.roleoption | Where-Object {$_.use -eq "1"}) {
                    switch ($roleopt.name) {
                        'Mode' {
                            Write-Log -Category info -Message "setting $($roleopt.name) = $($roleopt.params)"
                            Set-CMServiceConnectionPoint -SiteCode P01 -SiteSystemServerName "$HostName" -Mode $roleopt.params
                            break
                        }
                    } # switch
                } # foreach
                break
            }
            'mp' {
                foreach ($roleopt in $siterole.roleoptions.roleoption | Where-Object {$_.use -eq "1"}) {
                    switch ($roleopt.name) {
                        'PublicFqdn' {
                            Write-Log -Category info -Message "setting $($roleopt.name) = $($roleopt.params)"
                            Set-CMSiteSystemServer -SiteCode $sitecode -SiteSystemServerName "$HostName" -PublicFqdn "$($roleopt.params)"
                            break
                        }
                        'FdmOperation' {
                            Write-Log -Category info -Message "setting $($roleopt.name) = $($roleopt.params)"
                            if ($roleopt.params -eq 'FALSE') {
                                Set-CMSiteSystemServer -SiteCode $sitecode -SiteSystemServerName "$HostName" -FdmOperation $False
                            }
                            else {
                                Set-CMSiteSystemServer -SiteCode $sitecode -SiteSystemServerName "$HostName" -FdmOperation $True
                            }
                            break
                        }
                        'AccountName' {
                            Write-Log -Category info -Message "setting $($roleopt.name) = $($roleopt.params)"
                            if ($roleopt.params -eq 'NULL') {
                                Set-CMSiteSystemServer -SiteCode $sitecode -SiteSystemServerName "$HostName" -AccountName $null
                            }
                            else {
                                Set-CMSiteSystemServer -SiteCode $sitecode -SiteSystemServerName "$HostName" -AccountName "$($roleopt.params)"
                            }
                            break
                        }
                        'EnableProxy' {
                            Set-CMSiteSystemServer -SiteCode $sitecode -EnableProxy $True
                            # ProxyAccessAccount=NAME,ProxyServerName=NAME,ProxyServerPort=INT
                            $params = $roleopt.params
                            if ($params.length -gt 0) {
                                foreach ($param in $roleopt.params.split(',')) {
                                    $pset = $param.split('=')
                                    Write-Log -Category info -Message "setting $($pset[0]) = $($pset[1])"
                                    switch ($pset[0]) {
                                        'ProxyAccessAccount' {
                                            Set-CMSiteSystemServer -SiteCode $sitecode -ProxyAccessAccount "$($pset[1])"
                                            break
                                        }
                                        'ProxyServerName' {
                                            Set-CMSiteSystemServer -SiteCode $sitecode -ProxyServerName "$($pset[1])"
                                            break
                                        }
                                        'ProxyServerPort' {
                                            Set-CMSiteSystemServer -SiteCode $sitecode -ProxyServerPort $pset[1]
                                            break
                                        }
                                    } # switch
                                } # foreach
                            }
                            else {
                                Write-Log -Category "warning" -Message "EnableProxy parameters list is empty"
                            }
                            break
                        }
                        'PublishDNS' {
                            try {
                                if ($roleopt.params -eq 'True') {
                                    Set-CMManagementPointComponent -SiteCode "$sitecode" -PublishDns $True | Out-Null
                                    Write-Log -Category info -Message "publishing to DNS enabled"
                                }
                                catch {
                                    Write-Log -Category error -Message $_.Exception.Message
                                }
                            }
                            catch {}
                            break
                        }
                    } #switch
                } # foreach
                break
            }
            'ssrp' {
                # sql server reporting services point
                foreach ($roleopt in $siterole.roleoptions.roleoption | Where-Object {$_.use -eq "1"}) {
                    Write-Log -Category info -Message "setting $($roleopt.name) = $($roleopt.params)"
                    switch ($roleopt.name) {
                        'DatabaseServerName' {
                            $dbserver = $roleopt.params
                            break
                        }
                        'DatabaseName' {
                            $dbname = $roleopt.params
                            break
                        }
                        'UserName' {
                            $dbuser = $roleopt.params
                            break
                        }
                        'FolderName' {
                            $foldername = $roleopt.params
                            break
                        }
                    } # switch
                } # foreach
                if ($dbserver -and $dbname -and $dbuser) {
                    try {
                        Add-CMReportingServicePoint -SiteCode "$sitecode" -SiteSystemServerName "$HostName" -DatabaseServerName "$dbserver" -DatabaseName "$dbname" -UserName "$dbuser" -ErrorAction SilentlyContinue | Out-Null
                        Write-Log -Category info -Message "reporting services point has been configured"
                    }
                    catch {
                        if ($_.Exception.Message -like "*already exists*") {
                            Write-Log -Category info -Message "reporting services point is already active"
                        }
                        else {
                            Write-Log -Category error -Message "your code just blew chunks. what a mess."
                            Write-Log -Category error -Message $_.Exception.Message
                            $result = $False
                        }
                    }
                }
                break
            }
            'cmg' {
                # cloud management gateway
                foreach ($roleopt in $siterole.roleoptions.roleoption | Where-Object {$_.use -eq "1"}) {
                    switch ($roleopt.name) {
                        'CloudManagementGatewayName' {
                            try {
                                Add-CMCloudManagementGatewayConnectionPoint -CloudManagementGatewayName "$($roleopt.params)" -SiteSystemServerName "$HostName" -SiteCode "$sitecode" | Out-Null
                                Write-Log -Category info -Message "cloud management gateway has been configured"
                            }
                            catch {
                                Write-Log -Category error -Message $_.Exception.Message
                            }
                            break
                        }
                    } # switch
                } # foreach
                break
            }
            'acwsp' {
                if (Get-CMApplicationCatalogWebServicePoint) {
                    Write-Log -Category info -Message "application web catalog service point role is already configured"
                }
                else {
                    try {
                        Add-CMApplicationCatalogWebServicePoint -SiteCode "$sitecode" -SiteSystemServerName "$hostname" | Out-Null
                        Write-Log -Category info -Message "application web catalog service point role added successfully"
                    }
                    catch {
                        Write-Log -Category error -Message $_.Exception.Message
                        $result = $False
                    }
                }
                break
            }
            'acwp' {
                try {
                    Add-CMApplicationCatalogWebsitePoint -SiteSystemServerName "$hostname" -ApplicationWebServicePointServerName "$hostname" | Out-Null
                    Write-Log -Category info -Message "application website point role added successfully"
                    $go = $True
                }
                catch {
                    if (Get-CMApplicationCatalogWebsitePoint) {
                        $go = $True
                    }
                    else {
                        Write-Log -Category error -Message $_.Exception.Message
                        $go = $False
                        $result = $False
                    }
                }
                if ($go) {
                    foreach ($roleopt in $siterole.roleoptions.roleoption | Where-Object {$_.use -eq "1"}) {
                        $optName = $roleopt.name
                        $optData = $roleopt.params
                        Write-Log -Category info -Message "setting: $optName == $optData"
                        switch ($optName) {
                            'CommuncationType' {
                                try {
                                    Set-CMApplicationCatalogWebsitePoint -SiteCode "$sitecode" -SiteSystemServerName "$hostname" -CommunicationType $optData | Out-Null
                                }
                                catch {
                                    Write-Log -Category error -Message "failed to apply setting!"
                                }
                                break
                            }
                            'ClientConnectionType' {
                                try {
                                    Set-CMApplicationCatalogWebsitePoint -SiteCode "$sitecode" -SiteSystemServerName "$hostname" -ClientConnectionType $optData | Out-Null
                                }
                                catch {
                                    Write-Log -Category error -Message "failed to apply setting!"
                                }
                                break
                            }
                            'OrganizationName' {
                                try {
                                    Set-CMApplicationCatalogWebsitePoint -SiteCode "$sitecode" -SiteSystemServerName "$hostname" -OrganizationName "$optData" | Out-Null
                                }
                                catch {
                                    Write-Log -Category error -Message "failed to apply setting!"
                                }
                                break
                            }
                            'ThemeColor' {
                                try {
                                    Set-CMApplicationCatalogWebsitePoint -SiteCode "$sitecode" -SiteSystemServerName "$hostname" -Color $optData | Out-Null
                                }
                                catch {
                                    Write-Log -Category error -Message "failed to apply setting!"
                                }
                                break
                            }
                        } # switch
                    } # foreach
                }
                break
            }
        } # switch
        Write-Log -Category info -Message "- - - - - - - - - - - - - - - - - - - - - - - - - -"
    } # foreach
    Write-Log -Category info -Message "function runtime: $(Get-TimeOffset $time1)"
    Write-Output $result
}

function Import-CmxServerSettings {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        $DataSet
    )
    Write-Host "Configuring Server Settings" -ForegroundColor Green
    $result = $True
    $Time1  = Get-Date
    foreach ($item in $DataSet.configuration.cmsite.serversettings.serversetting | Where-Object {$_.use -eq "1"}) {
        $setName = $item.name
        $setComm = $item.comment
        $setKey  = $item.key
        $setVal  = $item.value
        switch ($setName) {
            'CMSoftwareDistributionComponent' {
                Write-Log -Category info -Message "setting name: $setName"
                switch ($setKey) {
                    'NetworkAccessAccountName' {
                        Write-Log -Category info -Message "setting $setKey == $setVal"
                        try {
                            Set-CMSoftwareDistributionComponent -SiteCode "$sitecode" -NetworkAccessAccountName "$setVal"
                        }
                        catch {
                            Write-Log -Category error -Message $_.Exception.Message
                            $result = $False
                        }
                        break
                    }
                } # switch
                break
            }
        } # switch
    } # foreach
    Write-Log -Category info -Message "function runtime: $(Get-TimeOffset $time1)"
    Write-Output $result
}

function Import-CmxClientSettings {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        $DataSet
    )
    Write-Host "Configuring Client Settings" -ForegroundColor Green
    $result = $True
    $Time1  = Get-Date
    foreach ($item in $DataSet.configuration.cmsite.clientsettings.clientsetting | Where-Object {$_.use -eq '1'}) {
        $csName = $item.name
        $csComm = $item.comment
        $csPri  = $item.priority
        $csType = $item.type
        Write-Log -Category info -Message "client setting.... $csName"
        try {
            New-CMClientSetting -Name "$csName" -Description "$csComm" -Type $csType -ErrorAction SilentlyContinue | Out-Null
            Write-Log -Category info -Message "client setting was created successfully."
        }
        catch {
            if ($_.Exception.Message -like "*already exists*") {
                Write-Log -Category info -Message "item already exists: $csName"
            }
            else {
                Write-Log -Category error -Message "your client setting just fell into a woodchipper. what a mess."
                Write-Error $_.Exception.Message
                $result = $False
                break
            }
        }
        foreach ($csopt in $cs.settings.setting | Where-Object {$_.use -eq '1'}) {
            $csoName = $csopt.name
            $csoComm = $csopt.comment
            $csoOpts = $csopt.options
            Write-Log -Category info -Message "client option.... $csoName"
            if ($csoOpts) {
                foreach ($opt in $csoOpts.Split(',')) {
                    Write-Log -Category info -Message "option setting: $opt"
                    $xx = $opt.Split('=')
                    switch ($csName) {
                        'BITS' {
                            switch ($xx[0]) {
                                'EnableBitsMaxBandwidth' {
                                    Set-CMClientSettingBackgroundIntelligentTransfer -Name $csName -EnableBitsMaxBandwidth $True
                                    break
                                }
                            } # switch
                            break
                        }
                        'ComputerAgent' {
                            Write-Log -Category info -Message "....setting: $($xx[0])"
                            switch ($xx[0]) {
                                'PortalUrl' {
                                    Set-CMClientSettingComputerAgent -PortalUrl $xx[1] -Name $csName
                                    break
                                }
                                'BrandingTitle' {
                                    Set-CMClientSettingComputerAgent -BrandingTitle $xx[1] -Name $csName
                                    break
                                }
                                'AddPortalToTrustedSiteList' {
                                    Set-CMClientSettingComputerAgent -AddPortalToTrustedSiteList $True -Name $csName
                                    break
                                }
                                'SuspendBitLocker' {
                                    Set-CMClientSettingComputerAgent -SuspendBitLocker $xx[1] -Name $csName
                                    break
                                }
                                'AllowPortalToHaveElevatedTrust' {
                                    Set-CMClientSettingComputerAgent -AllowPortalToHaveElevatedTrust $True -Name $csName
                                    break
                                }
                                'EnableThirdPartyOrchestration' {
                                    Set-CMClientSettingComputerAgent -EnableThirdPartyOrchestration Yes -Name $csName
                                    break
                                }
                                'FinalReminderMinutesInterval' {
                                    Set-CMClientSettingComputerAgent -FinalReminderMins $xx[1] -Name $csName
                                    break
                                }
                                'InitialReminderHoursInterval' {
                                    Set-CMClientSettingComputerAgent -InitialReminderHoursInterval $xx[1] -Name $csName
                                    break
                                }
                                'InstallRestriction' {
                                    Set-CMClientSettingComputerAgent -InstallRestriction $xx[1] -Name $csName
                                    break
                                }
                                'PowerShellExecutionPolicy=Bypass' {
                                    Set-CMClientSettingComputerAgent -PowerShellExecutionPolicy $xx[1] -Name $csName
                                    break
                                }
                            } # switch
                            break
                        }
                        'EndpointProtection' {
                            Write-Log -Category info -Message "....setting: $($xx[0])"
                            switch ($xx[0]) {
                                'InstallEndpointProtectionClient' {
                                    Set-CMClientSettingEndpointProtection -InstallEndpointProtectionClient $True -Name $csName
                                    break
                                }
                                'RemoveThirdParty' {
                                    Set-CMClientSettingEndpointProtection -RemoveThirdParty $True -Name $csName
                                    break
                                }
                                'SuppressReboot' {
                                    Set-CMClientSettingEndpointProtection -SuppressReboot $True -Name $csName
                                    break
                                }
                                'ForceRebootHr' {
                                    Set-CMClientSettingEndpointProtection -ForceRebootHr $xx[1] -Name $csName
                                    break
                                }
                                'DisableFirstSignatureUpdate' {
                                    Set-CMClientSettingEndpointProtection -DisableFirstSignatureUpdate $True -Name $csName
                                    break
                                }
                                'PersistInstallation' {
                                    Set-CMClientSettingEndpointProtection -PersistInstallation $True -Name $csName
                                    break
                                }
                            } # switch 
                            break
                        }
                    } # switch
                } # foreach
            }
        } # foreach
    } # foreach
    Write-Log -Category info -Message "function runtime: $(Get-TimeOffset -StartTime $Time1)"
    Write-Output $result
}

function Set-CMSiteConfigFolders {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [string] $SiteCode,
        [parameter(Mandatory=$True)]
            $DataSet
    )
    Write-Host "Configuring console folders" -ForegroundColor Green
    $result = $true
    $Time1  = Get-Date
    foreach ($item in $DataSet.configuration.cmsite.folders.folder | Where-Object {$_.use -eq '1'}) {
        $folderName = $item.name
        $folderPath = $item.path
        try {
            New-Item -Path "$SiteCode`:\$folderPath" -Name $folderName -ErrorAction SilentlyContinue | Out-Null
            Write-Log -Category "info" -Message "item created successfully: $folderName"
        }
        catch {
            Write-Log -Category "warning" -Message "item already exists: $folderName"
        }
        Write-Verbose "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
    } # foreach
    Write-Log -Category info -Message "function runtime: $(Get-TimeOffset $time1)"
    Write-Output $result
}

function Import-CmxQueries {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        $DataSet
    )
    Write-Host "Importing custom Queries" -ForegroundColor Green
    $result = $True
    $Time1  = Get-Date
    foreach ($item in $DataSet.configuration.cmsite.queries.query | Where-Object {$_.use -eq '1'}) {
        $queryName = $item.name
        $queryComm = $item.comment
        $queryType = $item.class
        $queryExp  = $item.expression
        try {
            New-CMQuery -Name $queryName -Expression $queryExp -Comment $queryComm -TargetClassName $queryType | Out-Null
            Write-Log -Category "info" -Message "item created successfully: $queryName"
        }
        catch {
            if ($_.Exception.Message -like "*already exists*") {
                Write-Log -Category info -Message "item already exists: $queryname"
            }
            else {
                Write-Log -Category "error" -Message $_.Exception.Message
                $result = $False
                break
            }
        }
        Write-Verbose "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
    } # foreach
    Write-Log -Category info -Message "function runtime: $(Get-TimeOffset $time1)"
    Write-Output $result
}

function Import-CmxOSImages {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        $DataSet
    )
    Write-Host "Importing OS images" -ForegroundColor Green
    $result = $True
    $Time1  = Get-Date
    foreach ($item in $DataSet.configuration.cmsite.osimages.osimage | Where-Object {$_.use -eq '1'}) {
        $imageName = $item.name
        $imagePath = $item.path
        $imageDesc = $item.comment
        $oldLoc = Get-Location
        Set-Location c:
        if (Test-Path $imagePath) {
            Set-Location $oldLoc
            Write-Log -Category "info" -Message "image name: $imageName"
            try {
                New-CMOperatingSystemImage -Name $imageName -Path $imagePath -Description $imageDesc | Out-Null
                Write-Log -Category "info" -Message "item created successfully"
            }
            catch {
                if ($_.Exception.Message -like "*already exists*") {
                    Write-Log -Category "info" -Message "item already exists: $imageName"
                }
                else {
                    Write-Log -Category "error" -Message $_.Exception.Message
                    $result = $False
                    break
                }
            }
        }
        else {
            Set-Location $oldLoc
            Write-Log -Category "error" -Message "failed to locate: $imagePath"
        }
        Write-Verbose "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
    } # foreach
    Write-Log -Category info -Message "function runtime: $(Get-TimeOffset $time1)"
    Write-Output $result
}

function Import-CmxOSInstallers {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        $DataSet
    )
    Write-Host "Configuring OS upgrade installers" -ForegroundColor Green
    $result = $True
    $Time1  = Get-Date
    foreach ($item in $DataSet.configuration.cmsite.osinstallers.osinstaller | Where-Object {$_.use -eq '1'}) {
        $instName = $item.name
        $instPath = $item.path
        $instDesc = $item.comment
        $instVer  = $item.version
        $oldLoc   = Get-Location
        Set-Location c:
        if (Test-Path $instPath) {
            Set-Location $oldLoc
            Write-Log -Category "info" -Message "installer name: $instName"
            try {
                New-CMOperatingSystemInstaller -Name $instName -Path $instPath -Description $instDesc -Version $instVer -ErrorAction SilentlyContinue | Out-Null
                Write-Log -Category "info" -Message "item created successfully"
            }
            catch {
                if ($_.Exception.Message -like "*already exists*") {
                    Write-Log -Category "info" -Message "item already exists: instName"
                }
                else {
                    Write-Log -Category "error" -Message $_.Exception.Message
                    $result = $False
                    break
                }
            }
        }
        else {
            Set-Location $oldLoc
            Write-Log -Category "error" -Message "failed to locate: $instPath"
        }
        Write-Verbose "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
    } # foreach
    Write-Log -Category info -Message "function runtime: $(Get-TimeOffset $time1)"
    Write-Output $result
}

function Import-CmxCollections {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        $DataSet
    )
    Write-Host "Configuring collections" -ForegroundColor Green
    $result = $True
    $Time1  = Get-Date
    foreach ($item in $DataSet.configuration.cmsite.collections.collection) {
        $collName     = $item.name
        $collType     = $item.type
        $collComm     = $item.comment
        $collBase     = $item.parent
        $collPath     = $item.folder
        $collRuleType = $item.ruletype
        $collRuleText = $item.rule
        try {
            $coll = New-CMCollection -Name $collName -CollectionType $collType -Comment $collComm -LimitingCollectionName $collBase -ErrorAction SilentlyContinue
            if ($coll) {
                Write-Log -Category "info" -Message "collection created: $collName"
                Write-Log -Category "info" -Message "moving object to folder: $collPath"
                $coll | Move-CMObject -FolderPath $collPath | Out-Null
                switch ($collRuleType) {
                    'direct' {
                        Write-Log -Category "info" -Message "associating direct membership rule"
                        break
                    }
                    'query' {
                        Write-Log -Category "info" -Message "associating query membership rule"
                        Add-CMUserCollectionQueryMembershipRule -CollectionName $collName -RuleName "1" -QueryExpression $collRuleText
                        break
                    }
                } # switch
            }
            Write-Log -Category "info" -Message "item created successfully."
        }
        catch {
            if ($_.ToString() -eq 'An object with the specified name already exists.') {
                Write-Log -Category "info" -Message "item already exists: collName"
            }
            else {
                Write-Log -Category "error" -Message $_.Exception.Message
                $result = $False
                break
            }
        }
        Write-Verbose "- - - - - - - - - - - - - - - - - - - - - - - - - - - -"
    } # foreach
    Write-Log -Category info -Message "function runtime: $(Get-TimeOffset $time1)"
    Write-Output $result
}

function Import-CmxMaintenanceTasks {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        $DataSet
    )
    Write-Host "Configuring site maintenance tasks" -ForegroundColor Green
    $result = $true
    $Time1  = Get-Date
    foreach ($item in $DataSet.configuration.cmsite.mtasks.mtask) {
        $mtName = $item.name
        $mtEnab = $item.enabled
        $mtOpts = $item.options
        if ($mtEnab -eq 'true') {
            Write-Log -Category "info" -Message "enabling task: $mtName"
            try {
                Set-CMSiteMaintenanceTask -MaintenanceTaskName $mtName -Enabled $True -SiteCode $sitecode | Out-Null
                Write-Log -Category "info" -Message "enabled task: $mtName"
            }
            catch {
                Write-Log -Category error -Message $_.Exception.Message
                $result = $False
                break
            }
        }
        else {
            Write-Log -Category "info" -Message "disabling task: $mtName"
            try {
                Set-CMSiteMaintenanceTask -MaintenanceTaskName $mtName -Enabled $False -SiteCode $sitecode | Out-Null
                Write-Log -Category "info" -Message "disabled task: $mtName"
            }
            catch {
                Write-Error $_
                $result = $False
                break
            }
        }
        Write-Verbose "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
    } # foreach
    Write-Log -Category info -Message "function runtime: $(Get-TimeOffset $time1)"
    Write-Output $result
}

function Import-CmxAppCategories {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        $DataSet
    )
    Write-Host "Configuring application categories" -ForegroundColor Green
    $result = $true
    $Time1  = Get-Date
    foreach ($item in $DataSet.configuration.cmsite.appcategories.appcategory | Where-Object {$_.use -eq '1'}) {
        $catName = $item.name
        $catComm = $item.comment
        try {
            New-CMCategory -CategoryType AppCategories -Name $catName -ErrorAction SilentlyContinue | Out-Null
            Write-Log -Category "info" -Message "item created successfully: $catName"
        }
        catch {
            if ($_.Exception.Message -like "*already exists*") {
                Write-Log -Category "info" -Message "item already exists: $catName"
            }
            else {
                Write-Log -Category error -Message $_.Exception.Message
                $result = $False
                break
            }
        }
    }
    Write-Log -Category info -Message "function runtime: $(Get-TimeOffset $time1)"
    Write-Output $result
}

function Import-CmxApplications {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        $DataSet
    )
    Write-Host "Importing applications" -ForegroundColor Green
    $result = $true
    $Time1  = Get-Date
    $PSDefaultParameterValues =@{
        "get-cimclass:namespace"="Root\SMS\site_$sitecode"
        "get-cimclass:computername"="$hostname"
        "get-cimInstance:computername"="$hostname"
        "get-ciminstance:namespace"="Root\SMS\site_$sitecode"}
    foreach ($item in $DataSet.configuration.cmsite.applications.application | Where-Object {$_.use -eq '1'}) {
        $timex = Get-Date
        $appName   = $item.name 
        $appComm   = $item.comment
        $appPub    = $item.publisher
        $appVer    = $item.version
        $appCats   = $item.categories
        $appKeys   = $item.keywords
        $appFolder = $item.folder

        Write-Log -Category "info" -Message "app name......... $appName"
        Write-Log -Category "info" -Message "app publisher.... $appPub"
        Write-Log -Category "info" -Message "app comment...... $appComm"
        Write-Log -Category "info" -Message "app version...... $appVer"
        Write-Log -Category "info" -Message "app categories... $appCats"
        Write-Log -Category "info" -Message "app keywords..... $appKeys"
        Write-Log -Category "info" -Message "app folder....... $appFolder"

        try {
            $app = New-CMApplication -Name "$appName" -Description "appComm" -SoftwareVersion "1.0" -AutoInstall $true -Publisher $appPub -ErrorAction SilentlyContinue
            Write-Log -Category "info" -Message "application created successfully"
        }
        catch {
            if ($_.Exception.Message -like "*already exists*") {
                Write-Log -Category "info" -Message "item already exists"
                $app = Get-CMApplication -Name $appName
            }
            else {
                Write-Log -Category error -Message $_.Exception.Message
                $result = $False
                $app = $null
            }
        }
        if ($app) {
            if ($appKeys -ne "") {
                Write-Log -Category "info" -Message "assigning keywords: $appKeys"
                try {
                    $app | Set-CMApplication -Keyword $appKeys -ErrorAction SilentlyContinue
                    Write-Log -Category info -Message "keywords have been assigned successfully"
                }
                catch {
                    Write-Log -Category "info" -Message "the object is locked by an evil person"
                }
            }
            if ($appCats -ne "") {
                Write-Log -Category "info" -Message "assigning categories: $appCats"
                try {
                    $app | Set-CMApplication -AppCategories $appCats.Split(',') -ErrorAction SilentlyContinue
                    Write-Log -Category info -Message "categories have been assigned successfully."
                }
                catch {
                    if ($_.Exception.Message -contains '*DeniedLockAlreadyAssigned*') {
                        Write-Log -Category "error" -Message "some idiot has the object open in a console and locked it."
                    }
                    else {
                        Write-Error "barf-o-matic - your code just puked up a buick!"
                    }
                }
            }
            foreach ($depType in $appSet.deptypes.deptype) {
                $depName   = $depType.name
                $depSource = $depType.source
                $depOpts   = $depType.options
                $depData   = $depType.detect
                $uninst    = $depType.uninstall
                $depComm   = $depType.comment
                $reqts     = $depType.requires
                $depCPU    = $depType.platform
                $depPath   = Split-Path -Path $depSource
                $depFile   = Split-Path -Path $depSource -Leaf
                $program   = "$depFile $depOpts"

                Write-Log -Category "info" -Message "dep name........ $depName"
                Write-Log -Category "info" -Message "dep comment..... $depComm"
                Write-Log -Category "info" -Message "dep Source...... $depSource"
                Write-Log -Category "info" -Message "dep options..... $depOpts"
                Write-Log -Category "info" -Message "dep detect...... $depData"
                Write-Log -Category "info" -Message "dep uninstall... $uninst"
                Write-Log -Category "info" -Message "dep reqts....... $reqts"
                Write-Log -Category "info" -Message "dep path........ $depPath"
                Write-Log -Category "info" -Message "dep file........ $depFile"
                Write-Log -Category "info" -Message "dep program..... $program"
                Write-Log -Category "info" -Message "dep platform.... $depCPU"

                if ($depOpts -eq 'auto') {
                    Write-Log -Category "info" -Message "installer type: msi"
                    try {
                        if ($depCPU -eq '32') {
                            Add-CMDeploymentType -ApplicationName $appName -AutoIdentifyFromInstallationFile -ForceForUnknownPublisher $true -InstallationFileLocation $depSource -MsiInstaller -DeploymentTypeName $depName -Force32BitInstaller $True
                        }
                        else {
                            Add-CMDeploymentType -ApplicationName $appName -AutoIdentifyFromInstallationFile -ForceForUnknownPublisher $true -InstallationFileLocation $depSource -MsiInstaller -DeploymentTypeName $depName
                        }
                        Write-Log -Category "info" -Message "deployment type created"
                    }
                    catch {
                        if ($_.Exception.Message -like '*already exists.') {
                            Write-Log -Category "info" -Message "deployment type already exists"
                        }
                        else {
                            Write-Error $_
                        }
                    }
                }
                else {
                    if ($depData.StartsWith("registry")) {
                        Write-Log -Category "info" -Message "detection type: registry"
                        # "registry:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++,DisplayVersion,-ge,7.5"
                        $depDetect  = $depData.Split(":")[1]
                        $depRuleSet = $depDetect.Split(",")
                        $ruleKey    = $depRuleSet[0] # "HKLM:\...."
                        $ruleKey    = $ruleKey.Substring(5)
                        $ruleVal    = $depRuleSet[1] # "DisplayVersion"
                        $ruleChk    = $depRuleSet[2] # "-ge"
                        $ruleData   = $depRuleSet[3] # "7.5"
                        $scriptDetection = @"
try {
    `$Reg = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, "default")
    `$key = `$reg.OpenSubKey("$ruleKey")
    `$val = `$key.GetValue("$ruleVal")
    if (`$val $ruleChk "$ruleData") {Write-Host 'Installed'}
}
catch {}
"@
                    }
                    elseif (($depData.StartsWith("file")) -or ($depData.StartsWith("folder"))) {
                        # "file:\Program Files\Something\file.exe"
                        # "folder:\Program Files\Something"
                        Write-Log -Category "info" -Message "detection type: file or folder"
                        $depDetect  = $depData.Split(":")[1]
                        $depRuleSet = $depDetect.Split(",")
                        $ruleKey    = $depRuleSet[0] # "\Program Files\Something\file.exe"
                        $ruleKey    = 'C:'+$ruleKey  # "C:\Program Files\Something\file.exe"
                        $ruleVal    = $null
                        $ruleChk    = $null
                        $ruleData   = $null
                        $scriptDetection = "if (Test-Path `"$ruleKey`") { Write-Host 'Installed' }"
                    }
                    Write-Log -Category "info" -Message "rule: $scriptDetection"
                    if ($uninst.length -gt 0) {
                        $DeploymentTypeHash = @{
                            ManualSpecifyDeploymentType = $true
                            ApplicationName = "$appName"
                            DeploymentTypeName = "$DepName"
                            DetectDeploymentTypeByCustomScript = $true
                            ScriptInstaller = $true
                            ScriptType = 'PowerShell'
                            ScriptContent =$scriptDetection
                            AdministratorComment = "$depComm"
                            ContentLocation = "$depPath"
                            InstallationProgram = "$program"
                            UninstallProgram = "$uninst"
                            RequiresUserInteraction = $false
                            InstallationBehaviorType = 'InstallForSystem'
                            InstallationProgramVisibility = 'Hidden'
                        }
                    }
                    else {
                        $DeploymentTypeHash = @{
                            ManualSpecifyDeploymentType = $true
                            ApplicationName = "$appName"
                            DeploymentTypeName = "$DepName"
                            DetectDeploymentTypeByCustomScript = $true
                            ScriptInstaller = $true
                            ScriptType = 'PowerShell'
                            ScriptContent =$scriptDetection
                            AdministratorComment = "$depComm"
                            ContentLocation = "$depPath"
                            InstallationProgram = "$program"
                            RequiresUserInteraction = $false
                            InstallationBehaviorType = 'InstallForSystem'
                            InstallationProgramVisibility = 'Hidden'
                        }
                    }
                    Write-Log -Category "info" -Message "Adding Deployment Type"

                    try {
                        if ($depCPU -eq '32') {
                            Add-CMDeploymentType @DeploymentTypeHash -EnableBranchCache $True -Force32BitInstaller $True
                        }
                        else {
                            Add-CMDeploymentType @DeploymentTypeHash -EnableBranchCache $True
                        }
                        Write-Log -Category "info" -Message "deployment type created"
                    }
                    catch {
                        if ($_.Exception.Message -like '*already exists.') {
                            Write-Log -Category "info" -Message "deployment type already exists: $depName"
                        }
                        else {
                            Write-Error $_.Exception.Message
                        }
                    }
                } # if
                if ($appFolder) {
                    Write-Log -Category "info" -Message "Moving application object to folder: $appFolder"
                    $app = Get-CMApplication -Name $appName
                    $app | Move-CMObject -FolderPath "Application\$appFolder" | Out-Null
                }
            } # foreach - deployment type
            Write-Log -Category "info" -Message "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
        } # if
        Write-Log -Category info -Message "task runtime: $(Get-TimeOffset $timex)"
    } # foreach - application
    Write-Log -Category info -Message "function runtime: $(Get-TimeOffset $time1)"
    Write-Output $result
}

function Import-CmxAccounts {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        $DataSet
    )
    Write-Host "Configuring accounts" -ForegroundColor Green
    $result = $true
    $time1  = Get-Date
    foreach ($item in $DataSet.configuration.cmsite.accounts.account | Where-Object {$_.use -eq '1'}) {
        $acctName = $item.name
        $acctPwd  = $item.password
        $pwd = ConvertTo-SecureString -String $acctPwd -AsPlainText -Force
        Write-Log -Category "info" -Message "adding account: $acctName"
        try {
            New-CMAccount -UserName $acctName -Password $pwd -SiteCode $sitecode | Out-Null
            Write-Log -Category info -Message "item created successfully: $acctName"
        }
        catch {
            if ($_.Exception.Message -like "*already exists*") {
                Write-Log -Category warning -Message "item already exists"
            }
            else {
                Write-Log -Category error -Message $_.Exception.Message
                $Result = $False
                break
            }
        }
        Write-Verbose "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
    } # foreach
    Write-Log -Category info -Message "function runtime: $(Get-TimeOffset $time1)"
    Write-Output $result
}

function Import-CmxDPGroups {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        $DataSet
    )
    Write-Host "Configuring distribution point groups" -ForegroundColor Green
    $result = $true
    $Time1  = Get-Date
    foreach ($item in $DataSet.configuration.cmsite.dpgroups.dpgroup | Where-Object {$_.use -eq '1'}) {
        $dpgName = $item.name
        $dpgComm = $item.comment
        try {
            New-CMDistributionPointGroup -Name $dpgName -Description $dpgComm | Out-Null
            Write-Log -Category info -Message "item created successfully: $dpgName"
        }
        catch {
            if ($_.Exception.Message -like "*already exists*") {
                Write-Log -Category info -Message "item already exists: dpgName"
            }
            else {
                Write-Log -Category error -Message $_.Exception.Message
                $Result = $False
            }
        }
        Write-Verbose "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
    } # foreach
    Write-Log -Category info -Message "function runtime: $(Get-TimeOffset $time1)"
    Write-Output $result
}

function Import-CmxMalwarePolicies {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        $DataSet
    )
    Write-Host "Configuring antimalware policies" -ForegroundColor Green
    $result = $true
    $Time1  = Get-Date
    foreach ($item in $DataSet.configuration.cmsite.malwarepolicies.malwarepolicy | Where-Object {$_.use -eq '1'}) {
        $itemName = $item.name
        $itemComm = $item.comment
        $itemPath = $item.path
        Write-Log -Category "info" -Message "policy name: $itemName"
        try {
            Import-CMAntimalwarePolicy -Path "$itemPath" -ErrorAction SilentlyContinue | Out-Null
            Write-Log -Category "info" -Message "item created successfully"
        }
        catch {
            if ($_.Exception.Message -like "*already exists*") {
                Write-Log -Category info -Message "item already exists: $itemName"
            }
            else {
                Write-Log -Category error -Message $_.Exception.Message
                $result = $False
                break
            }
        }
        Write-Verbose "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
    } # foreach
    Write-Log -Category info -Message "function runtime: $(Get-TimeOffset $time1)"
    Write-Output $result
}

# --------------------------------------------------------------------

Set-Location $env:USERPROFILE

Write-Log -Category "info" -Message "loading xml data from $XmlFile"
if (-not(Test-Path $XmlFile)) {Write-Warning "XmlFile not found: $XmlFile"; break}
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
if (-not (Import-CmxModule)) {
    Write-Warning "failed to load ConfigurationManager powershell module"
    break
}

# Set the current location to be the site code.
Write-Log -Category "info" -Message "mounting CM Site provider_ $sitecode`:"
Set-Location "$sitecode`:" 

$Site = Get-CMSite -SiteCode $sitecode
Write-Log -Category "info" -Message "site version = $($site.Version)"

if ($Override) {
    $controlset = $xmldata.configuration.cmsite.control.ci | Out-GridView -Title "Select Features to Run" -PassThru
}
else {
    $controlset = $xmldata.configuration.cmsite.control.ci | Where-Object {$_.use -eq '1'}
}

foreach ($control in $controlset) {
    $controlCode = $control.name
    Write-Log -Category info -Message "processing control code group: $controlCode"
    switch ($controlCode) {
        'ACCOUNTS' {
            Import-CmxAccounts -DataSet $xmldata | Out-Null
            break
        }
        'SERVERSETTINGS' {
            Import-CmxServerSettings -DataSet $xmldata | Out-Null
            break
        }
        'ADFOREST' {
            Set-CmxADForest -DataSet $xmldata | Out-Null
            break
        }
        'DISCOVERY' {
            Import-CmxDiscoveryMethods -DataSet $xmldata | Out-Null
            Invoke-CMForestDiscovery -SiteCode $sitecode | Out-Null
            #Invoke-CMSystemDiscovery
            break
        }
        'BOUNDARYGROUPS' {
            Import-CmxBoundaryGroups -DataSet $xmldata | Out-Null
            break
        }
        'BOUNDARIES' {
            if ((-not($AutoBoundaries)) -or ($ForceBoundaries)) {
                Set-CmxBoundaries -DataSet $xmldata | Out-Null
            }
            break
        }
        'SITEROLES' {
            Set-CmxSiteServerRoles -DataSet $xmldata | Out-Null
            break
        }
        'CLIENTSETTINGS' {
            Import-CmxClientSettings -DataSet $xmldata | Out-Null
            break
        }
        'CLIENTINSTALL' {
            break
        }
        'FOLDERS' {
            if (Set-CMSiteConfigFolders -SiteCode $sitecode -DataSet $xmldata) {
                Write-Host "Console folders have been created" -ForegroundColor Green
            }
            else {
                Write-Warning "Failed to create console folders"
            }
            break
        }
        'DPGROUPS' {
            Import-CmxDPGroups -DataSet $xmldata | Out-Null
            break
        }
        'QUERIES' {
            if (Import-CmxQueries -DataSet $xmldata) {
                Write-Host "Custom Queries have been created" -ForegroundColor Green
            }
            else {
                Write-Warning "Failed to create custom queries"
            }
            break
        }
        'COLLECTIONS' {
            Import-CmxCollections -DataSet $xmldata | Out-Null
            break
        }
        'OSIMAGES' {
            Import-CmxOSImages -DataSet $xmldata | Out-Null
            break
        }
        'OSINSTALLERS' {
            Import-CmxOSInstallers -DataSet $xmldata | Out-Null
            break
        }
        'MTASKS' {
            Import-CmxMaintenanceTasks -DataSet $xmldata | Out-Null
            break
        }
        'APPCATEGORIES' {
            Import-CmxAppCategories -DataSet $xmldata | Out-Null
            break
        }
        'APPLICATIONS' {
            Import-CmxApplications -DataSet $xmldata | Out-Null
            break
        }
        'MALWAREPOLICIES' {
            Import-CmxMalwarePolicies -DataSet $xmldata | Out-Null
            break
        }
    }
}

Write-Log -Category "info" -Message "---------------------------------------------------"
Write-Log -Category "info" -Message "restore working path to user profile"
Set-Location -Path $env:USERPROFILE

Write-Host "---------------- COMPLETED $(Get-Date) ------------------" -ForegroundColor Green

Write-Log -Category info -Message "total runtime: $(Get-TimeOffset $Runtime1)"

Stop-Transcript
