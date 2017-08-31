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
    [switch](optional) Display verbose output without using -Verbose
.NOTES
    1.2.02 - DS - 2017.08.31
    
    Read the associated XML to make sure the path and filename values
    all match up like you need them to.

.EXAMPLE
    .\cm_siteconfig.ps1 -XmlFile .\cm_siteconfig.xml -Verbose
#>

[CmdletBinding(SupportsShouldProcess=$True)]
param (
    [parameter(Mandatory=$True, HelpMessage="Path and name of XML input file")]
        [ValidateNotNullOrEmpty()]
        [string] $XmlFile,
    [parameter(Mandatory=$False, HelpMessage="Force custom site boundary creation from XML file")]
        [switch] $ForceBoundaries,
    [parameter(Mandatory=$False, HelpMessage="Display verbose output")]
        [switch] $Detailed
)

function Get-ScriptDirectory {
    $Invocation = (Get-Variable MyInvocation -Scope 1).Value
    Split-Path $Invocation.MyCommand.Path
}

$basekey = 'HKLM:\SOFTWARE\CM_SITECONFIG'
$ScriptVersion = '1.2.02'
$ScriptPath   = Get-ScriptDirectory
$LogsFolder   = "$ScriptPath\Logs"
if (-not(Test-Path $LogsFolder)) {New-Item -Path $LogsFolder -Type Directory}
$tsFile  = "$LogsFolder\cm_siteconfig_$($env:COMPUTERNAME)_transaction.log"
$logFile = "$LogsFolder\cm_siteconfig_$($env:COMPUTERNAME)_details.log"

try {stop-transcript -ErrorAction SilentlyContinue} catch {}
try {Start-Transcript -Path $tsFile -Force} catch {}
Write-Host "------------------- BEGIN $(Get-Date) -------------------" -ForegroundColor Green

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
                    if ($AutoBoundaries) {
                        Set-CMDiscoveryMethod -ActiveDirectoryForestDiscovery -SiteCode $sitecode -Enabled $True -EnableSubnetBoundaryCreation $True -ErrorAction SilentlyContinue
                        Write-Log -Category "info" -Message "AD forest discovery configured successfully: with subnet boundary option"
                    }
                    else {
                        Set-CMDiscoveryMethod -ActiveDirectoryForestDiscovery -SiteCode $sitecode -Enabled $True -ErrorAction SilentlyContinue
                        Write-Log -Category "info" -Message "AD forest discovery configured successfully"
                    }
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
    Write-Log -Category "info" -Message "----------------------------------------------------"
    Write-Host "Configuring Site System Roles" -ForegroundColor Green
    Write-Log -Category "info" -Message "function: set-cmsiteserverroles"
    foreach ($siterole in $DataSet.configuration.cmsite.sitesystemroles | Where-Object {$_.enabled -eq 'true'}) {
        $roleName = $siterole.name
        Write-Log -Category "info" -Message "configuring site system role: $roleName"
        switch ($RoleName) {
            'aisp' {
                try {
                    $x = Set-CMAssetIntelligenceSynchronizationPoint -Enable $True -EnableSynchronization $True -PassThru
                    if ($x) { Set-CMSiteAIClasses -DataSet $DataSet }
                }
                catch { Write.Error $_ }
                break
            }
            # ---------------- 
            # next rolename...
            # ----------------
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
    Write-Host "Configuring Asset Intelligence classes" -ForegroundColor Green
    Write-Log -Category "info" -Message "----------------------------------------------------"
    Write-Log -Category "info" -Message "function: Set-CMSiteAIClasses"
    $result = $True
    foreach ($srole in $DataSet.configuration.cmsite.sitesystemroles.sitesystemrole | Where-Object {$_.name -eq 'aisp'}) {
        foreach ($roleopt in $srole.roleoptions.roleoption) {
            $optName = $roleopt.name
            switch ($optName) {
                'EnableAllReportingClass' {
                    try {
                        Set-CMAssetIntelligenceClass -EnableAllReportingClass | Out-Null
                        Write-Log -Category "info" -Message "set option: $optName"
                    }
                    catch {
                        Write-Log -Category "error" -Message "failed to set option: $optName"
                        $Result = $False
                    }
                    break
                }
                'EnableReportingClass' {
                    foreach ($rclass in $optData.Split(",")) {
                        try {
                            Set-CMAssetIntelligenceClass -EnableReportingClass $rClass | Out-Null
                            Write-Log -Category "info" -Message "set option: $rClass"
                        }
                        catch {
                            Write-Log -Category "error" -Message "failed to set option: $rClass"
                            $result = $False
                        }
                    }
                    break
                }
            } # switch
        } # foreach
        Write-Verbose "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
    } # foreach
    Write-Output $result
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
    Write-Log -Category "info" -Message "----------------------------------------------------"
    Write-Host "Configuring console folders" -ForegroundColor Green
    Write-Log -Category "info" -Message "function set-cmsitefolders"
    $result = $true
    foreach ($folder in $DataSet.configuration.cmsite.folders.folder) {
        $folderName = $folder.name
        $folderPath = $folder.path
        try {
            New-Item -Path "$SiteCode`:\$folderPath" -Name $folderName -ErrorAction SilentlyContinue | Out-Null
            Write-Log -Category "info" -Message "folder created: $folderName"
        }
        catch {
            Write-Log -Category "warning" -Message "folder already exists: $folderName"
        }
        Write-Verbose "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
    } # foreach
    Write-Output $result
}

function Import-CMSiteQueries {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        $DataSet
    )
    Write-Log -Category "info" -Message "----------------------------------------------------"
    Write-Host "Importing custom Queries" -ForegroundColor Green
    Write-Log -Category "info" -Message "function Import-CMSiteQueries"
    $result = $True
    foreach ($query in $DataSet.configuration.cmsite.queries.query) {
        $queryName = $query.name
        $queryComm = $query.comment
        $queryType = $query.class
        $queryExp  = $query.expression
        try {
            New-CMQuery -Name $queryName -Expression $queryExp -Comment $queryComm -TargetClassName $queryType | Out-Null
            Write-Log -Category "info" -Message "query created: $queryName"
        }
        catch {
            Write-Log -Category "error" -Message "query failed: $queryName"
            $_
            $result = $False
            break
        }
        Write-Verbose "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
    } # foreach
    Write-Log -Category "info" -Message "finished importing custom queries"
    Write-Output $result
}

function Import-CMSiteOSImages {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        $DataSet
    )
    Write-Log -Category "info" -Message "----------------------------------------------------"
    Write-Host "Importing OS images" -ForegroundColor Green
    Write-Log -Category "info" -Message "function: import-cmsiteosimages"
    $result = $True
    foreach ($image in $DataSet.configuration.cmsite.osimages.osimage) {
        $imageName = $image.name
        $imagePath = $image.path
        $imageDesc = $image.comment
        $oldLoc = Get-Location
        Set-Location c:
        if (Test-Path $imagePath) {
            Set-Location $oldLoc
            Write-Log -Category "info" -Message "image name: $imageName"
            try {
                New-CMOperatingSystemImage -Name $imageName -Path $imagePath -Description $imageDesc | Out-Null
                Write-Log -Category "info" -Message "imported successfully"
            }
            catch {
                Write-Log -Category "error" -Message "failed to import: $imageName"
                $_
                $result = $False
                break
            }
        }
        else {
            Set-Location $oldLoc
            Write-Log -Category "error" -Message "failed to locate: $imagePath"
        }
        Write-Verbose "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
    } # foreach
    Write-Log -Category "info" -Message "finished importing os images"
    Write-Output $result
}

function Import-CMSiteOSInstallers {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        $DataSet
    )
    Write-Log -Category "info" -Message "----------------------------------------------------"
    Write-Host "Importing OS upgrade installers" -ForegroundColor Green
    Write-Log -Category "info" -Message "function: import-CMSiteOSInstallers"
    $result = $True
    foreach ($inst in $DataSet.configuration.cmsite.osinstallers.osinstaller) {
        $instName = $inst.name
        $instPath = $inst.path
        $instDesc = $inst.comment
        $instVer  = $inst.version
        $oldLoc   = Get-Location
        Set-Location c:
        if (Test-Path $instPath) {
            Set-Location $oldLoc
            Write-Log -Category "info" -Message "installer name: $instName"
            try {
                New-CMOperatingSystemInstaller -Name $instName -Path $instPath -Description $instDesc -Version $instVer -ErrorAction SilentlyContinue | Out-Null
                Write-Log -Category "info" -Message "imported successfully"
            }
            catch {
                Write-Log -Category "error" -Message "failed to import: $instName"
                $_
                $result = $False
                break
            }
        }
        else {
            Set-Location $oldLoc
            Write-Log -Category "error" -Message "failed to locate: $instPath"
        }
        Write-Verbose "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
    } # foreach
    Write-Log -Category "info" -Message "finished importing os installers"
    Write-Output $result
}

function Import-CMSiteCollections {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$True)]
        $DataSet
    )
    Write-Log -Category "info" -Message "----------------------------------------------------"
    Write-Log -Category "info" -Message "function: import-CMSiteCollections"
    $result = $True
    foreach ($collection in $DataSet.configuration.cmsite.collections.collection) {
        $collName = $collection.name
        $collType = $collection.type
        $collComm = $collection.comment
        $collBase = $collection.parent
        $collPath = $collection.folder
        $collRuleType = $collection.ruletype
        $collRuleText = $collection.rule
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
            Write-Log -Category "info" -Message "collection has been configured successfully."
        }
        catch {
            if ($_.ToString() -eq 'An object with the specified name already exists.') {
                Write-Log -Category "info" -Message "collection already exists"
            }
            else {
                Write-Log -Category "error" -Message "collection failed and spewed chunks everywhere :("
            }
        }
        Write-Verbose "- - - - - - - - - - - - - - - - - - - - - - - - - - - -"
    } # foreach
}

function Set-CMSiteMaintenanceTasks {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$True)]
            $DataSet
    )
    Write-Host "Configuring site maintenance tasks" -ForegroundColor Green
    Write-Log -Category "info" -Message "----------------------------------------------------"
    Write-Log -Category "info" -Message "function set-CMSiteMaintenanceTasks"
    $result = $true
    foreach ($mtask in $DataSet.configuration.cmsite.mtasks.mtask) {
        $mtName = $mtask.name
        $mtEnab = $mtask.enabled
        $mtOpts = $mtask.options
        if ($mtEnab -eq 'true') {
            Write-Log -Category "info" -Message "enabling task: $mtName"
            try {
                Set-CMSiteMaintenanceTask -MaintenanceTaskName $mtName -Enabled $True -SiteCode $sitecode | Out-Null
                Write-Log -Category "info" -Message "enabled task: $mtName"
            }
            catch {
                Write-Error $_
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
    Write-Output $result
}

function Import-CMSiteAppCategories {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$True)]
        $DataSet
    )
    Write-Host "Configuring application categories" -ForegroundColor Green
    Write-Log -Category "info" -Message "----------------------------------------------------"
    Write-Log -Category "info" -Message "function Set-CMSiteAppCategories"
    $result = $true
    foreach ($cat in $DataSet.configuration.cmsite.appcategories.appcategory | Where-Object {$_.enabled -eq 'true'}) {
        $catName = $cat.name
        $catComm = $cat.comment
        try {
            New-CMCategory -CategoryType AppCategories -Name $catName -ErrorAction SilentlyContinue | Out-Null
            Write-Log -Category "info" -Message "category created: $catName"
        }
        catch {
            if ($_.Exception.Message -eq 'An object with the specified name already exists.') {
                Write-Log -Category "info" -Message "category already exists: $catName"
            }
            else {
            }
        }
    }
    Write-Output $result
}

<#
function Import-CMSiteApplications {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$True)]
        $DataSet
    )
    Write-Host "Configuring applications" -ForegroundColor Green
    Write-Log -Category "info" -Message "----------------------------------------------------"
    Write-Log -Category "info" -Message "function set-CMSiteApplications"
    $result = $true

    foreach ($appn in $xmldata.configuration.cmsite.applications.application | Where-Object {$_.enabled -eq 'true'}) {
        $appName = $appn.name 
        $appPub  = $appn.publisher
        $appVer  = $appn.version 
        $appComm = $appn.comment 
        $appKeys = $appn.keywords 
        Write-Log -Category "info" -Message "creating application: $appName"
        try {
            $app = New-CMApplication -Name $appName -LocalizedApplicationName $appName -Publisher $appPub -Description $appComm -SoftwareVersion $appVer
            Write-Log -Category "info" -Message "application created: $appName"
        }
        catch {
            if ($_.Exception.Message -eq 'An object with the specified name already exists.') {
                Write-Log -Category "info" -Message "$appName already exists"
                $app = Get-CMApplication -Name $appName
            }
            else {
                Write-Log -Category "error" -Message "failed to create $appName"
                Write-Error $_
                $app = $null
            }
        }
        if ($app) {
            if ($appKeys -ne "") {
                Write-Log -Category "info" -Message "updating keywords list"
                $app | Set-CMApplication -Keyword $appKeys
            }
            Write-Log -Category "info" -Message "creating deployment types..."
            foreach ($depType in $appn.deptypes.deptype) {
                $depName = $depType.name
                $depFile = $depType.source 
                $depOpts = $depType.options 
                $depComm = $depType.comment
                Write-Log -Category "info" -Message "deployment type: $depname"
                if ($depOpts -eq 'auto') {
                    Write-Log -Category "info" -Message "installer type: msi"
                    try {
                        Add-CMDeploymentType -ApplicationName $appName -AutoIdentifyFromInstallationFile -ForceForUnknownPublisher $true -InstallationFileLocation $depFile -MsiInstaller -DeploymentTypeName $depName
                    }
                    catch {
                        if ($_.Exception.Message -like '*same name already exists.') {
                            Write-Log -Category "info" -Message "deployment type already exists"
                        }
                        else {
                            Write-Error $_
                        }
                    }
                }
                else {
                    Write-Log -Category "info" -Message "installer type: script"
                    $filepath = Split-Path $depFile
                    try {
                        Add-CMDeploymentType -ApplicationName $appName -DeploymentTypeName $depName -ForceForUnknownPublisher $true -InstallationCommandLine $depFile -ContentLocation $filepath
                    }
                    catch {
                        if ($_.Exception.Message -eq 'An object with the specified name already exists.') {
                            Write-Log -Category "info" -Message "deployment type already exists"
                        }
                        else {
                            Write-Error $_
                        }
                    }
                }
            } # foreach
        } # if
        Write-Verbose "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
    } # foreach
    Write-Output $result
}
#>

function Import-CMSiteApplications {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        $DataSet
    )
    Write-Host "Importing applications" -ForegroundColor Green
    Write-Log -Category "info" -Message "----------------------------------------------------"
    Write-Log -Category "info" -Message "function Import-CMSiteApplications"
    $result = $true
    $PSDefaultParameterValues =@{"get-cimclass:namespace"="Root\SMS\site_$sitecode";"get-cimclass:computername"="$hostname";"get-cimInstance:computername"="$hostname";"get-ciminstance:namespace"="Root\SMS\site_$sitecode"}
    foreach ($appSet in $DataSet.configuration.cmsite.applications.application | Where-Object {$_.enabled -eq 'true'}) {
        # APPLICATION
        # name="7-Zip" 
        # enabled="true" 
        # publisher="7-Zip" 
        # version="16.04" 
        # categories="General" 
        # comment="File compression utility" 
        # keywords="file,zip,utility,archive,compression"

        $appName = $appSet.name 
        $appComm = $appSet.comment
        $appPub  = $appSet.publisher
        $appVer  = $appSet.version
        $appCats = $appSet.categories
        $appKeys = $appSet.keywords
        $appFolder = $appSet.folder

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
            if ($_.Exception.Message -eq 'An object with the specified name already exists.') {
                Write-Log -Category "info" -Message "Application already defined"
                $app = Get-CMApplication -Name $appName
            }
            else {
                Write-Error $_.Exception.Message
                $app = $null
            }
        }
        if ($app) {
            if ($appKeys -ne "") {
                Write-Log -Category "info" -Message "updating keywords list"
                $app | Set-CMApplication -Keyword $appKeys
            }
            foreach ($depType in $appSet.deptypes.deptype) {
                # DEPLOYMENT TYPE:
                # name="x64 installer" 
                # source="\\contoso.com\software\Apps\Notepad++\7.5\npp.7.5.installer.x64.exe" 
                # options="/s" 
                # uninstall="C:\Program Files\Notepad++\uninstall.exe" 
                # detect="registry:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++,DisplayVersion(ge)7.5" 
                # requires="" 
                # comment="64-bit installer" />

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
                        if ($_.Exception.Message -like '*same name already exists.') {
                            Write-Log -Category "info" -Message "deployment type already exists"
                        }
                        else {
                            Write-Error $_
                        }
                    }
                }
                else {
                    if ($depData.StartsWith("registry")) {
                        # registry:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++,DisplayVersion,-ge,7.5
                        $depDetect  = $depData.Split(":")[1]
                        $depRuleSet = $depDetect.Split(",")
                        $ruleKey    = $depRuleSet[0] # "HKLM:\...."
                        $ruleKey    = $ruleKey.Substring(5)
                        $ruleVal    = $depRuleSet[1] # "DisplayVersion"
                        $ruleChk    = $depRuleSet[2] # "-ge"
                        $ruleData   = $depRuleSet[3] # "7.5"
                    }
                    $scriptDetection = @"
try {
    $Reg = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, "default")
    $key = $reg.OpenSubKey("$ruleKey")
    $val = $key.GetValue("$ruleVal")
    if ($val $ruleChk "$ruleData") {Write-Host 'Installed'}
}
catch {}
"@
                    Write-Log -Category "info" -Message "rule: $scriptDetection"

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
                        if ($_.Exception.Message -like '*same name already exists.') {
                            Write-Log -Category "info" -Message "deployment type already exists"
                        }
                        else {
                            Write-Error $_
                        }
                    }
                } # if
                if ($appFolder) {
                    Write-Log -Category "info" -Message "Moving application object to folder: $appFolder"
                    $app = Get-CMApplication -Name $appName
                    $app | Move-CMObject -FolderPath "Application\$appFolder" | Out-Null
                }
            } # foreach - deployment type
            Write-Log -Category "info" -Message "-------------------------------------------------"
        } # if
    } # foreach - application
    Write-Output $result
}

function Set-CMSiteAccounts {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$True)]
        $DataSet
    )
    Write-Host "Configuring accounts" -ForegroundColor Green
    Write-Log -Category "info" -Message "----------------------------------------------------"
    Write-Log -Category "info" -Message "function set-CMSiteAccounts"
    $result = $true
    foreach ($acct in $DataSet.configuration.cmsite.accounts.account | Where-Object {$_.enabled -eq 'true'}) {
        $acctName = $acct.name
        $acctPwd  = $acct.password
        $pwd = ConvertTo-SecureString -String $acctPwd -AsPlainText -Force
        Write-Log -Category "info" -Message "adding account: $acctName"
        try {
            New-CMAccount -UserName $acctName -Password $pwd -SiteCode $sitecode | Out-Null
            Write-Log -Category info -Message "account created successfully"
        }
        catch {
            if ($_.Exception.Message -eq 'An object with the specified name already exists.') {
                Write-Log -Category warning -Message "account already exists"
            }
            else {
                Write-Log -Category error -Message "Oh shit. They gonna fry yo ass now!"
                Write-Log -Category error -Message $_.Exception.Message
                Write-Error $_
                $Result = $False
            }
        }
        Write-Verbose "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
    } # foreach
    Write-Output $result
}

function Import-CMSiteDPGroups {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        $DataSet
    )
    Write-Host "Configuring distribution point groups" -ForegroundColor Green
    Write-Log -Category "info" -Message "----------------------------------------------------"
    Write-Log -Category "info" -Message "function set-CMSiteDPGroups"
    $result = $true
    foreach ($dpgroup in $DataSet.configuration.cmsite.dpgroups.dpgroup | Where-Object {$_.enabled -eq 'true'}) {
        $dpgName = $dpgroup.name
        $dpgComm = $dpgroup.comment
        try {
            New-CMDistributionPointGroup -Name $dpgName -Description $dpgComm | Out-Null
            Write-Log -Category info -Message "dp group created: $dpgName"
        }
        catch {
            if ($_.Exception.Message -eq 'An object with the specified name already exists.') {
                Write-Log -Category info -Message "dp group already exists"
            }
            else {
                Write-Log -Category error -Message "Oh shit. You gonna be drinking some drano now!"
                Write-Log -Category error -Message $_.Exception.Message
                Write-Error $_
                $Result = $False
            }
        }
        Write-Verbose "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
    } # foreach
    Write-Output $result
}

# --------------------------------------------------------------------

Set-Location $env:USERPROFILE

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

foreach ($control in $xmldata.configuration.cmsite.control.ci | Where-Object {$_.enabled -eq 'true'}) {
    $controlCode = $control.name
    switch ($controlCode) {
        'ACCOUNTS' {
            Set-CMSiteAccounts -DataSet $xmldata | Out-Null
            break
        }
        'ADFOREST' {
            Set-CMSiteADForest -DataSet $xmldata | Out-Null
            break
        }
        'DISCOVERY' {
            Set-CMSiteDiscoveryMethods -DataSet $xmldata | Out-Null
            #Invoke-CMSystemDiscovery
            break
        }
        'BOUNDARYGROUPS' {
            Set-CMSiteBoundaryGroups -DataSet $xmldata | Out-Null
            break
        }
        'BOUNDARIES' {
            if ((-not($AutoBoundaries)) -or ($ForceBoundaries)) {
                Set-Boundaries -DataSet $xmldata | Out-Null
            }
            break
        }
        'SITEROLES' {
            Set-CMSiteServerRoles -DataSet $xmldata | Out-Null
            Set-CMSiteAIClasses -DataSet $xmldata | Out-Null
            break
        }
        'CLIENTSETTINGS' {
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
            Import-CMSiteDPGroups -DataSet $xmldata | Out-Null
            break
        }
        'QUERIES' {
            if (Import-CMSiteQueries -DataSet $xmldata) {
                Write-Host "Custom Queries have been created" -ForegroundColor Green
            }
            else {
                Write-Warning "Failed to create custom queries"
            }
            break
        }
        'COLLECTIONS' {
            Import-CMSiteCollections -DataSet $xmldata | Out-Null
            break
        }
        'OSIMAGES' {
            Import-CMSiteOSImages -DataSet $xmldata | Out-Null
            break
        }
        'OSINSTALLERS' {
            Import-CMSiteOSInstallers -DataSet $xmldata | Out-Null
            break
        }
        'MTASKS' {
            Set-CMSiteMaintenanceTasks -DataSet $xmldata | Out-Null
            break
        }
        'APPCATEGORIES' {
            Import-CMSiteAppCategories -DataSet $xmldata | Out-Null
            break
        }
        'APPLICATIONS' {
            Import-CMSiteApplications -DataSet $xmldata | Out-Null
            break
        }
    }
}

Write-Log -Category "info" -Message "---------------------------------------------------"
Write-Log -Category "info" -Message "restore working path to user profile"
Set-Location -Path $env:USERPROFILE

Write-Host "---------------- COMPLETED $(Get-Date) ------------------" -ForegroundColor Green
$time2 = Get-TimeOffset -StartTime $RunTime1
Write-Log -Category "info" -Message "total runtime (hh:mm:ss) = $time2"

Stop-Transcript
