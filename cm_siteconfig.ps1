#requires -RunAsAdministrator
#requires -version 3
<#
.SYNOPSIS
    SCCM site configuration script
.DESCRIPTION
    Yeah, what he said.
.PARAMETER XmlFile
    [string](optional) Path and Name of XML input file
.PARAMETER Detailed
    [switch](optional) Verbose output without using -Verbose
.PARAMETER Override
    [switch](optional) Allow override of Controls in XML file using GUI (gridview) selection at runtime
.NOTES
    1.3.00 - DS - 2017.09.14
    
    Read the associated XML to make sure the path and filename values
    all match up like you need them to.

.EXAMPLE
    .\cm_siteconfig.ps1 -XmlFile .\cm_siteconfig.xml -Detailed
.EXAMPLE
    .\cm_siteconfig.ps1 -XmlFile .\cm_siteconfig.xml -Override
.EXAMPLE
    .\cm_siteconfig.ps1 -XmlFile .\cm_siteconfig.xml -Detailed -Override
.EXAMPLE
	.\cm_siteconfig.ps1 -XmlFile .\cm_siteconfig.xml -Detailed -WhatIf
#>

[CmdletBinding(SupportsShouldProcess=$True)]
param (
    [parameter(Mandatory=$True, HelpMessage="Path and name of XML input file")]
        [ValidateNotNullOrEmpty()]
        [string] $XmlFile,
    [parameter(Mandatory=$False, HelpMessage="Display verbose output")]
        [switch] $Detailed,
    [parameter(Mandatory=$False, HelpMessage="Override control set from XML file")]
        [switch] $Override
)

function Get-ScriptDirectory {
    $Invocation = (Get-Variable MyInvocation -Scope 1).Value
    Split-Path $Invocation.MyCommand.Path
}

$basekey        = 'HKLM:\SOFTWARE\CM_SITECONFIG'
$ScriptVersion  = '1.3.00'
$ScriptPath     = Get-ScriptDirectory
$HostName       = "$($env:COMPUTERNAME).$($env:USERDNSDOMAIN)"
$LogsFolder     = "$ScriptPath\Logs"
if (-not(Test-Path $LogsFolder)) {New-Item -Path $LogsFolder -Type Directory}
$tsFile         = "$LogsFolder\cm_siteconfig`_$HostName`_transaction.log"
$logFile        = "$LogsFolder\cm_siteconfig`_$HostName`_details.log"
$AutoBoundaries = $False

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
        Write-Host "DETAILED`: $(Get-Date -f 'yyyy-M-dd HH:mm:ss')`t$Category`t$Message" -ForegroundColor Cyan
    }
}

$RunTime1 = Get-Date
Write-Log -Category "info" -Message "Script version.... $ScriptVersion"

Set-Location "$($env:USERPROFILE)\Documents"
if (-not(Test-Path $XmlFile)) {
    Write-Warning "unable to locate input file: $XmlFile"
    break
}

### functions

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
                                    Set-CMDiscoveryMethod -ActiveDirectoryForestDiscovery -SiteCode $sitecode -Enabled $True -EnableActiveDirectorySiteBoundaryCreation $True -ErrorAction SilentlyContinue | Out-Null
                                }
                                'EnableSubnetBoundaryCreation' {
                                    Set-CMDiscoveryMethod -ActiveDirectoryForestDiscovery -SiteCode $sitecode -Enabled $True -EnableSubnetBoundaryCreation $True -ErrorAction SilentlyContinue | Out-Null
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
						Write-Log -Category info -Message "value  = $($optx[$optx.Count-1])"
                        switch ($optx[0]) {
                            'ADContainer' {
                                Set-CMDiscoveryMethod -ActiveDirectorySystemDiscovery -SiteCode $sitecode -ActiveDirectoryContainer "LDAP://$($optx[1])" -Recursive -ErrorAction SilentlyContinue | Out-Null
                                break
                            }
                            'EnableDetaDiscovery' {
                                Set-CMDiscoveryMethod -ActiveDirectorySystemDiscovery -SiteCode $sitecode -EnableDeltaDiscovery $True -ErrorAction SilentlyContinue | Out-Null
                                break
                            }
                            'EnableFilteringExpiredLogon' {
                                Set-CMDiscoveryMethod -ActiveDirectorySystemDiscovery -SiteCode $sitecode -EnableFilteringExpiredLogon $True -TimeSinceLastLogonDays $optx[1] -ErrorAction SilentlyContinue | Out-Null
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
				}
                catch {
                    Write-Log -Category error -Message $_.Exception.Message
					break
                }
				foreach ($opt in $discOpts.Split("|")) {
					$optx = $opt.Split(':')
					Write-Log -Category info -Message "option = $($optx[0])"
					Write-Log -Category info -Message "value  = $($optx[$optx.Count-1])"
					switch ($optx[0]) {
						'EnableDeltaDiscovery' {
							Set-CMDiscoveryMethod -ActiveDirectoryGroupDiscovery -SiteCode $sitecode -EnableDeltaDiscovery $True | Out-Null
							break
						}
						'ADContainer' {
							$scope = New-CMADGroupDiscoveryScope -LdapLocation "LDAP://$($optx[1])" -Name "Domain Root" -RecursiveSearch $True
							try {
								Set-CMDiscoveryMethod -ActiveDirectoryGroupDiscovery -SiteCode $sitecode -AddGroupDiscoveryScope $scope -ErrorAction SilentlyContinue | Out-Null
							}
							catch {
								if ($_.Exception.Message -like "*already exists*") {
									Write-Log -Category info -Message "ldap path is already configured"
								}
								else {
									Write-Log -Category error -Message $_.Exception.Message
								}
							}
							break
						}
						'EnableFilteringExpiredLogon' {
							Set-CMDiscoveryMethod -ActiveDirectoryGroupDiscovery -SiteCode $sitecode -EnableFilteringExpiredLogon $True -TimeSinceLastLogonDays $optx[1] -ErrorAction SilentlyContinue | Out-Null
							break
						}
						'EnableFilteringExpiredPassword' {
							Set-CMDiscoveryMethod -ActiveDirectoryGroupDiscovery -SiteCode $sitecode -EnableFilteringExpiredPassword $True -TimeSinceLastPasswordUpdateDays $optx[1] -ErrorAction SilentlyContinue | Out-Null
							break
						}
					} # switch
				} # foreach
                break
            }
            'ActiveDirectoryUserDiscovery' {
                try {
                    Set-CMDiscoveryMethod -ActiveDirectoryUserDiscovery -SiteCode $sitecode -Enabled $True -ErrorAction SilentlyContinue | Out-Null
                    Write-Log -Category info -Message "discovery has been enabled. configuring options"
                    foreach ($opt in $discOpts.Split("|")) {
                        $optx = $opt.Split(':')
                        Write-Log -Category info -Message "option = $($optx[0])"
						Write-Log -Category info -Message "value  = $($optx[$optx.Count-1])"
                        switch ($optx[0]) {
                            'ADContainer' {
                                Set-CMDiscoveryMethod -ActiveDirectoryUserDiscovery -SiteCode $sitecode -ActiveDirectoryContainer "LDAP://$($optx[1])" -Recursive -ErrorAction SilentlyContinue | Out-Null
                                break
                            }
                            'EnableDetaDiscovery' {
                                Set-CMDiscoveryMethod -ActiveDirectoryUserDiscovery -SiteCode $sitecode -EnableDeltaDiscovery $True -ErrorAction SilentlyContinue | Out-Null
                                break
                            }
                            'ADAttributes' {
                                Set-CMDiscoveryMethod -ActiveDirectoryUserDiscovery -SiteCode $sitecode -AddAdditionalAttribute $optx[1].split(',') -ErrorAction SilentlyContinue | Out-Null
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
        Write-Log -Category "info" -Message "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
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
		if (Get-CMBoundaryGroup -Name $bgName) {
			Write-Log -Category "info" -Message "boundary group already exists"
		}
		else {
			try {
				New-CMBoundaryGroup -Name $bgName -Description "$bgComm" -DefaultSiteCode $sitecode | Out-Null
				Write-Log -Category "info" -Message "boundary group $bgName created"
			}
			catch {
				Write-Log -Category "error" -Message $_.Exception.Message
				$result = $false
				break
			}
		}
        if ($bgServer.Length -gt 0) {
            $bgSiteServer = @{$bgServer = $bgLink}
            Write-Log -Category "info" -Message "site server assigned: $bgServer ($bgLink)"
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
		$roleopts = $item.roleoptions.roleoption | Where-Object {$_.use -eq '1'}
        Write-Log -Category "info" -Message "configuring site system role: $roleComm [$roleName]"
        switch ($RoleName) {
            'aisp' {
				if (Get-CMAssetIntelligenceSynchronizationPoint -SiteCode "$sitecode" -SiteSystemServerName "$hostname") {
					Write-Log -Category "info" -Message "asset intelligence sync point was already enabled"
				}
				else {
					try {
						Add-CMAssetIntelligenceSynchronizationPoint -SiteSystemServerName "$hostname" -ErrorAction SilentlyContinue | Out-Null
						Write-Log -Category "info" -Message "asset intelligence sync point enabled successfully"
						Set-CMAssetIntelligenceSynchronizationPoint -EnableSynchronization $True -ErrorAction SilentlyContinue | Out-Null
					}
					catch {
						Write-Log -Category error -Message $_.Exception.Message
						$result = $False
						break
					}
				}
				foreach ($roleopt in $roleopts) {
					switch ($roleopt.name) {
						'EnableAllReportingClass' {
							Write-Log -Category info -Message "enabling all reporting classes"
							try {
								Set-CMAssetIntelligenceClass -EnableAllReportingClass | Out-Null
							}
							catch {
								Write-Log -Category error -Message $_.Exception.Message
								$result = $False
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
								$result = $False
							}
							break
						}
					} # switch
				} # foreach
                break
            }
            'dp' {
				if (Get-CMDistributionPoint -SiteSystemServerName "$hostname" -ErrorAction SilentlyContinue) {
                    Write-Log -Category "info" -Message "distribution point role already added"
                }
				else {
					try {
						Add-CMDistributionPoint -SiteSystemServerName "$hostname" -ErrorAction SilentlyContinue | Out-Null
						Write-Log -Category "info" -Message "distribution point role added successfully"
					}
					catch {
						Write-Log -Category error -Message $_.Exception.Message
						$result = $False
						break
					}
				}
				$code = "Set-CMDistributionPoint `-SiteCode `"$sitecode`" `-SiteSystemServerName `"$hostname`""
				foreach ($roleopt in $roleopts) {
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
					break
				}
                break
            }
            'sup' {
                if (Get-CMSoftwareUpdatePoint -SiteCode "$sitecode" -SiteSystemServerName "$hostname") {
                    Write-Log -Category info -Message "software update point has already been configured"
					$code1 = ""
					$code2 = "Set-CMSoftwareUpdatePointComponent `-SiteCode `"$sitecode`" `-EnableSynchronization `$True"
                }
                else {
                    $code1 = "Add-CMSoftwareUpdatePoint `-SiteSystemServerName `"$hostname`" `-SiteCode `"$sitecode`""
					$code2 = "Set-CMSoftwareUpdatePointComponent `-SiteCode `"$sitecode`" `-EnableSynchronization `$True"
				}
				foreach ($roleopt in $roleopts) {
					$optname = $roleopt.name
					$params  = $roleopt.params
					switch ($optname) {
<#						'WsusAccessAccount' {
							if ($code1.Length -gt 0) {
								if ($params -eq 'NULL') {
									$code1 += " `-WsusAccessAccount `$null"
								}
								else {
									$code1 += " `-WsusAccessAccount `"$params`""
								}
							}
							break
						}
#>
						'HttpPort' {
							if ($code1.Length -gt 0) {
								$code1 += " `-WsusIisPort $params"
							}
							break
						}
						'HttpsPort' {
							if ($code1.Length -gt 0) {
								$code1 += " `-WsusIisSslPort $params"
							}
							break
						}
						'ClientConnectionType' {
							if ($code1.Length -gt 0) {
								$code1 += " `-ClientConnectionType $params"
							}
							break
						}
						'SynchronizeAction' {
							$code2 += " `-SynchronizeAction $params"
							break
						}
						'AddUpdateClassifications' {
							$code2 += " `-AddUpdateClassification "
							foreach ($uclass in $params.Split(',')) {
								if ($code2.EndsWith("AddUpdateClassification ")) {
									$code2 += " `"$uclass`""
								}
								else {
									$code2 += ",`"$uclass`""
								}
							}
							break
						}
						'AddProducts' {
							$code2 += " `-AddProduct "
							foreach ($product in $params.Split(',')) {
								if ($code2.EndsWith("AddProduct ")) {
									$code2 += " `"$product`""
								}
								else {
									$code2 += ",`"$product`""
								}
							}
							break
						}
						'ImmediatelyExpireSupersedence' {
							$code2 += " `-ImmediatelyExpireSupersedence `$$params"
							break
						}
						'EnableCallWsusCleanupWizard' {
							$code2 += " `-EnableCallWsusCleanupWizard `$$params"
							break
						}
						'ContentFileOption' {
							$code2 += " `-ContentFileOption `"$params`""
							break
						}
					} # switch
				} # foreach
				if ($code1.Length -gt 0) {
					Write-Log -Category "info" -Message "command1 >> $code1"
                    try {
                        Invoke-Expression -Command $code1 -ErrorAction Stop
                        Write-Log -Category info -Message "expression has been applied successfully"
                    }
                    catch {
                        Write-Log -Category error -Message $_.Exception.Message
                        $result = $False
						break
                    }
				}
				if ($code2.Length -gt 0) {
					Write-Log -Category "info" -Message "command2 >> $code2"
					try {
						Invoke-Expression -Command $code2 -ErrorAction Stop
						Write-Log -Category info -Message "expression has been applied successfully"
					}
                    catch {
                        Write-Log -Category error -Message $_.Exception.Message
                        $result = $False
						break
                    }
				} # if
                break
            }
            'scp' {
                foreach ($roleopt in $siterole.roleoptions.roleoption | Where-Object {$_.use -eq '1'}) {
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
                foreach ($roleopt in $roleopts) {
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
                foreach ($roleopt in $roleopts) {
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
				Write-Log -Category "info" -Message "configuring role options"
                foreach ($roleopt in $roleopts) {
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
						Write-Log -Category error -Message $_
                        $result = $False
						break
                    }
                }
                break
            }
            'acwp' {
				if (Get-CMApplicationCatalogWebsitePoint) {
					Write-Log -Category "info" -Message "application website point site role already added"
				}
				else {
					$code = "Add-CMApplicationCatalogWebsitePoint `-SiteSystemServerName `"$hostname`" `-SiteCode `"$sitecode`""
					$code += " `-ApplicationWebServicePointServerName `"$hostname`""
					foreach ($roleopt in $roleopts) {
						$optName = $roleopt.name
						$optData = $roleopt.params
						switch ($optName) {
							'CommuncationType' {
								$code += " `-CommunicationType $optData"
								break
							}
							'ClientConnectionType' {
								$code += " `-ClientConnectionType $optData"
								break
							}
							'OrganizationName' {
								$code += " `-OrganizationName `"$optData`""
								break
							}
							'ThemeColor' {
								$code += " `-Color $optData"
								break
							}
						} # switch
					} # foreach
					Write-Log -Category "info" -Message "command >> $code"
					try {
						Invoke-Expression -Command $code -ErrorAction Stop
						Write-Log -Category info -Message "expression has been applied successfully"
					}
                    catch {
                        Write-Log -Category error -Message $_.Exception.Message
                        $result = $False
						break
                    }
				} # if
                break
            }
			'epp' {
				if (Get-CMEndpointProtectionPoint -SiteCode "P01") {
					Write-Log -Category "info" -Message "endpoint protection role already added"
				}
				else {
					try {
						Add-CMEndpointProtectionPoint -SiteCode "P01" -SiteSystemServerName $hostname -ProtectionService BasicMembership -ErrorAction SilentlyContinue | Out-Null
						Write-Log -Category "info" -Message "endpoint protection role added successfully"
					}
					catch {
						Write-Log -Category "error" -Message $_.Exception.Message
						$result = $False
						break
					}
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
		$csName = $item.Name
		$csComm = $item.comment 
		$csPri  = $item.priority
		$csType = $item.type
		Write-Log -Category "info" -Message "setting group name... $csName"
		if (Get-CMClientSetting -Name $csName) {
			Write-Log -Category info -Message "client setting is already created"
		}
		else {
			try {
				New-CMClientSetting -Name "$csName" -Description "$csComm" -Type $csType -ErrorAction SilentlyContinue | Out-Null
				Write-Log -Category info -Message "client setting was created successfully."
			}
			catch {
                Write-Log -Category error -Message "your client setting just fell into a woodchipper. what a mess."
                Write-Error $_.Exception.Message
                $result = $False
                break
            }
        }
		foreach ($csSet in $item.settings.setting | Where-Object {$_.use -eq '1'}) {
			$setName = $csSet.name
			Write-Log -Category "info" -Message "setting name......... $setName"
			$code = "Set-CMClientSetting$setName `-Name `"$csName`""
			foreach ($opt in $csSet.options.option) {
				$optName = $opt.name
				$optVal  = $opt.value
				Write-Log -Category "info" -Message "setting option name.. $optName --> $optVal"
				switch ($optVal) {
					'true' {
						$param = " `-$optName `$true"
						break
					}
					'false' {
						$param = " `-$optName `$false"
						break
					}
					'null' {
						$param = " `-$optName `$null"
						break
					}
					default {
						if ($optName -eq 'SWINVConfiguration') {
							$paramx = "`@`{"
							foreach ($opt in $optVal.Split('|')) {
								$opx = $opt.Split('=')
								$op1 = $opx[0]
								$op2 = $opx[1]
								if (('False','True','null') -icontains $op2) {
									$y = "$op1`=`$$op2`;"
								}
								else {
									$y = "$op1`=`"$op2`"`;"
								}
								$paramx += $y
							}
							$paramx += "`}"
							$param = " `-AddInventoryFileType $paramx"
						}
						else {
							$param = " `-$optName `"$optVal`""
						}
						break
					}
				} # switch
				$code += $param
			} # foreach - setting option
			Write-Log -Category "info" -Message "CODE >> $code"
			try {
				Invoke-Expression -Command $code -ErrorAction Stop
				Write-Log -Category info -Message "client setting has been applied successfully"
			}
			catch {
				Write-Log -Category error -Message $_.Exception.Message
				$result = $False
				break
			}
			Write-Log -Category "info" -Message "............................................................"
		} # foreach - setting group
	} # foreach - client setting policy
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
		Write-Log -Category "info" -Message "folder path: $folderPath\folderName"
		if (Test-Path "$folderPath\$folderName") {
			Write-Log -Category "info" -Message "folder already exists"
		}
		else {
			try {
				New-Item -Path "$SiteCode`:\$folderPath" -Name $folderName -ErrorAction SilentlyContinue | Out-Null
				Write-Log -Category "info" -Message "folder created successfully"
			}
			catch {
				Write-Log -Category "error" -Message $_.Exception.Message
			}
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
                Write-Log -Category "info" -Message "item already exists: $queryname"
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
		$imgFolder = $item.folder
        $oldLoc    = Get-Location
		if ($osi = Get-CMOperatingSystemImage -Name "$imageName") {
			Write-Log -Category "info" -Message "operating system image already created"
		}
		else {
			Set-Location c:
			if (Test-Path $imagePath) {
				Set-Location $oldLoc
				Write-Log -Category "info" -Message "image name: $imageName"
				Write-Log -Category "info" -Message "image path: $imagePath"
				try {
					$osi = New-CMOperatingSystemImage -Name "$imageName" -Path $imagePath -Description "$imageDesc" -ErrorAction SilentlyContinue
					Write-Log -Category "info" -Message "item created successfully"
				}
				catch {
                    Write-Log -Category "error" -Message $_.Exception.Message
					Write-Error $_
                    $result = $False
                    break
                }
            }
			else {
				Write-Log -Category "error" -Message "failed to locate image source: $imagePath"
				$result = $False
				break
			}
		}
		Write-Log -Category "info" -Message "moving object to folder: $imgFolder"
		$osi | Move-CMObject -FolderPath $imgFolder | Out-Null
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
        $instName  = $item.name
        $instPath  = $item.path
        $instDesc  = $item.comment
        $instVer   = $item.version
		$imgFolder = $item.folder
        $oldLoc    = Get-Location
        Set-Location c:
        if (Test-Path $instPath) {
            Set-Location $oldLoc
            Write-Log -Category "info" -Message "installer name: $instName"
			if ($osi = Get-CMOperatingSystemInstaller -Name $instName) {
				Write-Log -Category "info" -Message "operating system installer already created"
			}
			else {
				try {
					$osi = New-CMOperatingSystemInstaller -Name $instName -Path $instPath -Description $instDesc -Version $instVer -ErrorAction SilentlyContinue
					Write-Log -Category "info" -Message "operating system installer created successfully"
				}
				catch {
					Write-Log -Category "error" -Message $_.Exception.Message
					$result = $False
					break
				}
			}
			Write-Log -Category "info" -Message "moving object to folder: $imgFolder"
            $osi | Move-CMObject -FolderPath $imgFolder | Out-Null
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
		Write-Log -Category "info" -Message "collection: $collName"
		if ($coll = Get-CMCollection -Name $collName) {
			Write-Log -Category "info" -Message "collection already created"
		}
		else {
			try {
				$coll = New-CMCollection -Name $collName -CollectionType $collType -Comment $collComm -LimitingCollectionName $collBase -ErrorAction SilentlyContinue
				Write-Log -Category "info" -Message "collection created successfully"
			}
			catch {
				Write-Log -Category "error" -Message $_.Exception.Message
				$result = $False
				break
			}
		}
		Write-Log -Category "info" -Message "moving object to folder: $collPath"
		$coll | Move-CMObject -FolderPath $collPath | Out-Null
		Write-Log -Category "info" -Message "configuring membership rules"
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
            }
            catch {
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
		Write-Log -Category "info" -Message "application category: $catName"
		if (Get-CMCategory -Name $catName -CategoryType AppCategories) {
			Write-Log -Category "info" -Message "category already exists"
		}
		else {
			try {
				New-CMCategory -CategoryType AppCategories -Name $catName -ErrorAction SilentlyContinue | Out-Null
				Write-Log -Category "info" -Message "category was created successfully"
			}
			catch {
				Write-Log -Category error -Message $_.Exception.Message
				$result = $False
				break
			}
		}
    } # foreach
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
            if ($appKeys.Length -gt 0) {
                Write-Log -Category "info" -Message "assigning keywords: $appKeys"
                try {
                    $app | Set-CMApplication -Keyword $appKeys -ErrorAction SilentlyContinue
                    Write-Log -Category info -Message "keywords have been assigned successfully"
                }
                catch {
                    Write-Log -Category "info" -Message "the object is locked by an evil person"
                }
            }
            if ($appCats.Length -gt 0) {
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
			if ($appFolder.Length -gt 0) {
				Write-Log -Category "info" -Message "Moving application object to folder: $appFolder"
				#$app = Get-CMApplication -Name $appName
				$app | Move-CMObject -FolderPath "Application\$appFolder" | Out-Null
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
		Write-Log -Category "info" -Message "account: $acctName"
        if (Get-CMAccount -UserName $acctName) {
			Write-Log -Category "info" -Message "account already created"
		}
		else {
			if (Test-CMxAdUser -UserName $acctName) {
				try {
					$pwd = ConvertTo-SecureString -String $acctPwd -AsPlainText -Force
					New-CMAccount -UserName $acctName -Password $pwd -SiteCode $sitecode | Out-Null
					Write-Log -Category "info" -Message "account added successfully: $acctName"
				}
				catch {
					Write-Log -Category "error" -Message $_.Exception.Message
					$Result = $False
					break
				}
			}
			else {
				Write-Log -Category "error" -Message "account not found in domain: $acctName"
				$result = $False
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
		Write-Log -Category info -Message "distribution point group: $dpgName"
		if (Get-CMDistributionPointGroup -Name $dpgName) {
			Write-Log -Category info -Message "dp group already exists"
		}
		else {
			try {
				New-CMDistributionPointGroup -Name $dpgName -Description $dpgComm | Out-Null
				Write-Log -Category info -Message "dp group created successfully"
			}
			catch {
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
		if (Get-CMAntimalwarePolicy -Name $itemName) {
			Write-Log -Category info -Message "po;icy already exists"
		}
		else {
			try {
				Import-CMAntimalwarePolicy -Path "$itemPath" -NewName "$itemName" -ErrorAction SilentlyContinue | Out-Null
				Write-Log -Category "info" -Message "policy created successfully"
			}
			catch {
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

function Test-CMxAdContainer {
	param()
	Write-Host "Searching for AD container: System Management" -ForegroundColor Green
	$strFilter = "(&(objectCategory=Container)(Name=System Management))"
	$objDomain = New-Object System.DirectoryServices.DirectoryEntry
	$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
	$objSearcher.SearchRoot = $objDomain
	$objSearcher.PageSize = 1000
	$objSearcher.Filter = $strFilter
	$objSearcher.SearchScope = "Subtree"
	$colProplist = "name"
	foreach ($i in $colProplist){$objSearcher.PropertiesToLoad.Add($i) | Out-Null}
	$colResults = $objSearcher.FindAll()
	Write-Output ($colResults.Count -gt 0)
}

function Test-CMxAdSchema {
	param ()
	Write-Host "Verifying for AD Schema extension" -ForegroundColor Green
	$strFilter = "(&(objectClass=mSSMSSite)(Name=*))"
	$objDomain = New-Object System.DirectoryServices.DirectoryEntry
	$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
	$objSearcher.SearchRoot = $objDomain
	$objSearcher.PageSize = 1000
	$objSearcher.Filter = $strFilter
	$objSearcher.SearchScope = "Subtree"
	$colProplist = "name"
	foreach ($i in $colProplist){$objSearcher.PropertiesToLoad.Add($i) | Out-Null}
	$colResults = $objSearcher.FindAll()
	Write-Output ($colResults.Count -gt 0)
}

function Test-CMxAdUser {
    [CmdletBinding(SupportsShouldProcess=$True)]
	param(
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [string] $UserName
    )
    $tmpuser = $UserName.Split('\')[$UserName.Split('\').Count - 1]
	Write-Host "Searching for AD user: $UserName" -ForegroundColor Green
	$strFilter = "(&(objectCategory=user)(sAMAccountName=$tmpuser))"
    Write-Verbose $strFilter
	$objDomain   = New-Object System.DirectoryServices.DirectoryEntry
	$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
	$objSearcher.SearchRoot = $objDomain
	$objSearcher.PageSize = 1000
	$objSearcher.Filter = $strFilter
	$objSearcher.SearchScope = "Subtree"
	$colProplist = "sAMAccountName"
	foreach ($i in $colProplist){$objSearcher.PropertiesToLoad.Add($i) | out-null}
	$colResults = $objSearcher.FindAll()
	Write-Output ($colResults.Count -gt 0)
}

function Import-CmxClientPush {
	[CmdletBinding(SupportsShouldProcess=$True)]
	param (
		[parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		$DataSet
	)
	foreach ($set in $DataSet.configuration.cmsite.clientoptions.CMClientPushInstallation | Where-Object {$_.use -eq '1'}) {
		if ($set.AutomaticInstall -eq 'true') {
			try {
				Set-CMClientPushInstallation -SiteCode "$sitecode" -EnableAutomaticClientPushInstallation $True | Out-Null
				Write-Log -Category "info" -Message "client push: enabled automatic client push installation"
			}
			catch {
				Write-Log -Category "error" -Message $_.Exception.Message
			}
		}
		if ($set.ClientCMServer -eq 'true') {
			try {
				Set-CMClientPushInstallation -SiteCode "$sitecode" -EnableSystemTypeConfigurationManager $True | Out-Null
				Write-Log -Category "info" -Message "client push: enabled client install on CM site systems"
			}
			catch {
				Write-Log -Category "error" -Message $_.Exception.Message
			}
		}
		if ($set.ClientServer -eq 'true') {
			try {
				Set-CMClientPushInstallation -SiteCode "$sitecode" -EnableSystemTypeServer $True | Out-Null
				Write-Log -Category "info" -Message "client push: enabled client install on servers"
			}
			catch {
				Write-Log -Category "error" -Message $_.Exception.Message
			}
		}
		if ($set.ClientDC -eq 'true') {
			try {
				Set-CMClientPushInstallation -SiteCode "$sitecode" -InstallClientToDomainController $True | Out-Null
				Write-Log -Category "info" -Message "client push: enabled client install on domain controllers"
			}
			catch {
				Write-Log -Category "error" -Message $_.Exception.Message
			}
		}
		if ($set.ClientWorkstation -eq 'true') {
			try {
				Set-CMClientPushInstallation -SiteCode "$sitecode" -EnableSystemTypeWorkstation $True | Out-Null
				Write-Log -Category "info" -Message "client push: enabled client install on workstations"
			}
			catch {
				Write-Log -Category "error" -Message $_.Exception.Message
			}
		}
		if ($set.Accounts.length -gt 0) {
			foreach ($acct in $set.Accounts.Split(",")) {
				try {
					Set-CMClientPushInstallation -SiteCode "$sitecode" -AddAccount $acct | Out-Null
					Write-Log -Category "info" -Message "client push: set installation account to $($acct)"
				}
				catch {
					Write-Log -Category "error" -Message $_.Exception.Message
				}
			} # foreach
		}
		if ($set.InstallationProperty.Length -gt 0) {
			try {
				Set-CMClientPushInstallation -SiteCode "$sitecode" -InstallationProperty $set.InstallationProperty | Out-Null
				Write-Log -Category "info" -Message "client push: set installation property $($set.InstallationProperty)"
			}
			catch {
				Write-Log -Category "error" -Message $_.Exception.Message
			}
		}
	} # foreach
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
        'ENVIRONMENT' {
			if (Test-CMxAdContainer) {
				Write-Log -Category "info" -Message "AD container verified"
			}
			else {
				Write-Log -Category "warning" -Message "AD container could not be verified"
			}
			if (Test-CMxAdSchema) {
				Write-Log -Category "info" -Message "AD schema has been extended"
			}
			else {
				Write-Log -Category "warning" -Message "AD schema has not been extended"
			}
			break
		}
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
			Import-CmxClientPush -DataSet $xmldata | Out-Null
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
