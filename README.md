# Overview

Refer to https://skatterbrainz.wordpress.com/2017/09/04/cm_siteconfig-1-2/

# CM_BUILD

 placeholder
 
# CM_SITECONFIG

 placeholder

# Revision History
* 1.x.xx - xxxx.xx.xx
* 1.2.22 - 2017.09.04
* 1.2.21 - 2017.09.02
* 1.1.43 - 2017.08.28
* 1.1.42 - 2017.08.24
* 1.1.00 - 2017.08.17
* 1.0.00 - 2017.08.16

# Recommended Platforms and Resources

* Software
 * Windows Server 2016 (or 2012 R2)
 * SQL Server 2016 SP1 (or 2016, 2014)
 * Configuration Manager Current Branch (supported versions only)
 * Windows 10 ADK (current version)
 * MDT (current version)
 * AD domain joined, static IPv4 address
* Hardware
 * 16 GB memory or more
 * 3 logical disks (OS, SQL/CM, Data/Content), more disks preferred (for temp db, logs, etc.)
 * 2 vCPUs
* Tested on Windows Server 2016 Datacenter, with SQL Server 2016 SP1, ADK 1703, MDT 8443 and SCCM 1702

# Examples

* cm_build.ps1 -XmlFile cm_build.xml
* cm_build.ps1 -XmlFile cm_build.xml -NoCheck
* cm_build.ps1 -XmlFile cm_build.xml -NoReboot
* cm_build.ps1 -XmlFile cm_build.xml -Detailed
* (combinations of above, eg.: -NoCheck -NoReboot -Detailed)

## CM_SiteConfig Usage

* cm_siteconfig.ps1 -xmlfile .\cm_siteconfig.xml [-ForceBoundaries] [-Detailed] [-Override] [-Verbose] [-WhatIf]
* [Detailed] is like -Verbose, only prettier, and doesn't get fall-down drunk on you
* [ForceBoundaries] was an idea I had while on 1.5 hrs of sleep. stay away from it for now.
* [Override] displays a PS GridView menu to allow you to select individual tasks to run regardless of enabled=true in the XML file.

## CM_SiteConfig Examples

* .\cm_siteconfig.ps1 -xmlfile .\cm_siteconfig.xml -Detailed
* .\cm_siteconfig.ps1 -xmlfile .\cm_siteconfig.xml -Detailed -Override
