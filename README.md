# CM_Build 1.2 / CM_SiteConfig 1.2
ConfigMgr Site Server installer and Site Configuration scripts

## CM_Build Revision History
* 1.2.21 - 2017.09.02 - added sqloptions to XML for control over max memory allocation and DB recovery model, minor bug fixes
* 1.1.43 - 2017.08.28 - bug fixes, verbose output, enhanced features
* 1.1.42 - 2017.08.24 - bug fixes
* 1.1.00 - 2017.08.17 - redesigned XML schema and powershell code framework
* 1.0.00 - 2017.08.16 - initial release

## CM_SiteConfig Revision History
* 1.2.21 - 2017.09.02 - added more capabilities, bug fixes, documentation in XML
* 1.1.20 - 2017.08.28 - redesigned XML schema and powershell code framework
* 1.1.10 - 2017.08.24 - added folders, queries
* 1.1.00 - 2017.08.17 - added to repository

Tested on Windows Server 2016 Datacenter, with SQL Server 2016 SP1, ADK 1703, MDT 8443 and SCCM 1702

### CM_Build Usage

* cm_build.ps1 -xmlfile .\cm_build.xml [-NoCheck] [-NoReboot] [-Verbose] [-WhatIf]
  * -xmlfile [filepath]
  * -NoCheck (skip platform validation)
  * -NoReboot (suppress reboots)
  * a transcript log is created in the runtime folder

## CM_Build System Requirements

* Server installed and patched (Windows Server 2012 R2 or 2016)
* Server is joined to domain
* Static IPv4 address
* Disks are allocated (e.g. E:, F:, G:)
* At least 8 GB memory

## CM_Build Execution

* Installs Windows Server Roles and Features
* Installs ADK
* Installs MDT
* Installs SQL Server
* Installs SSMS
* Configures SQL Server memory
* Installs WSUS role
* Installs ConfigMgr
* Installs ConfigMgr Toolkit
* Installs Right-click Tools
* Installs anything else you want it to

## CM_Build Process Overview

* Download installation media
  * Configuration Manager 1702
  * SQL Server 2016
  * Windows 10 ADK 1703
  * MDT 8443
  * ConfigMgr Toolkit 2012 R2
  * Recast Right-click Tools
* Extract content into shared location
* Edit cm_build.xml to suit your environment and needs
* Open PowerShell console using "Run as Administrator"
* Set-ExecutionPolicy to ByPass 
* Execute (see examples)

## CM_Build Examples

* .\cm_build.ps1 -xmlfile .\cm_build.xml -Verbose
* .\cm_build.ps1 -xmlfile .\cm_build.xml -NoCheck -Verbose
* .\cm_build.ps1 -xmlfile .\cm_build.xml -NoReboot -Verbose

## CM_Build Notes

* To use the internal function process for adding server roles/features, leave the XML setting under [packages] to use *type*="feature".
* To use an external XML role config file, change the SERVERROLES *type*="payload", and edit the [payload] entry to specify the *file*="filename.xml".  The XML file needs to reside in the same folder where the -XmlFile filename resides.

## CM_SiteConfig Usage

* cm_siteconfig.ps1 -xmlfile .\cm_siteconfig.xml [-Verbose] [-WhatIf]

## CM_SiteConfig Examples

* .\cm_siteconfig.ps1 -xmlfile .\cm_siteconfig.xml -Verbose
