# CM_Build
ConfigMgr Site Server installer script

## Revision History
1.0.0 - 2017.08.14 - initial release
1.1.0 - 2017.08.15 - redesigned XML structure, process and code factoring

Tested on Windows Server 2016 Datacenter, with SQL Server 2016 SP1, ADK 1703, MDT 8443 and SCCM 1702

### Usage

* cm_build.ps1 -xmlfile .\cm_build.xml [-NoCheck] [-NoReboot] [-Verbose] [-WhatIf]
* -xmlfile [filepath]
* -NoCheck (skip platform validation)
* -NoReboot (suppress reboots)
* a transcript log is created in the runtime folder

## Assumptions

* Server installed and patched (Windows Server 2012 R2 or 2016)
* Server is joined to domain
* Static IPv4 address
* Disks are allocated (e.g. E:, F:, G:)
* At least 8 GB memory

## Overview

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

## Examples

* .\cm_build.ps1 -xmlfile .\cm_build.xml -Verbose
* .\cm_build.ps1 -xmlfile .\cm_build.xml -NoCheck -Verbose
