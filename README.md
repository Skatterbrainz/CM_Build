# Overview

Refer to https://skatterbrainz.wordpress.com/2017/09/04/cm_siteconfig-1-2/

# CM_BUILD

Part 1 of 2 = builds on top of a standard Windows Server instance to having Configuration Manager.  This includes server roles and features, ADK, MDT, SQL Server, WSUS, and Configuration Manager.  It also includes things like SQL memory and recovery settings, registry keys, custom folders and files, and optional tools (ConfigMgr Toolkit, Right-click Tools, etc.).

* 1.2.19 - Fixed bugs in parsing SQL setup.ini when multiple sqladmins are configured
* 1.2.18 - Added -Override feature like cm_siteconfig has
* 1.2.17 - Fixed bugs in function output consistency and output handling
 
# CM_SITECONFIG

Part 2 of 2 = builds on top of cm_build (a functional but non-configured ConfigMgr instance).  Configures AD forest connection, discovery methods, boundary groups, collections, queries, client settings, applications, operating system images, operating system upgrade installers, site maintenance tasks, application categories and antimalware policies. 

* 1.2.26 - Fixed logfile path declaration
* 1.2.25 - Fixed bugs in creating boundary groups
* 1.2.24 - Fixed bugs in importing apps, queries and folders. Fixed inconsistencies in cm_siteconfig.xml

# Noteable Updates

* [Override] parameter added to both scripts - provides a gridview menu to choose individual XML sections to apply
* Added cm_build_nosql.xml template for skipping SQL Server (when on a separate host)
* Added [localaccounts] section to cm_build.xml and cm_build_nosql.xml - adds domain accounts to local admins group and assigns policy privileges like Logon as a Service, etc.
* Fixed numerous bugs with control flow logic, especially for handling step failures and terminating gracefully.

# Recommended Platforms and Resources

* Recommended Software
  * Windows Server 2016 (or current version)
  * SQL Server 2016 SP1 (or current version)
  * SQL Server Management Studio 2017 (or latest version)
  * Configuration Manager Current Branch (supported versions only)
  * Windows 10 ADK 1703 (or current version)
  * MDT 8443 (or current version)
  * ConfigMgr Toolkit 2012 R2 (or current version)
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
* cm_build.ps1 -XmlFile cm_build.xml -Override
* (combinations of above, eg.: -NoCheck -NoReboot -Detailed -Override)

* cm_siteconfig.ps1 -XmlFile cm_siteconfig.xml
* cm_siteconfig.ps1 -XmlFile cm_siteconfig.xml -Detailed
* cm_siteconfig.ps1 -XmlFile cm_siteconfig.xml -Override
* (combinations of above, eg.: -Detailed -Override)

* [Detailed] is like -Verbose, only prettier, and doesn't get fall-down drunk on you
* [ForceBoundaries] was an idea I had while on 1.5 hrs of sleep. stay away from it for now.
* [NoCheck] skips platform requirements validation checks, like memory, etc.
* [NoReboot] suppresses reboots during the execution
* [Override] displays a PS GridView menu to allow you to select individual tasks to run regardless of enabled=true in the XML file.
