# Overview

Refer to https://skatterbrainz.wordpress.com/2017/09/04/cm_siteconfig-1-2/

# Disclaimer

* This is not a funded project: it has no official resources allocated to it, and is only worked on by 1 volunteer as of now. Do not create any production dependency on this project unless you are willing to support it completely yourself. Feel free to file Issues and submit Pull Requests, but please understand that with limited resources, it may be a while before your submissions are addressed.

* This is an experimental project: it is not fully baked, and you should expect breaking changes to be made often.

* There is no official "support" provided for this project.  Issue submissions will be reviewed and addressed as quickly as possible, based upon resource and time availability, but there is no promise of an explicit or implied response time limit.

# CM_BUILD

## History

Part 1 of 2 = builds on top of a standard Windows Server instance to having Configuration Manager.  This includes server roles and features, ADK, MDT, SQL Server, WSUS, and Configuration Manager.  It also includes things like SQL memory and recovery settings, registry keys, custom folders and files, and optional tools (ConfigMgr Toolkit, Right-click Tools, etc.).

* 1.3.09 - Fixed bug in SQL memory configuration function
* 1.3.08 - Minor updates
* 1.3.07 - Fixed bug in dependency and detection methods
* 1.3.06 - Incorporated ps module "carbon" to support user account permissions
* 1.3.05 - Fixed bugs in the User Account processing function
* 1.3.04 - Added support for -XmlFile input from file or URI (ex. Github gist)
* 1.3.02 - Fixed sql memory config issue caused by removing dbatools PS module reference
* 1.3.00 - Most bugs terminated with extreme nuclear resources, new features, new day (September 2017)
* 1.2.20 - Fixed bug in Write-Log function affecting HH:mm:ss format display
* 1.2.19 - Fixed bugs in parsing SQL setup.ini when multiple sqladmins are configured
* 1.2.18 - Added -Override feature like cm_siteconfig has
* 1.2.17 - Fixed bugs in function output consistency and output handling
* 1.2.00 - breakfast and then coffee
* 1.1.00 - second cup of coffee
* 1.0.00 - first cup of coffee (September 2017)
 
# CM_SITECONFIG

Part 2 of 2 = builds on top of cm_build (a functional but non-configured ConfigMgr instance).  Configures AD forest connection, discovery methods, boundary groups, collections, queries, client settings, applications, operating system images, operating system upgrade installers, site maintenance tasks, application categories and antimalware policies. 

* 1.3.04 - Added support for -XmlFile input from file or URI (ex. Github gist)
* 1.3.00 - Most bugs terminated with extreme nuclear resources, new features, new day.  New XML format.  Refactored code.
* 1.2.31 - Fixed bugs in site roles, discovery methods, and software update point settings
* 1.2.30 - Fixed bug in Write-Log function affecting HH:mm:ss format display, and client push installation code
* 1.2.28 - Added checks for AD accounts before importing, fixed bug with applications import and folder assignments
* 1.2.27 - Added checks for AD schema extension and AD container
* 1.2.26 - Fixed logfile path declaration
* 1.2.25 - Fixed bugs in creating boundary groups
* 1.2.24 - Fixed bugs in importing apps, queries and folders. Fixed inconsistencies in cm_siteconfig.xml
* 1.2.00 - first time getting 8 hrs of sleep in almost 5 months
* 1.1.00 - second cup of coffee
* 1.0.00 - first cup of coffee

# Noteable Updates

* [Override] parameter added to both scripts - provides a gridview menu to choose individual XML sections to apply
* Added cm_build_nosql.xml template for skipping SQL Server (when on a separate host)
* Added [localaccounts] section to cm_build.xml and cm_build_nosql.xml - adds domain accounts to local admins group and assigns policy privileges like Logon as a Service, etc.
* Fixed numerous bugs with control flow logic, especially for handling step failures and terminating gracefully.

# Requirements

* Physical or Virtual machine running Windows Server 2012 R2 or 2016
* Static IPv4 Address
* AD domain joined
* Internet Connection
* Local administrator rights
* PowerShell Execution Policy set to ByPass or Unrestricted
* Installation Media for SQL Server 2016, MDT 8443, ADK 1703 and ConfigMgr 1702 (or latest appropriate versions)

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
* cm_build.ps1 -XmlFile "https://..../cm_build.xml"
* cm_build.ps1 -XmlFile cm_build.xml -NoCheck
* cm_build.ps1 -XmlFile cm_build.xml -NoReboot
* cm_build.ps1 -XmlFile cm_build.xml -Detailed
* cm_build.ps1 -XmlFile cm_build.xml -Override
* (combinations of above, eg.: -NoCheck -NoReboot -Detailed -Override)

* cm_siteconfig.ps1 -XmlFile cm_siteconfig.xml
* cm_siteconfig.ps1 -XmlFile "https://..../cm_siteconfig.xml"
* cm_siteconfig.ps1 -XmlFile cm_siteconfig.xml -Detailed
* cm_siteconfig.ps1 -XmlFile cm_siteconfig.xml -Override
* (combinations of above, eg.: -Detailed -Override)

* [Detailed] is like -Verbose, only prettier, and doesn't get fall-down drunk on you
* [NoCheck] skips platform requirements validation checks, like memory, etc.
* [NoReboot] suppresses reboots during the execution
* [Override] displays a PS GridView menu to allow you to select individual tasks to run regardless of enabled=true in the XML file.
