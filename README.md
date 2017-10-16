# Overview

Refer to https://skatterbrainz.wordpress.com/2017/09/04/cm_siteconfig-1-2/

# Disclaimer

* This is not a funded project: it has no official resources allocated to it, and is only worked on by 1 volunteer as of now. Do not create any production dependency on this project unless you are willing to support it completely yourself. Feel free to file Issues and submit Pull Requests, but please understand that with limited resources, it may be a while before your submissions are addressed.

* This is an experimental project: it is not fully baked, and you should expect breaking changes to be made often.

* There is no official "support" provided for this project.  Issue submissions will be reviewed and addressed as quickly as possible, based upon resource and time availability, but there is no promise of an explicit or implied response time limit.

# CM_BUILD

CM_BUILD is part 1 of a 2 part solution (the 2nd part being CM_SITECONFIG).  CM_BUILD provides automation for building services and configuration changes on top of a "vanilla" Windows Server machine up to having Configuration Manager installed and ready for configuration.  CM_SITECONFIG automates the configuration of a "vanilla" ConfigMgr site installation into a functional Primary or CAS site server.  In short, CM_BUILD provides for automating the following installations and configuration changes:

* Server Roles and Features
* Local user accounts and account rights (e.g. Log on as a Service)
* File system folders
* Windows 10 ADK
* MDT
* SQL Server and SQL Management Studio
* Configure SQL options (memory, recovery plan, etc.)
* Configuration Manager
* ConfigMgr Toolkit
* Right-Click Tools
* Want more? Submit an issue (above)

## CM_BUILD Examples

* cm_build.ps1 -XmlFile cm_build.xml
* cm_build.ps1 -XmlFile "https://..../cm_build.xml"
* cm_build.ps1 -XmlFile cm_build.xml -NoCheck
* cm_build.ps1 -XmlFile cm_build.xml -NoReboot
* cm_build.ps1 -XmlFile cm_build.xml -Detailed
* cm_build.ps1 -XmlFile cm_build.xml -Override
* (combinations of above, eg.: -NoCheck -NoReboot -Detailed -Override)

* [Detailed] is like -Verbose, only prettier, and doesn't get fall-down drunk on you
* [NoCheck] skips platform requirements validation checks, like memory, etc.
* [NoReboot] suppresses reboots during the execution
* [Override] displays a PS GridView menu to allow you to select individual tasks to run regardless of enabled=true in the XML file.

## CM_BUILD History

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

CM_SITECONFIG is the 2nd part of the 2 part solution. It builds on top of CM_BUILD, and configures a base ConfigMgr installation into a functional Primary or CAS site environment.  It was intended for lab and demo builds, but has been used in production scenarios as well. 
In short, CM_SITECONFIG provides automation for the following configuration changes:

* AD forest connection
* Discovery Methods
* Boundary Groups
* Queries
* User and Device Collections (Direct and Query rules)
* ConfigMgr (user) Accounts
* Client Settings
* Client Push Installation Settings
* Additional Site System Roles (SUP, CP, SSRP, AISP, DP, AppCatWS, AppCatWSP, etc.)
* Applications
* Application Categories
* Console Folders
* OS images and OS upgrade packages
* Site Maintenance Tasks
* EPP Antimalware policies
* Want more?  Submit an Issue (above)

## CM_SITECONFIG Examples

* cm_siteconfig.ps1 -XmlFile cm_siteconfig.xml
* cm_siteconfig.ps1 -XmlFile "https://..../cm_siteconfig.xml"
* cm_siteconfig.ps1 -XmlFile cm_siteconfig.xml -Detailed
* cm_siteconfig.ps1 -XmlFile cm_siteconfig.xml -Override
* (combinations of above, eg.: -Detailed -Override)

* [Detailed] is like -Verbose, only prettier, and doesn't get fall-down drunk on you
* [NoCheck] skips platform requirements validation checks, like memory, etc.
* [NoReboot] suppresses reboots during the execution
* [Override] displays a PS GridView menu to allow you to select individual tasks to run regardless of enabled=true in the XML file.

## CM_SITECONFIG History

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

# SYSTEM REQUIREMENTS

## Minimum Requirements (both)

* Physical or Virtual machine running Windows Server 2012 R2 or 2016
* Minimum supported CPU and Memory per Microsoft
* Windows 10 ADK 1703 (or latest version)
* Static IPv4 Address
* AD domain joined
* Internet Connection
* Local administrator rights
* PowerShell Execution Policy set to ByPass or Unrestricted
* Installation Media for SQL Server, MDT, ADK and ConfigMgr (latest appropriate versions)

## Recommended (both)

* Virtual machine running Windows Server 2016
* Recommended CPU and Memory per Microsoft
* Windows 10 ADK 1703 (or latest version)
* SQL Server 2016 SP1 w/SSMS 2017
* Static IPv4 Address
* AD domain joined
* Internet Connection
* Local administrator rights
* PowerShell Execution Policy set to ByPass or Unrestricted
* Installation Media for SQL Server, MDT, ADK and ConfigMgr (latest appropriate versions)
* ConfigMgr Toolkit 2012 R2 (or current version)

# Testing Conditions

CM_BUILD and CM_SITECONFIG have been tested on Windows Server 2016 Datacenter, with SQL Server 2016 SP1, SQL Server Management Studio 2017, ADK 1703, MDT 8443 and SCCM 1702, 1706, 1708, and 1709.

# Support

There is no official support.  Please submit bugs, enhancement requests and questions using the "Issues" tool within this Github repository (linked above).  I will make every possible effort to respond ASAP.  Any and all feedback is welcome and very much appreciated!
