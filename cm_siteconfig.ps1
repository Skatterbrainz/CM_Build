<?xml version="1.0" encoding="ISO-8859-1"?>
<!-- Version 1.2.02 - DS - 2017-08-31 -->
<configuration>
    <cmsite sitecode="P01" forest="contoso.com">
        <control comment="Enable configuration steps and specify sequence order">
            <ci name="ACCOUNTS" enabled="true" />
            <ci name="ADFOREST" enabled="true" />
            <ci name="DISCOVERY" enabled="true" />
            <ci name="BOUNDARIES" enabled="false" />
            <ci name="BOUNDARYGROUPS" enabled="true" />
            <ci name="SITEROLES" enabled="true" />
            <ci name="CLIENTSETTINGS" enabled="false" />
            <ci name="CLIENTINSTALL" enabled="false" />
            <ci name="DPGROUPS" enabled="true" />
            <ci name="FOLDERS" enabled="true" />
            <ci name="QUERIES" enabled="true" />
            <ci name="COLLECTIONS" enabled="true" />
            <ci name="OSIMAGES" enabled="true" />
            <ci name="OSINSTALLERS" enabled="true" />
            <ci name="MTASKS" enabled="true" />
            <ci name="APPCATEGORIES" enabled="true" />
            <ci name="APPLICATIONS" enabled="true" />
        </control>
        <schedules>
            <schedule name="sch15min" unit="minutes" value="15" />
            <schedule name="schDaily" unit="days" value="1" />
            <schedule name="schWeekly" unit="days" value="7" />
        </schedules>
        <discoveries comment="https://docs.microsoft.com/en-us/powershell/sccm/configurationmanager/vlatest/set-cmdiscoverymethod">
            <discovery enabled="true" name="ActiveDirectoryForestDiscovery" PollingSchedule="sch15mins" options="" />
            <!--<discovery enabled="true" name="ActiveDirectoryForestDiscovery" PollingSchedule="sch15mins" options="EnableSubnetBoundaryCreation" />-->
            <discovery enabled="true" name="ActiveDirectorySystemDiscovery" PollingSchedule="schDaily" options="EnableDeltaDiscovery:15|ADContainer:dc=contoso,dc=com|EnableFilteringExpiredLogon:90|EnableFilteringExpiredPassword:90" />
            <discovery enabled="true" name="ActiveDirectoryGroupDiscovery" PollingSchedule="schDaily" options="EnableDeltaDiscovery:15" />
            <discovery enabled="true" name="ActiveDirectoryUserDiscovery" PollingSchedule="schDaily" options="EnableDeltaDiscovery:15|ADAttributes:title,department,division|ADContainer:dc=contoso,dc=com|EnableFilteringExpiredLogon:90|EnableFilteringExpiredPassword:90" />
            <discovery enabled="false" name="NetworkDiscovery" PollingSchedule="schDaily" />
            <discovery enabled="true" name="HeartbeatDiscovery" PollingSchedule="DEFAULT" />
        </discoveries>
        <boundarygroups comment="Configure Boundary Groups">
            <boundarygroup name="NA-US-VA-Norfolk" SiteSystemServer="cm02.contoso.com" LinkType="FastLink" comment="Norfolk" />
            <boundarygroup name="NA-US-VA-VB" SiteSystemServer="cm02.contoso.com" LinkType="FastLink" comment="Virginia Beach" />
            <boundarygroup name="NA-US-CA-Fremont" SiteSystemServer="" LinkType="" comment="Fremont" />
            <boundarygroup name="NA-US-NY-NewYork" SiteSystemServer="" LinkType="" comment="New York" />
        </boundarygroups>
        <boundaries comment="Configure Site Boundaries if not set to AD discovery-automatic">
            <boundary name="NA-US-VA-Norfolk-Servers" type="IPRange" value="192.168.0.10-192.168.0.99" boundarygroup="NA-US-VA-Norfolk" comment="Norfolk" />
            <boundary name="NA-US-VA-Norfolk-Workstations" type="IPRange" value="192.168.0.100-192.168.0.150" boundarygroup="NA-US-VA-Norfolk" comment="Norfolk" />
            <boundary name="NA-US-NY-NewYork-Servers" type="IPRange" value="192.168.2.10-192.168.2.99" boundarygroup="NA-US-NY-NewYork" comment="New York" />
        </boundaries>
        <clientoptions comment="Configure Default Client Push Installation settings">
            <CMClientPushInstallation EnableAutomaticClientPushInstallation="false" EnableSystemTypeConfiguationManager="false" ChosenAccount="CONTOSO\sccmclient" InstallationProperty="SMSSITECODE=P01" />
        </clientoptions>
        <clientsettings comment="Client Settings">
            <clientsetting name="Workstations" comment="Workstation Client Settings" type="Device" priority="1">
                <settings>
                    <setting name="BITS" enabled="true" options="EnableBitsMaxBandwidth" />
                    <setting name="ComputerAgent" enabled="true" options="AddPortalToTrustedSiteList,AllowPortalToHaveElevatedTrust,BrandingTitle=Contoso IT,EnableThirdPartyOrchestration,FinalReminderMinutesInterval=25,InitialReminderHoursInterval=6,InstallRestriction=OnlyAdministrators,PortalUrl=http://cm02.contoso.com,PowerShellExecutionPolicy=Bypass,SuspendBitLocker=Always" />
                    <setting name="ComputerRestart" enabled="false" />
                    <setting name="EndpointProtection" enabled="false" />
                    <setting name="HardwareInventory" enabled="false" />
                    <setting name="PowerOptions" enabled="false" />
                    <setting name="RemoteTools" enabled="false" />
                    <setting name="SoftwareDeployment" enabled="false" />
                    <setting name="SoftwareInventory" enabled="false" />
                    <setting name="SoftwareUpdates" enabled="false" />
                </settings>
            </clientsetting>
                <settings>
                    <setting name="HardwareInventory" enabled="false" />
                    <setting name="RemoteTools" enabled="false" />
                    <setting name="SoftwareInventory" enabled="false" />
                </settings>
            <clientsetting name="Servers" comment="Server Client Settings" type="Device" priority="2">
            </clientsetting>
        </clientsettings>
        <dpgroups comment="Distribution Point Groups">
            <dpgroup name="All Distribution Points" enabled="true" comment="All DP servers throughout the organization" />
            <dpgroup name="Virginia DPs" enabled="true" comment="DP servers in Virginia" />
            <dpgroup name="California DPs" enabled="true" comment="DP servers in California" />
            <dpgroup name="Azure DPs" enabled="true" comment="DP servers in Azure" />
        </dpgroups>
        <sitesystemroles>
            <sitesystemrole name="aisp" enabled="true" comment="Asset Intelligence Synchronization Point">
                <roleoptions comment="Configure Asset Intelligence Classes">
                    <roleoption name="EnableAllReportingClass" params="" />
                    <!-- <roleoption name="EnableReportingClass" params="" /> -->
                </roleoptions>
            </sitesystemrole>
        </sitesystemroles>
        <folders comment="Console Folders to create">
            <folder name="Deploy Applications" path="DeviceCollection" comment="" />
            <folder name="Deploy Updates" path="DeviceCollection" comment="" />
            <folder name="Inventory Hardware" path="DeviceCollection" comment="" />
            <folder name="Inventory Software" path="DeviceCollection" comment="" />
            <folder name="Inventory Organization" path="UserCollection" comment="" />
            <folder name="Deploy Applications" path="UserCollection" comment="" />
            <folder name="Production" path="TaskSequence" comment="" />
            <folder name="Testing" path="TaskSequence" comment="" />
            <folder name="WinPE" path="DriverPackage" comment="" />
            <folder name="HP" path="DriverPackage" comment="" />
            <folder name="EliteBook.9470m" path="DriverPackage/HP" comment="" />
            <folder name="ZBook.15uG2" path="DriverPackage/HP" comment="" />
            <folder name="Windows Desktop" path="OperatingSystemImage" comment="" />
            <folder name="Windows Server" path="OperatingSystemImage" comment="" />
            <folder name="Contoso" path="BootImage" comment="" />
            <folder name="Google" path="Application" comment="" />
            <folder name="Microsoft" path="Application" comment="" />
            <folder name="Utilities" path="Application" comment="" />
            <!--
            Valid Folder Paths...
            Application
            BootImage
            ConfigurationBaseline
            ConfigurationItem
            DeviceCollection
            Driver
            DriverPackage
            OperatingSystemImage
            OperatingSystemInstaller
            Package
            Query
            SmsProvider
            SoftwareMetering
            SoftwareUpdate
            TaskSequence
            UserCollection
            UserStateMigration
            VirtualHardDisk
            -->
        </folders>
        <queries comment="Custom queries">
            <query name="Contoso - Serial, MAC and Hostname" comment="Serial Number, MAC address and Hostname for all Devices" class="SMS_R_System" expression="select distinct SMS_R_System.Name, SMS_G_System_SYSTEM_ENCLOSURE.SerialNumber, SMS_G_System_NETWORK_ADAPTER.MACAddress, SMS_G_System_NETWORK_ADAPTER_CONFIGURATION.IPEnabled from  SMS_R_System inner join SMS_G_System_SYSTEM_ENCLOSURE on SMS_G_System_SYSTEM_ENCLOSURE.ResourceID = SMS_R_System.ResourceId inner join SMS_G_System_NETWORK_ADAPTER on SMS_G_System_NETWORK_ADAPTER.ResourceID = SMS_R_System.ResourceId inner join SMS_G_System_NETWORK_ADAPTER_CONFIGURATION on SMS_G_System_NETWORK_ADAPTER_CONFIGURATION.ResourceID = SMS_R_System.ResourceId where SMS_G_System_NETWORK_ADAPTER_CONFIGURATION.IPEnabled = 1 and SMS_G_System_NETWORK_ADAPTER.MACAddress not like '' order by SMS_R_System.Name" />
            <query name="Contoso - Windows Server Features" comment="Windows Server Feature Names" class="SMS_R_System" expression="select distinct SMS_G_System_SERVER_FEATURE.Name from  SMS_R_System inner join SMS_G_System_SERVER_FEATURE on SMS_G_System_SERVER_FEATURE.ResourceID = SMS_R_System.ResourceId order by SMS_G_System_SERVER_FEATURE.Name" />
        </queries>
        <osimages comment="For bare-metal and build-and-capture installs">
            <osimage name="Windows 10 x64 Ent 1703" path="\\contoso.com\software\OSD\w10x64ent\sources\install.wim" comment="Windows 10 x64 Enterprise 1703" />
            <osimage name="Windows Server 2016 Datacenter" path="\\contoso.com\software\OSD\ws2016dc\sources\install.wim" comment="Windows Server 2016 Datacenter" />
        </osimages>
        <osinstallers comment="For in-place upgrades">
            <osinstaller name="Windows 10 x64 Ent 1703" path="\\contoso.com\software\OSD\w10x64ent" comment="Windows 10 x64 Enterprise 1703" version="1703.15063.540" />
            <osinstaller name="Windows Server 2016 Datacenter 1607" path="\\contoso.com\software\OSD\ws2016dc" comment="Windows Server 2016 Datacenter" version="1607.14393.1593" />
        </osinstallers>
        <collections comment="Custom Collections">
            <collection name="Users - Title - Research Analysts" type="User" comment="Users by Job Title: Research Analyst" parent="All Users" folder="UserCollection\Inventory Organization" ruletype="query" rule="select SMS_R_USER.ResourceID,SMS_R_USER.ResourceType,SMS_R_USER.Name,SMS_R_USER.UniqueUserName,SMS_R_USER.WindowsNTDomain from SMS_R_User where sms_R_User.title = 'Research Analyst'" />
            <collection name="Users - Title - Sales Managers" type="User" comment="Users by Job Title: Sales Manager" parent="All Users" folder="UserCollection\Inventory Organization" ruletype="query" rule="select distinct SMS_R_User.ResourceId, SMS_R_User.ResourceType, SMS_R_User.Name, SMS_R_User.UniqueUserName, SMS_R_User.WindowsNTDomain from  SMS_R_User where SMS_R_User.title = 'Sales Manager'" />
            <collection name="Users - Deploy - Dev Apps" type="User" comment="Developer Apps Bundle" parent="All Users" folder="UserCollection\Deploy Applications" ruletype="" rule="" />
            <collection name="Clients - Servers - All Windows Servers" type="Device" comment="Clients with Windows Server" parent="All Desktop and Server Clients" folder="DeviceCollection\Inventory Software" ruletype="query" rule="select distinct SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System inner join SMS_G_System_OPERATING_SYSTEM on SMS_G_System_OPERATING_SYSTEM.ResourceId = SMS_R_System.ResourceId where SMS_G_System_OPERATING_SYSTEM.Name like '%Server%'" />
            <collection name="Clients - Servers - 2012 R2" type="Device" comment="Server clients with Windows Server 2012 R2" parent="All Desktop and Server Clients" folder="DeviceCollection\Inventory Software" ruletype="query" rule="select distinct SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System inner join SMS_G_System_OPERATING_SYSTEM on SMS_G_System_OPERATING_SYSTEM.ResourceId = SMS_R_System.ResourceId where SMS_G_System_OPERATING_SYSTEM.Name like '%Server 2012 R2%'" />
            <collection name="Clients - Servers - 2016" type="Device" comment="Server clients with Windows Server 2016" parent="All Desktop and Server Clients" folder="DeviceCollection\Inventory Software" ruletype="query" rule="select distinct SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System inner join SMS_G_System_OPERATING_SYSTEM on SMS_G_System_OPERATING_SYSTEM.ResourceId = SMS_R_System.ResourceId where SMS_G_System_OPERATING_SYSTEM.Name like '%Server 2016%'" />
            <collection name="Clients - Servers - Dell" type="Device" comment="Dell server clients" parent="All Desktop and Server Client" folder="DeviceCollection\Inventory Hardware" ruletype="query" rule="select distinct SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceID = SMS_R_System.ResourceId inner join SMS_G_System_OPERATING_SYSTEM on SMS_G_System_OPERATING_SYSTEM.ResourceID = SMS_R_System.ResourceId where SMS_G_System_COMPUTER_SYSTEM.Manufacturer = 'Dell' and SMS_G_System_OPERATING_SYSTEM.Name like '%Server%'" />
            <collection name="Clients - Servers - HP" type="Device" comment="HP server clients" parent="All Desktop and Server Client" folder="DeviceCollection\Inventory Hardware" ruletype="query" rule="select distinct SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceID = SMS_R_System.ResourceId inner join SMS_G_System_OPERATING_SYSTEM on SMS_G_System_OPERATING_SYSTEM.ResourceID = SMS_R_System.ResourceId where SMS_G_System_COMPUTER_SYSTEM.Manufacturer = 'Hewlett-Packard' and SMS_G_System_OPERATING_SYSTEM.Name like '%Server%'" />
            <collection name="Clients - Servers - Lenovo" type="Device" comment="Lenovo server clients" parent="All Desktop and Server Client" folder="DeviceCollection\Inventory Hardware" ruletype="query" rule="select distinct SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceID = SMS_R_System.ResourceId inner join SMS_G_System_OPERATING_SYSTEM on SMS_G_System_OPERATING_SYSTEM.ResourceID = SMS_R_System.ResourceId where SMS_G_System_COMPUTER_SYSTEM.Manufacturer = 'Lenovo' and SMS_G_System_OPERATING_SYSTEM.Name like '%Server%'" />
            <collection name="Clients - Server Role - File Servers" type="Device" comment="File Servers" parent="All Desktop and Server Clients" folder="DeviceCollection\Inventory Software" ruletype="query" rule="select distinct SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System inner join SMS_G_System_SERVER_FEATURE on SMS_G_System_SERVER_FEATURE.ResourceId = SMS_R_System.ResourceId where SMS_G_System_SERVER_FEATURE.Name = 'File and Storage Services'" />
            <collection name="Clients - Server Role - Web Servers" type="Device" comment="Web Servers" parent="All Desktop and Server Clients" folder="DeviceCollection\Inventory Software" ruletype="query" rule="select distinct SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System inner join SMS_G_System_SERVER_FEATURE on SMS_G_System_SERVER_FEATURE.ResourceId = SMS_R_System.ResourceId where SMS_G_System_SERVER_FEATURE.Name = 'Web Server (IIS)'" />
            <collection name="Clients - Server Role - WSUS Servers" type="Device" comment="WSUS Servers" parent="All Desktop and Server Clients" folder="DeviceCollection\Inventory Software" ruletype="query" rule="select distinct SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System inner join SMS_G_System_SERVER_FEATURE on SMS_G_System_SERVER_FEATURE.ResourceId = SMS_R_System.ResourceId where SMS_G_System_SERVER_FEATURE.Name = 'WSUS Services'" />
            <collection name="Clients - Workstations - Windows 10" type="Device" comment="Workstation clients with Windows 10" parent="All Desktop and Server Clients" folder="DeviceCollection\Inventory Software" ruletype="query" rule="select distinct SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System inner join SMS_G_System_OPERATING_SYSTEM on SMS_G_System_OPERATING_SYSTEM.ResourceId = SMS_R_System.ResourceId where SMS_G_System_OPERATING_SYSTEM.Name like 'Microsoft Windows 10%'" />
            <collection name="Clients - Workstations - Windows 8.1" type="Device" comment="Workstation clients with Windows 8.1" parent="All Desktop and Server Clients" folder="DeviceCollection\Inventory Software" ruletype="query" rule="select distinct SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System inner join SMS_G_System_OPERATING_SYSTEM on SMS_G_System_OPERATING_SYSTEM.ResourceId = SMS_R_System.ResourceId where SMS_G_System_OPERATING_SYSTEM.Name like 'Microsoft Windows 8.1%'" />
            <collection name="Clients - Workstations - Windows 7" type="Device" comment="Workstation clients with Windows 7" parent="All Desktop and Server Clients" folder="DeviceCollection\Inventory Software" ruletype="query" rule="select distinct SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System inner join SMS_G_System_OPERATING_SYSTEM on SMS_G_System_OPERATING_SYSTEM.ResourceId = SMS_R_System.ResourceId where SMS_G_System_OPERATING_SYSTEM.Name like 'Microsoft Windows 7%'" />
            <collection name="Clients - Workstations - Dell" type="Device" comment="Dell workstation clients" parent="All Desktop and Server Client" folder="DeviceCollection\Inventory Hardware" ruletype="query" rule="select distinct SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceID = SMS_R_System.ResourceId inner join SMS_G_System_OPERATING_SYSTEM on SMS_G_System_OPERATING_SYSTEM.ResourceID = SMS_R_System.ResourceId where SMS_G_System_COMPUTER_SYSTEM.Manufacturer = 'Dell' and SMS_G_System_OPERATING_SYSTEM.Name not like '%Server%'" />
            <collection name="Clients - Workstations - HP" type="Device" comment="HP workstation clients" parent="All Desktop and Server Client" folder="DeviceCollection\Inventory Hardware" ruletype="query" rule="select distinct SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceID = SMS_R_System.ResourceId inner join SMS_G_System_OPERATING_SYSTEM on SMS_G_System_OPERATING_SYSTEM.ResourceID = SMS_R_System.ResourceId where SMS_G_System_COMPUTER_SYSTEM.Manufacturer = 'Hewlett-Packard' and SMS_G_System_OPERATING_SYSTEM.Name not like '%Server%'" />
            <collection name="Clients - Workstations - Lenovo" type="Device" comment="Lenovo workstation clients" parent="All Desktop and Server Client" folder="DeviceCollection\Inventory Hardware" ruletype="query" rule="select distinct SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceID = SMS_R_System.ResourceId inner join SMS_G_System_OPERATING_SYSTEM on SMS_G_System_OPERATING_SYSTEM.ResourceID = SMS_R_System.ResourceId where SMS_G_System_COMPUTER_SYSTEM.Manufacturer = 'Lenovo' and SMS_G_System_OPERATING_SYSTEM.Name not like '%Server%'" />
        </collections>
        <appcategories comment="">
            <appcategory name="IT" enabled="true" comment="" />
            <appcategory name="Developer" enabled="true" comment="" />
            <appcategory name="Engineering" enabled="true" comment="" />
            <appcategory name="Finance" enabled="true" comment="" />
            <appcategory name="General" enabled="true" comment="" />
            <appcategory name="Sales" enabled="true" comment="" />
        </appcategories>
        <applications comment="Applications">
            <application name="7-Zip" enabled="true" publisher="7-Zip" version="16.04" categories="General" comment="File compression utility" folder="Utilities" keywords="file,zip,utility,archive,compression">
                <deptypes comment="Deployment Types">
                    <deptype name="x64 installer" platform="64" source="\\contoso.com\software\apps\7-zip\1701\7z1701-x64.msi" options="auto" comment="64-bit installer" />
                    <deptype name="x86 installer" platform="32" source="\\contoso.com\software\apps\7-zip\1701\7z1701.msi" options="auto" comment="32-bit installer" />
                </deptypes>
            </application>
            <application name="Notepad++ 7.5" enabled="true" publisher="Notepad++" version="7.5" categories="Developer,Engineering" comment="Text and Code editor" folder="Utilities" keywords="editor,text,code,programming,script">
                <deptypes comment="Deployment Types">
                    <deptype name="x64 installer" platform="64" source="\\contoso.com\software\Apps\Notepad++\7.5\npp.7.5.installer.x64.exe" options="/s" uninstall="C:\Program Files\Notepad++\uninstall.exe" detect="registry:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++,DisplayVersion,-ge,7.5" requires="" comment="64-bit installer" />
                    <deptype name="x86 installer" platform="32" source="\\contoso.com\software\Apps\Notepad++\7.5\npp.7.5.installer.exe" options="/s" uninstall="C:\Program Files\Notepad++\uninstall.exe" detect="registry:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++,DisplayVersion,-ge,7.5" requires="" comment="32-bit installer" />
                </deptypes>
            </application>
            <application name="Microsoft RDC Manager" enabled="true" publisher="Microsoft" version="2.7" categories="IT,Developer" comment="Remote Desktop Connection Manager" folder="Microsoft" keywords="remote,rdc,rdp,desktop">
                <deptypes comment="Deployment Types">
                    <deptype name="x86 installer" platform="32" source="\\contoso.com\software\apps\Microsoft\RDCman\rdcman.msi" options="auto" comment="32-bit installer" />
                </deptypes>
            </application>
            <application name="Google Earth" enabled="true" publisher="Google" version="7.1" categories="Developer" comment="Mapping and visualization" folder="Google" keywords="google,earth,maps,model,3d">
                <deptypes comment="Deployment Types">
                    <deptype name="x86 installer" platform="32" source="\\contoso.com\software\apps\Google\Earth\GoogleEarth7.1.5.1557.msi" options="auto" comment="32-bit installer" />
                </deptypes>
            </application>
            <application name="VLC Player" enabled="true" publisher="VideoLAN" version="2.2.6" categories="General" comment="Media player" folder="Utilities" keywords="vlc,video,audio,media,player">
                <deptypes comment="Deployment Types">
                    <deptype name="x86 installer" platform="32" source="\\contoso.com\software\apps\vlc_player\vlc-2.2.6-win32.exe" options="/S" uninstall="C:\Program Files\VideoLAN\VLC\uninstall.exe /S" detect="file:\Program Files\VideoLAN\VLC\vlc.exe" comment="32-bit installer" />
                </deptypes>
            </application>
            <!--
            <application name="" enabled="true" publisher="" version="" categories="" comment="" folder="" keywords="">
                <deptypes comment="Deployment Types">
                    <deptype name="" platform="[32/64]" source="" options="[auto/other..]" comment="" />
                </deptypes>
            </application>
            -->
        </applications>
        <mtasks comment="">
            <mtask name="Backup SMS Site Server" enabled="false" options="F:\BACKUPS" />
            <mtask name="Rebuild Indexes" enabled="false" options="" />
            <mtask name="Monitor Keys" enabled="true" options="" />
            <mtask name="Delete Aged Inventory History" enabled="true" options="" />
            <mtask name="Delete Aged Status Messages" enabled="true" options="" />
            <mtask name="Delete Aged Discovery Data" enabled="true" options="" />
            <mtask name="Delete Aged Collected Files" enabled="true" options="" />
            <mtask name="Delete Aged Metering Data" enabled="true" options="" />
            <mtask name="Delete Aged Metering Summary Data" enabled="true" options="" />
            <mtask name="Summarize File Usage Metering Data" enabled="true" options="" />
            <mtask name="Summarize Monthly Usage Metering Data" enabled="true" options="" />
            <mtask name="Clear Undiscovered Clients" enabled="true" options="" />
            <mtask name="Delete Inactive Client Discovery Data" enabled="true" options="" />
            <mtask name="Delete Obsolete Client Discovery Data" enabled="true" options="" />
            <mtask name="Delete Aged Computer Association Data" enabled="true" options="" />
            <mtask name="Evaluate Provisioned AMT Computer Certificates" enabled="true" options="" />
            <mtask name="Delete Obsolete Alerts" enabled="true" options="" />
            <mtask name="Delete Aged Application Revisions" enabled="true" options="" />
            <mtask name="Delete Aged Log Data" enabled="true" options="" />
            <mtask name="Delete Aged Client Download History" enabled="true" options="" />
            <mtask name="Delete Aged Replication Data" enabled="true" options="" />
            <mtask name="Delete Aged Replication Summary Data" enabled="true" options="" />
            <mtask name="Delete Aged Application Request Data" enabled="true" options="" />
            <mtask name="Delete Aged Exchange Partnership" enabled="true" options="" />
            <mtask name="Delete Aged Device Wipe Record" enabled="true" options="" />
            <mtask name="Delete Obsolete Forest Discovery Sites And Subnets" enabled="true" options="" />
            <mtask name="Check Application Title with Inventory Information" enabled="true" options="" />
            <mtask name="Summarize Installed Software Data" enabled="true" options="" />
            <mtask name="Delete Aged Enrolled Devices" enabled="true" options="" />
            <mtask name="Delete Aged Threat Data" enabled="true" options="" />
            <mtask name="Delete Aged EP Health Status History Data" enabled="true" options="" />
            <mtask name="Delete Aged Client Operations" enabled="true" options="" />
            <mtask name="Delete Aged User Device Affinity Data" enabled="true" options="" />
            <mtask name="Delete Aged Delete Detection Data" enabled="true" options="" />
            <mtask name="Delete Aged Notification Task History" enabled="true" options="" />
            <mtask name="Delete Aged Notification Server History" enabled="true" options="" />
            <mtask name="Delete Aged Unknown Computers" enabled="true" options="" />
            <mtask name="Delete Aged Distribution Point Usage Stats" enabled="true" options="" />
            <mtask name="Delete Aged Passcode Records" enabled="true" options="" />
            <mtask name="Update Application Available Targeting" enabled="true" options="" />
            <mtask name="Delete Expired MDM Bulk Enroll Package Records" enabled="true" options="" />
            <mtask name="Delete Orphaned Client Deployment State Records" enabled="true" options="" />
            <mtask name="Delete Aged Console Connection Data" enabled="true" options="" />
            <mtask name="Delete Aged Cloud Management Gateway Traffic Data" enabled="true" options="" />
        </mtasks>
        <accounts comment="">
            <account name="CONTOSO\sccmadmin" enabled="true" password="Jj09340934" comment="For client push installations to DCs" />
            <account name="CONTOSO\cm-clientinstall" enabled="true" password="P@ssW0rd!" comment="For client push installations in general" />
        </accounts>
    </cmsite>
</configuration>
