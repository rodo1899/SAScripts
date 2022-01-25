#Finding domains in forest
# company.local
Get-ADForest | Select Domains
#Find Netbios Names. In a single-domain environment, run the following command:
Get-ADDomain | FL NetBIOSName
#In a multidomain environment, run the following command:
Get-ADDomain -identity company.local | FL NetBIOSName
#View Trusts for domain
Get-ADTrust -filter *
#finding dup sids
ntdsutil "sec acc man" "co to se dc1" "check dup sid" q q
type dupsid.log
#AD FSMO roles
Get-ADDomain | Select-Object InfrastructureMaster, RIDMaster, PDCEmulator
Get-ADForest | Select-Object DomainNamingMaster, SchemaMaster
Get-ADDomainController -Filter * |
     Select-Object Name, Domain, Forest, OperationMasterRoles |
     Where-Object {$_.OperationMasterRoles} |
     Format-Table -AutoSize
#AD FSMO roles, mopre
Get-ADForest company.local | Format-Table SchemaMaster,DomainNamingMaster
Get-ADDomain company.local | format-table PDCEmulator,RIDMaster,InfrastructureMaster
# get GC
Get-ADDomainController -Discover -Service "GlobalCatalog"#HostName    : {dc.company.local}
Get-ADDomainController -Discover
Get-ADDomainController -Discover -Domain "company.local"
# https://technet.microsoft.com/en-us/library/hh852194(v=wps.630).aspx
Get-ADDomain -Identity company.local # good info, including DomainMode: Windows2000Domain
Get-ADReplicationFailure -Target DC01.company.local #empty
Get-ADReplicationFailure -Target "company.local" -Scope Domain #empty
# Get replication failure data for all domain controllers in a forest
Get-ADReplicationFailure -Target "company.local" -Scope Forest

# Verifying the Promotion of a Domain Controller
dcdiag /test:replications /s:dc01
dcdiag /s:dc01 /test:knowsofroleholders
dcdiag /s:dc01 /test:fsmocheck
#3.12. Finding the Domain Controllers for a Domain
Get-ADDomainController -Filter { domain -eq "company.local" } | select Name
#3.13. Finding the Closest Domain Controller
Get-ADDomainController -Discover
#3.14. Finding a Domain Controller’s Site
Get-ADDomainController -Server company.local | FL Name,Site
#3.16. Finding the Services a Domain Controller Is Advertising
dcdiag /v /s:dc01 /test:advertising
#nltest /server:dc01 /dsgetdc:company.local
#3.19. Configuring a Domain Controller to Use an External Time Source - to be done later

#3.23. Determining Whether Global Catalog Promotion Is Complete
Get-ADDomainController -Server dc01 | FT Name,IsGlobalCatalog -AutoSize
#3.24. Finding the Global Catalog Servers in a Forest
Get-ADDomainController -Filter { IsGlobalCatalog -eq $true } | Select Name
#3.28. Disabling the Global Catalog Requirement for User Logon
#The following command will query the forest-level FSMO roles:
Get-ADForest | FL DomainNamingMaster,SchemaMaster
#The following command will query the domain-level FSMO roles for the specified domain:
Get-ADDomain -Identity company.local | FL InfrastructureMaster,PDCEmulator,RIDMaster
#3.32. Finding the PDC Emulator FSMO Role Owner via DNS
nslookup -type=SRV _ldap._tcp.pdc._msdcs.company.local
#4.1. Viewing the RootDSE
Get-ADRootDSE #Get-ADRootDSE : The operation returned because the timeout limit was exceeded.
#.\AdFind.exe -rootdse
#5.2. Enumerating the OUs in a Domain
dsquery ou
#.\AdFind.exe default -f "objectcategory=organizationalUnit" -dn
Get-ADOrganizationalUnit -Filter * | Select DistinguishedName
#5.3. Finding an OU
Get-ADOrganizationalUnit -SearchBase "OU=IT,OU=LA,DC=company,DC=local" -LDAPFilter {(ObjectCategory=OrganizationalUnit)} | Where {$_.Name -Match "Test"}
#5.4. Enumerating the Objects in an OU
Get-ADObject -SearchBase "OU=IT,OU=LA,DC=company,DC=local" -Filter *
#6.13. Finding Locked-Out Users
Search-ADAccount -LockedOut -UsersOnly | FT Name,LockedOut -AutoSize
#6.16. Viewing the Domain-Wide Account Lockout and Password Policies
Get-ADObject "dc=company,DC=local" -Properties * | FL minPwdLength,pwdHistoryLength,pwdProperties,lockoutThreshold
#6.20. Finding Disabled Users
Get-ADUser -Filter {Enabled -eq "False"} | FL Name
#6.21. Viewing a User’s Group Membership
Get-ADUser "joe" -Properties MemberOf | select -ExpandProperty MemberOf
#6.29. Finding Users Whose Passwords Are About to Expire
#Using a command-line interface
dsquery user -stalepwd 60 # <NumDaysSinceLastPwdChange>
#You can also use the FindExpAcc joeware tool with the following syntax:
# findexpacc -pwd -days <NumDaysUntilExpiration>
#Using PowerShell
#The following script finds users whose passwords will expire within seven days:
$Policy = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.days
$DaysUntil = 7
Get-ADUser -Filter {(Enabled -eq "True") -and (PasswordNeverExpires -eq "False")} -Properties * | 
Select Name,@{Name="Expires"; Expression={$Policy - ((Get-Date) - ($_.PasswordLastSet)).days}} | 
Where-Object {$_.Expires -gt 0 -AND $_.Expires -le $DaysUntil}
#6.33. Determining a User’s Last Logon Time
#.\AdFind.exe -b joe lastLogonTimestamp -tdc #errors
#Using lastLogonTimeStamp to find a users last logon: http://ss64.com/ps/syntax-lastlogon.html
$user = Get-ADUser "joe" -Server "dc01" -Properties lastLogonTimeStamp #empty
$user | select-object @{Name="Last Logon"; Expression={[DateTime]::FromFileTime($_.lastLogonTimestamp)}}
#Using lastLogonTimeStamp to find a computer accounts last logon:
$computer = Get-ADComputer "server01" -Properties LastLogonTimeStamp
$computer | select-object @{Name="Last Logon"; Expression={[DateTime]::FromFileTime($_.lastLogonTimestamp)}}
#6.34. Finding Users Who Have Not Logged On Recently
$DaysSince = (Get-Date).comdDays(-60)
Get-ADUser -Filter * -Properties LastLogonDate | 
Where-Object {($_.LastLogonDate -le $DaysSince) -and ($_.Enabled -eq $True) -and ($_.LastLogonDate -ne $NULL)} | 
Select Name,LastLogonDate
#6.35. Viewing and Modifying a User’s Permitted Logon Hours.  Should modify.  Later
#6.36. Viewing a User’s Managed Objects
Get-ADUser -Identity "joe" -Properties managedObjects | Select -ExpandProperty managedObjects
#6.39. Protecting a User Against Accidental Deletion
Set-ADObject -Identity "sqlservice" -ProtectedFromAccidentalDeletion $True #error: can't find
#7.2. Viewing the Permissions of a Group
Get-ADGroup "domain users" #Get GroupDN (distinguished name)
#Get-ADPermission -Identity "CN=Domain Users,CN=Users,DC=company,DC=ad" #error If you have Exchange 2007 or later management tools installed on your workstation, you can retrieve DACL and SACL information using the following Exchange cmdlet:
dsacls "CN=Domain Users,CN=Users,DC=company,DC=local" | Out-File c:\scripts\domainuserspermissions.txt
#7.3. Viewing the Direct Members of a Group
dsget group "CN=Domain admins,CN=Users,DC=company,DC=local" -members
#7.4. Viewing the Nested Members of a Group
dsget group "CN=Domain admins,CN=Users,DC=company,DC=local" -members -expand
Get-ADGroupMember -Identity "Domain Admins" -recursive | Select Name
#7.11. Resolving a Primary Group ID. You want to find the name of a user’s primary group.
Get-ADUser joe -Properties DistinguishedName #* #Get userdn
Get-ADUser -Identity "CN=joe smith,OU=IT,OU=LA,DC=company,DC=local" -Properties PrimaryGroup | Select PrimaryGroup
#8.9. Testing the Secure Channel for a Computer.  If for some reason the LSA secret and computer password become out of sync, the computer will no longer be able to authenticate in the domain.
#Using a command-line interface.  Input list of computers
#nltest /server:sql01 /sc_query:company.local
#Using PowerShell
Test-ComputerSecureChannel -Server sql01 -Verbose
#8.11. Finding Inactive or Unused Computers
#The following query will locate all inactive computers in the current forest:
dsquery computer forestroot -inactive 52
#You can also use domainroot in combination with the -d option to query a specific domain:
dsquery computer domainroot -d company.local -inactive 26
#Or you can target your query at a specific container:
#dsquery computer OU=Workstations,DC=company,DC=local #-inactive 52
#You can also use the OldCmp joeware utility to create a report of all computer accounts whose passwords are older than a certain number of days (90 by default) by using the following syntax:
#oldcmp -report #this works great!
#8.14. Finding Computers with a Particular OS
#The following example finds all computers that are running Windows Server 2012 Datacenter without regard for the service pack level:
Get-ADComputer -Filter {OperatingSystem -eq "*Server*"} | Select Name # Doesn't work
#The following example searches for all computers that are running Windows Server 2008 R2 Enterprise with Service Pack 1:
Get-ADComputer -Filter {OperatingSystem -eq "Windows Server 2008 *" -and OperatingSystemVersion -eq "6.1 (7601)"} | Select Name # Doesn't work
dsquery * "DC=company,DC=local" -scope subtree -attr "*" -filter "(&(objectcategory=computer)(operatingSystem=Windows Server *))"
#8.17. Listing All the Computer Accounts in a Domain
Get-ADComputer -Filter * | Select Name,Enabled  | Format-Table -Auto 
#8.18. Identifying a Computer Role
Get-WmiObject Win32_ComputerSystem -ComputerName dc01 -Property Name,DomainRole
#9.1. Finding the GPOs in a Domain
#You can generate a list of all GPOs in a domain using the listastallgpos.wsf script, as well as DSQuery and AdFind:
#listallgpos.wsf /domain:DC=company,DC=ad /v
#dsquery * domainroot -filter (objectcategory=grouppolicycontainer) -attr displayname
# adfind -default -f (objectcategory=grouppolicycontainer) displayname
#Using PowerShell
#To get all of the GPOs in the current domain and return their display name, run the following PowerShell command:
Get-GPO -All | Select DisplayName
#9.5. Viewing the Settings of a GPO
Get-GPOReport -Name "SQLDBA" -Path C:\scripts\SQLDBA.html -ReportType HTML
#9.23. Backing Up a GPO
Backup-Gpo -Name SQLDBA -Path C:\scripts\ -Comment "SQLDBA"
#9.25. Simulating the RSoP
#You want to simulate the Resultant Set of Policies (RSoP) based on OU, site, and security group membership. This is also referred to as Group Policy Modeling.
# Do this from GUI
#You can simulate the RSoP based on user-defined OU, site, group, and domain membership.
#This is very powerful because it allows you to create one or more GPOs, simulate
#them being applied to a user and computer, and determine whether any changes are
#necessary before deployment.
#9.26. Viewing the RSoP
#To display summary RSoP data to the screen, use the following command:
gpresult /R
#To generate an RSoP in HTML format, use the following command:
gpresult /H RSoP.htm
#9.27. Refreshing GPO Settings on a Computer
gpupdate [/target:{Computer | User}]
Invoke-GPUpdate -Computer "<Machine FQDN>"
#9.28. Restoring a Default GPO
#dcgpofix /target:Both #careful
#9.29. Creating a Fine-Grained Password Policy
#11.2. Listing Sites in a Domain
dsquery site
Get-ADReplicationSite -Filter * | Select Name
#12.1. Determining Whether Two Domain Controllers Are in Sync
repadmin /showutdvec dc01 <NamingContextDN>
repadmin /showutdvec dc01 <NamingContextDN>
Get-ADReplicationUpToDatenessVectorTable -Target DC01 #,dc1
#12.2. Viewing the Replication Status of Several Domain Controllers
repadmin /replsum
repadmin /replsum dc*
Get-ADReplicationPartnerMetadata dc01 | FL LastReplicationSuccess
#12.3. Viewing Unreplicated Changes Between Two Domain Controllers
#Run the following commands to find the differences between two domain controllers.
#Use the /statistics option to view a summary of the changes.
repadmin /showchanges dc01 <NamingContextDN>
> repadmin /showchanges <DC2Name> <NamingContextDN>
#12.5. Enabling and Disabling Replication
#You can also disable replication for an entire forest by issuing the following command:
#repadmin /options * +DISABLE_INBOUND_REPL careful, research if this is recommended at sphs
#12.9. Checking for Potential Replication Problems
dcdiag /test:replications /s:dc01
repadmin /showrepl /errorsonly
#12.12. Finding conflict Objects
Get-ADObject -Filter {Name -eq "*\0ACNF:*"}
#12.13. Finding Orphaned Objects
Get-ADObject -SearchBase "cn=LostAndFound,DC=company,DC=ad" -Filter *
#12.14. Listing the Replication Partners for a DC
Get-ADReplicationConnection -Server "dc01"
#13.3. Viewing a Server’s Zones.  These have to be run frm DNS servers
dnscmd dc01 /enumzones /s:dc01
Get-DnsServerZone /s:dc01
Get-DnsServerZone 

#14.1. Enabling SSL/TLS.  
<#
The default Windows 2000 installation of Active Directory was not as secure as it could
have been out of the box. It allowed anonymous queries to be executed, which could
take up valuable processing resources, and it did not place any requirements on encrypting
or signing traffic between clients and domain controllers. As a result, usernames,
passwords, and search results could be sent over the network in clear text. Fortunately,
beginning with Windows Server 2003, things tightened up significantly. LDAP
traffic is signed by default, and anonymous queries are disabled by default. Additionally,
Transport Layer Security (TLS), the more flexible cousin of Secure Sockets Layer (SSL),
is supported, allowing for end-to-end encryption of traffic between domain controllers
and clients.
#>
#14.10. Viewing the Effective Permissions on an Object.  Iffy, work this!
acldiag \\dc01\Backups /geteffective:"CN=Domain Users,CN=Users,DC=company,DC=local"
#The AclDiag tool is from the Windows Server 2003 Service Pack 2 32-bit Support Tools.
#It is a free download, and it installs and works successfully up to Windows Server 2012.
# 14.19. Viewing and Purging Your Kerberos Tickets
#Run the following command to list your current tickets:
klist tickets
#Run the following command to purge your tickets:
#> klist purge careful
#14.22. Viewing Access Tokens.  Not working
#tokensz /compute_tokensize /package:negotiate /target_server:host/dc01 /user:joe /domain:company.com /password:Senna2005! /dumpgroups
#15.5. Viewing DNS Server Performance Statistics
dnscmd dc01 /statistics # run from DC, pipeoutput to file
#> sticks the output into a text file. If the text file already exists it deletes the text file and recreates it with the output you've just created.
#>> appends the output to a text file. If the text file doesn't exist it creates it. if it does exist it adds the output on the end.
#You can obtain a subset of the statistics by providing a statid after the /statistics
#option. Each statistics category has an associated number (i.e., statid). For a complete
#list of categories and their statids, run the following command:
#> dnscmd /statistics /?
Get-EventLog "dc01" # run from dnsserver, pipeoutput to file
#15.6. Monitoring the Windows Time Service
#The following syntax verifies that the Windows Time Service is functioning on dc1.comatum.
#com and dc2.comatum.com:
#> w32tm /monitor /computers:dc1.comatum.com,dc2.comatum.com
#15.8. Using the STATS Control to View LDAP Query Statistics
#adfind -stats  > c:\scripts\adfindstats.txt #Lots of stuff
#15.9. Monitoring the Performance of Active Directory.  This looks like a one-off.  Use perfmon on a schedule instead.
#To retrieve a continuous counter for a performance object, use the following PowerShell command:
Get-Counter -Counter "<PerformanceObject>" -Continuous
#For example, to view the performance counter for the DS Directory Searches/sec object, run the following command:
#Get-Counter -Counter "\NTDS\DS Directory Searches/sec" -Continuous
#16.1. Backing Up the Active Directory Database
# last backup http://www.tomsitpro.com/articles/powershell-repadmin-utility,2-945.html
repadmin /showbackup company.local
#(repadmin /showbackup lab.local) | Where-Object { $_ -match '(d{4}-d{2}-d{2} d{2}:d{2}:d{2})' } | foreach
#{ [pscustomobject]@{'Last Backup' = [datetime]$matches[1]}}
wbadmin start systemstatebackup -backuptarget:"<BackupTarget>" #must write to share, not local machine
    #adds windows server backup powershell snapin
    Add-Pssnapin windows.serverbackup
    #gets date
    $date = Get-Date -Format MM.dd.yyyy
    #declares backup location and adds date
    $backdir = ("\\dc1\Backups\AD\$date")
    #makes backup directory on network share
    mkdir $backdir | out-null 
    #runs system statebackup
    wbadmin start systemstatebackup -backupTarget:"$backdir" -quiet
    #sends and email at the nd of the process
    $smtp = "exch01.company.com"  
    $from = "Domain Controller <joe@company.com>"  
    $to = "Network Admin <joe@company.com>"   
    $body = "The backup operation has been done but put try catch in PS script to send either success or failure.  Date: $date"  
    $subject = "Backup on $date"  
    #Send an Email to User   
    send-MailMessage -SmtpServer $smtp -From $from -To $to -Subject $subject -Body $body #- BodyAsHtml  
    write-host "Please review Summary" 
#16.10. Checking the DIT File’s Integrity. 
<# This recipe can be performed while the Active Directory Domain Services service is in
a stopped state; it is not necessary to reboot the DC into DSRM. To stop the AD DS
service, use services.msc, or issue the net stop command. 
May want to do this on weekend#>
#17.2. Finding the Application Partitions in a Forest. Looks like you should get always get at least forest and domain zone.
Get-ADObject -SearchBase "cn=partitions,cn=configuration,DC=company,DC=local" -Filter {(objectCategory -eq "crossref") -and (systemFlags -eq "5")}
#adfind -sc appparts+
Get-ADForest #what about this?
#17.6. Verifying Application Partitions Are Instantiated Correctly on a Server
dcdiag /test:checksdrefdom /test:verifyreplicas /test:crossrefvalidation /s:dc01
#18.6. Listing the AD LDS Instances Installed on a Computer. run these on DCs.  Empty means no instances.
#dsdbutil 
#Get-Service -Include "ADAM_*"
#AD FS.  How to determine if it is installed.
Import-Module ServerManager
Get-WindowsFeature | 
    Where-Object {$_.Installed -match “True”} | 
    Select-Object -ExpandProperty Name |
    Write-Host
#AD FS, con't. or from pshell cmd line
Get-Module
Get-Module -List
Import-Module ServerManager
Get-Module
Get-WindowsFeature | out-file C:\scripts\gtshv01WindowsFeatures.txt
# Get applications installed
Get-WmiObject Win32_Pjoeuct | Select-Object Name,Version,InstallDate | ft | out-file C:\scripts\hv01appsinstalled2.txt