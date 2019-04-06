# Orchard
JavaScript for Automation (JXA) tool to do Active Directory enumeration. Current version: 1.2

# Purpose
Live off the land for macOS. This program allows users to do Active Directory enumeration via macOS' JXA (JavaScript for Automation) code. This is the newest version of AppleScript, and thus has very poor documentation on the web. 

# Execution
Host the Orchard.js code somewhere you can access and pull it into a scripting session like so:
```JavaScript
testmac: ~$ osascript -l JavaScript -i
>> eval(ObjC.unwrap($.NSString.alloc.initWithDataEncoding($.NSData.dataWithContentsOfURL($.NSURL.URLWithString('https://raw.githubusercontent.com/its-a-feature/Orchard/master/Orchard.js')),$.NSUTF8StringEncoding)));
=> true
>> Get_CurrentDomain();
=> "test.local"
>>
```
This requires the user to already have execution on the machine. Additionally, the capitalization for JavaScript in the first command is extremely important. **All of JXA is case sensitive.** The second line does an HTTP GET request for Orchard.js and loads the functions into the current session. If you just want to execute a single line (if there's only one function you want to execute for example) you can do the following instead:
```JavaScript
testmac: ~$ osascript -l JavaScript -e "eval(ObjC.unwrap($.NSString.alloc.initWithDataEncoding($.NSData.dataWithContentsOfURL($.NSURL.URLWithString('https://raw.githubusercontent.com/its-a-feature/Orchard/master/Orchard.js')),$.NSUTF8StringEncoding))); Get_CurrentDomain();"
```

## Execution Methods
All of the commands provide an API parameter. Right now they all default to *false* and changing them to *true* won't do anything. My first goal was to get everything implemented using the native macOS binaries, then I will go back and start implementing the same techniques using the Objective-C bridge to leverage API calls.

This means that every command does the following: `currApp.doShellScript(command);`. This will execute the necessary shell commands to accomplish the function goals. **Note:** From my testing, this doesn't spawn a Terminal.app window, but I make no guarantees.

## Calling a Function
After you've imported the Orchard.js code into your current session, you can call any of the functions with a slight tweak to normal JavaScript function calls. I wanted to make the code a bit more python-esque, so I modified the calling convention. You'll see functions defined as:

`function ConvertTo_SID({API=false, object=".\\root", type="Users"} = {}) { code here; }`. This allows me to provide default values (if desired) to each function parameter as well as preventing them from being positional arguments like standard function calls. To call this function, simply do any of the following:
```JavaScript
ConvertTo_SID(); //Uses all of the default values to call the function
ConvertTo_SID({object:"TEST\\Domain Admins", type:"Groups"}); //leaves API as false, but sets object and type
ConvertTo_SID({type:"Groups",object:"TEST\\Domain Admins"}); //same as above - the order of the arguments doesn't matter
```
**Note1:** In defining a function this way, it's "name=value", but when calling the function it's "name:value". It's a little odd, I know, but you're most likely going to be just calling functions anyway.

**Note2:** Every function has a Help flag that can be used to get information about how to run the function

**Note3:** All of the APIs currently take advantage of the OpenDirectory APIs that are available through the JXA-ObjC bridge. These can be pretty powerful, but at the moment means that I can only query information within the current forest. These functions will by default query all domains within the forest. For exmaple: If I'm running on a computer, spooky$, in test.lab.local, then my queries will search the `test.lab.local` and `lab.local` domains automatically. I couldn't find a way to specify a specific server outside the forest to query though, so I cannot query a separate forest that you might have trust with.

# Functions
| Function | Version Introduced | Description| API Version is Default|
| ---------|:------------------|:-----------|:--------|
| ConvertTo_SID |1.2 |Convert Users, Groups, Or Computers to domain or local SIDs | True | 
| ConvertFrom_SID |1.2 |Convert Users, Groups, or Computers from SIDs to names | True |
| Get_PathAcl |1.0 |Get linux and mac specific ACLs on a file or folder | False |
| Get_PathXattr |1.0 |Get mac specific extended attributes on a file or folder | False |
| Get_MountedVolumes |1.0 |Get the mounted volumes on the current computer | False |
| Set_MountVolume |1.0 |Mount a remote share on the current computer | False | 
| Get_DomainUser |1.2 |List all domain users or get information on a specific user | True |
| Get_DomainComputer |1.2 |List all domain computers or get information on a specific computer | True |
| Get_LDAPSearch |1.0 |Execute a customized LDAP search query via the ldapsearch binary | False | 
| Get_DomainOU |1.0 |List all domain organizational units or get information on a specific unit | False | 
| Get_DomainSID |1.2 |Gets the SID of the domain by truncating the SID for the "Domain Admins" group | True |
| Get_DomainGroup |1.2 |List all domain groups or get information on a specific group | True | 
| Get_DomainGroupMember |1.2 |Get all the members of a specific domain group | True | 
| Get_CurrentDomain |1.2 |Get the fully qualified current domain | True | 
| Get_CurrentNETBIOSDomain |1.2 |Get the NETBIOS name of the current domain | True |
| Get_Forest |1.0 |Get the fully qualified forest name via the dsconfigad binary | False |
| Get_LocalUser | 1.2 | List all local user or get information on a specific user | True | 
| Get_LocalGroup | 1.2 | List all local groups or get information on a specific group | True |
| Get_LocalGroupMember | 1.2 | Get all members for a specific local group | True |
| Search_LocalGroup | 1.1 | Search all local groups for a specific attribute and value pair | False |
| Search_LocalUser | 1.1 | Search all local users for a specific attribute and value pair | False |
| Search_DomainGroup | 1.1 | Search all domain groups for a specific attribute and value pair | False |
| Search_DomainUser | 1.1 | Search all domain users for a specific attribute and value pair | False |
| Get_OD_ObjectClass | 1.2 | Use the OpenDirectory APIs to query the domain, similar to LDAP | True |

**Not:** The search functionality can be achieved via the Get_* functions when APIs are involved. It's only when dealing with the `dscl` binary that things have to be split into different functions.

# Sample Outputs and Common Attributes
These are some common attributes I've seen that might be useful to query:
## Users
The following are specific commands, parameters, and outputs that are useful for working with users both locally and in a domain.
### Domain
Get_DomainUser({user:"test_lab_admin",verbose:true});
```
dsAttrTypeNative:accountExpires: 0
dsAttrTypeNative:adminCount: 1
dsAttrTypeNative:badPasswordTime: 0
dsAttrTypeNative:badPwdCount: 0
dsAttrTypeNative:cn: test_lab_admin
dsAttrTypeNative:codePage: 1252
dsAttrTypeNative:countryCode: 1
dsAttrTypeNative:distinguishedName: CN=test_lab_admin,CN=Users,DC=test,DC=lab,DC=local
dsAttrTypeNative:dSCorePropagationData: 20181113040113.0Z 20181113034604.0Z 16010101000416.0Z
dsAttrTypeNative:instanceType: 4
dsAttrTypeNative:lastLogoff: 0
dsAttrTypeNative:lastLogon: 131874076789166783
dsAttrTypeNative:lastLogonTimestamp: 131865551727265342
dsAttrTypeNative:logonCount: 12
dsAttrTypeNative:logonHours:
 ffffffff ffffffff ffffffff ffffffff ffffffff ff
dsAttrTypeNative:memberOf: CN=Users,CN=Builtin,DC=test,DC=lab,DC=local CN=Administrators,CN=Builtin,DC=test,DC=lab,DC=local
dsAttrTypeNative:name: test_lab_admin
dsAttrTypeNative:objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=lab,DC=local
dsAttrTypeNative:objectClass: top person organizationalPerson user
dsAttrTypeNative:objectGUID:
 9e75d538 cc81b14e 89837304 227f63f5
dsAttrTypeNative:objectSid:
 01050000 00000005 15000000 b4d9f10f b3681f10 b16ffdbe e8030000
dsAttrTypeNative:sAMAccountName: test_lab_admin
dsAttrTypeNative:sAMAccountType: 805306368
dsAttrTypeNative:userAccountControl: 512
dsAttrTypeNative:uSNChanged: 12976
dsAttrTypeNative:uSNCreated: 8199
dsAttrTypeNative:whenChanged: 20181113040113.0Z
dsAttrTypeNative:whenCreated: 20181113034510.0Z
AppleMetaNodeLocation:
 /Active Directory/TEST/test.lab.local
AppleMetaRecordName: CN=test_lab_admin,CN=Users,DC=test,DC=lab,DC=local
GeneratedUID: 38D5759E-81CC-4EB1-8983-7304227F63F5
MCXFlags:
 <?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>has_mcx_settings</key>
	<true/>
</dict>
</plist>

MCXSettings:
 <?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>mcx_application_data</key>
	<dict>
		<key>com.apple.MCX</key>
		<dict>
			<key>Forced</key>
			<array>
				<dict>
					<key>mcx_precedence</key>
					<integer>500</integer>
					<key>mcx_preference_settings</key>
					<dict>
						<key>com.apple.cachedaccounts.CreateAtLogin</key>
						<false/>
						<key>com.apple.cachedaccounts.WarnOnCreate</key>
						<true/>
					</dict>
				</dict>
			</array>
		</dict>
		<key>com.apple.dock</key>
		<dict>
			<key>Forced</key>
			<array>
				<dict>
					<key>mcx_precedence</key>
					<integer>500</integer>
					<key>mcx_preference_settings</key>
					<dict>
						<key>AppItems-Raw</key>
						<array/>
						<key>DocItems-Raw</key>
						<array/>
						<key>MCXDockSpecialFolders-Raw</key>
						<array>
							<string>AddDockMCXOriginalNetworkHomeFolder</string>
						</array>
					</dict>
					<key>mcx_union_policy_keys</key>
					<array>
						<dict>
							<key>mcx_input_key_names</key>
							<array>
								<string>AppItems-Raw</string>
							</array>
							<key>mcx_output_key_name</key>
							<string>static-apps</string>
							<key>mcx_remove_duplicates</key>
							<true/>
						</dict>
						<dict>
							<key>mcx_input_key_names</key>
							<array>
								<string>DocItems-Raw</string>
							</array>
							<key>mcx_output_key_name</key>
							<string>static-others</string>
							<key>mcx_remove_duplicates</key>
							<true/>
						</dict>
						<dict>
							<key>mcx_input_key_names</key>
							<array>
								<string>MCXDockSpecialFolders-Raw</string>
							</array>
							<key>mcx_output_key_name</key>
							<string>MCXDockSpecialFolders</string>
							<key>mcx_remove_duplicates</key>
							<true/>
						</dict>
					</array>
				</dict>
			</array>
		</dict>
		<key>loginwindow</key>
		<dict>
			<key>Forced</key>
			<array>
				<dict>
					<key>mcx_precedence</key>
					<integer>500</integer>
					<key>mcx_preference_settings</key>
					<dict>
						<key>AutoLaunchedApplicationDictionary-raw</key>
						<array>
							<dict>
								<key>AuthenticateAsLoginUserShortName</key>
								<true/>
								<key>MCX-NetworkHomeDirectoryItem</key>
								<true/>
							</dict>
						</array>
					</dict>
					<key>mcx_union_policy_keys</key>
					<array>
						<dict>
							<key>mcx_input_key_names</key>
							<array>
								<string>AutoLaunchedApplicationDictionary-raw</string>
							</array>
							<key>mcx_output_key_name</key>
							<string>AutoLaunchedApplicationDictionary-managed</string>
							<key>mcx_remove_duplicates</key>
							<true/>
						</dict>
					</array>
				</dict>
			</array>
		</dict>
	</dict>
</dict>
</plist>

NFSHomeDirectory: /Users/test_lab_admin
Password: ********
PrimaryGroupID: 672378028
PrimaryNTDomain: TEST
RecordName: test_lab_admin
RecordType: dsRecTypeStandard:Users
SMBGroupRID: 513
SMBPasswordLastSet: 131865513517001768
SMBPrimaryGroupSID: S-1-5-21-267508148-270493875-3204280241-513
SMBSID: S-1-5-21-267508148-270493875-3204280241-1000
UniqueID: 953513374
UserShell: /bin/bash
```
Get_DomainUser({attribute:"SMBSID",verbose:true});
```
administrator    S-1-5-21-267508148-270493875-3204280241-500
defaultaccount   S-1-5-21-267508148-270493875-3204280241-503
guest            S-1-5-21-267508148-270493875-3204280241-501
krbtgt           S-1-5-21-267508148-270493875-3204280241-502
lab$             S-1-5-21-267508148-270493875-3204280241-1104
test_lab_admin   S-1-5-21-267508148-270493875-3204280241-1000
```
Search_DomainUser({attribute:"SMBGroupRID",value:513});
```
administrator		SMBGroupRID = (
    513
)
defaultaccount		SMBGroupRID = (
    513
)
test_lab_admin		SMBGroupRID = (
    513
)
krbtgt		SMBGroupRID = (
    513
)
lab$		SMBGroupRID = (
    513
)
```
### Local
Get_LocalUser({user:"itsafeature"});
```
dsAttrTypeNative:_writers_AvatarRepresentation: itsafeature
dsAttrTypeNative:_writers_hint: itsafeature
dsAttrTypeNative:_writers_jpegphoto: itsafeature
dsAttrTypeNative:_writers_passwd: itsafeature
dsAttrTypeNative:_writers_picture: itsafeature
dsAttrTypeNative:_writers_unlockOptions: itsafeature
dsAttrTypeNative:_writers_UserCertificate: itsafeature
dsAttrTypeNative:accountPolicyData:
 <?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>creationTime</key>
	<real>1540611063.535651</real>
	<key>failedLoginCount</key>
	<integer>0</integer>
	<key>failedLoginTimestamp</key>
	<integer>0</integer>
	<key>passwordLastSetTime</key>
	<real>1540611064.6205959</real>
</dict>
</plist>

dsAttrTypeNative:AvatarRepresentation: 
dsAttrTypeNative:record_daemon_version: 4850000
dsAttrTypeNative:unlockOptions: 0
AppleMetaNodeLocation: /Local/Default
AuthenticationAuthority: ;ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2,SRP-RFC5054-4096-SHA512-PBKDF2> ;Kerberosv5;;itsafeature@LKDC:SHA1.B58C56AD77898DE69AAEFD22A538D6EDDEFF8D47;LKDC:SHA1.B58C56AD77898DE69AAEFD22A538D6EDDEFF8D47; ;SecureToken;
GeneratedUID: C4713E84-50C7-419E-ABC4-766DFE170F56
JPEGPhoto:
... < LOTS of hex characters here > ...
NFSHomeDirectory: /Users/itsafeature
Password: ********
Picture:
 /Library/User Pictures/Sports/Golf.png
PrimaryGroupID: 20
RealName:
 It's a feature
RecordName: itsafeature
RecordType: dsRecTypeStandard:Users
UniqueID: 501
UserShell: /bin/bash
```
Get_LocalUser({attributes:"UserShell"});
```
_amavisd                 /usr/bin/false
_analyticsd              /usr/bin/false
_appleevents             /usr/bin/false
...
_mbsetupuser             /bin/bash
_mcxalr                  /usr/bin/false
...
_unknown                 /usr/bin/false
_update_sharing          /usr/bin/false
_usbmuxd                 /usr/bin/false
_uucp                    /usr/sbin/uucico
_warmd                   /usr/bin/false
_webauthserver           /usr/bin/false
_windowserver            /usr/bin/false
_www                     /usr/bin/false
_wwwproxy                /usr/bin/false
_xserverdocs             /usr/bin/false
daemon                   /usr/bin/false
itsafeature              /bin/bash
nobody                   /usr/bin/false
root                     /bin/sh
```
Search_LocalUsers({attribute:"UserShell", value:"/bin/bash"});
```
_mbsetupuser		UserShell = (
    "/bin/bash"
)
itsafeature		UserShell = (
    "/bin/bash"
)
```

## Groups
### Domain
Get_DomainGroup();
```
TEST\Allowed RODC Password Replication Group
TEST\Cert Publishers
TEST\Cloneable Domain Controllers
TEST\Denied RODC Password Replication Group
TEST\DnsAdmins
TEST\DnsUpdateProxy
TEST\Domain Admins
TEST\Domain Computers
TEST\Domain Controllers
TEST\Domain Guests
TEST\Domain Users
TEST\Group Policy Creator Owners
TEST\Key Admins
TEST\Protected Users
TEST\RAS and IAS Servers
TEST\Read-only Domain Controllers
```
Get_DomainGroup({attributes:"SMBSID"});
```
TEST\Allowed RODC Password Replication Group   S-1-5-21-267508148-270493875-3204280241-571
TEST\Cert Publishers                           S-1-5-21-267508148-270493875-3204280241-517
TEST\Cloneable Domain Controllers              S-1-5-21-267508148-270493875-3204280241-522
TEST\Denied RODC Password Replication Group    S-1-5-21-267508148-270493875-3204280241-572
TEST\DnsAdmins                                 S-1-5-21-267508148-270493875-3204280241-1102
TEST\DnsUpdateProxy                            S-1-5-21-267508148-270493875-3204280241-1103
TEST\Domain Admins                             S-1-5-21-267508148-270493875-3204280241-512
TEST\Domain Computers                          S-1-5-21-267508148-270493875-3204280241-515
TEST\Domain Controllers                        S-1-5-21-267508148-270493875-3204280241-516
TEST\Domain Guests                             S-1-5-21-267508148-270493875-3204280241-514
TEST\Domain Users                              S-1-5-21-267508148-270493875-3204280241-513
TEST\Group Policy Creator Owners               S-1-5-21-267508148-270493875-3204280241-520
TEST\Key Admins                                S-1-5-21-267508148-270493875-3204280241-526
TEST\Protected Users                           S-1-5-21-267508148-270493875-3204280241-525
TEST\RAS and IAS Servers                       S-1-5-21-267508148-270493875-3204280241-553
TEST\Read-only Domain Controllers              S-1-5-21-267508148-270493875-3204280241-521
```
Get_DomainGroup({group:"Domain Admins", verbose:true});
```
dsAttrTypeNative:adminCount: 1
dsAttrTypeNative:distinguishedName:
 CN=Domain Admins,CN=Users,DC=test,DC=lab,DC=local
dsAttrTypeNative:dSCorePropagationData: 20181113040113.0Z 20181113034604.0Z 16010101000416.0Z
dsAttrTypeNative:groupType: -2147483646
dsAttrTypeNative:instanceType: 4
dsAttrTypeNative:isCriticalSystemObject: TRUE
dsAttrTypeNative:member: CN=Administrator,CN=Users,DC=test,DC=lab,DC=local
dsAttrTypeNative:memberOf:
 CN=Denied RODC Password Replication Group,CN=Users,DC=test,DC=lab,DC=local
 CN=Administrators,CN=Builtin,DC=test,DC=lab,DC=local
dsAttrTypeNative:name:
 Domain Admins
dsAttrTypeNative:objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=lab,DC=local
dsAttrTypeNative:objectClass: top group
dsAttrTypeNative:objectGUID:
 b8d83cdc 107f964c 9de74bf8 7b4a07e8
dsAttrTypeNative:objectSid:
 01050000 00000005 15000000 b4d9f10f b3681f10 b16ffdbe 00020000
dsAttrTypeNative:sAMAccountName:
 Domain Admins
dsAttrTypeNative:sAMAccountType: 268435456
dsAttrTypeNative:uSNChanged: 12977
dsAttrTypeNative:uSNCreated: 12315
dsAttrTypeNative:whenChanged: 20181113040113.0Z
dsAttrTypeNative:whenCreated: 20181113034604.0Z
AppleMetaNodeLocation:
 /Active Directory/TEST/test.lab.local
AppleMetaRecordName:
 CN=Domain Admins,CN=Users,DC=test,DC=lab,DC=local
Comment:
 Designated administrators of the domain
GeneratedUID: DC3CD8B8-7F10-4C96-9DE7-4BF87B4A07E8
GroupMembership: TEST\Administrator
PrimaryGroupID: 1547491512
RealName:
 Domain Admins
RecordName:
 TEST\Domain Admins
RecordType: dsRecTypeStandard:Groups
SMBPrimaryGroupSID: S-1-5-21-267508148-270493875-3204280241-512
SMBSID: S-1-5-21-267508148-270493875-3204280241-512
```
Get_DomainGroupMember();
```
TEST\Denied RODC Password Replication Group   LAB\Enterprise Admins LAB\Schema Admins TEST\Read-only Domain Controllers TEST\Group Policy Creator Owners TEST\Domain Admins TEST\Cert Publishers TEST\Domain Controllers TEST\krbtgt
TEST\Domain Admins                            TEST\Administrator
TEST\Group Policy Creator Owners              TEST\Administrator
```
### Local
Get_LocalGroup({group:"admin", verbose:true});
```
dsAttrTypeNative:record_daemon_version: 4850000
AppleMetaNodeLocation: /Local/Default
GeneratedUID: ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000050
GroupMembers: FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000 C4713E84-50C7-419E-ABC4-766DFE170F56
GroupMembership: root itsafeature
Password: *
PrimaryGroupID: 80
RealName: Administrators
RecordName: admin BUILTIN\Administrators
RecordType: dsRecTypeStandard:Groups
SMBSID: S-1-5-32-544
```
Get_LocalGroup({group:"_appserveradm", verbose:true});
```
dsAttrTypeNative:record_daemon_version: 4850000
AppleMetaNodeLocation: /Local/Default
GeneratedUID: ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000051
GroupMembership: itsafeature
Password: *
PrimaryGroupID: 81
RealName:
 App Server Admins
RecordName: _appserveradm appserveradm
RecordType: dsRecTypeStandard:Groups
```
Get_LocalGroup({group:"admin"}); (default is verbose:false)
```
name: admin
password: *
gid: 80
users: root itsafeature 
```
Get_LocalGroupMember();
```
_analyticsd              _analyticsd
_analyticsusers          _analyticsd _networkd _timed _reportmemoryexception
_appserveradm            itsafeature
_appserverusr            itsafeature
_appstore                _appstore
_calendar                _teamsserver
_detachedsig             _locationd
_eppc                    _eppc
_fpsd                    _fpsd
_keytabusers             _calendar _jabber _postfix
_lpadmin                 itsafeature
_odchpass                _teamsserver
_postgres                _devicemgr _calendar _teamsserver _xserverdocs
_reportmemoryexception   _reportmemoryexception
_softwareupdate          _softwareupdate
_taskgated               _taskgated
_teamsserver             _devicemgr
_warmd                   _warmd
_webauthserver           _teamsserver _devicemgr
_www                     _devicemgr _teamsserver
admin                    root itsafeature
certusers                root _jabber _postfix _cyrus _calendar _dovecot
com.apple.access_ssh     itsafeature
daemon                   root
kmem                     root
mail                     _teamsserver
operator                 root
procmod                  root
procview                 root
staff                    root
sys                      root
tty                      root
wheel                    root
```
Search_LocalGroups({value:"itsafeature", attribute:"GroupMembership"});
```
admin		GroupMembership = (
    root,
    itsafeature
)
_appserveradm		GroupMembership = (
    itsafeature
)
_appserverusr		GroupMembership = (
    itsafeature
)
_lpadmin		GroupMembership = (
    itsafeature
)

```
Get_OD_ObjectClass({objectclass:"Groups", match:"Contains", value:"admin", max_results:0, query_attributes:"RecordName", return_attributes:["SMBSID", "distinguishedName"]});

Apple's OpenDirectory standard is really weird and picky. When picking a main object class to query, you can select from any of the following on the left-hand side:
```
"AFPUserAliases": 			$.kODRecordTypeAFPUserAliases,
"Aliases": 					$.kODRecordTypeAliases,
"AutoMount": 				$.kODRecordTypeAutoMount,
"AutomountMap": 			$.kODRecordTypeAutoMountMap,
"CertificateAuthorities": 	$.kODRecordTypeCertificateAuthorities,
"ComputerGroups": 			$.kODRecordTypeComputerGroups,
"ComputerLists": 			$.kODRecordTypeComputerLists,
"Computers": 				$.kODRecordTypeComputers,
"Config": 					$.kODRecordTypeConfig,
"Ethernets": 				$.kODRecordTypeEthernets,
"FileMakerServers": 		$.kODRecordTypeFileMakerServers,
"Groups": 					$.kODRecordTypeGroups,
"Hosts": 					$.kODRecordTypeHosts,
"Maps": 					$.kODRecordTypeMaps,
"Mounts": 					$.kODRecordTypeMounts,
"NetGroups": 				$.kODRecordTypeNetGroups,
"Networks": 				$.kODRecordTypeNetworks,
"OrganizationalUnit": 		$.kODRecordTypeOrganizationalUnit,
"People": 					$.kODRecordTypePeople,
"Places": 					$.kODRecordTypePlaces,
"Printers": 				$.kODRecordTypePrinters,
"Protocols": 				$.kODRecordTypeProtocols,
"RPC": 						$.kODRecordTypeRPC,
"Resources": 				$.kODRecordTypeResources,
"Services": 				$.kODRecordTypeServices,
"SharePoints": 				$.kODRecordTypeSharePoints,
"Users": 					$.kODRecordTypeUsers,
```
There are more possibilities (listed below these in the actual code), but these are the only ones I saw that were supported. You can generally think of these as the `objectclass` in a standard ldap query (i.e. `(&(objectclass=user)(name=*admin*))`.
When it comes to matching values, you can select any of the following match types:
```
"Any": 		$.kODMatchAny,
"BeginsWith": 	$.kODMatchInsensitiveBeginsWith,
"EndsWith": 	$.kODMatchInsensitiveEndsWith,
"Contains": 	$.kODMatchInsensitiveContains,
"EqualTo": 	$.kODMatchInsensitiveEqualTo,
"LessThan": 	$.kODMatchLessThan,
"GreaterThan": 	$.kODMatchGreaterThan
```
The most annoying part is the `query_attribute`. If you look in the code for this function, you'll see `var attributes_list = ` and a big list. When you want to use a match type other than `Any` with a specific field, the field **MUST** have a corresponding `$.kODAttributeType` field. If this doesn't exist, you can't match on it. For example, `accountExpires` is a valid property to return, but it cannot be used in your selection criteria because it doesn't have a `$.kODAttributeType` field. If anybody is able to help fill in the missing appropriate `kODAttributeType` values, that would be much appreciated!
