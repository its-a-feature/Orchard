//Author Cody Thomas, @its_a_feature_
ObjC.import("Foundation");
ObjC.import("stdio");
ObjC.import('OpenDirectory');
//for all of these, there is a switch to use ObjC calls vs terminal calls
currApp = Application.currentApplication();
currApp.includeStandardAdditions = true;
// Lookup tables for doing OpenDirectory queries via LDAP
var object_class = {
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

	"Configuration": 			$.kODRecordTypeConfiguration,
	"FTPServer": 				$.kODRecordTypeFTPServer,
	"LocalServices": 			$.kODRecordTypeHostServices,
	"LDAPServer": 				$.kODRecordTypeLDAPServer,
	"NFS": 						$.kODRecordTypeNFS,
	"Machines": 				$.kODRecordTypesMachines,
	"PrintService": 			$.kODRecordTypePrintService,
	"UserAuthenticationData": 	$.kODRecordTypeUserAuthenticationData,
	"AFPServer": 				$.kODRecordTypeAFPServer,
	"Augments": 				$.kODRecordTypeAugments,
	"HostServices": 			$.kODRecordTypeHostServices,
	"SMBServer": 				$.kODRecordTypeSMBServer,
	"Servers": 					$.kODRecordTypeServer,
	"WebServer": 				$.kODRecordTypeWebServer,
	"AutoServerSetup": 			$.kODRecordTypeAutoServerSetup,
	"Bootp": 					$.kODRecordTypeBootp,
	"Locations": 				$.kODRecordTypeLocations,
	"NetDomains":  				$.kODRecordTypeNetDomains,
	"PrintServiceUser": 		$.kODRecordTypePrintServiceUser,
	"All": 						$.kODRecordTypeRecordTypes,
	"AccessControls":			$.kODRecordTypeAccessControls,	
}
var match_type = {
	"Any": 			$.kODMatchAny,
	"BeginsWith": 	$.kODMatchInsensitiveBeginsWith,
	"EndsWith": 	$.kODMatchInsensitiveEndsWith,
	"Contains": 	$.kODMatchInsensitiveContains,
	"EqualTo": 		$.kODMatchInsensitiveEqualTo,
	"LessThan": 	$.kODMatchLessThan,
	"GreaterThan": 	$.kODMatchGreaterThan
}
var attributes_list = {
	"all": 							["All",								$.kODAttributeTypeAllAttributes,		"dsAttributesAll"],
	"*": 							["*",								$.kODAttributeTypeAllAttributes,		"dsAttributesAll"],
	"accountpolicydata": 			["accountPolicyData",				""	,									"dsAttrTypeNative:"],
	"accountexpires": 				["accountExpires",				 	""	,									"dsAttrTypeNative:"],
	"admincount": 					["adminCount",						""	,									"dsAttrTypeNative:"],
	"adminlimits": 					["AdminLimits", 					$.kODAttributeTypeAdminLimits,			"dsAttrTypeStandard:"],
	"altsecurityidentities": 		["AltSecurityIdentities",			$.kODAttributeTypeAltSecurityIdentities,"dsAttrTypeStandard:"], //x509
	"afp_guestaccess": 				["afp_guestaccess",					""	,									"dsAttrTypeNative:"],
	"afp_name": 					["afp_name",					 	""	,									"dsAttrTypeNative:"],
	"afp_shared":  					["afp_shared",						""	,									"dsAttrTypeNative:"],
	"authenticationhint": 			["AuthenticationHint", 				$.kODAttributeTypeAuthenticationHint,	"dsAttrtypeStandard:"],
	"badpasswordtime": 				["badPasswordTime",					""	,									"dsAttrTypeNative:"],
	"badpwdcount": 					["badPwdCount",						""	,									"dsAttrTypeNative:"],
	"bootfile": 					["BootFile", 						""	,									"dsAttrTypeStandard:"],
	"bootparams": 					["BootParams", 						$.kODAttributeTypeBootParams,			"dsAttrTypeStandard:"],
	"cacertificiate": 				["CACertificate", 					$.kODAttributeTypeCACertificate,		"dsAttrTypeStandard:"],
	"capacity": 					["Capacity", 						$.kODAttributeTypeCapacity,				"dsAttrTypeStandard:"],
	"category": 					["Category", 						""	,									"dsAttrtypeStandard:"],
	"certificaterevocationlist": 	["CertificateRevocationList", 		$.kODAttributeTypeCertificateRevocationList,"dsAttrTypeStandard:"],
	"codepage": 					["codePage",						""	,									"dsAttrTypeNative:"],
	"comment": 						["Comment",							$.kODAttributeTypeComment, 				"dsAttrTypeStandard:"],
	"contactguid": 					["ContactGUID",						$.kODAttributeTypeContactGUID,			"dsAttrtypeStandard:"],
	"countrycode": 					["countryCode",						""	,									"dsAttrTypeNative:"],
	"creationtimestamp": 			["CreationTimestamp",				$.kODAttributeTypeCreationTimestamp,	"dsAttrTypeStandard:"],
	"crosscertificatepair": 		["CrossCertificatePair", 			$.kODAttributeTypeCrossCertificatePair, "dsAttrTypeStandard:"],
	"cn": 							["cn",								""	,									"dsAttrTypeNative:"],
	"fullname": 					["FullName",						$.kODAttributeTypeFullName,				""], //have to use realname
	"displayname": 					["displayName",						""	,									"dsAttrTypeNative:"],
	"distinguishedname": 			["distinguishedName",				""	,									"dsAttrTypeNative:"],
	"directory_path": 				["directory_path",					""	,									"dsAttrTypeNative:"],
	"dnsdomain": 					["DNSDomain",						$.kODAttributeTypeDNSDomain,			"dsAttrTypeStandard:"],
	"dnsnameserver": 				["DNSNameServer",					$.kODAttributeTypeDNSNameServer,		"dsAttrTypeStandard:"],
	"dscorepropagationdata": 		["dsCorePropagationData",			""	,									"dsAttrTypeNative:"],
	"emailaddress": 				["EMailAddress", 					$.kODAttributeTypeEMailAddress,			"dsAttrTypeStandard:"],
	"enetaddress": 					["ENetAddress", 					$.kODAttributeTypeENetAddress,			"dsAttrTypeNative:"],
	"expire": 						["Expire", 							$.kODAttributeTypeExpire,				"dsAttrTypeStandard:"],
	"firstname": 					["FirstName",						$.kODAttributeTypeFirstName,			"dsAttrTypeStandard:"],
	"ftp_name": 					["ftp_name",						""	,									"dsAttrTypeNative:"],
	"generateduid": 				["GeneratedUID",					$.kODAttributeTypeGUID, 				"dsAttrTypeStandard:"],
	"grouptype": 					["groupType",						""	,									"dsAttrTypeNative:"],
	"hardwareuuid": 				["HardwareUUID", 					$.kODAttributeTypeHardwareUUID,			"dsAttrTypeStandard:"],
	"heimdalsrpkey": 				["HeimdalSRPKey", 					""	,					"dsAttrTypeNative:"],
	"ishidden": 					["IsHidden",						""	,									"dsAttrTypeNative:"],
	"instancetype": 				["instanceType",					""	,									"dsAttrTypeNative:"],
	"iscriticalsystemobject": 		["isCriticalSystemObject",			""	,									"dsAttrTypeNative:"],
	"jobtitle": 					["JobTitle", 						$.kODAttributeTypeJobTitle,				"dsAttrTypeStandard:"],
	"kerberoskeys": 			["KerberosKeys", 				""	,							"dsAttrTypeNative:"],
	"kerberosservices": 			["KerberosServices",				$.kODAttributeTypeKerberosServices, 	"dsAttrTypeStandard:"], //host, afpserver, cifs, vnc, etc
	"lastname": 					["LastName",						$.kODAttributeTypeLastName,				"dsAttrTypeStandard:"],
	"lastlogoff": 					["lastLogoff",						""	,									"dsAttrTypeNative:"],
	"lastlogon": 					["lastLogon",					 	""	,									"dsAttrTypeNative:"],
	"lastlogontimestamp": 			["lastLogonTimestamp",				""	,									"dsAttrTypeNative:"],
	"localpolicyglags": 			["localPolicyFlags",				""	,									"dsAttrTypeNative:"],
	"logoncount": 					["logonCount",						""	,									"dsAttrTypeNative:"],
	"logonhours": 					["logonHours",					 	""	,									"dsAttrTypeNative:"],
	"ldapsearchbasesuffix": 		["LDAPSearchBaseSuffix",			$.kODAttributeTypeLDAPSearchBaseSuffix,	"dsAttrtypeStandard:"],
	"automountmap": 				["AutomountMap",					$.kODAttributeTypeMetaAutomountMap,		"dsAttrTypeStandard:"],
	"applemetanodelocation":  		["AppleMetaNodeLocation",			$.kODAttributeTypeMetaNodeLocation,		"dsAttrTypeStandard:"],
	"applemetarecordname": 			["AppleMetaRecordName",				""	,									"dsAttrTypeStandard:"],
	"machineserves": 				["MachineServes", 					""	,									"dsAttrTypeStandard:"],
	"mcxflags": 					["MCXFlags",						$.kODAttributeTypeMCXFlags,				"dsAttrTypeStandard:"],
	"mcxsettings": 					["MCXSettings",						$.kODAttributeTypeMCXSettings,			"dsAttrTypeStandard:"],
	"middlename": 					["MiddleName",						$.kODAttributeTypeMiddleName,			"dsAttrTypeStandard:"],
	"member": 						["member",							""	,									"dsAttrTypeNative:"],
	"memberof": 					["memberOf",						""	,									"dsAttrTypeNative:"],
	"members": 						["members",							""	,									"dsAttrTypeNative:"],
	"msdfsr-computerreferencebl": 	["msDFSR-ComputerReferenceBL",	 	""	,									"dsAttrTypeNative:"],
	"msds-generationid": 			["msDS-GenerationId",				""	,									"dsAttrTypeNative:"],
	"msds-supportedencryptiontypes":["msDS-SupportedEncryptionTypes",	""	,									"dsAttrTypeNative:"],
	"modificationtimestamp": 		["ModificationTimestamp",			$.kODAttributeTypeModificationTimestamp,"dsAttrTypeStandard:"],
	"name": 						["name",						 	""	,									"dsAttrTypeNative:"],
	"networkaddress": 				["networkAddress",				 	""	,									"dsAttrTypeNative:"],
	"networkview": 					["NetworkView", 					""	,									"dsAttrTypeStandard:"],
	"nfshomedirectory": 			["NFSHomeDirectory",				$.kODAttributeTypeNFSHomeDirectory, 	"dsAttrTypeStandard:"],
	"nodesaslrealm": 				["NodeSASLRealm", 					$.kODAttributeTypeNodeSASLRealm,		"dsAttrTypeStandard:"],
	"note": 						["Note",							$.kODAttributeTypeNote, 				"dsAttrTypeStandard:"],//says this is for last name attribute???
	"objectclass": 					["objectClass",						""	,									"dsAttrTypeNative:"],
	"objectcategory": 				["objectCategory",					""	,									"dsAttrTypeNative:"],
	"objectguid": 					["objectGUID",						""	,									"dsAttrTypeNative:"],
	"objectsid": 					["objectSid",						""	,									"dsAttrTypeNative:"], 
	"olcdatabase": 					["OLCDatabase", 					""	,									"dsAttrTypeStandard:"],
	"olcdatabaseindex": 			["OLCDatabaseIndex", 				""	,									"dsAttrTypeStandard:"],
	"olcsyncrepl": 					["OLCSyncRepl", 					""	,									"dsAttrTypeStandard:"],
	"operatingsystem": 				["operatingSystem",					$.kODAttributeTypeOperatingSystem,		"dsAttrTypeNative:"],
	"operatingsystemversion": 		["operatingSystemVersion",			$.kODAttributeTypeOperatingSystemVersion,"dsAttrTypeNative:"],
	"owner": 						["Owner",							$.kODAttributeTypeOwner,				"dsAttrTypeStandard:"],
	"ownerguid": 					["OwnerGUID",						$.kODAttributeTypeOwnerGUID,			"dsAttrTypeStandard:"],
	"password": 					["Password",						$.kODAttributeTypePassword, 			"dsAttrTypeStandard:"],
	"passwordplus": 				["PasswordPlus",					$.kODAttributeTypePasswordPlus, 		"dsAttrTypeStandard:"],//indicates authentication redirection
	"passwordpolicyoptions": 		["PasswordPolicyOptions",			$.kODAttributeTypePasswordPolicyOptions,"dsAttrTypeStandard:"],
	"passwordserverlist": 			["PasswordServerList",				$.kODAttributeTypePasswordServerList,	"dsAttrTypeStandard:"],
	"passwordserverlocation": 		["PasswordServerLocation",			$.kODAttributeTypePasswordServerLocation,"dsAttrTypeStandard:"],
	"port": 						["Port",							$.kODAttributeTypePort, 				"dsAttrTypeStandard:"],//which port a service is on
	"presetuserisadmin": 			["PresetUserIsAdmin", 				$.kODAttributeTypePresetUserIsAdmin,	"dsAttrTypeStandard:"],
	"primarycomputerguid": 			["PrimaryComputerGUID",				$.kODAttributeTypePrimaryComputerGUID, 	"dsAttrTypeStandard:"],
	"primarycomputerlist": 			["PrimaryComputerList", 			$.kODAttributeTypePrimaryComputerList,	"dsAttrTypeStandard:"],
	"primarygroupid": 				["PrimaryGroupID",					$.kODAttributeTypePrimaryGroupID, 		"dsAttrTypeStandard:"],
	"profiles": 					["Profiles", 						$.kODAttributeTypeProfiles,				"dsAttrTypeStandard:"],
	"profilestimestamp": 			["ProfilesTimestamp", 				$.kODAttributeTypeProfilesTimestamp,	"dsAttrTypeStandard:"],
	"realname": 					["RealName",						$.kODAttributeTypeFullName,				"dsAttrTypeStandard:"], //Yes, fullname maps to realname because... apple
	"realuserid": 					["RealUserID",						$.kODAttributeTypeRealUserID,			"dsAttrTypeStandard:"],
	"relativednprefix": 			["RelativeDNPrefix",				$.kODAttributeTypeRelativeDNPrefix, 	"dsAttrTypeStandard:"],//relative distinguished name,
	"ridsetreferences": 			["rIDSetReferences",				""	,									"dsAttrTypeNative:"],
	"samaccountname": 				["sAMAccountName",					""	,									"dsAttrTypeNative:"],
	"samaccounttype": 				["sAMAccountType",					""	,									"dsAttrTypeNative:"],
	"serverreferencebl": 			["serverReferenceBL",				""	,									"dsAttrTypeNative:"],
	"serviceprincipalname": 		["servicePrincipalName",			""	,									"dsAttrTypeNative:"],
	"shadowhashdata": 			["ShadowHashData", 				""	,									"dsAttrTypeNative:"],
	"smbacctflags": 				["SMBAccountFlags",					$.kODAttributeTypeSMBAcctFlags, 		"dsAttrTypeStandard:"],//account control flag
	"smbgrouprid": 					["SMBGroupRID",						$.kODAttributeTypeSMBGroupRID,			"dsAttrTypeStandard:"], //define PDC SMB interaction with DirectoryService
	"smbhome": 						["SMBHome",							$.kODAttributeTypeSMBHome, 				"dsAttrTypeStandard:"],//UNC address of a windows home directory mount point
	"smbhomedrive": 				["SMBHomeDrive",					$.kODAttributeTypeSMBHomeDrive,			"dsAttrTypeStandard:"],
	"smbprimarygroupsid": 			["SMBPrimaryGroupSID",				$.kODAttributeTypeSMBPrimaryGroupSID,	"dsAttrTypeStandard:"],
	"smbpasswordlastset": 			["SMBPasswordLastSet",				$.kODAttributeTypeSMBPWDLastSet, 		"dsAttrTypeStandard:"],// used in SMB interaction
	"smbprofilepath": 				["SMBProfilePath",					$.kODAttributeTypeSMBProfilePath, 		"dsAttrTypeStandard:"],//defines desktop management info
	"smbrid": 						["SMBRID",							$.kODAttributeTypeSMBRID, 				"dsAttrTypeStandard:"], //used in SMB interaction
	"smbscriptpath": 				["SMBScriptPath",					$.kODAttributeTypeSMBScriptPath, 		"dsAttrTypeStandard:"],//define SMB login script path
	"smbsid": 						["SMBSID",							$.kODAttributeTypeSMBSID, 				"dsAttrTypeStandard:"], //define SMB Security ID
	"smbuserworkstations": 			["SMBUserWorkstations",				$.kODAttributeTypeSMBUserWorkstations, 	"dsAttrTypeStandard:"],//list of workstations a user can log in from
	"smblogofftime": 				["SMBLogoffTime",					$.kODAttributeTypeSMBLogoffTime,		"dsAttrTypeStandard:"],
	"smblogontime": 				["SMBLogonTime",					$.kODAttributeTypeSMBLogonTime,			"dsAttrTypeStandard:"],
	"smb_createmask": 				["smb_createmask",					""	,									"dsAttrTypeNative:"],
	"smb_directorymask": 			["smb_directorymask",				""	,									"dsAttrTypeNative:"],
	"smb_guestaccess": 				["smb_guestaccess",					""	,									"dsAttrTypeNative:"],
	"smb_name": 					["smb_name",						""	,									"dsAttrTypeNative:"],
	"smb_shared":  					["smb_shared",						""	,									"dsAttrTypeNative:"],
	"servicetype": 					["ServiceType",						$.kODAttributeTypeServiceType, 			"dsAttrTypeStandard:"],//define SMB login script path
	"serviceslocator": 				["ServicesLocator", 				$.kODAttributeTypeServicesLocator,		"dsAttrTypeStandard:"],
	"setupadvertising": 			["SetupAssistantAdvertising",		$.kODAttributeTypeSetupAdvertising, 	"dsAttrTypeStandard:"],//raw service type of a service, ex: http or https for kODRecordTypeWebServer
	"sharepoint_account_uuid": 		["sharepoint_account_uuid",			""	,									"dsAttrTypeNative:"],
	"sharepoint_group_id": 			["sharepoint_group_id",				""	,									"dsAttrTypeNative:"],
	"showinadvancedviewonly": 		["showInAdvancedViewOnly",			""	,									"dsAttrTypeNative:"],
	"uniqueid": 					["UniqueID",						$.kODAttributeTypeUniqueID, 			"dsAttrTypeStandard:"], //user's 32bit ID in legacy manner
	"unlockoptions": 				["unlockOptions",					""	,									"dsAttrTypeNative:"],
	"url": 							["URL", 							$.kODAttributeTypeURL,					"dsAttrTypeStandard:"],
	"users": 						["users",						 	""	,									"dsAttrTypeNative:"],
	"usnchanged": 					["uSNChanged",						""	,									"dsAttrTypeNative:"],
	"usncreated": 					["uSNCreated",						""	,									"dsAttrTypeNative:"], 
	"useraccountcontrol": 			["userAccountControl",				""	,									"dsAttrTypeNative:"],
	"usercertificate": 				["UserCertificate",					$.kODAttributeTypeUserCertificate,		"dsAttrTypeStandard:"],
	"userpkcs12data": 				["UserPKCS12Data",					$.kODAttributeTypeUserPKCS12Data,		"dsAttrTypeStandard:"],
	"usershell": 					["UserShell",						$.kODAttributeTypeUserShell, 			"dsAttrTypeStandard:"],
	"usersmimecertificate": 		["UserSMIMECertificate",			$.kODAttributeTypeUserSMIMECertificate,	"dsAttrTypeStandard:"],
	"webloguri": 					["WeblogURI",						$.kODAttributeTypeWeblogURI, 			"dsAttrTypeStandard:"],//URI of a user's weblog
	"whenchanged": 					["whenChanged",						""	,									"dsAttrTypeNative:"],
	"whencreated": 					["whenCreated",						""	,									"dsAttrTypeNative:"],
	"_writers_usercertificate": 	["_writers_UserCertificate",		""	,									"dsAttrTypeNative:"],
	"_writers_hint": 				["_writers_hint",					""	,									"dsAttrTypeNative:"],
	"_writers_passwd": 				["_writers_passwd",				 	""	,									"dsAttrTypeNative:"],
	"_writers_unlockoptions": 		["_writers_unlockOptions",			""	,									"dsAttrTypeNative:"],
	"_writers_usercertificate": 	["_writers_UserCertificate",		""	,									"dsAttrTypeNative:"],
	"xmlplist": 					["XMLPlist",						$.kODAttributeTypeXMLPlist, 			"dsAttrTypeStandard:"],//specify an XML Property List
	"protocolnumber": 				["ProtocolNumber",					$.kODAttributeTypeProtocolNumber,		"dsAttrTypeStandard:"],
	"rpcnumber": 					["RPCNumber",						$.kODAttributeTypeRPCNumber,			"dsAttrTypeStandard:"],
	"networknumber": 				["NetworkNumber",					$.kODAttributeTypeNetworkNumber,		"dsAttrTypeStandard:"],
	"accesscontrolentry": 			["AccessControlEntry",				$.kODAttributeTypeAccessControlEntry,	"dsAttrTypeStandard:"],
	"authenticationauthority": 		["AuthenticationAuthority",			$.kODAttributeTypeAuthenticationAuthority, "dsAttrTypeStandard:"], //specify mechanism used to verify or set a user's password
	"authorityrevocationlist": 		["AuthorityRevocationList", 		$.kODAttributeTypeAuthorityRevocationList,	"dsAttrTypeStandard:"],
	"automountinformation": 		["AutomountInformation",			$.kODAttributeTypeAutomountInformation,	"dsAttrTypeStandard:"],
	"computers": 					["Computers",						$.kODAttributeTypeComputers,			"dsAttrTypeStandard:"],
	"dnsname": 						["DNSName",							$.kODAttributeTypeDNSName,				"dsAttrTypeStandard:"],
	"group": 						["Group",							$.kODAttributeTypeGroup, 				"dsAttrTypeStandard:"],//store a list of groups
	"groupmembers": 				["GroupMembers",					$.kODAttributeTypeGroupMembers, 		"dsAttrTypeStandard:"], //specify GUID values of members of a group that are not groups
	"groupmembership": 				["GroupMembership",					$.kODAttributeTypeGroupMembership, 		"dsAttrTypeStandard:"], //specify list of users that belong to a given group
	"groupservices": 				["GroupServices",					$.kODAttributeTypeGroupServices, 		"dsAttrTypeStandard:"],//XML plist to define group's services,
	"homedirectory": 				["HomeDirectory",					$.kODAttributeTypeHomeDirectory,		"dsAttrTypeStandard:"],
	"imhandle": 					["IMHandle",						$.kODAttributeTypeIMHandle, 			"dsAttrTypeStandard:"],//user's instant messaging handles
	"ipaddress": 					["IPAddress",						$.kODAttributeTypeIPAddress, 			"dsAttrTypeStandard:"],
	"ipv6address": 					["IPv6Address",						$.kODAttributeTypeIPv6Address, 			"dsAttrTypeStandard:"],
	"kdcauthkey": 					["KDCAuthKey",						$.kODAttributeTypeKDCAuthKey, 			"dsAttrTypeStandard:"],//store a KDC master key
	"kdcconfigdata": 				["KDCConfigData", 					$.kODAttributeTypeKDCConfigData,		"dsAttrTypeStandard:"],
	"keywords": 					["Keywords", 						$.kODAttributeTypeKeywords,				"dsAttrTypeStandard:"],
	"ldapreadreplicas": 			["LDAPReadReplicas",				$.kODAttributeTypeLDAPReadReplicas, 	"dsAttrTypeStandard:"],//list of LDAP server URLs that can be used to read directory data
	"ldapwritereplicas": 			["LDAPWriteReplicas",				$.kODAttributeTypeLDAPWriteReplicas,	"dsAttrTypeStandard:"],
	"linkedidentity": 				["LinkedIdentity",					"" ,  									"dsAttrTypeNative:"],
	"localerelay": 					["LocaleRelay", 					$.kODAttributeTypeLocaleRelay,			"dsAttrTypeStandard:"],
	"localesubnets": 				["LocaleSubnets", 					$.kODAttributeTypeLocaleSubnets,		"dsAttrTypeStandard:"],
	"nestedgroups": 				["NestedGroups",					$.kODAttributeTypeNestedGroups,			"dsAttrTypeStandard:"], //specify list of nested group GUID values in a group attribute
	"netgroups": 					["NetGroups",						$.kODAttributeTypeNetGroups, 			"dsAttrTypeStandard:"],//specify a list of net groups that a user or host record is a member of
	"nickname": 					["NickName",						$.kODAttributeTypeNickName,				"dsAttrTypeStandard:"],
	"organizationinfo": 			["OrganizationInfo",				$.kODAttributeTypeOrganizationInfo,		"dsAttrTypeStandard:"],
	"organizationname": 			["OrganizationName",				$.kODAttributeTypeOrganizationName,		"dsAttrTypeStandard:"],
	"pgppublickey": 				["PGPPublicKey",					$.kODAttributeTypePGPPublicKey,			"dsAttrTypeStandard:"],
	"protocols": 					["Protocols",						$.kODAttributeTypeProtocols, 			"dsAttrTypeStandard:"],
	"recordname": 					["RecordName",						$.kODAttributeTypeRecordName, 			"dsAttrTypeStandard:"],
	"record_daemon_version": 		["record_daemon_version",			""	,									"dsAttrTypeNative:"],
	"relationships": 				["Relationships",					$.kODAttributeTypeRelationships,		"dsAttrTypeStandard:"],
	"resourceinfo": 				["ResourceInfo",					$.kODAttributeTypeResourceInfo,			"dsAttrTypeStandard:"],
	"resourcetype": 				["ResourceType",					$.kODAttributeTypeResourceType,			"dsAttrTypeStandard:"],
	"authcredential": 				["AuthCredential",					$.kODAttributeTypeAuthCredential, 		"dsAttrTypeStandard:"],//stores an authentication credential used to authenticate to a directory
	"daterecordcreated": 			["DateRecordCreated",				$.kODAttributeTypeDateRecordCreated,	"dsAttrTypeStandard:"],
	"kerberosflags": 				["KerberosFlags",					""	,									"dsAttrTypeNative:"],
	"kerberosrealm": 				["KerberosRealm",					$.kODAttributeTypeKerberosRealm,		"dsAttrTypeStandard:"],
	"ntdomaincomputeraccount": 		["NTDomainComputerAccount",			$.kODAttributeTypeNTDomainComputerAccount, "dsAttrTypeStandard:"],//support kerberos SMB server services
	"primaryntdomain": 				["PrimaryNTDomain",					$.kODAttributeTypePrimaryNTDomain,		"dsAttrTypeStandard:"],
	"pwdagingpolicy": 				["PwdAgingPolicy",					$.kODAttributeTypePwdAgingPolicy, 		"dsAttrTypeStandard:"],//record's password aging policy
	"readonlynode": 				["ReadOnlyNode",					$.kODAttributeTypeReadOnlyNode,			"dsAttrTypeStandard:"],
	"authmethod": 					["AuthMethod",						$.kODAttributeTypeAuthMethod, 			"dsAttrTypeStandard:"],//specify a record's authentication method
	"recordtype": 					["RecordType",						$.kODAttributeTypeRecordType, 			"dsAttrTypeStandard:"], //specify type of a record or directory node
	"advertisedservices": 			["AdvertisedServices",				$.kODAttributeTypeAdvertisedServices, 	"dsAttrTypeStandard:"],//specify (Bounjour) advertised services
	"networkinterfaces": 			["NetworkInterfaces",				$.kODAttributeTypeNetworkInterfaces,	"dsAttrTypeStandard:"],
	"primarylocale": 				["PrimaryLocale",					$.kODAttributeTypePrimaryLocale,		"dsAttrTypeStandard:"]
}
var node_list = {
	"network": 			$.kODNodeTypeNetwork,
	"local": 			$.kODNodeTypeLocalNodes,
	"config": 			$.kODNodeTypeConfigure,
	"contacts": 		$.kODNodeTypeContacts
}
// helper functions to actually do the OD queries and return results
function Get_OD_ObjectClass({objectclass="Users", match="Any", value=null, max_results=0, query_attributes="All", return_attributes=[null], nodetype='network'} = {}){
	//gets all attributes for all local users
	var session = Ref();
	var node = Ref();
	var query = Ref();
	session = $.ODSession.defaultSession;
	var fixed_return_attributes = [];
	for(var i in return_attributes){
		if(return_attributes[i] != null){
			ret_attr_lower = return_attributes[i].toLowerCase();
			if(attributes_list.hasOwnProperty(ret_attr_lower)){
				if(attributes_list[ret_attr_lower][2] != ""){
					fixed_return_attributes.push(attributes_list[ret_attr_lower][2] + attributes_list[ret_attr_lower][0]);
				}else{
					fixed_return_attributes.push(attributes_list[ret_attr_lower][1]);
				}
			}
		}else{
			fixed_return_attributes.push(null);
		}
	}
	if(fixed_return_attributes.length == 1){
		fixed_return_attributes = fixed_return_attributes[0];
	}
	if(attributes_list.hasOwnProperty(query_attributes.toLowerCase())){
		query_attr_lower = query_attributes.toLowerCase();
		query_attributes = attributes_list[query_attr_lower][1];
	}
	else{
		console.log("query attribute " + query_attributes + " not found");
		return;
	}
	node = $.ODNode.nodeWithSessionTypeError(session, node_list[nodetype], null);
	//console.log("about to print subnode names\n");
	//console.log(ObjC.deepUnwrap($.ODNodeCopySubnodeNames(node, $())));
	//console.log("about to print supported attributes\n");
	//console.log(JSON.stringify([ObjC.deepUnwrap($.ODNodeCopySupportedAttributes(node, object_class[objectclass], $()))], null, 2));
	//https://developer.apple.com/documentation/opendirectory/odquery/1391709-querywithnode?language=objc
	//console.log("about to print supported record types\n");
	//console.log(JSON.stringify([ObjC.deepUnwrap($.ODNodeCopySupportedRecordTypes(node, $()))], null, 2));
	query = $.ODQuery.queryWithNodeForRecordTypesAttributeMatchTypeQueryValuesReturnAttributesMaximumResultsError(
	node, 
	object_class[objectclass], //(objectclass) https://developer.apple.com/documentation/opendirectory/opendirectory_functions/record_types?language=objc
	//$.kODAttributeTypeAllAttributes, //https://developer.apple.com/documentation/opendirectory/odattributetype?language=objc
	query_attributes,
	match_type[match], //(operator - equals, beginsWith, contains, etc) https://developer.apple.com/documentation/opendirectory/opendirectory_functions/match_types?language=objc
	value, // input query (like admin)
	//return_attributes, // properties to return
	fixed_return_attributes,
	max_results, //maximum number of results, 0=all
	null); //error
	var results = query.resultsAllowingPartialError(false, null);
	//results;
	//console.log(results.count);
	var output = {};
	output[objectclass] = {};
	for(var i = 0; i < results.count; i++){
		var error = Ref();
		var attributes = results.objectAtIndex(i).recordDetailsForAttributesError($(),error);
		var keys = attributes.allKeys;
		output[objectclass][i] = {};
		for(var j = 0; j < keys.count; j++){
			var key = ObjC.unwrap(keys.objectAtIndex(j));
			var val = ObjC.deepUnwrap(attributes.valueForKey(keys.objectAtIndex(j)));
			output[objectclass][i][key] = val;
		}
	}
	return output;
}
function Get_OD_Node_Configuration({node="all"} = {}){
	var session = $.ODSession.defaultSession;
	var names = session.nodeNamesAndReturnError($());
	names = ObjC.deepUnwrap(names);
	configuration = {};
	for(var i in names){
		//console.log(names[i]);
		var config = session.configurationForNodename(names[i]);
		configuration[names[i]] = {};
		configuration[names[i]]['nodeName'] = ObjC.deepUnwrap(config.nodeName);
		configuration[names[i]]['trustAccount'] = ObjC.deepUnwrap(config.trustAccount);
		configuration[names[i]]['trustKerberosPrincipal'] = ObjC.deepUnwrap(config.trustKerberosPrincipal);
		configuration[names[i]]['trustMetaAccount'] = ObjC.deepUnwrap(config.trustMetaAccount);
		configuration[names[i]]['trustType'] = ObjC.deepUnwrap(config.trustType);
		configuration[names[i]]['trustUsesKerberosKeytab'] = ObjC.deepUnwrap(config.trustUsesKerberosKeytab);
		configuration[names[i]]['trustUsesMutualAuthentication'] = ObjC.deepUnwrap(config.trustUsesMutualAuthentication);
		configuration[names[i]]['trustUsesSystemKeychain'] = ObjC.deepUnwrap(config.trustUsesSystemKeychain);
		//configuration[names[i]]['defaultMappings'] = ObjC.deepUnwrap(config.defaultModuleEntries);
		//configuration[names[i]]['authenticationModuleEntries'] = config.authenticationModuleEntries;
		configuration[names[i]]['virtualSubnodes'] = ObjC.deepUnwrap(config.virtualSubnodes);
		configuration[names[i]]['templateName'] = ObjC.deepUnwrap(config.templateName);
		configuration[names[i]]['preferredDestinationHostName'] = ObjC.deepUnwrap(config.preferredDestinationHostName);
		configuration[names[i]]['preferredDestinationHostPort'] = ObjC.deepUnwrap(config.preferredDestinationHostPort);
		//[names[i]]['discoveryModuleEntries'] = ObjC.deepUnwrap(config.discoveryModuleEntries);
	}
	return configuration;
}
// main functions
function ConvertTo_SID({API=true, object=".\\root", type="Users",help=false} = {}){
	//goes from "Domain\User" or "Domain\Group" or "Domain\Computer" to SID
	//type should be: Users, Groups, or Computers
	if(help){
	    var output = "";
		output += "\\nConvert Users, Groups, Or Computers to domain or local SIDs.";
		output += "\\n\"object\" should be either \".\\\\localthing\" or \"NETBIOSDOMAIN\\\\thing\"";
		output += "\\n\"type\" should be \"Users\", \"Groups\", or \"Computers\"";
		output += "\\ncalled: ConvertTo_SID({object:\".\\\\root\",type:\"Users\"});";
		return output;
	}
	command = "";
	splitObject = object.split('\\');
	if (splitObject.length != 2)
	{
		return "Invalid format for the object. Should be DOMAIN\\object\n";
	}
	if (API == true) {
		//Use ObjC calls
		if(object.includes(".")){
			//we need to do a local query instead
			var fixed_query = object.split("\\").slice(1);
			var query = Get_OD_ObjectClass({objectclass:type, max_results:1, value:fixed_query, match:"EqualTo", query_attributes:"RecordName", return_attributes:["SMBSID"], nodetype:"local"});
		}else{
			var query = Get_OD_ObjectClass({objectclass:type, max_results:1, value:object, match:"EqualTo", query_attributes:"RecordName", return_attributes:["SMBSID"]});
		}
		try{
	        var sid = query[type][0]["dsAttrTypeStandard:SMBSID"][0];
	        return sid;
	    }catch(err){
	    	return "No such object";
	    }
	}
	else{
		//use command-line functionality
		if (splitObject[0] == ".")
		{ //do a local query
			command = "dscl . read \"/" + type + "/" + splitObject[1] + "\" SMBSID";
		}
		else{
			command = "dscl \"/Active Directory/" + splitObject[0] + 
				"/All Domains\" read \"/" + type + "/" + splitObject[1] + "\" SMBSID";
		}
		//output will either have SMBSID: S-1-5... or No Such Key: SMBSID if user exists
		try{
			output = currApp.doShellScript(command);
			if (output.indexOf("SMBSID: S-") != -1)
				return output.split(" ")[1].trim();
			else
				return "No such key";
		}
		catch(err){
			//<dscl_cmd> DS Error: -14136 (eDSRecordNotFound) if object doesn't exist
			return err.toString();
		}
	}
}
function ConvertFrom_SID({API=true, sid="S-1-5-21-3278496235-3004902057-1244587532-512", type="Users",help=false} = {}){
	//goes from S-1-5-21-... to "Domain\User", "Domain\Group", or "Domain\Computer"
	if(help){
	    var output = "";
		output += "\\nConvert Users, Groups, or Computers from SIDs to names";
		output += "\\n\"sid\" should be a full SID value in quotes for either a User, Group, or Computer. No other type is currently supported.";
		output += "\\n\"type\" should be \"Users\",\"Groups\", or \"Computers\"";
		output += "\\ncalled: ConvertFrom_SID({sid:\"S-1-5-21-3278496235-3004902057-1244587532-512\",type:\"Users\"})";
		return output;
	}
	command = "";
	domain = Get_CurrentNETBIOSDomain(API);
	if (!domain){
		return "Failed to get domain.";
	}
	if (API == true){
		var query = Get_OD_ObjectClass({objectclass:type, max_results:1, value:sid, match:"EqualTo", query_attributes:"SMBSID", return_attributes:["RecordName"]});
        try{
	        var name = query[type][0]["dsAttrTypeStandard:RecordName"][0];
	        return name;
	    }catch(err){
	    	return "No such object";
	    }
	}
	else{
		command = "dscl \"/Active Directory/" + domain + "/All Domains\"" +
		" search /" + type + " SMBSID " + sid;
		try{
			output = currApp.doShellScript(command);
			//example output:
			//root		SMBSID = (
    		//"S-1-5-18"
			//)
			//check to make sure we actually got a result
			if (output){
				user = output.split("\n")[0].split("\t")[0].trim();
				return user;
			}
			return "Command executed returned no output: " + command;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Get_PathAcl({API=false, path="/",help=false} = {}){
	//enumerates and makes readable formats for each ACL on that path
	//ex for "\\SERVER\Share"
	//remote shares need to be mounted first
	//  will be mounted to /Volumes/SERVER/Share
	//https://support.apple.com/kb/PH25344?locale=en_US&viewlocale=en_US
	//	check out that affects things if I still need to deal with the right prefix
	if(help){
	    var output = "";
		output += "\\nGet linux and mac specific ACLs on a file or folder.";
		output += "\\n\"path\" should be any FULL path to a local file or folder. Be careful about escaping quotes though.";
		output += "\\ncalled: Get_PathAcl({path:\"/Users/useraccount/Desktop\"});";
		return output;
	}
	if (API == true){
        return "API method not implemented yet";
	}
	else{
		try{
			//without using an API, the default way to get ACLs on a file/folder is with ls -le
			//where the -e shows ACLs if there are additional ones outside of the standard POSIX ones
			//sample output: -rw-r--r--+ 1 john users  175  5 Jun 00:23 foo
			//				 0: user:dave allow write
			output = currApp.doShellScript("ls -ale \"" + path + "\"");
			return output;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Get_PathXattr({API=false, path="/", recurse=true, value=true, help=false} = {}){
	//Similar to getting ACLs on a file/folder, this gets the extended attributes for it (xattr)
	//can also get these with "ls -l@"
	if(help){
	    var output = "";
		output += "\\nGet mac specific extended attributes on a file or folder.";
		output += "\\n\"path\" should be any FULL path to a file or folder. Be careful about escaping quotes though.";
		output += "\\n\"recurse\" should be true if you want to recursively view the extended attributes.";
		output += "\\n\"value\" should be true if you also want to see the value of the attribute. Default is true.";
		output += "\\ncalled: Get_PathXattr({path:\"/Users/useraccount\",recurse:true});";
		return output;
	}
	if(API == true){
        return "API method not implemented yet";
	}
	else{
		command = "xattr";
		if(recurse){
			command += " -s";
		}
		if(value){
			command += " -l";
		}
		command += " " + path;
		try{
			output = currApp.doShellScript(command);
			return output;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Get_MountedVolumes({API=false, help=false} = {}){
	//list out the current mounted volumes
	//remote ones will be like:
	// //user@host/share size size size % size size % /mount/point
	if(help){
	    var output = "";
		output += "\\nGet the mounted volumes on the current computer";
		output += "\\ncalled: Get_MountedVolumes()";
		return output;
	}
	if (API == true){
        return "API method not implemented yet";
	}
	else{
		try{
			output = currApp.doShellScript("df");
			return output;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Set_MountVolume({API=false, user="", pass="", computerName="", remotePath="", localPath="", type="ntfs", help=false} = {}){
	//mount remote volumes
	if(help){
	    var output = "";
		output += "\\nMount a remote share on the current computer";
		output += "\\n\"user\" should be a username in quotes.";
		output += "\\n\"pass\" should be the password in quotes. This will be escaped with the JavaScript escape function.";
		output += "\\n\"computerName\" is the name of the remote machine that has the share we want to mount.";
		output += "\\n\"remotePath\" is the remote share we want to mount, such as \"ADMIN$\".";
		output += "\\n\"localPath\" is the local mount point. This should already be created.";
		output += "\\n\"type\" will typically be ntfs (which is default) for mounting windows shares.";
		output += "\\ncalled: Set_MountVolume({user:\"mac\",pass:\"abc123!!!\",computerName:\"dc\",remotePath:\"ADMIN$\",localPath:\"/Users/localuser/testmount\"});";
		return output;
	}
	command = "mount -t ";
	if (API == true){
        return "API method not implemented yet";
	}
	else{
		if(type == "ntfs"){
			command += "smbfs";
		}
		else{
			command += type;
		}
		command += " //" + user + ":" + escape(pass) + "@" + computerName + "/" + remotePath + " " + localPath;
		//example: mount -t smbfs //mac:abc123%21%21%21@dc/ADMIN$ /Users/testuser/testmount
		//console.log(command);
		try{
			output = currApp.doShellScript(command);
			return output;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Get_DomainUser({API=true, user, attribute, requested_domain,limit=0, help=false} = {}){
	//returns all users or specific user objects in AD
	//can specify different properties they want returned
	if(help){
	    var output = "";
		output += "\\nList all domain users or get information on a specific user. If no user is specified, list all users.";
		output += "\\n\"user\" should be a domain name.";
		output += "\\n\"attribute\" should be a comma separated list of attributes to select from the returned user. This only works in conjunction with a specific user, not when listing out all users.";
		output += "\\n\"requested_domain\" should be the NETBIOS domain name to query. Most often this will be left blank and auto filled by the function.";
		output += "\\ncalled: Get_DomainUser() <--- list out all domain users";
		output += "\\ncalled: Get_DomainUser({user:\"bob\",attribute:\"name, SMBSID\"});";
		output += "\\nNote: cannot currently query outside of the current forest";
		return output;
	}
	if (API == true){
		if(user){
			if(attribute){
				var query = Get_OD_ObjectClass({value:user, match:"Contains", query_attributes:"recordname", return_attributes:attribute.split(", "), max_results:limit});
			}else{
				var query = Get_OD_ObjectClass({value:user, match:"Contains", query_attributes:"recordname", max_results:limit});
			}
			return JSON.stringify(query, null, 2);
		}
		if(attribute){
			var query = Get_OD_ObjectClass({return_attributes:attribute.split(", "), max_results:limit});
			return JSON.stringify(query, null, 2);
		}
		return JSON.stringify(Get_OD_ObjectClass({max_results:limit}), null, 2);
	}
	else{
		domain = requested_domain ? requested_domain : Get_CurrentNETBIOSDomain(API);
		if(user){
			command = "dscl \"/Active Directory/" + domain + "/All Domains\" read /Users/" + user;
			if(attribute){
				command += " " + attribute;
			}
		}
		else{
			command = "dscl \"/Active Directory/" + domain + "/All Domains\" ls /Users";
			if(attribute){
			    command += " " + attribute;
			}
		}
		try{
		    //console.log(command);
			output = currApp.doShellScript(command);
			return output;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Get_LocalUser({API=true, user, attribute, limit=0, help=false} = {}){
	//returns all users or specific user objects in AD
	//can specify different properties they want returned
	if(help){
	    var output = "";
		output += "\\nList all local users or get information on a specific user. If no user is specified, list all users.";
		output += "\\n\"user\" should be a local user's name.";
		output += "\\n\"attributes\" should be a comma separated list of attributes to select from the returned user. This only works in conjunction with a specific user, not when listing out all users.";
		output += "\\ncalled: Get_LocalUser() <--- list out all local users";
		output += "\\ncalled: Get_LocalUser({user:\"bob\",attribute:\"name, SMBSID\"});";
		return output;
	}
	if (API == true){
		if(user){
			if(attribute){
				var query = Get_OD_ObjectClass({value:user, match:"Contains", query_attributes:"recordname", return_attributes:attribute.split(","), max_results:limit, nodetype:"local"});
			}else{
				var query = Get_OD_ObjectClass({value:user, match:"Contains", query_attributes:"recordname", max_results:limit, nodetype:"local"});
			}
			return JSON.stringify(query, null, 2);
		}
		if(attribute){
			var query = Get_OD_ObjectClass({return_attributes:attribute.split(","), max_results:limit, nodetype:"local"});
			return JSON.stringify(query, null, 2);
		}
		return JSON.stringify(Get_OD_ObjectClass({max_results:limit, nodetype:"local"}), null, 2);
	}
	else{
		if(user){
			command = "dscl . read /Users/" + user;
			if(attribute){
				command += " " + attribute;
			}
		}
		else{
			command = "dscl . ls /Users";
			if(attribute){
			    command += " " + attribute;
			}
		}
		try{
		    //console.log(command);
			output = currApp.doShellScript(command);
			return output;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Get_DomainComputer({API=true, computer, attribute, limit=0, requested_domain,help=false} = {}){
	//returns all computers or specific computer objects in AD
	if(help){
	    var output = "";
		output += "\\nList all domain computers or get information on a specific computer. If no computer is specified, list all computer.";
		output += "\\n\"computer\" should be a domain computer name.";
		output += "\\n\"attributes\" should be a comma separated list of attributes to select from the returned computer. This only works in conjunction with a specific computer, not when listing out all computers.";
		output += "\\n\"requested_domain\" should be the NETBIOS domain name to query. Most often this will be left blank and auto filled by the function.";
		output += "\\ncalled: Get_DomainComputer() <--- list out all domain computers";
		output += "\\ncalled: Get_DomainComputer({computer:\"testmac$\",attribute:\"name\"});";
		return output;
	}
	if (API == true){
		if(computer){
			if(attribute){
				var query = Get_OD_ObjectClass({objectclass:"Computers", value:computer, match:"Contains", query_attributes:"recordname", return_attributes:attribute.split(","), max_results:limit});
			}else{
				var query = Get_OD_ObjectClass({objectclass:"Computers", value:computer, match:"Contains", query_attributes:"recordname", max_results:limit});
			}
			return JSON.stringify(query, null, 2);
		}
		if(attribute){
			var query = Get_OD_ObjectClass({objectclass:"Computers", return_attributes:attribute.split(","), max_results:limit});
			return JSON.stringify(query, null, 2);
		}
		return JSON.stringify(Get_OD_ObjectClass({objectclass:"Computers", max_results:limit}), null, 2);
	}
	else{
		domain = requested_domain ? requested_domain : Get_CurrentNETBIOSDomain(API);
		if(computer){
			command = "dscl \"/Active Directory/" + domain + "/All Domains\" read \"/Computers/" + computer + "\"";
			if(attribute){
				command += " " + attribute;
			}
		}
		else{
			command = "dscl \"/Active Directory/" + domain + "/All Domains\" ls /Computers";
			if(attribute){
			    command += " " + attribute;
			}
		}
		try{
			output = currApp.doShellScript(command);
			return output;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Get_LDAPSearch({API=false, currDomain, remoteDomain, numResults=0, query="", attribute,help=false} = {}){
	if(help){
	    var output = "";
		output += "\\nExecute a customized LDAP search query";
		output += "\\n\"currDomain\" should be the domain to query. Ex: in ldap://currDomain.";
		output += "\\n\"remoteDomain\" should be the search base, typically the same as the currDomain, so it can be left out.";
		output += "\\n\"numResults\" specifies how many results to return where 0 indicates all results.";
		output += "\\n\"query\" is the LDAP query.";
		output += "\\n\"attributes\" is a comma separated list of attributes to selet from the query results.";
		output += "\\ncalled: Get_LDAPSearch({query=\"(objectclass=user)\"})";
		return output;
	}
	if(API == true){
        return "API method not implemented yet";
	}
	else{
		domain = currDomain ? currDomain : Get_CurrentDomain(API);
		adjust = remoteDomain ? remoteDomain.split(".") : domain.split(".");
		rdomain = "";
		for(var i = 0; i < adjust.length; i++){
			rdomain += "DC=" + adjust[i];
			if(i+1 < adjust.length){
				rdomain += ","
			}
		}
		command = "ldapsearch -H ldap://" + domain + " -b " + rdomain + " -z " + numResults + " \"" + query + "\" ";
		if(attribute){
			command += attribute;
		}
		//console.log(command);
		try{
			output = currApp.doShellScript(command);
			return output;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Get_DomainOU({API=false, OU, attribute, requested_domain,help=false} = {}){
	//search for all OUs or specific OU objects in AD
	if(help){
	    var output = "";
		output += "\\nList all domain OUs or get information on a specific OU. If no OU is specified, list all OUs.";
		output += "\\n\"OU\" should be a domain OU name.";
		output += "\\n\"attributes\" should be a comma separated list of attributes to select from the returned OU. This only works in conjunction with a specific OU, not when listing out all OUs.";
		output += "\\n\"requested_domain\" should be the NETBIOS domain name to query. Most often this will be left blank and auto filled by the function.";
		output += "\\ncalled: Get_DomainOU() <--- list out all domain computers";
		output += "\\ncalled: Get_DomainOU({OU:\"Domain Controllers\"});";
		return output;
	}
	if (API == true){
        return "API method not implemented yet";
	}
	else{
		domain = requested_domain ? requested_domain : Get_CurrentNETBIOSDomain(API);
		if(OU){
			command = "dscl \"/Active Directory/" + domain + "/All Domains\" read \"/OrganizationalUnit/" + OU + "\"";
			if(attribute){
				command += " " + attribute;
			}
		}
		else{
			command = "dscl \"/Active Directory/" + domain + "/All Domains\" ls /OrganizationalUnit";
			if(attribute){
			    command += " " + attribute;
			}
		}
		try{
			output = currApp.doShellScript(command);
			return output;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Get_DomainSID({API=true,help=false} = {}){
	//returns SID for current domain or specified domain
	if(help){
	    var output = "";
		output += "\\nGets the SID of the domain by truncating the SID for the \"Domain Admins\" group.";
		output += "\\ncalled: Get_DomainSID()";
		return output;
	}
	if(API == true){
		var domain = Get_CurrentNETBIOSDomain(API);
		var search_value = domain + "\\Domain Computers";
		var domain_computers = Get_OD_ObjectClass({objectclass:"Groups", max_results:1, value:search_value, match:"Contains", query_attributes:"RecordName", return_attributes:["SMBSID"]});
        var sid = domain_computers["Groups"][0]["dsAttrTypeStandard:SMBSID"][0];
        var sid_array = sid.split("-");
        return sid_array.slice(0, sid_array.length-1).join("-");
	}
	else{
		command = "dsmemberutil getsid -G \"Domain Admins\"";
		try{
			output = currApp.doShellScript(command);
			return output.slice(0,-4); //take off the last -512 on the SID that's specific to Domain Admins group
		}
		catch(err){
			return err.toString();
		}
	}
}
function Get_DomainGroup({API=true, group, attribute, requested_domain,help=false,verbose=false, limit=0} = {}){
	//returns all groups or specific groups in an AD
	if(help){
	    var output = "";
		output += "\\nList all domain groups or get information on a specific group. If no group is specified, list all groups.";
		output += "\\n\"group\" should be a domain group name.";
		output += "\\n\"attributes\" should be a comma separated list of attributes to select from the returned group. This only works in conjunction with a specific group, not when listing out all group.";
		output += "\\n\"requested_domain\" should be the NETBIOS domain name to query. Most often this will be left blank and auto filled by the function.";
		output += "\\ncalled: Get_DomainGroup() <--- list out all domain groups";
		output += "\\ncalled: Get_DomainGroup({group:\"Domain Admins\",attribute:\"GroupMembership\"});";
		return output;
	}
	if(API == true){
        if(group){
			if(attribute){
				var query = Get_OD_ObjectClass({objectclass:"Groups", value:group, match:"Contains", query_attributes:"recordname", return_attributes:attribute.split(","), max_results:limit});
			}else{
				var query = Get_OD_ObjectClass({objectclass:"Groups", value:group, match:"Contains", query_attributes:"recordname", max_results:limit});
			}
			return JSON.stringify(query, null, 2);
		}
		if(attribute){
			var query = Get_OD_ObjectClass({objectclass:"Groups", return_attributes:attribute.split(","), max_results:limit});
			return JSON.stringify(query, null, 2);
		}
		return JSON.stringify(Get_OD_ObjectClass({objectclass:"Groups", max_results:limit}), null, 2);
	}
	else{
		domain = requested_domain ? requested_domain : Get_CurrentNETBIOSDomain(API);
		if(group){
		    if(verbose){
                command = "dscl \"/Active Directory/" + domain + "/All Domains\" read \"/Groups/" + group + "\"";
                if(attribute){
                    command += " " + attribute;
                }
            }else{
                command = "dscacheutil -q group -a name \"" + group + "\"";
            }
		}
		else{
			command = "dscl \"/Active Directory/" + domain + "/All Domains\" ls /Groups";
			if(attribute){
			    command += " " + attribute;
			}
		}
		try{
			output = currApp.doShellScript(command);
			return output;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Get_LocalGroup({API=true, group, attribute,help=false, verbose=false, limit=0} = {}){
	//returns all groups or specific groups in an AD
	if(help){
	    var output = "";
		output += "\\nList all local groups or get information on a specific group. If no group is specified, list all groups.";
		output += "\\n\"group\" should be a local group name.";
		output += "\\n\"verbose\" get more verbose output with dscl instead of dscacheutil"
		output += "\\n\"attributes\" should be a comma separated list of attributes to select from the returned group. This only works in conjunction with a specific group, not when listing out all groups, and only when verbose is true.";
		output += "\\ncalled: Get_LocalGroup() <--- list out all domain groups";
		output += "\\ncalled: Get_LocalGroup({group:\"admin\",attributes:\"GroupMembership\"});";
		output += "\\ncalled: Get_LocalGroup({attribute:\"GroupMembership\", verbose:true}); <--- get a mapping of all groups and their GroupMembership";
		return output;
	}
	if(API == true){
        if(group){
			if(attribute){
				var query = Get_OD_ObjectClass({objectclass:"Groups", value:group, match:"Contains", query_attributes:"recordname", return_attributes:attribute.split(","), max_results:limit, nodetype:"local"});
			}else{
				var query = Get_OD_ObjectClass({objectclass:"Groups", value:group, match:"Contains", query_attributes:"recordname", max_results:limit, nodetype:"local"});
			}
			return JSON.stringify(query, null, 2);
		}
		if(attribute){
			var query = Get_OD_ObjectClass({objectclass:"Groups", return_attributes:attribute.split(","), max_results:limit, nodetype:"local"});
			return JSON.stringify(query, null, 2);
		}
		return JSON.stringify(Get_OD_ObjectClass({objectclass:"Groups", max_results:limit, nodetype:"local"}), null, 2);
	}
	else{
		if(group){
		    if(verbose){
                command = "dscl . read \"/Groups/" + group + "\"";
                if(attribute){
                    command += " " + attribute;
                }
            }
            else{
                command = "dscacheutil -q group -a name " + group;
            }
		}
		else{
		    if(verbose){
		        command = "dscl . ls /Groups";
		        if(attribute){
		            command += " " + attribute;
		        }
			}
			else{
			    command = "dscacheutil -q group";
			}
		}
		try{
			output = currApp.doShellScript(command);
			return output;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Get_DomainGroupMember({API=true, group="Domain Admins", domain,help=false, limit=0} = {}){
	if(help){
	    var output = "";
		output += "\\nGet all the members of a specific domain group";
		output += "\\n\"group\" should be a specific domain group to query.";
		output += "\\n\"domain\" is the NETBIOS domain name to query, but if not specified, the function will figure it out.";
		output += "\\ncalled: Get_DomainGroupMember({group:\"Domain Admins\"});";
		return output;
	}
	//return members of a specific domain group
	if(!domain){
		domain = Get_CurrentNETBIOSDomain(API);
	}
	if (API == true){
        return Get_DomainGroup({group:group, attribute:"distinguishedName,member,memberOf,nestedgroups,groupmembership", limit:limit});
	}
	else{
		try{
            if(group){
                command = "dscl \"/Active Directory/" + domain + "/All Domains\" read \"/Groups/" + group + "\" GroupMembership";
            }
			else{
			    command = "dscl \"/Active Directory/" + domain + "/All Domains\" ls /Groups GroupMembership";
			}
			output = currApp.doShellScript(command);
			return output;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Get_LocalGroupMember({API=true, group,help=false, limit=0} = {}){
	if(help){
	    var output = "";
		output += "\\nGet all the members of a specific local group";
		output += "\\n\"group\" should be a specific local group to query.";
		output += "\\ncalled: Get_LocalGroupMember({group:\"admin\"});";
		return output;
	}
	if (API == true){
        return Get_LocalGroup({group:group, attribute:"GroupMembership,nestedGroups,member,memberOf,nestedgroups",limit:limit});
	}
	else{
		try{
            if(group){
                command = "dscl . read \"/Groups/" + group + "\" GroupMembership";
            }
            else{
                command = "dscl . ls /Groups GroupMembership"
            }

			output = currApp.doShellScript(command);
			return output;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Search_LocalGroup({API=false, attribute="GroupMembership", value="", help=false} = {}){
    if(help){
        var output = "";
        output += "\\nSearch a specific group attribute for a specific value";
        output += "\\n\"attribute\" is a specific group attribute to search through, default is \"GroupMembership\"";
        output += "\\n\"value\" is the value to search for";
        output += "\\ncalled: Search_LocalGroups({attribute:\"GroupMembership\", value:\"username\"});";
        return output;
    }
    if (API == true){
        return "API method not implemented yet";
    }
    else{
        try{
            command = "dscl . -search /Groups " + attribute + " " + value;
            output = currApp.doShellScript(command);
            return output;
        }catch(err){
            return err.toString();
        }
    }
}
function Search_DomainGroup({API=false, attribute="GroupMembership", value="", help=false, domain} = {}){
    if(help){
        var output = "";
        output += "\\nSearch a specific group attribute for a specific value";
        output += "\\n\"attribute\" is a specific group attribute to search through, default is \"GroupMembership\"";
        output += "\\n\"value\" is the value to search for";
        output += "\\ncalled: Search_DomainGroups({attribute:\"GroupMembership\", value:\"username\"});";
        return output;
    }
    if(!domain){
		domain = Get_CurrentNETBIOSDomain(API);
	}
    if (API == true){
        return "API method not implemented yet";
    }
    else{
        command = "dscl \"/Active Directory/" + domain + "/All Domains\" -search /Groups " + attribute + " " + value;
        try{
            output = currApp.doShellScript(command);
            return output;
        }
        catch(error){
            return error.toString();
        }
    }
}
function Search_LocalUser({API=false, attribute="UserShell", value="/bin/bash", help=false} = {}){
    if(help){
        var output = "";
        output += "\\nSearch local users attribute for a specific value";
        output += "\\n\"attribute\" is a specific user attribute to search through, default is \"UserShell\"";
        output += "\\n\"value\" is the value to search for, default is \"/bin/bash\"";
        output += "\\ncalled: Search_LocalUsers({attribute:\"UserShell\", value:\"/bin/bash\"});";
        return output;
    }
    if (API == true){
        return "API method not implemented yet";
    }
    else{
        try{
            command = "dscl . -search /Users " + attribute + " " + value;
            output = currApp.doShellScript(command);
            return output;
        }catch(err){
            return err.toString();
        }
    }
}
function Search_DomainUser({API=false, attribute="", value="", help=false, domain} = {}){
    if(help){
        var output = "";
        output += "\\nSearch a specific group attribute for a specific value";
        output += "\\n\"attribute\" is a specific user attribute to search through, default is \"\"";
        output += "\\n\"value\" is the value to search for";
        output += "\\ncalled: Search_DomainUsers({attribute:\"\", value:\"username\"});";
        return output;
    }
    if(!domain){
		domain = Get_CurrentNETBIOSDomain(API);
	}
    if (API == true){
        return "API method not implemented yet";
    }
    else{
        command = "dscl \"/Active Directory/" + domain + "/All Domains\" -search /Users " + attribute + " " + value;
        try{
            output = currApp.doShellScript(command);
            return output;
        }
        catch(error){
            return error.toString();
        }
    }
}
////////////////////////////////////////////////
///////// HELPER FUNCTIONS /////////////////////
////////////////////////////////////////////////
function Get_CurrentDomain(API=true,help=false){
	if(help){
	    var output = "";
		output += "\\nGet the fully qualified current domain";
		output += "\\ncalled: Get_CurrentDomain();";
		return output;
	}
	if(API == true){
		var config = Get_OD_Node_Configuration();
		var keys = Object.keys(config);
		for(var i in keys){
			if(config[keys[i]]['nodeName'] != "Contacts" && config[keys[i]]['nodeName'] != "Search" && config[keys[i]]['nodeName']){
				return config[keys[i]]['trustKerberosPrincipal'].split("@")[1];
			}
		}
	}
	else{
		try{
			output = currApp.doShellScript("dsconfigad -show");
			//Active Directory Forest 		= forest.tld
			//Active Directory Domain 		= domain.tld
			//Computer Account 				= computer-name
			//a bunch of others with (something = something) format
			//Look into Advanced Options - Administrative
			//	preferred domain controller, allowed admin group
			components = output.split("\r");
			domain = components[1].split("=")[1].trim();
			return domain;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Get_CurrentNETBIOSDomain(API=true,help=false){
	if(help){
	    var output = "";
		output += "\\nGet the NETBIOS name of the current domain";
		output += "\\ncalled: Get_CurrentNETBIOSDomain();";
		return output;
	}
	if(API == true){
        var config = Get_OD_Node_Configuration();
		var keys = Object.keys(config);
		for(var i in keys){
			if(config[keys[i]]['nodeName'] != "Contacts" && config[keys[i]]['nodeName'] != "Search" && config[keys[i]]['nodeName']){
				return config[keys[i]]['nodeName'];
			}
		}
	}
	else{
		try{
			output = currApp.doShellScript("echo show com.apple.opendirectoryd.ActiveDirectory | scutil");
			//<dictionary>{
			//DomainForestName : test.local
			//DomainGuid : 01FDCACC-C89D-45B8-8829-3BAB54490F6C
			//DomainNameDns : test.local
			//DomainNameFlat : TEST
			//MachineRole : 3
			//NodeName: /Active Directory/TEST
			//TrustAccount : testmac$
			//}
			components = output.split("\r");
			domain = components[4].split(":")[1].trim();
			return domain;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Get_Forest(API=false,help=false){
	if(help){
	    var output = "";
		output += "\\nGet the fully qualified forest name";
		output += "\\ncalled: Get_Forest();";
		return output;
	}
	if(API == true){
        return "API method not implemented yet";
	}
	else{
		try{
			output = currApp.doShellScript("dsconfigad -show");
			//Active Directory Forest 		= forest.tld
			//Active Directory Domain 		= domain.tld
			//Computer Account 				= computer-name
			//a bunch of others with (something = something) format
			//Look into Advanced Options - Administrative
			//	preferred domain controller, allowed admin group
			components = output.split("\r");
			forest = components[0].split("=")[1].trim();
			return forest;
		}
		catch(err){
			return err.toString();
		}
	}
}
//ConvertTo_SID({API:true, object:"TEST\\Domain Computers", type:"Groups",help:false});
//ConvertFrom_SID({API:true, sid:"S-1-5-21-267508148-270493875-3204280241-515", type:"Groups",help:false});
//Get_DomainUser({user:"lab_admin", attribute:"SMBSID, NFSHomeDirectory"});
//Get_LocalUser({user:"root", attribute:"UserShell, RecordName"});
//Get_DomainComputer({attribute:"servicePrincipalName, distinguishedName"});
//Get_DomainGroup({group:"Domain Admins", attribute:"distinguishedName,member,memberOf"});
//Get_DomainGroupMember({group:"admin"});
//Get_LocalGroup({group:"admin", attribute:"GroupMembership,nestedGroups"});
//Get_LocalGroupMember({group:"admin"});
//console.log("auto executed on import\n" + Get_Forest(false));
