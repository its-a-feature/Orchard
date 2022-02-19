# Orchard
JavaScript for Automation (JXA) tool to do Active Directory enumeration. Current version: 1.3

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

## Calling a Function
After you've imported the Orchard.js code into your current session, you can call any of the functions with a slight tweak to normal JavaScript function calls. I wanted to make the code a bit more python-esque, so I modified the calling convention. You'll see functions defined as:

`function ConvertTo_SID({object=".\\root", type="Users"} = {}) { code here; }`. This allows me to provide default values (if desired) to each function parameter as well as preventing them from being positional arguments like standard function calls. To call this function, simply do any of the following:
```JavaScript
ConvertTo_SID(); //Uses all of the default values to call the function
ConvertTo_SID({object:"TEST\\Bob"}); //Sets object and leaves type as "Users"
ConvertTo_SID({object:"TEST\\Bob"}); //same as above - the order of the arguments doesn't matter
```
**Note1:** In defining a function this way, it's "name=value", but when calling the function it's "name:value". It's a little odd, I know, but you're most likely going to be just calling functions anyway.

**Note2:** Every function has a Help flag that can be used to get information about how to run the function

**Note3:** All of the APIs currently take advantage of the OpenDirectory APIs that are available through the JXA-ObjC bridge. These can be pretty powerful, but at the moment means that I can only query information within the current forest. These functions will by default query all domains within the forest. For exmaple: If I'm running on a computer, spooky$, in test.lab.local, then my queries will search the `test.lab.local` and `lab.local` domains automatically. I couldn't find a way to specify a specific server outside the forest to query though, so I cannot query a separate forest that you might have trust with.

# Functions
| Function | Version Introduced | Description| API Version is Default|
| ---------|:------------------|:-----------|:--------|
| ConvertTo_SID |1.2 |Convert Users, Groups, Or Computers to domain or local SIDs | True | 
| ConvertFrom_SID |1.2 |Convert Users, Groups, or Computers from SIDs to names | True |
| Get_DomainUser |1.2 |List all domain users or get information on a specific user | True |
| Get_DomainComputer |1.2 |List all domain computers or get information on a specific computer | True |
| Get_DomainSID |1.2 |Gets the SID of the domain by truncating the SID for the "Domain Admins" group | True |
| Get_DomainGroup |1.2 |List all domain groups or get information on a specific group | True | 
| Get_DomainGroupMember |1.2 |Get all the members of a specific domain group | True | 
| Get_CurrentDomain |1.2 |Get the fully qualified current domain | True | 
| Get_CurrentNETBIOSDomain |1.2 |Get the NETBIOS name of the current domain | True |
| Get_LocalUser | 1.2 | List all local user or get information on a specific user | True | 
| Get_LocalGroup | 1.2 | List all local groups or get information on a specific group | True |
| Get_LocalGroupMember | 1.2 | Get all members for a specific local group | True |
| Get_OD_ObjectClass | 1.2 | Use the OpenDirectory APIs to query the domain, similar to LDAP | True |
| Get_Forest | 1.3 | Use `dsconfigad` to get the name of the forest by running it via bash on the command line | False

# Sample Outputs and Common Attributes
These are some common attributes I've seen that might be useful to query:
## Users / Groups / Computers
The following are specific commands, parameters, and outputs that are useful for working with users both locally and in a domain.

```
Get_DomainUser({match_attribute="recordname", match_attribute_value, return_attributes_list=[null], limit=0, help=false} = {});
```
If you want to get all domain users:
`Get_DomainUser();`
If you want to get all information for a specific user:
`Get_DomainUser({match_attribute_value:"username"});
If you want to get just the SMBSID for a specific user:
`Get_DomainUser({match_attribute_value:"bob", return_attributes_list:["SMBSID"]});`
If you want to look for users that container a certain attribute:
`Get_DomainUser({match_attribute:"HomeDirectory", match_attribute_value:"\\", return_attributes_list:["samaccountname", "HomeDirectory"]});`

The Local versions function exactly the same way:
```
function Get_LocalUser({match_attribute="recordname", match_attribute_value, return_attributes_list=[null], limit=0, help=false} = {})
```

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
