ObjC.import("Foundation");
ObjC.import("stdio");
//for all of these, there is a switch to use ObjC calls vs terminal calls
currApp = Application.currentApplication();
currApp.includeStandardAdditions = true;

function ConvertTo_SID({API=false, object=".\\root", type="Users",help=false} = {}){
	//goes from "Domain\User" or "Domain\Group" or "Domain\Computer" to SID
	//type should be: Users, Groups, or Computers
	if(help){
		console.log("Convert Users, Groups, Or Computers to domain or local SIDs.");
		console.log("\"object\" should be either \".\\\\localthing\" or \"NETBIOSDOMAIN\\\\thing\"");
		console.log("\"type\" should be \"Users\", \"Groups\", or \"Computers\"");
		console.log("called: ConvertTo_SID({object:\".\\\\root\",type:\"Users\"});");
		return;
	}
	command = "";
	splitObject = object.split('\\');
	if (splitObject.length != 2)
	{
		console.log("Invalid format for the object. Should be DOMAIN\\object\n");
		return;
	}
	if (API == true) {
		//Use ObjC calls
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
				return;
		}
		catch(err){
			//<dscl_cmd> DS Error: -14136 (eDSRecordNotFound) if object doesn't exist
			console.log(err.message);
			return;
		}
	}
}
function ConvertFrom_SID({API=false, sid="S-1-5-21-3278496235-3004902057-1244587532-512", type="Users",help=false} = {}){
	//goes from S-1-5-21-... to "Domain\User", "Domain\Group", or "Domain\Computer"
	if(help){
		console.log("Convert Users, Groups, or Computers from SIDs to names");
		console.log("\"sid\" should be a full SID value in quotes for either a User, Group, or Computer. No other type is currently supported.");
		console.log("\"type\" should be \"Users\",\"Groups\", or \"Computers\"");
		console.log("called: ConvertFrom_SID({sid:\"S-1-5-21-3278496235-3004902057-1244587532-512\",type:\"Users\"})");
		return;
	}
	command = "";
	domain = Get_CurrentNETBIOSDomain(API);
	if (!domain){
		return;
	}
	if (API == true){

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
			return;
		}
		catch(err){
			console.log(err.message);
			return;
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
		console.log("Get linux and mac specific ACLs on a file or folder.");
		console.log("\"path\" should be any FULL path to a local file or folder. Be careful about escaping quotes though.");
		console.log("called: Get_PathAcl({path:\"/Users/useraccount/Desktop\"});");
		return;
	}
	if (API == true){

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
			console.log(err.message);
		}
	}
}
function Get_PathXattr({API=false, path="/", recurse=true, value=true,help=false} = {}){
	//Similar to getting ACLs on a file/folder, this gets the extended attributes for it (xattr)
	//can also get these with "ls -l@"
	if(help){
		console.log("Get mac specific extended attributes on a file or folder.");
		console.log("\"path\" should be any FULL path to a file or folder. Be careful about escaping quotes though.");
		console.log("\"recurse\" should be true if you want to recursively view the extended attributes.");
		console.log("\"value\" should be true if you also want to see the value of the attribute. Default is true.");
		console.log("called: Get_PathXattr({path:\"/Users/useraccount\",recurse:true});");
		return;
	}
	if(API == true){

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
			console.log(err.message);
			return;
		}
	}
}
function Get_MountedVolumes({API=false,help=false} = {}){
	//list out the current mounted volumes
	//remote ones will be like:
	// //user@host/share size size size % size size % /mount/point
	if(help){
		console.log("Get the mounted volumes on the current computer");
		console.log("called: Get_MountedVolumes()");
		return;
	}
	if (API == true){

	}
	else{
		try{
			output = currApp.doShellScript("df");
			return output;
		}
		catch(err){
			console.log(err.message);
			return;
		}
	}
}
function Set_MountVolume({API=false, user="", pass="", computerName="", remotePath="", localPath="", type="ntfs",help=false} = {}){
	//mount remote volumes
	if(help){
		console.log("Mount a remote share on the current computer");
		console.log("\"user\" should be a username in quotes.");
		console.log("\"pass\" should be the password in quotes. This will be escaped with the JavaScript escape function.");
		console.log("\"computerName\" is the name of the remote machine that has the share we want to mount.");
		console.log("\"remotePath\" is the remote share we want to mount, such as \"ADMIN$\".");
		console.log("\"localPath\" is the local mount point. This should already be created.");
		console.log("\"type\" will typically be ntfs (which is default) for mounting windows shares.");
		console.log("called: Set_MountVolume({user:\"mac\",pass:\"abc123!!!\",computerName:\"dc\",remotePath:\"ADMIN$\",localPath:\"/Users/localuser/testmount\"});");
		return;
	}
	command = "mount -t ";
	if (API == true){

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
		console.log(command);
		try{
			output = currApp.doShellScript(command);
			return output;
		}
		catch(err){
			console.log(err.message);
			return;
		}
	}
}
function Get_DomainUser({API=false, user, attributes, requested_domain,help=false} = {}){
	//returns all users or specific user objects in AD
	//can specify different properties they want returned
	if(help){
		console.log("List all domain users or get information on a specific user. If no user is specified, list all users.");
		console.log("\"user\" should be a domain name.")
		console.log("\"attributes\" should be a comma separated list of attributes to select from the returned user. This only works in conjunction with a specific user, not when listing out all users.");
		console.log("\"requested_domain\" should be the NETBIOS domain name to query. Most often this will be left blank and auto filled by the function.");
		console.log("called: Get_DomainUser() <--- list out all domain users");
		console.log("called: Get_DomainUser({user:\"bob\",attributes:\"name, SMBSID\"});");
		return;
	}
	if (API == true){

	}
	else{
		domain = requested_domain ? requested_domain : Get_CurrentNETBIOSDomain(API);
		if(user){
			command = "dscl \"/Active Directory/" + domain + "/All Domains\" read /Users/" + user;
			if(attributes){
				command += " " + attributes;
			}
		}
		else{
			command = "dscl \"/Active Directory/" + domain + "/All Domains\" ls /Users";
		}
		try{
			output = currApp.doShellScript(command);
			return output;
		}
		catch(err){
			console.log(err.message);
			return;
		}
	}
}
function Get_DomainComputer({API=false, computer, attributes, requested_domain,help=false} = {}){
	//returns all computers or specific computer objects in AD
	if(help){
		console.log("List all domain computers or get information on a specific computer. If no computer is specified, list all computer.");
		console.log("\"computer\" should be a domain computer name.")
		console.log("\"attributes\" should be a comma separated list of attributes to select from the returned computer. This only works in conjunction with a specific computer, not when listing out all computers.");
		console.log("\"requested_domain\" should be the NETBIOS domain name to query. Most often this will be left blank and auto filled by the function.");
		console.log("called: Get_DomainComputer() <--- list out all domain computers");
		console.log("called: Get_DomainComputer({computer:\"testmac$\",attributes:\"name\"});");
		return;
	}
	if (API == true){

	}
	else{
		domain = requested_domain ? requested_domain : Get_CurrentNETBIOSDomain(API);
		if(computer){
			command = "dscl \"/Active Directory/" + domain + "/All Domains\" read \"/Computers/" + computer + "\"";
			if(attributes){
				command += " " + attributes;
			}
		}
		else{
			command = "dscl \"/Active Directory/" + domain + "/All Domains\" ls /Computers";
		}
		try{
			output = currApp.doShellScript(command);
			return output;
		}
		catch(err){
			console.log(err.message);
			return;
		}
	}
}
function Get_LDAPSearch({API=false, currDomain, remoteDomain, numResults=0, query="", attributes,help=false} = {}){
	if(help){
		console.log("Execute a customized LDAP search query");
		console.log("\"currDomain\" should be the domain to query. Ex: in ldap://currDomain.");
		console.log("\"remoteDomain\" should be the search base, typically the same as the currDomain, so it can be left out.");
		console.log("\"numResults\" specifies how many results to return where 0 indicates all results.");
		console.log("\"query\" is the LDAP query.");
		console.log("\"attributes\" is a comma separated list of attributes to selet from the query results.");
		console.log("called: Get_LDAPSearch({query=\"(objectclass=user)\"})");
		return;
	}
	if(API == true){

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
		if(attributes){
			command += attributes;
		}
		console.log(command);
		try{
			output = currApp.doShellScript(command);
			return output;
		}
		catch(err){
			console.log(err.message);
			return;
		}
	}
}
function Get_DomainOU({API=false, OU, attributes, requested_domain,help=false} = {}){
	//search for all OUs or specific OU objects in AD
	if(help){
		console.log("List all domain OUs or get information on a specific OU. If no OU is specified, list all OUs.");
		console.log("\"OU\" should be a domain OU name.")
		console.log("\"attributes\" should be a comma separated list of attributes to select from the returned OU. This only works in conjunction with a specific OU, not when listing out all OUs.");
		console.log("\"requested_domain\" should be the NETBIOS domain name to query. Most often this will be left blank and auto filled by the function.");
		console.log("called: Get_DomainOU() <--- list out all domain computers");
		console.log("called: Get_DomainOU({OU:\"Domain Controllers\"});");
		return;
	}
	if (API == true){

	}
	else{
		domain = requested_domain ? requested_domain : Get_CurrentNETBIOSDomain(API);
		if(OU){
			command = "dscl \"/Active Directory/" + domain + "/All Domains\" read \"/OrganizationalUnit/" + OU + "\"";
			if(attributes){
				command += " " + attributes;
			}
		}
		else{
			command = "dscl \"/Active Directory/" + domain + "/All Domains\" ls /OrganizationalUnit";
		}
		try{
			output = currApp.doShellScript(command);
			return output;
		}
		catch(err){
			console.log(err.message);
			return;
		}
	}
}
function Get_DomainSID({API=false,help=false} = {}){
	//returns SID for current domain or specified domain
	if(help){
		console.log("Gets the SID of the domain by truncating the SID for the \"Domain Admins\" group.");
		console.log("called: Get_DomainSID()");
		return;
	}
	if(API == true){

	}
	else{
		command = "dsmemberutil getsid -G \"Domain Admins\"";
		try{
			output = currApp.doShellScript(command);
			return output.slice(0,-4); //take off the last -512 on the SID that's specific to Domain Admins group
		}
		catch(err){
			console.log(err.message);
			return;
		}
	}
}
function Get_DomainGroup({API=false, group, attributes, requested_domain,help=false} = {}){
	//returns all groups or specific groups in an AD
	if(help){
		console.log("List all domain groups or get information on a specific group. If no group is specified, list all groups.");
		console.log("\"group\" should be a domain group name.")
		console.log("\"attributes\" should be a comma separated list of attributes to select from the returned group. This only works in conjunction with a specific group, not when listing out all group.");
		console.log("\"requested_domain\" should be the NETBIOS domain name to query. Most often this will be left blank and auto filled by the function.");
		console.log("called: Get_DomainGroup() <--- list out all domain groups");
		console.log("called: Get_DomainGroup({group:\"Domain Admins\",attributes:\"GroupMembership\"});");
		return;
	}
	if(API == true){

	}
	else{
		domain = requested_domain ? requested_domain : Get_CurrentNETBIOSDomain(API);
		if(group){
			command = "dscl \"/Active Directory/" + domain + "/All Domains\" read \"/Groups/" + group + "\"";
			if(attributes){
				command += " " + attributes;
			}
		}
		else{
			command = "dscl \"/Active Directory/" + domain + "/All Domains\" ls /Groups";
		}
		try{
			output = currApp.doShellScript(command);
			return output;
		}
		catch(err){
			console.log(err.message);
			return;
		}
	}
}
function Get_DomainGroupMember({API=false, group="Domain Admins", domain,help=false} = {}){
	if(help){
		console.log("Get all the members of a specific domain group");
		console.log("\"group\" should be a specific domain group to query.");
		console.log("\"domain\" is the NETBIOS domain name to query, but if not specified, the function will figure it out.");
		console.log("called: Get_DomainGroupMember({group:\"Domain Admins\"});");
		return;
	}
	//return members of a specific domain group
	if(!domain){
		domain = Get_CurrentNETBIOSDomain(API);
	}
	if (API == true){

	}
	else{
		try{

			command = "dscl \"/Active Directory/" + domain + "/All Domains\" read \"/Groups/" + group + "\" GroupMembership";
			output = currApp.doShellScript(command);
			return output;
		}
		catch(err){
			console.log(err.message);
			return;
		}
	}
}
////////////////////////////////////////////////
///////// HELPER FUNCTIONS /////////////////////
////////////////////////////////////////////////
function Get_CurrentDomain(API,help=false){
	if(help){
		console.log("Get the fully qualified current domain");
		console.log("called: Get_CurrentDomain();");
		return;
	}
	if(API == true){

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
			console.log(err.message);
			return;
		}
	}
}
function Get_CurrentNETBIOSDomain(API,help=false){
	if(help){
		console.log("Get the NETBIOS name of the current domain");
		console.log("called: Get_CurrentNETBIOSDomain();");
		return;
	}
	if(API == true){

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
			console.log(err.message);
			return;
		}
	}
}
function Get_Forest(API,help=false){
	if(help){
		console.log("Get the fully qualified forest name");
		console.log("called: Get_Forest();");
		return;
	}
	if(API == true){

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
			console.log(err.message);
			return;
		}
	}
}
//console.log("auto executed on import\n" + Get_Forest(false));