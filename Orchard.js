//Author Cody Thomas, @its_a_feature_
ObjC.import("Foundation");
ObjC.import("stdio");
//for all of these, there is a switch to use ObjC calls vs terminal calls
currApp = Application.currentApplication();
currApp.includeStandardAdditions = true;

function ConvertTo_SID({API=false, object=".\\root", type="Users",help=false} = {}){
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
		return "API method not implemented yet";
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
function ConvertFrom_SID({API=false, sid="S-1-5-21-3278496235-3004902057-1244587532-512", type="Users",help=false} = {}){
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
        return "API method not implemented yet."
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
function Get_PathXattr({API=false, path="/", recurse=true, value=true,help=false} = {}){
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
function Get_MountedVolumes({API=false,help=false} = {}){
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
function Set_MountVolume({API=false, user="", pass="", computerName="", remotePath="", localPath="", type="ntfs",help=false} = {}){
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
function Get_DomainUser({API=false, user, attribute, requested_domain,help=false} = {}){
	//returns all users or specific user objects in AD
	//can specify different properties they want returned
	if(help){
	    var output = "";
		output += "\\nList all domain users or get information on a specific user. If no user is specified, list all users.";
		output += "\\n\"user\" should be a domain name.";
		output += "\\n\"attributes\" should be a comma separated list of attributes to select from the returned user. This only works in conjunction with a specific user, not when listing out all users.";
		output += "\\n\"requested_domain\" should be the NETBIOS domain name to query. Most often this will be left blank and auto filled by the function.";
		output += "\\ncalled: Get_DomainUser() <--- list out all domain users";
		output += "\\ncalled: Get_DomainUser({user:\"bob\",attribute:\"name, SMBSID\"});";
		return output;
	}
	if (API == true){
        return "API method not implemented yet";
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
function Get_LocalUser({API=false, user, attribute, help=false} = {}){
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
        return "API method not implemented yet";
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
function Get_DomainComputer({API=false, computer, attribute, requested_domain,help=false} = {}){
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
        return "API method not implemented";
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
function Get_DomainSID({API=false,help=false} = {}){
	//returns SID for current domain or specified domain
	if(help){
	    var output = "";
		output += "\\nGets the SID of the domain by truncating the SID for the \"Domain Admins\" group.";
		output += "\\ncalled: Get_DomainSID()";
		return output;
	}
	if(API == true){
        return "API method no implemented yet";
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
function Get_DomainGroup({API=false, group, attribute, requested_domain,help=false,verbose=false} = {}){
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
        return "API method not implemented yet";
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
function Get_LocalGroup({API=false, group, attribute,help=false, verbose=false} = {}){
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
        return "API method not implemented yet";
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
function Get_DomainGroupMember({API=false, group, domain,help=false} = {}){
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
        return "API method not implemented yet";
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
function Get_LocalGroupMember({API=false, group,help=false} = {}){
	if(help){
	    var output = "";
		output += "\\nGet all the members of a specific local group";
		output += "\\n\"group\" should be a specific local group to query.";
		output += "\\ncalled: Get_LocalGroupMember({group:\"admin\"});";
		return output;
	}
	if (API == true){
        return "API method not implemented yet";
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
function Get_CurrentDomain(API,help=false){
	if(help){
	    var output = "";
		output += "\\nGet the fully qualified current domain";
		output += "\\ncalled: Get_CurrentDomain();";
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
			domain = components[1].split("=")[1].trim();
			return domain;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Get_CurrentNETBIOSDomain(API,help=false){
	if(help){
	    var output = "";
		output += "\\nGet the NETBIOS name of the current domain";
		output += "\\ncalled: Get_CurrentNETBIOSDomain();";
		return output;
	}
	if(API == true){
        return "API method not implemented yet";
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
function Get_Forest(API,help=false){
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
//console.log("auto executed on import\n" + Get_Forest(false));
