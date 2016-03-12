# Access Tokens on Windows

Privilege escalation is something often performed using a variety of tools or exploits, from Meterpreter's "getsystem" to MS15-051. During this quick introduction to Windows access tokens, I wanted to explore the internal workings of some of these tools, and show just how access token impersonation can be leveraged by penetration testers to help with privilege escalation, or with moving through a Windows domain.

It should be said that there are no 0-days presented in this tutorial. This information presented is gathered from a variety of sources and tools (credited where possible at the bottom of this tutorial), and was initially conceived to satisfy my own curiosity of understanding how many common tools work under the hood.

_Note: The tools created for this tutorial should not be used for a live engagement, they are simply a recreation of other functionality offered by other battle hardened tools for the purpose of learning._

### Access Token Introduction

To quote Wikipedia:

>"An access token is an object encapsulating the security identity of a process or thread". This means that every Windows process has an access token associated with it, containing all the information that Windows requires to make a decision on if the process should be allowed to interact with another securable object, such as a file or another process.

To paraphrase, an access token contains the security permissions for a process or thread, and lets the Windows OS know just what actions a process is permitted to complete.

It is possible for a process to contain 2 different tokens:

* **Primary Token** - This is the access token associated with a process, derived from the users privileges, and is usually a copy of the parent process primary token.
* **Impersonation Token** - This is a secondary token which can be used by a process or thread to allow it to "act" as another user.

Impersonation is an interesting concept, similar to setuid in the \*nix world, a process is permitted to impersonate another user via an impersonation token. This token can come from a variety of sources, from a process connecting to a named pipe, or simply by authenticating a user with a username and password and retrieving an impersonation token.

The uses for this technology make more sense in a domain environment, in which a remote user can connect to a server process, and have his/her account impersonated by a daemon. This allows a daemon to offload access control to the Windows operating system, permitting access only to the files or assets that the connecting user would have.

Of course as with any technology like this, there are a number of areas for exploitation. As shown in the coming sections, I'll present some of the better known ways in which access tokens can be used to an penetration testers benefit.

### Meterpreter _getsystem_ and how it leverages access tokens:

Many of you will have used the _getsystem_ module in Meterpreter before. For those that haven't, _getsystem_ is a module offered by the Metasploit-Framework which allows an administrative account to escalate to the local SYSTEM account. This allows meterpreter to complete useful tasks such as  dumping hashes, a task usually only accessible to the SYSTEM user. With this being such a brilliant tool, I wanted to explore just how this exploit worked under the hood, and how easy it would be to recreate this attack without the use of Metasploit.

For reference, the _getsystem_ module is open-source, and available on [github](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/escalate/getsystem.rb). Offering multiple modes of operation, we will be focusing on the elements which utilise access tokens.

Before continuing, we first need to understand a little on how a process can gain an impersonation token for a user. To facilitate impersonation, Windows provides a number of native API's to developers, for example:

* ImpersonateNamedPipeClient
* ImpersonateLoggedOnUser
* ReturnToSelf
* LogonUser
* OpenProcessToken

Of these, the _ImpersonateNamedPipeClient_ API call is key to the _getsystem_ module, and takes credit for how it achieves its privilege escalation. This call allows a process to impersonate the access token of a process which connects to a named pipe and performs a write of data to that pipe (that last requirement is important ;). For example, if a process belonging to "victim" connects and writes to a named pipe belonging to "attacker", the attacker can effectively call _ImpersonateNamedPipeClient_ to retrieve an impersonation token belonging to "victim", and therefore impersonate this user.

And this is exactly how _getsystem_ works, with the following steps:

1. _getsystem_ creates a new Windows service, set to run as SYSTEM, which when started connects to a named pipe.
2. _getsystem_ spawns a process, which creates a named pipe and awaits a connection from the service.
3. The Windows service is started, causing a connection to be made to the named pipe.
4. The process receives the connection, and calls _ImpersonateNamedPipeClient_, resulting in an impersonation token being created for the SYSTEM user.

All that is left to do is to spawn cmd.exe with the newly gathered SYSTEM impersonation token, and we have a SYSTEM privileged process.

To show how this can be achieved outside of the Meterpreter-Framework, I've created a simple tool which will spawn a SYSTEM shell when executed. This tool follows the same steps as above, and can be found on my github account [here](https://github.com/xpn/getsystem-offline).

To see how this works when executed, a demo can be found below:

[![](http://img.youtube.com/vi/PcMD2eT62bg/0.jpg)](https://youtu.be/PcMD2eT62bg)

### Attacking Process Tokens with Meterpreter with Incognito

OK, so we've seen how access tokens can be used to escalate privileges on a local host, but how about using impersonation to access data stored on other hosts on the network.

For many, _Pass The Hash_ or _SMBRelay_ are still king when it comes to moving throughout a Windows network. However access tokens can, under the right conditions, yield access to file shares, or even Kerberos sessions.

One tool that demonstrates this well is _Incognito_, developed by MWR and integrated into Meterpreter, this module allows an attacker to easily steal access tokens from other running processes, and ultimately allows a pentester to impersonate other users.

A simplistic view of this module boils down to 3 commands:

```
load incognito      # Loads the incognito extension into Meterpereter
list_tokens -u      # Lists all available access tokens by user
impersonate_token   # Steals the access token, and forces the Meterpreter session to act as the victim user
```

As well as allowing us to elevate from an Administrator account to SYSTEM, and onto any other authenticated account currently logged into the host, the real beauty of this attack takes place when there are existing domain logons on a host. For example, using the "list_tokens" command, we find a number of access tokens belonging to domain users listed in one of two categories:

* Delegation Tokens
* Impersonation Tokens

By impersonating a user within the "Impersonation Tokens" category, you are free to access local secure objects, such as files or registry locations which are accessible by this user.

It is with "Delegation Tokens" that things get really interesting. Impersonating a user within this list gives us the ability to access network resources in the context of the user, such as file shares or remote management services.

Below you can find a recreation of this attack using Meterpreter:

[![](http://img.youtube.com/vi/5sxJ4bJT8DM/0.jpg)](https://youtu.be/5sxJ4bJT8DM)

As you will notice, by impersonating the LAB\\Administrator user with a delegation token we have permission to mount the domain controller system drive. This is down to the Kerberos tickets cached in the user session, which are relayed transparently by Windows upon connecting to another domain system, in our case an SMB share.

### How Incognito works

OK, so we've seen how _Incognito_ works when called from a Meterpreter session, but how does this work under the hood?

To understand this, we first need to introduce a few undocumented API's available in the Windows OS, mainly _NtQuerySystemInformation_ and _NtQueryObject_. Whilst Microsoft have released partial documentation regarding these API calls, the majority of useful references can be found within the infosec, or RE community.

First, _NtQuerySystemInformation_. This partially [documented](https://msdn.microsoft.com/en-us/library/windows/desktop/ms724509.aspx) API call allows the caller to perform a wide array of information gathering tasks on the Windows OS, including the ability to retrieve a list of all currently utilised HANDLE's.

By enumerating available HANDLE's, we can use another undocumented API call, _NtQueryObject_, to retrieve information on the type of HANDLE that each represents. Of course for our purpose we are interested in "Token" HANDLE's only, which represent references to Token objects used by a process. By retrieving a list of all Token's exposed by processes on Windows, we can again leverage additional (but supported) Windows API's to spawn a process in the context of the owning account.

And this is exactly how _Incognito_ works:

1. It calls _NtQuerySystemInformation_ with an information class of _SystemHandleInformation_ to retrieve a list of HANDLE's.
2. With each returned HANDLE, it calls _NtQueryObject_ (after duplicating the HANDLE with _DuplicateHandle_, a quirk of this API call) with an information class of _ObjectTypeInformation_.
3. If the returned type is of the type "Token", it calls _GetTokenInformation_ to make sure that it belongs to our victim account.
4. If so, it finally prepares the token (promoting it to a primary token etc..), and calls _CreateProcessWithToken_ to spawn "cmd.exe" in the context of the token owner.

Again to highlight this point, all of the above are Windows API's, nothing relies on an exploit or bypass of Windows security. For this reason, this method still functions on Windows 10 as it did on Windows XP.

To demonstrate the concepts shown above and to help me explore the concepts closely, I've created a simple tool, WinSudo, which can be found on my github account [here](https://github.com/xpn/winsudo). This performs the same tasks as Incognito, except in a standalone tool. A demo of this tool being run against Windows 7 to attack a domain admin can be found here:

[![](http://img.youtube.com/vi/pJz7U6YyTcQ/0.jpg)](https://youtu.be/pJz7U6YyTcQ)

### Bonus Round - How Tokens are managed by the Kernel

For this final section, I'll touch on just how access tokens are managed by the Windows kernel, and recreate some of the concepts shown in the "McDermott Cybersecurity" blog referenced at the end of this tutorial.

Often you will see Windows kernel privilege escalation exploits tamper with a process structure in the kernel address space, with the aim of updating a process token. For example, in the popular MS15-010 privilege escalation exploit (found on exploit-db [here](https://www.exploit-db.com/exploits/37098/)), we can see a number of references to access tokens. We'll be digging a little further into how exploits like this work, and recreating the replacing of a token in the kernel address space.

To complete this analysis, we will be using WinDBG on a Windows 7 x64 virtual machine in which we will be looking to elevate the privileges of our cmd.exe process to SYSTEM by manipulating kernel structures.

OK, so first we need to gather information on our running process:

```
!process 0 0 cmd.exe
```

Here we can see some important information about our process, such as the number of open handles, and the process environment block address:

```
PROCESS fffffa8002edd580
    SessionId: 1  Cid: 0858    Peb: 7fffffd4000  ParentCid: 0578
    DirBase: 09d37000  ObjectTable: fffff8a0012b8ca0  HandleCount:  21.
    Image: cmd.exe
```

For our purpose, we are interested in the provided _PROCESS_ address _fffffa8002edd580_, which is actually a pointer to an _EPROCESS_ structure. The _EPROCESS_ structure, documented by Microsoft [here](https://msdn.microsoft.com/en-us/library/windows/hardware/ff544273.aspx), holds important information about a process, such as the process ID and references to the process threads.

Amongst the many fields in this structure is a pointer to the process's access token, defined by a _TOKEN_ structure. To view the contents of the token, we first must calculate the _TOKEN_ address. On Windows 7 x64, the process _TOKEN_ is located at offset 0x208, which differs throughout each version (and potentially service pack) of Windows. We can retrieve the pointer with the following command:

```
kd> dq fffffa8002edd580+0x208 L1
```

This returns the token address as follows:

```
fffffa80`02edd788  fffff8a0`00d76c51
```

As the token address is referenced within a _EX_FAST_REF_ structure, we must AND the value to gain the true pointer address:

```
kd> ? fffff8a0`00d76c51 & ffffffff`fffffff0

Evaluate expression: -8108884136880 = fffff8a0`00d76c50
```

Which means that our true _TOKEN_ address for cmd.exe is at _fffff8a0\`00d76c50_. Next we can dump out the _TOKEN_ structure members for our process using the following command:

```
kd> !token fffff8a0`00d76c50
```

This gives us an idea of the different information held by the process token:

```
User: S-1-5-21-3262056927-4167910718-262487826-1001
User Groups:
 00 S-1-5-21-3262056927-4167910718-262487826-513
    Attributes - Mandatory Default Enabled
 01 S-1-1-0
    Attributes - Mandatory Default Enabled
 02 S-1-5-32-544
    Attributes - DenyOnly
 03 S-1-5-32-545
    Attributes - Mandatory Default Enabled
 04 S-1-5-4
    Attributes - Mandatory Default Enabled
 05 S-1-2-1
    Attributes - Mandatory Default Enabled
 06 S-1-5-11
    Attributes - Mandatory Default Enabled
 07 S-1-5-15
    Attributes - Mandatory Default Enabled
 08 S-1-5-5-0-2917477
    Attributes - Mandatory Default Enabled LogonId
 09 S-1-2-0
    Attributes - Mandatory Default Enabled
 10 S-1-5-64-10
    Attributes - Mandatory Default Enabled
 11 S-1-16-8192
    Attributes - GroupIntegrity GroupIntegrityEnabled
Primary Group: S-1-5-21-3262056927-4167910718-262487826-513
Privs:
 19 0x000000013 SeShutdownPrivilege               Attributes -
 23 0x000000017 SeChangeNotifyPrivilege           Attributes - Enabled Default
 25 0x000000019 SeUndockPrivilege                 Attributes -
 33 0x000000021 SeIncreaseWorkingSetPrivilege     Attributes -
 34 0x000000022 SeTimeZonePrivilege               Attributes -
```

So how do we escalate our process to SYSTEM access? We just steal the token from another SYSTEM privileged process, such as lsass.exe, and splice this into our cmd.exe _EPROCESS_ using the following:

```
kd> !process 0 0 lsass.exe
kd> dq <LSASS_PROCESS_ADDRESS>+0x208 L1
kd> ? <LSASS_TOKEN_ADDRESS> & FFFFFFFF`FFFFFFF0
kd> !process 0 0 cmd.exe
kd> eq <CMD_EPROCESS_ADDRESS+0x208> <LSASS_TOKEN_ADDRESS>
```

To see what this looks like when run against a live system, I've created a quick demo showing cmd.exe being elevated from a low level user, to SYSTEM privileges.

[![](http://img.youtube.com/vi/wUIfTYSQOO4/0.jpg)](https://youtu.be/wUIfTYSQOO4)

Although this is purely an academic exercise, in further tutorials we will be looking at exploiting Kernel privilege escalation vulnerabilities using this exact technique.

### What's Next?

Hopefully this tutorial has given you a good introduction into the world of Windows access token impersonation, enough to start exploring just how this technology can be leveraged during an assessment.

As you probably will have noticed, the tools above require a bypass of UAC to be useful on an engagement. This is what we will be exploiting in our next tutorial, mainly how tools like "bypassuac" work and how we can achieve this without Metasploit.

Plus, I'm putting the final touches into a kernel exploit which, when executed, results in the removal of code integrity checks which block unsigned Windows drivers from being loaded. Whilst I don't plan on releasing the exploit portion of the code, we will look at code integrity and how this is enforced by the Windows kernel, and just how we can bypass this.

Other than that, I'm open to suggestions :)

### Credit where credit's due:

The below are a bunch of resources useful or recreated in this tutorial:

Token stealing - http://www.ntdsxtract.com/downloads/Token_stealing.pdf  
Token stealing via kernel debug - http://mcdermottcybersecurity.com/articles/x64-kernel-privilege-escalation  
Incognito: https://github.com/rapid7/meterpreter/tree/master/source/extensions/incognito  
GetSystem: https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/escalate/getsystem.rb
