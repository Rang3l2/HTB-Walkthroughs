
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


insert image on reg------------


The tester searched the repositories and found Tomcat credentials in the 971f3aa3f0a0cc8aac12fd696d9631ca540f44c7 commit on the 5 May 2021. 


## Mitigations 

## References
