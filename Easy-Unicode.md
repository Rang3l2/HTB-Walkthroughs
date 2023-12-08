
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

The scan showed that port 80 was open and hosting a threat analisys company. Its possible to create a n account on the site which revealed that the site is using json web token(JWT) for authenication. 

insert screen on jwk ------------------------


when the JWK is decoded it shows that the JWK uses the jku header that points to the URL containing the JWKS file containing the public key for verifying the token. 


screen of decoded jwk --------------


If it is possible to change the jku header to point to an attacker controlled server an malicious public key can subsitiued to allow the malicious actor to forge a ticket and have the server verify it on the malicious actors server. This server has controls in place to prevent the server from verifying the token on another server. 

The tester used gobuster to bruteforce the web sites directories and found a "redirect" endpoint. 

```
└──╼ [★]$ gobuster dir -t 1 -u http://10.10.11.126/  -w '/home/rang3r/Documents/Tools/SecLists-master/Discovery/Web-Content/common.txt' --exclude-length 9294
===============================================================
Gobuster v3.1.0

<snip>

/logout               (Status: 308) [Size: 260] [--> http://10.10.11.126/logout/]   
/pricing              (Status: 308) [Size: 262] [--> http://10.10.11.126/pricing/]  
/redirect             (Status: 308) [Size: 264] [--> http://10.10.11.126/redirect/] 
/register             (Status: 308) [Size: 264] [--> http://10.10.11.126/register/] 
/upload               (Status: 308) [Size: 260] [--> http://10.10.11.126/upload/]   
                                                                                    
===============================================================
2023/12/07 23:53:49 Finished
===============================================================

```

Using the redirect endpoint it was possible for the tester to set the jku header to point to the redirect endpoint and set the redirect to point to the tester host. First the tester needed to set up  

```
┌─[192.168.93.129]─[rang3r@parrot]─[~/Projects/machines/unicode/report]
└──╼ [★]$ openssl genrsa -out keypair.pem 2048
Generating RSA private key, 2048 bit long modulus (2 primes)
.....................+++++
..........+++++
e is 65537 (0x010001)
┌─[192.168.93.129]─[rang3r@parrot]─[~/Projects/machines/unicode/report]
└──╼ [★]$ openssl rsa -in keypair.pem -pubout -out publickey.crt
writing RSA key
┌─[192.168.93.129]─[rang3r@parrot]─[~/Projects/machines/unicode/report]
└──╼ [★]$ openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out pkcs8.key
┌─[192.168.93.129]─[rang3r@parrot]─[~/Projects/machines/unicode/report]
└──╼ [★]$ 

```


```
└──╼ [★]$ cat extract_nande.js 
const NodeRSA = require('node-rsa');
const fs = require('fs');
keyPair = fs.readFileSync("keypair.pem");
const key = new NodeRSA(keyPair);
const publicComponents = key.exportKey('components-public');
console.log('Parameter n: ', publicComponents.n.toString("hex"));
console.log('Parameter e: ', publicComponents.e.toString(16));
```


```
└──╼ [★]$ node '/home/rang3r/Projects/machines/unicode/report/extract_nande.js' Parameter n:  00caaea8ebc0afb014ae8fdb83d8a10751bb81c37dbce568b4ca77eba255d20183300a0079f3cddb3b0d89acc85b750f63fb4496ab5ed4d0696d444fbb5b09ca2352e0817f1d912c3631ae406938db3c0bcb136694099e94aac69e5ece40fc0212f749d8c8f0653edd2c13a95ebbc3a2349cb64d845c2265e49cfebd9473e632a7e0ea374b163fe1ae8405e1e3a06c95eb06b4a0549ff152f00b95e8b6a91ae2895eef889059fdddd56949bcdf4c15e74dced3d8ef8405a3aef9801f80ad5edb404507f58057037ffc1222091fc086034a9a8ce0cdbcacda24ddbfff7767493e882c48895133c0e3fcd387fb1fc59c8be9ae9624f3cd121c6cc5e63d37db97d669
Parameter e:  10001

```

## Mitigations 

## References

- https://jwt.io/
- https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection
