# Init
## common tcp
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 9c:40:fa:85:9b:01:ac:ac:0e:bc:0c:19:51:8a:ee:27 (RSA)
|   256 5a:0c:c0:3b:9b:76:55:2e:6e:c4:f4:b9:5d:76:17:09 (ECDSA)
|_  256 b7:9d:f7:48:9d:a2:f2:76:30:fd:42:d3:35:3a:80:8c (ED25519)
80/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Welcome

## all tcp
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp   open  http    nginx 1.14.2
8065/tcp open  unknown

## common udp
some results are open|filtered

## Vuln scan
Dos, not interesting.

# Enum
## 8065
Used browser and it is a website: Mattermost
no exploit found

gobuster => error because it redirects to the login page for every url.
wfuzz and ignore that login page response => nothing

google, mattermost is a slack-like app.


## 80
source code => html5 up

gobuster => /error/ => nothing

RTFSC => helpdesk.delivery.htb => "Support Ticket System" by osticket.com

(TODO: surrendered, do it again)
