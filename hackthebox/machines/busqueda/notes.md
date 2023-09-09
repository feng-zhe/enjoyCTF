# Scan
nmap shows there is 22 and 80 port. It also said "http-title: Did not follow redirect to http://searcher.htb/".

# Enum
Added searcher.htb to the /etc/hosts. Visit the http, found a page called "Searcher".
The end of page shows "Powered by Flask and Searchor 2.4.0"
google => https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection/blob/main/exploit.sh
=> foothold

# priv esc
apache config file shows there is another gitea service.
Find the user and password from /var/www/app/.git/config. Try the password and it is the user's password.
sudo -l with password => 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py * 


Play with it and use docker-inspect => find a few passwords

try mysql to docker mysql_db, remember to use `--protocol=tcp`, this can git rid of the `mysqld.sock` error. Because this forces it to connect to server via TCP not sock.
=> I don't want to crack gitea's password.
=> found the administrator user, tried the password we found and try to logon gitea.searcher.htb
=> login as admin
=> can read the src of the scripts hosted in gitea now
=> the './full-chekcup.sh' call in the script is very interesting
=> hijacket it
=> root
