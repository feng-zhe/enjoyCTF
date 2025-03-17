TL;DR: just return-to-main and ret2lib

# Initial Contact

> pwn checksec sp_retribution
[*] '/root/projects/tmp/challenge/sp_retribution'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'./glibc/'
    Stripped:   No
=> stack overflow allowed.

# BF
A buffer overflow issue is in the missle_launcher(). => after it asks for verification, it calls `read(0,&local_58,0x84)` while the local_58 is just an `undefined8`.
=> ROP may work

pwn cyclic 500 =. pwn cyclic -l 0x6161617861616177 => 88 

# Find GLIBC Base Address

Ran the binary several times and looks like the system() address is fixed. Weird. But we can try. Perhaps the glibc has some speical settings, or just my computer settings.

Noticed that after we enter the coordinates, it prints out some random data. This is because it doesn't clean the buffer before read.
=> This may leak glibc base address.

Test:
- glibc base 0x00007ffff7800000
- the values on the stack doesn't start with 0x7ffff ...

Checking the values on the stack, they are like `0x0000555555400d68`.
=> the value is among the binary's main code. Perhaps we can call system@plt directly?
=> negative, there is no such plt entry because the binary doesn't call it.

TODO: tips: since we can get the binary base address, we can jump back to the missle_launcher and get more chances of buffer overflow.
