# Init
`file reg` =>
reg: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=134349a67c90466b7ce51c67c21834272e92bdbf, for GNU/Linux 3.2.0, not stripped

`pwn checksec reg` =>
[*] '/sda6/tmp/Reg/reg'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No

BOF possible
shellcode not likely
binary addr fixed. 

# RevEng
run() has a simple BOF.

# Debug
