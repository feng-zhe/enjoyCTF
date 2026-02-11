# Initial Contact
└─# pwn checksec sick_rop                                                                                                                                                                                                                                                                                                                                                            130 ⨯
[*] '/sda6/tmp/sick-rop/sick_rop'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No

shellcode execution is not likely.
stackoverflow is possible.
binary address is fixed.

# RevEng
ghidra => vuln() has buffer overflow issue.

# Debugging
gdb+gef && pwn cyclic 200 && pwn cyclic -l kaaa
