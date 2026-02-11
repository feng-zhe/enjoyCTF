# Initial Contact

## checksec
[*] '/sda6/tmp/challenge/sp_retribution'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'./glibc/'
    Stripped:   No

no canary => stack overflow is possible.
NX enabled => ret2lib is our best hope.

## reveng
ghidra => two sub functions.
- show_missles() => nothing interesting, just printing hardcoded text.
- missle_launcher() contains 2 bugs:
  1. `read(0,local_38,0x1f)` and then printf("...%s...", local_38), but the local_38 is not initialized so it may leak some base address. And I do see some extra output data when it get printed.
  1. `read(0,&local_58,0x84);` can cause stackoverflow

## debugging
gdb + gef
pwn cyclic 500 => pwn cyclic -l 0x6161617861616177 => 88
