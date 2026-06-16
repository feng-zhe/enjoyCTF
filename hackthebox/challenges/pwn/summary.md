# checklist:

- unprotected format string (e.g. `%100d%7$hn`)
- buffer overflow
- jmp rsi to shellcode
- ret2libc
- ret2plt (e.g. HTB finale)
- ret2dlresolve (e.g. HTB void)
- libc identification (e.g. HTB shooting star)
- overwrite GOT
- execve (syscall with 59)
- ROP
- SROP (e.g. HTB laconic)
- staged shellcode (i.e. read part2 shellcode later) (e.g. HTB assemblers-avenge, crossbow)
- shellcode compression (e.g. HTB assemblers-avenge)
- Out-Of-Bound(OOB) write (e.g. HTB crossbow)
- stack pivot (e.g. HTB crossbow)
- mprotect to change NX (e.g. HTB crossbow)
- leverage fix-address sections (e.g. .bss, See tips)
- one gadget (e.g. HTB spooky-time)

# tips:

- always try pwntools + gdb first 
- use gdb to see the value, don't have to read the rev code and calc values in mind.
- pay attention to the stack alignment (e.g. multiples of 16 bytes), otherwise some instructions may fail. e.g. `movaps` in printf, or some libc versions' system().
- To use .bss as the place to read/write data, you need to use (.bss + 0x20) or with more offset otherwise you may overwrite the stdin/out/err address and cause puts() to have no output.
