# checklist:

- unprotected format string (e.g. `%100d%7$hn`)
- buffer overflow
- jmp rsi to shellcode
- ret2lib
- overwrite GOT
- execve (syscall with 59)
- ROP
- SROP (e.g. HTB laconic)
- staged shellcdoe (i.e. read part2 shellcode later) (e.g. HTB assemblers-avenge, crossbow)
- shellcode compression (e.g. HTB assemblers-avenge)
- Out-Of-Bound(OOB) write (e.g. HTB crossbow)
- stack pivot (e.g. HTB crossbow)
- mprotect to change NX (e.g. HTB crossbow)
- leverage fix-address sections when PIE is off (e.g. .bss)

# tips:

- always try pwntools + gdb first 
- use gdb to see the value, don't have to read the rev code and calc values in mind.
- pay attention to the stack alignment (e.g. multiples of 15 bytes), otherwise some instructions may fail. e.g. `movaps` in printf

