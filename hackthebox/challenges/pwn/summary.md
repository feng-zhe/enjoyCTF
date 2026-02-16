# checklist:

- unprotected format string (e.g. `%100d%7$hn`)
- buffer overflow
- jmp rsi to shellcode
- ret2lib
- overwrite GOT
- execve (syscall with 59)
- ROP
- SROP (e.g. HTB laconic)
- read again (e.g. HTB assemblers-avenge)
- shellcode compression (e.g. HTB assemblers-avenge)

# tips:

- always try pwntools + gdb first 
- use gdb to see the value, don't have to read the rev code and calc values in mind.
- pay attention to the stack alignment (e.g. multiples of 15 bytes), otherwise some instructions may fail. e.g. `movaps`

