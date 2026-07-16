# checklist:

- FSB (Format String Bug) (e.g. `%100d%7$hn`, HTB format)
    - reads: leak binary base/libc function/libc base addresses
    - writes: any location writes
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
- use rop gadget like `mov qword ptr[rdi], rsi` to write content to places like .bss.
- partial overwrite (e.g. HTB snow-scan)
- skip overwriting canary (e.g. HTB bad-grades)
- libc.__malloc_hook overwriting (e.g. HTB format) (only works for glibc <= 2.31)

# tips:

- always try pwntools + gdb first 
- use gdb to see the value, don't have to read the rev code and calc values in mind.
- pay attention to the stack alignment (e.g. multiples of 16 bytes), otherwise some instructions may fail. e.g. `movaps` in printf, or some libc versions' system() (may have not error messages in the output).
- To use .bss as the place to read/write data, you are likely need to use (.bss + 0x20) or with more offset otherwise you may overwrite the stdin/out/err address and cause puts() to have no output.
- The overwrite content may come cross some variables like the buffer pointer which affects the overwriting itself. e.g. HTB abyss, snow-scan.
- For canary, either skip overwriting it or read it from somewhere and write it during BF or Out-Of-Bound writes.
- The rop.chain() may use some gadgets from non-executable segments. If this happens, we should use .search(asm('...'), executable=True) instead.
