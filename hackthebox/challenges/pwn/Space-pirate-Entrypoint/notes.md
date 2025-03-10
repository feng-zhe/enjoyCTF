TL;DR: unprotected format string. Use the `%100d%7$hn` to overwrite the value pointed by the 7th argument to 100.

ghidra => RTFSC => on obvious vuln found. All read() reads less bytes than the buffer size.

Actually the canary was found, so no stuck overflow:
pwn checksec sp_entrypoint =>
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'./glibc/'
    Stripped:   No

So there might be some logic flaw among the code.

Not likely to overwrite the "deadbeef" to "dead1337". So possibly there is some flaw in `strncpy()` in the `check_pass()`.

I was wrong, this is just FSB.
