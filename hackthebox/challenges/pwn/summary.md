# checklist:

- unprotected format string
- stack overflow
- ret2lib

# tips:

- always try pwntools + gdb first 
- use gdb to see the value, don't have to read the rev code and calc values in mind.
- pay attention to the stack alignment (e.g. multiples of 15 bytes), otherwise some instructions may fail. e.g. `movaps`

