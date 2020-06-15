#!/usr/bin/python3
from pwn import *

# PwnTools
context(arch = 'amd64', os = 'linux', terminal = ['tmux','new-window'])
p = gdb.debug('./myapp')
# p = remote("<url>", "<port>")

# Create Payload
payload = ""
#addr = p64(0x1111)

# p.recvuntil("xxxx")
p.sendline(payload)
p.interactive()
