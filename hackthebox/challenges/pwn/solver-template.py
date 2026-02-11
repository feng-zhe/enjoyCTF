#!/usr/bin/python3
from pwn import *
import warnings
import re
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'

fname = './sp_entrypoint' 

if len(sys.argv) < 2:
  r    = process(fname)
  # r = gdb.debug(fname, gdbscript='break main\ncontinue')
  print('Running solver locally..\n')
else:
  IP   = str(sys.argv[1]) if len(sys.argv) >= 2 else '0.0.0.0'
  PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337
  r    = remote(IP, PORT)
  print(f'Running solver remotely at {IP} {PORT}\n')

# Shellcode from https://shell-storm.org/shellcode/files/shellcode-806.html
sc = 'TODO'

# Send shellcode
# r.sendlineafter('>', '1')
# r.recvuntil(': ')
r.sendline(sc)
match = re.search(r"HTB{([^}]+)}", r.recvall(timeout=2).decode())
if match:
    print(f'Flag --> {match.group(1)}\n')
else:
    print('No flag found')
