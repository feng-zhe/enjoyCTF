#!/usr/bin/env python3

from pwn import *

{bindings}
# libc = elf('./libc.so.6')
# rop = ROP({bin_name})

context.binary = {bin_name}
context.terminal = ['tmux', 'split', '-h']


def conn():
    if args.LOCAL:
        r = process({proc_args})
    elif args.GDB:
          # TODO: add break points, e.g. b *(_main + 0x12)
        r = gdb.debug({proc_args}, '''
                      c
                      ''')
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()

    # good luck pwning :)

    r.interactive()

if __name__ == "__main__":
    main()
