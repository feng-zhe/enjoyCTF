#!/usr/bin/env python3

from pwn import *

{bindings}
# libc = ELF('./libc.so.6')
# rop = ROP({bin_name})

context.binary = {bin_name}
context.terminal = ['tmux', 'split', '-h']


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

    # good luck pwning :)

    r.interactive()

if __name__ == "__main__":
    main()
